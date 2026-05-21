use std::sync::Arc;
use std::io::Read;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroize;

fn spawn_supervised<F, Fut>(f: F, name: &'static str)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let jh = tokio::spawn(f());
    tokio::spawn(async move {
        if let Err(e) = jh.await {
            eprintln!("[sesame] task '{name}' panicked: {e:?}");
        }
    });
}

mod auth;
mod crypto;
mod obfuscate;
mod os_hardening;
mod panic;
mod peer;
mod protocol;
mod ratchet;
mod session;
mod tls;
mod tui;
mod types;

use panic::PanicHandler;
use crypto::LockedBytes;
use types::{
    ChatMessage, PeerAddr, PeerId, FLAG_SYSTEM_ALONE, FLAG_SYSTEM_INFO, FLAG_SYSTEM_JOIN,
    FLAG_SYSTEM_LEAVE,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    os_hardening::apply_process_hardening();

    let mut peers: Vec<PeerAddr> = Vec::new();
    let mut phrase_bytes: Vec<u8> = Vec::new();
    let mut decoy_phrase_bytes: Vec<u8> = Vec::new();
    let mut start_decoy = false;
    let mut listen_port: u16 = 9000;
    let mut inactivity_timeout_secs: u64 = 300;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--peer" => {
                let peer = args.next().ok_or("missing value for --peer")?;
                let addr: PeerAddr = peer
                    .parse()
                    .map_err(|e: String| format!("invalid --peer '{peer}': {e}"))?;
                peers.push(addr);
            }
            "--phrase" => {
                phrase_bytes = args.next().ok_or("missing value for --phrase")?.into_bytes();
            }
            "--phrase-fd" => {
                let fd: i32 = args
                    .next()
                    .ok_or("missing value for --phrase-fd")?
                    .parse()
                    .map_err(|_| "invalid phrase fd")?;
                phrase_bytes = read_phrase_fd(fd)?;
            }
            "--decoy-phrase" => {
                decoy_phrase_bytes = args
                    .next()
                    .ok_or("missing value for --decoy-phrase")?
                    .into_bytes();
            }
            "--decoy" => {
                start_decoy = true;
            }
            "--port" => {
                listen_port = args
                    .next()
                    .ok_or("missing value for --port")?
                    .parse()
                    .map_err(|_| "invalid port")?;
            }
            "--inactivity-timeout" => {
                inactivity_timeout_secs = args
                    .next()
                    .ok_or("missing value for --inactivity-timeout")?
                    .parse()
                    .map_err(|_| "invalid timeout")?;
            }
            "--help" | "-h" => {
                println!("Usage: sesame --peer IP:PORT [--peer IP:PORT ...] (--phrase \"frase\" | --phrase-fd FD) [--decoy-phrase \"señuelo\"] [--decoy] [--port 9000] [--inactivity-timeout 300]");
                println!();
                println!("Flags:");
                println!("  --peer IP:PORT              Known peer to connect to (can be repeated)");
                println!("  --phrase \"phrase\"            Auth phrase");
                println!("  --phrase-fd FD               Read auth phrase from file descriptor");
                println!("  --decoy-phrase \"phrase\"      Decoy phrase (default: decoy-<phrase>)");
                println!("  --decoy                     Start in decoy mode");
                println!("  --port N                    Listen port (default: 9000)");
                println!("  --inactivity-timeout N       Seconds before idle peer is dropped (default: 300)");
                println!("  --help, -h                  Show this help");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
    }

    if phrase_bytes.is_empty() {
        eprintln!("Usage: sesame --peer IP:PORT [--peer IP:PORT ...] (--phrase \"frase\" | --phrase-fd FD) [--decoy-phrase \"señuelo\"] [--decoy] [--port 9000] [--inactivity-timeout 300]");
        std::process::exit(1);
    }

    if decoy_phrase_bytes.is_empty() {
        decoy_phrase_bytes.extend_from_slice(b"decoy-");
        decoy_phrase_bytes.extend_from_slice(&phrase_bytes[..phrase_bytes.len().min(16)]);
    }

    let locked_phrase = if start_decoy {
        LockedBytes::new(std::mem::take(&mut decoy_phrase_bytes))
    } else {
        LockedBytes::new(std::mem::take(&mut phrase_bytes))
    };
    phrase_bytes.zeroize();
    decoy_phrase_bytes.zeroize();

    let (certs, key) = tls::generate_cert()?;
    let my_id = PeerId::from_cert_der(certs[0].as_ref());

    let key_clone = key.clone_key();
    let server_config = tls::make_server_config(certs.clone(), key)?;
    let client_config = tls::make_client_config(certs, key_clone)?;

    let (msg_tx, mut msg_rx) = mpsc::channel::<(PeerId, ChatMessage)>(1024);

    let my_listen_addr = PeerAddr {
        ip: "0.0.0.0".parse().unwrap(),
        port: listen_port,
    };

    let session_mgr = Arc::new(session::SessionManager::new(
        locked_phrase,
        msg_tx.clone(),
        Duration::from_secs(inactivity_timeout_secs),
        my_listen_addr,
        my_id,
    ));

    let panic_handler = Arc::new(std::sync::Mutex::new(PanicHandler::new(start_decoy)));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{listen_port}")).await?;

    let tcp_listener = listener;
    let acceptor = TlsAcceptor::from(server_config);
    let shared_acceptor = Arc::new(std::sync::Mutex::new(acceptor));

    let session_mgr_listener = session_mgr.clone();
    let acc = shared_acceptor.clone();

    let connector = TlsConnector::from(client_config);
    let shared_connector = Arc::new(std::sync::Mutex::new(connector));

    spawn_supervised(
        move || async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, addr)) => {
                        let current_acceptor = {
                            let guard = acc.lock().expect("acceptor poisoned");
                            guard.clone()
                        };
                        let tls_stream = match current_acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                session_mgr_listener.system_msg(&format!("listener: TLS accept error: {e}"));
                                continue;
                            }
                        };
                        let sm = session_mgr_listener.clone();
                        let peer_addr = PeerAddr {
                            ip: addr.ip(),
                            port: addr.port(),
                        };
                        tokio::spawn(async move {
                            peer::handle_incoming(tls_stream, peer_addr, sm).await;
                        });
                    }
                    Err(e) => {
                        session_mgr_listener.system_msg(&format!("listener: accept error: {e}"));
                    }
                }
            }
        },
        "listener",
    );

    // Reconnection loop — every 30s try known peers
    {
        let sm = session_mgr.clone();
        let sc = shared_connector.clone();
        spawn_supervised(
            move || async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let addrs = sm.known_peers_list();
                    for addr in addrs {
                        if !sm.is_connected_to_addr(&addr) {
                            let cn = sc.lock().expect("connector poisoned").clone();
                            let a = addr;
                            let s = sm.clone();
                            tokio::spawn(async move {
                                peer::connect_peer(a, s, cn).await;
                            });
                        }
                    }
                }
            },
            "reconnection",
        );
    }

    // Discovery channel — peers discovered via FLAG_PEER_LIST_RES
    let (discovery_tx, mut discovery_rx) = mpsc::channel::<PeerAddr>(256);
    session_mgr.set_discovery_tx(discovery_tx);

    // Inactivity timeout checker
    session_mgr.spawn_timeout_checker();

    // Connect to known peers on startup
    if !peers.is_empty() {
        let cn = shared_connector.lock().expect("connector poisoned").clone();
        peer::connect_peers(&peers, session_mgr.clone(), cn);
    }

    // ── TUI ──
    let mut terminal = match tui::setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[tui] setup error: {e}");
            std::process::exit(1);
        }
    };

    let mut event_rx = tui::spawn_event_reader();
    let mut tui_state = tui::TuiState::new(my_id, session_mgr.clone(), panic_handler.clone());

    let result: Result<(), Box<dyn std::error::Error>> = loop {
        if let Err(e) = terminal.draw(|f| tui_state.render(f)) {
            break Err(format!("draw error: {e}").into());
        }

        tokio::select! {
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        tui_state.handle_event(event);
                        if tui_state.panic_requested {
                            session_mgr.panic_shutdown();
                            tui_state.clear_messages();
                            break Ok(());
                        }
                        if tui_state.quit {
                            break Ok(());
                        }
                    }
                    None => {
                        break Err("event channel closed".into());
                    }
                }
            }
            maybe_addr = discovery_rx.recv() => {
                match maybe_addr {
                    Some(addr) => {
                        let cn = shared_connector.lock().expect("connector poisoned").clone();
                        let sm = session_mgr.clone();
                        let a = addr;
                        tokio::spawn(async move {
                            peer::connect_peer(a, sm, cn).await;
                        });
                    }
                    None => {}
                }
            }
            maybe_msg = msg_rx.recv() => {
                match maybe_msg {
                    Some((_peer_id, msg)) => {
                        match msg.flags {
                            FLAG_SYSTEM_ALONE => {
                                let (certs, key) = tls::generate_cert()?;
                                let new_id = PeerId::from_cert_der(certs[0].as_ref());
                                let kc = key.clone_key();
                                let server_config = tls::make_server_config(certs.clone(), key)?;
                                let client_config = tls::make_client_config(certs, kc)?;
                                let new_acceptor = TlsAcceptor::from(server_config);
                                let new_connector = TlsConnector::from(client_config);
                                 *shared_acceptor.lock().expect("acceptor poisoned") = new_acceptor;
                                 *shared_connector.lock().expect("connector poisoned") = new_connector;
                                 session_mgr.clear_sessions();
                                 session_mgr.clear_known_peers();
                                 session_mgr.set_my_peer_id(new_id);
                                 tui_state.my_id = new_id;
                                tui_state.clear_messages();
                                tui_state.add_message(new_id, "[new identity — waiting for connections]".to_string(), 0);
                            }
                            FLAG_SYSTEM_INFO => {
                                tui_state.add_message(msg.peer_id, msg.text, msg.flags);
                            }
                            FLAG_SYSTEM_JOIN | FLAG_SYSTEM_LEAVE => {
                                tui_state.add_message(msg.peer_id, msg.text, msg.flags);
                            }
                            _ => {
                                tui_state.add_message(msg.peer_id, msg.text, msg.flags);
                            }
                        }
                    }
                    None => {
                        break Err("message channel closed".into());
                    }
                }
            }
        }
    };

    let _ = tui::restore_terminal();

    if let Err(e) = result {
        eprintln!("[sesame] error: {e}");
        std::process::exit(1);
    }

    std::process::exit(0);
}

fn read_phrase_fd(fd: i32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let path = format!("/proc/self/fd/{fd}");
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        Ok(bytes)
    }

    #[cfg(not(unix))]
    {
        let _ = fd;
        Err("--phrase-fd is only supported on Unix targets".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn read_phrase_fd_trims_newline() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let path = std::env::temp_dir().join("sesame-phrase-fd-test");
        {
            let mut file = std::fs::File::create(&path).expect("create phrase fd fixture");
            file.write_all(b"secret\n").expect("write phrase fixture");
        }
        let file = std::fs::File::open(&path).expect("open phrase fd fixture");
        let phrase = read_phrase_fd(file.as_raw_fd()).expect("read phrase fd");
        let _ = std::fs::remove_file(path);

        assert_eq!(phrase, b"secret");
    }
}
