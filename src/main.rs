use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
mod panic;
mod peer;
mod protocol;
mod ratchet;
mod session;
mod tls;
mod tui;
mod types;

use panic::PanicHandler;
use types::{
    ChatMessage, PeerAddr, PeerId, FLAG_SYSTEM_ALONE, FLAG_SYSTEM_INFO, FLAG_SYSTEM_JOIN,
    FLAG_SYSTEM_LEAVE,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut peers: Vec<PeerAddr> = Vec::new();
    let mut phrase = String::new();
    let mut decoy_phrase = String::new();
    let mut start_decoy = false;
    let mut listen_port: u16 = 9000;
    let mut inactivity_timeout_secs: u64 = 300;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" => {
                i += 1;
                let addr: PeerAddr = args[i]
                    .parse()
                    .map_err(|e: String| format!("invalid --peer '{}': {e}", args[i]))?;
                peers.push(addr);
            }
            "--phrase" => {
                i += 1;
                phrase = args[i].clone();
            }
            "--decoy-phrase" => {
                i += 1;
                decoy_phrase = args[i].clone();
            }
            "--decoy" => {
                start_decoy = true;
            }
            "--port" => {
                i += 1;
                listen_port = args[i].parse().map_err(|_| "invalid port")?;
            }
            "--inactivity-timeout" => {
                i += 1;
                inactivity_timeout_secs = args[i].parse().map_err(|_| "invalid timeout")?;
            }
            "--help" | "-h" => {
                println!("Usage: sesame --peer IP:PORT [--peer IP:PORT ...] --phrase \"frase\" [--decoy-phrase \"señuelo\"] [--decoy] [--port 9000] [--inactivity-timeout 300]");
                println!();
                println!("Flags:");
                println!("  --peer IP:PORT              Known peer to connect to (can be repeated)");
                println!("  --phrase \"phrase\"            Auth phrase");
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
        i += 1;
    }

    if phrase.is_empty() {
        eprintln!("Usage: sesame --peer IP:PORT [--peer IP:PORT ...] --phrase \"frase\" [--decoy-phrase \"señuelo\"] [--decoy] [--port 9000] [--inactivity-timeout 300]");
        std::process::exit(1);
    }

    if decoy_phrase.is_empty() {
        decoy_phrase = format!("decoy-{}", &phrase[..phrase.len().min(16)]);
    }

    let active_phrase = if start_decoy { &decoy_phrase } else { &phrase };

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
        active_phrase.to_string(),
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
    }

    Ok(())
}
