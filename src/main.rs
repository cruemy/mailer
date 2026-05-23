use std::sync::Arc;
#[cfg(unix)]
use std::io::Read;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════════════════
// SESAME — P2P ENCRYPTED CHAT (punto de entrada)
// ═══════════════════════════════════════════════════════════════════════════
// Este archivo es el corazon del programa: procesa argumentos, inicializa
// todos los sistemas (TLS, sesiones, TUI), y arranca el loop principal
// que maneja eventos de teclado, mensajes entrantes, y peers descubiertos.
//
// Flujo general:
// 1. Parsear argumentos CLI
// 2. Cargar/establecer configuracion (display name)
// 3. Generar certificados TLS efimeros
// 4. Crear SessionManager
// 5. Arrancar listener TCP/TLS
// 6. Arrancar loop de reconexion
// 7. Arrancar timeout checker
// 8. Conectar a peers iniciales
// 9. Iniciar TUI
// 10. Loop principal: eventos TUI / mensajes descubrimiento / mensajes chat
// ═══════════════════════════════════════════════════════════════════════════

/// Lanza una tarea Tokio supervisada.
///
/// Si la tarea paniquea, el error se captura y se imprime, pero el
/// programa no se cae. Es una capa basica de resiliencia.
///
/// Parametros
/// * `f` — un closure que produce un Future (la tarea a ejecutar)
/// * `name` — nombre de la tarea (para los mensajes de error)
fn spawn_supervised<F, Fut>(f: F, name: &'static str)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = tokio::spawn(f()).await {
            eprintln!("[sesame] task '{name}' panicked: {e:?}");
        }
    });
}

// Declaracion de modulos (cada archivo en src/)
mod auth;
mod config;
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
    ChatMessage, PeerAddr, PeerId, FLAG_SYSTEM_ALONE, FLAG_SYSTEM_DISPLAY_NAME,
    FLAG_SYSTEM_GOODBYE, FLAG_SYSTEM_INFO, FLAG_SYSTEM_JOIN, FLAG_SYSTEM_LEAVE,
};

/// PUNTO DE ENTRADA PRINCIPAL.
///
/// Que hace
/// 1. Aplica hardening al OS (desactivar core dumps, etc.)
/// 2. Parsea argumentos CLI
/// 3. Carga/configura display name
/// 4. Genera certificados TLS efimeros (Ed25519)
/// 5. Crea SessionManager con la frase y config
/// 6. Arranca listener TCP (acepta conexiones entrantes)
/// 7. Arranca loop de reconexion
/// 8. Arranca timeout checker
/// 9. Conecta a peers iniciales
/// 10. Inicia TUI
/// 11. Loop principal: eventos de teclado / peers descubiertos / mensajes
/// 12. Cuando termina, restaura terminal y sale
///
/// Flags CLI
/// --peer IP:PORT (repetible)
/// --phrase "frase" o --phrase-fd FD
/// --decoy-phrase "frase señuelo"
/// --decoy
/// --port N (default 9000)
/// --inactivity-timeout N (default 300)
/// --display-name "Nombre"
/// --help | -h
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Paso 1: Hardening del sistema operativo ──────────────────────
    os_hardening::apply_process_hardening();

    // ── Paso 2: Parsear argumentos CLI ───────────────────────────────
    let mut peers: Vec<PeerAddr> = Vec::new();
    let mut phrase_bytes: Vec<u8> = Vec::new();
    let mut decoy_phrase_bytes: Vec<u8> = Vec::new();
    let mut start_decoy = false;
    let mut listen_port: u16 = 9000;
    let mut inactivity_timeout_secs: u64 = 300;
    let mut cli_display_name: Option<String> = None;

    let mut args = std::env::args().skip(1); // skip el nombre del binario
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
                // Lee la frase desde un file descriptor (Unix only)
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
            "--display-name" => {
                cli_display_name = Some(
                    args.next().ok_or("missing value for --display-name")?,
                );
            }
            "--help" | "-h" => {
                println!("Usage: sesame --peer IP:PORT [--peer IP:PORT ...] (--phrase \"frase\" | --phrase-fd FD) [--decoy-phrase \"señuelo\"] [--decoy] [--port 9000] [--inactivity-timeout 300] [--display-name \"Nombre\"]");
                println!();
                println!("Flags:");
                println!("  --peer IP:PORT              Known peer to connect to (can be repeated)");
                println!("  --phrase \"phrase\"            Auth phrase");
                println!("  --phrase-fd FD               Read auth phrase from file descriptor");
                println!("  --decoy-phrase \"phrase\"      Decoy phrase (default: decoy-<phrase>)");
                println!("  --decoy                     Start in decoy mode");
                println!("  --port N                    Listen port (default: 9000)");
                println!("  --inactivity-timeout N       Seconds before idle peer is dropped (default: 300)");
                println!("  --display-name \"Name\"        Set or update your display name (persisted)");
                println!("  --help, -h                  Show this help");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
    }

    // La frase es obligatoria
    if phrase_bytes.is_empty() {
        eprintln!("Usage: sesame --peer IP:PORT [--peer IP:PORT ...] (--phrase \"frase\" | --phrase-fd FD) [--decoy-phrase \"señuelo\"] [--decoy] [--port 9000] [--inactivity-timeout 300] [--display-name \"Nombre\"]");
        std::process::exit(1);
    }

    // Si no se especifico decoy-phrase, generamos una por defecto
    if decoy_phrase_bytes.is_empty() {
        decoy_phrase_bytes.extend_from_slice(b"decoy-");
        decoy_phrase_bytes.extend_from_slice(&phrase_bytes[..phrase_bytes.len().min(16)]);
    }

    // ── Paso 3: Elegir que frase usar y lockearla en memoria ──────────
    let locked_phrase = if start_decoy {
        LockedBytes::new(std::mem::take(&mut decoy_phrase_bytes))
    } else {
        LockedBytes::new(std::mem::take(&mut phrase_bytes))
    };
    phrase_bytes.zeroize();
    decoy_phrase_bytes.zeroize();

    // ── Paso 4: Cargar/configurar display name ───────────────────────
    let display_name = if let Some(ref name) = cli_display_name {
        eprintln!("[sesame] setting display name to '{name}' at {}",
            config::config_path().display());
        match config::set_display_name(name) {
            Ok(cfg) => cfg.display_name,
            Err(e) => {
                eprintln!("[sesame] warning: could not save display name: {e}");
                Some(name.clone())
            }
        }
    } else {
        let cfg = config::load_config();
        if let Some(ref name) = cfg.display_name {
            eprintln!("[sesame] loaded display name '{name}' from {}",
                config::config_path().display());
        }
        cfg.display_name
    };

    // ── Paso 5: Generar certificados TLS ──────────────────────────────
    // Cada ejecucion genera certificados NUEVOS -> PeerId NUEVO
    let (certs, key) = tls::generate_cert()?;
    // El PeerId es SHA-256 del certificado DER
    let my_id = PeerId::from_cert_der(certs[0].as_ref());

    // Necesitamos clonar la key para tener server + client config
    let key_clone = key.clone_key();
    let server_config = tls::make_server_config(certs.clone(), key)?;
    let client_config = tls::make_client_config(certs, key_clone)?;

    // ── Paso 6: Canal de mensajes (peer -> loop principal -> TUI) ───
    let (msg_tx, mut msg_rx) = mpsc::channel::<(PeerId, ChatMessage)>(1024);

    // ── Paso 7: Crear SessionManager ──────────────────────────────────
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
        display_name,
    ));

    let panic_handler = Arc::new(std::sync::Mutex::new(PanicHandler::new(start_decoy)));

    // ── Paso 8: Arrancar listener TCP ──────────────────────────────────
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{listen_port}")).await?;

    let tcp_listener = listener;
    let acceptor = TlsAcceptor::from(server_config);
    let shared_acceptor = Arc::new(std::sync::Mutex::new(acceptor));

    let session_mgr_listener = session_mgr.clone();
    let acc = shared_acceptor.clone();

    let connector = TlsConnector::from(client_config);
    let shared_connector = Arc::new(std::sync::Mutex::new(connector));

    // Tarea: aceptar conexiones entrantes
    spawn_supervised(
        move || async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, addr)) => {
                        // Configuramos TCP keepalive (detectar conexion muerta)
                        let stream = apply_keepalive(stream);
                        // Clonamos el acceptor actual (por si cambia por panic)
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
                        // Lanzamos una tarea por cada conexion entrante
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

    // ── Paso 9: Loop de reconexion ────────────────────────────────────
    // Cada 5 segundos, intenta reconectar a peers conocidos que no
    // esten conectados actualmente.
    {
        let sm = session_mgr.clone();
        let sc = shared_connector.clone();
        let mut cancel_rx = sm.cancel_rx();
        spawn_supervised(
            move || async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = cancel_rx.changed() => {
                            if *cancel_rx.borrow() {
                                return; // cancelacion global (panic)
                            }
                        }
                    }
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

    // ── Paso 10: Canal de descubrimiento de peers ──────────────────────
    // Cuando recibimos PEER_LIST_RES con direcciones nuevas, van a parar
    // a este canal y el loop principal las procesa para conectarse.
    let (discovery_tx, mut discovery_rx) = mpsc::channel::<PeerAddr>(256);
    session_mgr.set_discovery_tx(discovery_tx);

    // ── Paso 11: Timeout checker ───────────────────────────────────────
    // Cada 30 segundos revisa si hay peers inactivos y los desconecta.
    session_mgr.spawn_timeout_checker();

    // ── Paso 12: Conectar a peers iniciales ────────────────────────────
    if !peers.is_empty() {
        let cn = shared_connector.lock().expect("connector poisoned").clone();
        peer::connect_peers(&peers, session_mgr.clone(), cn);
    }

    // ── Paso 13: Iniciar TUI ──────────────────────────────────────────
    let mut terminal = match tui::setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[tui] setup error: {e}");
            std::process::exit(1);
        }
    };

    let mut event_rx = tui::spawn_event_reader();
    let mut tui_state = tui::TuiState::new(my_id, session_mgr.clone(), panic_handler.clone());

    // ── Paso 14: LOOP PRINCIPAL ───────────────────────────────────────
    //
    // Espera TRES cosas simultaneamente:
    //
    // 1. Evento de teclado (event_rx) -> handle_event()
    //    - Esc: sale del programa (quit = true)
    //    - F12: panic shutdown completo del proceso
    //
    // 2. Peer descubierto (discovery_rx) -> intentar conectar
    //
    // 3. Mensaje entrante (msg_rx) -> segun flags:
    //    - FLAG_SYSTEM_ALONE: panic shutdown completo del proceso
    //    - FLAG_SYSTEM_INFO: mostrar en TUI
    //    - FLAG_SYSTEM_DISPLAY_NAME: actualizar nombre del peer
    //    - FLAG_SYSTEM_GOODBYE: desconectar peer (no reconectar)
    //    - FLAG_SYSTEM_JOIN/LEAVE: mostrar en TUI
    //    - Otro: mostrar en TUI (mensaje real)
    let result: Result<(), Box<dyn std::error::Error>> = loop {
        // Renderizar TUI en cada iteracion
        if let Err(e) = terminal.draw(|f| tui_state.render(f)) {
            break Err(format!("draw error: {e}").into());
        }

        tokio::select! {
            // ── Branch 1: Evento de teclado ─────────────────────────
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        tui_state.handle_event(event);
                        // F12 -> panic shutdown
                        if tui_state.panic_requested {
                            session_mgr.panic_shutdown();
                            let _ = tui::restore_terminal();
                            std::process::exit(0);
                        }
                        // Esc -> salir (enviar GOODBYE si hay peers)
                        if tui_state.quit {
                            if session_mgr.peer_count() > 0 {
                                let goodbye = ChatMessage {
                                    peer_id: my_id,
                                    text: String::new(),
                                    timestamp: 0,
                                    flags: FLAG_SYSTEM_GOODBYE,
                                };
                                if let Ok(data) = serde_json::to_vec(&goodbye) {
                                    session_mgr.broadcast(&data);
                                }
                                // Esperamos 200ms para que los peers reciban el goodbye
                                tokio::time::sleep(Duration::from_millis(200)).await;
                            }
                            break Ok(());
                        }
                    }
                    None => {
                        break Err("event channel closed".into());
                    }
                }
            }

            // ── Branch 2: Peer descubierto ──────────────────────────
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

            // ── Branch 3: Mensaje entrante ──────────────────────────
            maybe_msg = msg_rx.recv() => {
                match maybe_msg {
                    Some((_peer_id, msg)) => {
                        match msg.flags {
                            FLAG_SYSTEM_ALONE => {
                                session_mgr.panic_shutdown();
                                let _ = tui::restore_terminal();
                                std::process::exit(0);
                            }
                            FLAG_SYSTEM_INFO => {
                                tui_state.add_message(msg.peer_id, msg.text, msg.flags);
                            }
                            FLAG_SYSTEM_DISPLAY_NAME => {
                                session_mgr.set_display_name(msg.peer_id, msg.text);
                            }
                            FLAG_SYSTEM_GOODBYE => {
                                // Desconectar peer y no reconectar
                                session_mgr.disconnect_peer(&msg.peer_id);
                                let text = format!("{peer} disconnected", peer = msg.peer_id);
                                tui_state.add_message(PeerId([0u8; 32]), text, FLAG_SYSTEM_INFO);
                                // Si no quedan peers, cerramos tambien
                                if session_mgr.peer_count() == 0 {
                                    tui_state.quit = true;
                                }
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

    // ── Paso 15: Limpieza y salida ────────────────────────────────────
    let _ = tui::restore_terminal();

    if let Err(e) = result {
        eprintln!("[sesame] error: {e}");
        std::process::exit(1);
    }

    std::process::exit(0);
}

/// Configura TCP keepalive en un stream TCP.
///
/// Que hace
/// - Activa keepalive (SO_KEEPALIVE)
/// - Configura tiempo de inicio: 15 segundos
/// - Intervalo entre probes: 5 segundos
///
/// Por que
/// Para detectar conexiones muertas (peer se cuelga, se corta la red,
/// etc.). Sin keepalive, una conexion rota puede quedar abierta
/// indefinidamente.
fn apply_keepalive(stream: tokio::net::TcpStream) -> tokio::net::TcpStream {
    let std = stream.into_std().expect("into_std failed for keepalive");
    let socket_ref = socket2::SockRef::from(&std);
    let _ = socket_ref.set_keepalive(true);
    let _ = socket_ref.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(15))
            .with_interval(std::time::Duration::from_secs(5)),
    );
    tokio::net::TcpStream::from_std(std).expect("from_std after keepalive")
}

/// Lee la frase desde un file descriptor (Unix only).
///
/// Como funciona
/// Lee el archivo vinculado al FD (ej: `/proc/self/fd/0` para stdin).
/// Recorta el ultimo newline si existe.
///
/// Por que es util
/// Pasar la frase por un FD es mas seguro que por la linea de comandos
/// porque:
/// - No queda en el historial del shell
/// - No es visible en `ps aux`
/// - Se puede pasar desde otro proceso via pipe
///
/// Solo Unix
/// En Windows no existe el concepto de /proc/self/fd/N.
///
/// Parametros
/// * `fd` — el numero de file descriptor (0 = stdin, etc.)
///
/// Devuelve
/// Los bytes leidos del FD (sin el newline final).
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

    /// Verifica que read_phrase_fd recorta el newline final.
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
