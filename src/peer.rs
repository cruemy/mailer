use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, Semaphore};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::auth::{perform_handshake, AuthRole};
use crate::crypto::LockedDhSecret;
use crate::protocol::{apply_padding, read_frame, remove_padding, write_frame};
use crate::ratchet::{DoubleRatchet, ReceivedFrame};
use crate::session::SessionManager;
use crate::types::{
    ChatMessage, PeerAddr, PeerId, FLAG_DUMMY, FLAG_PEER_LIST_REQ, FLAG_PEER_LIST_RES,
    FLAG_REAL, FLAG_SYSTEM_DISPLAY_NAME, FLAG_SYSTEM_JOIN, FLAG_SYSTEM_LEAVE,
};

// ═══════════════════════════════════════════════════════════════════════════
// MANEJO DE CONEXIONES ENTRE PEERS (handshake + envio/recibo de mensajes)
// ═══════════════════════════════════════════════════════════════════════════
// Este archivo contiene la logica de:
// 1. Conexion saliente (connect_peer) y entrante (handle_incoming)
// 2. Handshake completo sobre TLS (auth + DH + ratchet init)
// 3. Loop principal de mensajes (cifrado, envio, recepcion, descifrado)
// 4. Serializacion de frames del ratchet a la red
// 5. Trafico dummy periodico para ofuscar
// ═══════════════════════════════════════════════════════════════════════════

// Constantes del protocolo wire (formato de red)

/// Tamaño maximo de un mensaje JSON aceptado (64 KB).
const MAX_JSON_SIZE: usize = 1024 * 64; // 64 KB

/// Maximo de handshakes simultaneos (4). Evita que muchos peers
/// intenten conectarse a la vez y sobrecarguen el CPU con Argon2.
const MAX_CONCURRENT_HANDSHAKES: usize = 4;

/// Timeout para el handshake completo (20 segundos).
/// Si en 20 segundos no se completa TLS + PAKE + DH, se aborta.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Version actual del formato de frame del ratchet.
/// Si cambiamos el formato, incrementamos esto para que peers
/// viejos rechacen frames nuevos y viceversa.
const FRAME_VERSION: u8 = 1;

/// Flag para indicar que un frame incluye clave publica DH.
const FRAME_FLAG_DH_PUB: u8 = 1;

/// Semaphore global que limita los handshakes simultaneos.
///
/// Usamos OnceLock para inicializarlo lazy (la primera vez que se
/// llama a esta funcion). Es un singleton compartido por todas las
/// conexiones entrantes y salientes.
fn handshake_limiter() -> &'static Semaphore {
    static LIMITER: OnceLock<Semaphore> = OnceLock::new();
    LIMITER.get_or_init(|| Semaphore::new(MAX_CONCURRENT_HANDSHAKES))
}

// ─── Serializacion de frames del ratchet ─────────────────────────────────
// Estas funciones convierten EncryptedFrame <-> bytes para mandar por la red.
// Formato wire:
//   [1 byte: version] [1 byte: flags] [8 bytes: msg_number] [8 bytes: dh_epoch]
//   [12 bytes: nonce] [0 o 32 bytes: dh_public_key] [N bytes: ciphertext]
//   [16 bytes: tag]

/// Convierte un EncryptedFrame a bytes listos para enviar.
///
/// Formato
/// ```
/// Byte 0:     version (FRAME_VERSION)
/// Byte 1:     flags (bit 0 = tiene DH pub)
/// Bytes 2-9:  msg_number (u64 big-endian)
/// Bytes 10-17: dh_epoch (u64 big-endian)
/// Bytes 18-29: nonce (12 bytes)
/// [Si flags & 1]: bytes 30-61: dh_public_key (32 bytes)
/// Resto:        ciphertext
/// Ultimos 16:  tag Poly1305
/// ```
fn encode_ratchet_frame(encrypted: crate::ratchet::EncryptedFrame) -> Vec<u8> {
    let mut frame = Vec::with_capacity(
        1 + 1 + 8 + 8 + 12 + encrypted.dh_public_key.map(|_| 32).unwrap_or(0) + encrypted.ciphertext.len() + 16,
    );
    let flags = if encrypted.dh_public_key.is_some() {
        FRAME_FLAG_DH_PUB
    } else {
        0
    };
    frame.push(FRAME_VERSION);
    frame.push(flags);
    frame.extend_from_slice(&encrypted.msg_number.to_be_bytes());
    frame.extend_from_slice(&encrypted.dh_epoch.to_be_bytes());
    frame.extend_from_slice(&encrypted.nonce);
    if let Some(dh_pub) = encrypted.dh_public_key {
        frame.extend_from_slice(dh_pub.as_bytes());
    }
    frame.extend_from_slice(&encrypted.ciphertext);
    frame.extend_from_slice(&encrypted.tag);
    frame
}

/// Convierte bytes recibidos a un ReceivedFrame.
///
/// Validaciones
/// - Version debe ser FRAME_VERSION
/// - Flags solo pueden tener FRAME_FLAG_DH_PUB (bits desconocidos = rechazar)
/// - El frame debe tener al menos el tamaño minimo (sin ciphertext)
/// - Si tiene DH pub, debe tener 32 bytes extra
/// - Debe tener al menos 16 bytes para el tag al final
///
/// Devuelve
/// `Some(ReceivedFrame)` si el formato es valido, `None` si no.
fn decode_ratchet_frame(frame: &[u8]) -> Option<ReceivedFrame> {
    // Tamaño minimo: version(1) + flags(1) + msg_number(8) + dh_epoch(8) + nonce(12) + tag(16) = 46
    if frame.len() < 1 + 1 + 8 + 8 + 12 + 16 {
        return None;
    }

    let version = frame[0];
    if version != FRAME_VERSION {
        return None;
    }

    let flags = frame[1];
    // Rechazar flags desconocidos (solo permitimos FRAME_FLAG_DH_PUB)
    if flags & !FRAME_FLAG_DH_PUB != 0 {
        return None;
    }

    let mut cursor = 2;
    let msg_number = u64::from_be_bytes(frame[cursor..cursor + 8].try_into().ok()?);
    cursor += 8;
    let dh_epoch = u64::from_be_bytes(frame[cursor..cursor + 8].try_into().ok()?);
    cursor += 8;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&frame[cursor..cursor + 12]);
    cursor += 12;

    let dh_public_key = if flags & FRAME_FLAG_DH_PUB != 0 {
        // Necesitamos 32 bytes de DH + al menos 16 de tag
        if frame.len() < cursor + 32 + 16 {
            return None;
        }
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&frame[cursor..cursor + 32]);
        cursor += 32;
        Some(PublicKey::from(dh_bytes))
    } else {
        None
    };

    if frame.len() < cursor + 16 {
        return None;
    }
    let tag_start = frame.len() - 16;
    let ciphertext = frame[cursor..tag_start].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&frame[tag_start..]);

    Some(ReceivedFrame {
        nonce,
        msg_number,
        dh_epoch,
        ciphertext,
        tag,
        dh_public_key,
    })
}

/// Calcula el "transcript" de la sesion DH.
///
/// Es un hash SHA-256 de:
/// - Constante "sesame-session-v1"
/// - TLS exporter (key material de la sesion TLS)
/// - Peer IDs de ambos peers (ordenados: initiator, responder)
/// - Claves publicas DH de ambos (ordenadas initiator, responder)
/// - Version del frame
///
/// Por que es necesario
/// Este transcript vincula criptograficamente:
/// - La sesion TLS (exporter)
/// - Las identidades (PeerIDs)
/// - Las claves DH efimeras (X25519)
/// - La version del protocolo
///
/// Si un atacante intenta hacer "key confusion" (ej: convencer a un
/// peer de que una clave DH es de otra sesion), el transcript no
/// coincidiria y la derivacion de claves daria otro resultado.
fn session_transcript(
    is_initiator: bool,
    tls_exporter: &[u8; 32],
    our_peer_id: PeerId,
    their_peer_id: PeerId,
    our_public: PublicKey,
    their_public: PublicKey,
) -> [u8; 32] {
    let (initiator_id, responder_id, initiator_pub, responder_pub) = if is_initiator {
        (our_peer_id, their_peer_id, our_public, their_public)
    } else {
        (their_peer_id, our_peer_id, their_public, our_public)
    };
    crate::crypto::sha256_many(&[
        b"sesame-session-v1",
        tls_exporter,
        &initiator_id.0,
        &responder_id.0,
        initiator_pub.as_bytes(),
        responder_pub.as_bytes(),
        &[FRAME_VERSION],
    ])
}

/// Crea el prefijo AAD (Authenticated Associated Data) para el cifrado.
///
/// Este prefijo se pasa al Double Ratchet, que lo incluye en el AAD
/// de ChaCha20-Poly1305. Asegura que los mensajes solo puedan ser
/// descifrados por el peer correcto en la sesion correcta.
///
/// Contenido
/// - Version del frame (1 byte)
/// - Transcript de sesion (32 bytes)
/// - Peer ID del emisor (32 bytes)
/// - Peer ID del receptor (32 bytes)
fn frame_aad_prefix(transcript: &[u8; 32], sender: PeerId, receiver: PeerId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + 32 + 32);
    aad.push(FRAME_VERSION);
    aad.extend_from_slice(transcript);
    aad.extend_from_slice(&sender.0);
    aad.extend_from_slice(&receiver.0);
    aad
}

// ─── Conexiones entrantes y salientes ─────────────────────────────────────

/// Conecta a un peer remoto (rol CLIENTE).
///
/// Flujo
/// 1. TCP connect a la direccion del peer
/// 2. Configura TCP keepalive
/// 3. Handshake TLS (como cliente, presenta nuestro certificado)
/// 4. Delega a `handle_outgoing` (que llama a `run_peer_session`)
///
/// Parametros
/// * `addr` — direccion IP:puerto del peer a conectar
/// * `session_mgr` — el SessionManager global
/// * `connector` — TlsConnector configurado con nuestro certificado
///
/// Errores manejados
/// - TCP connection refused / timeout
/// - TLS handshake failure
/// - Errores de configuracion de socket
pub async fn connect_peer(
    addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    connector: tokio_rustls::TlsConnector,
) {
    match tokio::net::TcpStream::connect(addr.to_string()).await {
        Ok(stream) => {
            let stream = match stream.into_std() {
                Ok(std) => {
                    let socket_ref = socket2::SockRef::from(&std);
                    let _ = socket_ref.set_keepalive(true);
                    let _ = socket_ref.set_tcp_keepalive(
                        &socket2::TcpKeepalive::new()
                            .with_time(std::time::Duration::from_secs(15))
                            .with_interval(std::time::Duration::from_secs(5)),
                    );
                    tokio::net::TcpStream::from_std(std)
                        .expect("from_std after keepalive")
                }
                Err(e) => {
                    session_mgr.system_msg(&format!("connect_peer: into_std failed: {e}"));
                    return;
                }
            };
            let dns_name = match rustls::pki_types::ServerName::try_from(addr.ip.to_string()) {
                Ok(n) => n,
                Err(e) => {
                    session_mgr.system_msg(&format!("connect_peer: invalid server name: {e}"));
                    return;
                }
            };
            let tls_stream = match connector.connect(dns_name, stream).await {
                Ok(s) => s,
                Err(e) => {
                    session_mgr.system_msg(&format!("connect_peer: TLS connect error: {e}"));
                    return;
                }
            };
            handle_outgoing(tls_stream, addr, session_mgr).await;
        }
        Err(e) => {
            session_mgr.system_msg(&format!("connect_peer: TCP connect error to {addr}: {e}"));
        }
    }
}

/// Conecta a MULTIPLES peers al mismo tiempo.
///
/// Cada peer se conecta en su propia tarea Tokio (paralelo).
/// Esta funcion no espera a que terminen, solo las lanza.
///
/// Parametros
/// * `peers` — slice de direcciones a conectar
/// * `session_mgr` — SessionManager global
/// * `connector` — TlsConnector (clonado para cada peer)
pub fn connect_peers(
    peers: &[PeerAddr],
    session_mgr: Arc<SessionManager>,
    connector: tokio_rustls::TlsConnector,
) {
    for addr in peers {
        let sm = session_mgr.clone();
        let a = addr.clone();
        let cn = connector.clone();
        tokio::spawn(async move {
            connect_peer(a, sm, cn).await;
        });
    }
}

/// Maneja una conexion ENTRANTE (rol SERVIDOR).
///
/// Flujo
/// 1. Envuelve el stream TLS como TlsStream::Server
/// 2. Obtiene el PeerId del peer remoto de su certificado
/// 3. Delega a `run_peer_session`
///
/// Parametros
/// * `inner_stream` — stream TLS entrante
/// * `peer_addr` — direccion IP-puerto del que conecto
/// * `session_mgr` — SessionManager global
pub async fn handle_incoming(
    inner_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
) {
    let tls_stream = tokio_rustls::TlsStream::Server(inner_stream);

    let peer_id = match crate::tls::get_peer_id(&tls_stream) {
        Some(id) => id,
        None => {
            session_mgr.system_msg("incoming: no peer cert, dropping");
            return;
        }
    };

    let sm = session_mgr.clone();
    let result = run_peer_session(tls_stream, peer_id, peer_addr, sm, false).await;
    if let Err(e) = result {
        session_mgr.system_msg(&format!("incoming session error: {e}"));
    }
}

/// Maneja una conexion SALIENTE (rol CLIENTE).
///
/// Similar a `handle_incoming` pero con el stream en modo Client.
///
/// Parametros
/// * `inner_stream` — stream TLS saliente
/// * `peer_addr` — direccion a la que conectamos
/// * `session_mgr` — SessionManager global
pub async fn handle_outgoing(
    inner_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
) {
    let tls_stream = tokio_rustls::TlsStream::Client(inner_stream);

    let peer_id = match crate::tls::get_peer_id(&tls_stream) {
        Some(id) => id,
        None => {
            session_mgr.system_msg("outgoing: no peer cert, dropping");
            return;
        }
    };

    let sm = session_mgr.clone();
    let result = run_peer_session(tls_stream, peer_id, peer_addr, sm, true).await;
    if let Err(e) = result {
        session_mgr.system_msg(&format!("outgoing session error: {e}"));
    }
}

// ─── Loop principal de sesion ────────────────────────────────────────────

/// Ejecuta la sesion completa con un peer: handshake + loop de mensajes.
///
/// Que hace
/// 1. Adquiere un permiso del semaforo de handshake (max 4 simultaneos)
/// 2. Determina el rol (Initiator si conectamos, Responder si recibimos)
/// 3. Exporta el TLS exporter key material
/// 4. Ejecuta el handshake SPAKE2 (PAKE) + auth proof
/// 5. Intercambia claves publicas DH + puerto de escucha
/// 6. Calcula el transcript de sesion
/// 7. Deriva la root chain del Double Ratchet
/// 8. Crea el DoubleRatchet con las claves iniciales
/// 9. Registra la sesion en SessionManager
/// 10. Si hay mas de 1 peer (incluyendo este nuevo), avisa a los demas via SYSTEM_JOIN
/// 11. Envia nuestro display name al nuevo peer (si tenemos uno configurado)
/// 12. Si somos initiator, pide la lista de peers conocidos (mesh discovery)
/// 13. Entra en el loop principal de mensajes
///
/// Loop principal de mensajes (tokio::select! con 5 branches):
/// a. Mensaje para enviar (msg_rx) -> cifra con ratchet y envia
/// b. Frame recibido (read_frame) -> descifra con ratchet y procesa
/// c. Timer de dummy -> envia mensaje dummy periodico para ofuscar trafico
/// d. Cancelacion global (cancel_rx) -> panic shutdown
/// e. Cancelacion local (cancel_notify) -> disconnect_peer forzado
///
/// Cuando se sale del loop (desconexion), envia SYSTEM_LEAVE a los
/// demas peers y remueve la sesion.
///
/// Parametros
/// * `tls_stream` — stream TLS (puede ser Client o Server)
/// * `peer_id` — PeerId del peer remoto
/// * `peer_addr` — direccion del peer (IP:puerto)
/// * `session_mgr` — SessionManager global
/// * `is_initiator` — true si nosotros iniciamos la conexion
#[allow(clippy::too_many_arguments)]
async fn run_peer_session(
    mut tls_stream: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    peer_id: PeerId,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    is_initiator: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Handshake ──────────────────────────────────────────────────────

    // Esperamos un permiso del semaforo (max N handshakes simultaneos)
    let _handshake_permit = handshake_limiter().acquire().await?;
    let role = if is_initiator {
        AuthRole::Initiator
    } else {
        AuthRole::Responder
    };

    // Exportamos material unico de la sesion TLS (previene MITM)
    let tls_exporter = crate::tls::export_transcript_key(&tls_stream)?;

    // Handshake SPAKE2 con timeout de 20 segundos
    let auth = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        perform_handshake(
            &mut tls_stream,
            session_mgr.phrase(),
            role,
            session_mgr.my_peer_id(),
            peer_id,
            &tls_exporter,
        ),
    )
    .await??;
    let session_key = auth.session_key;

    // ── Intercambio de claves DH + puerto ──────────────────────────────

    // Generamos nuestro par DH efimero
    let our_secret = LockedDhSecret::generate();
    let our_public = our_secret.public_key();

    // Intercambiamos 34 bytes: clave publica DH (32) + puerto de escucha (2)
    // El puerto de escucha es necesario para que el otro peer sepa a donde
    // reconectarnos (porque el puerto de la conexion TCP actual puede ser
    // efimero/distinto del puerto de escucha).
    let mut their_buf = [0u8; 34];
    let mut our_buf = [0u8; 34];
    our_buf[..32].copy_from_slice(our_public.as_bytes());
    our_buf[32..34].copy_from_slice(&session_mgr.my_listen_addr.port.to_be_bytes());

    if is_initiator {
        tls_stream.write_all(&our_buf).await?;
        tls_stream.read_exact(&mut their_buf).await?;
    } else {
        tls_stream.read_exact(&mut their_buf).await?;
        tls_stream.write_all(&our_buf).await?;
    }

    let mut their_pub_bytes = [0u8; 32];
    their_pub_bytes.copy_from_slice(&their_buf[..32]);
    let their_listen_port = u16::from_be_bytes([their_buf[32], their_buf[33]]);
    let their_public = PublicKey::from(their_pub_bytes);
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // ── Derivacion de la root chain del Double Ratchet ─────────────────

    // El transcript vincula: TLS exporter + PeerIDs + claves DH
    let transcript = session_transcript(
        is_initiator,
        &tls_exporter,
        session_mgr.my_peer_id(),
        peer_id,
        our_public,
        their_public,
    );

    // La root chain se deriva de: session_key (SPAKE2) + DH shared_secret + transcript
    let mut root_chain = [0u8; 32];
    crate::crypto::hkdf_expand_with_salt(
        session_key.as_bytes(),
        &crate::crypto::sha256_many(&[shared_secret.as_bytes(), &transcript]),
        b"sesame-root-v1",
        &mut root_chain,
    );

    // Creamos el Double Ratchet
    let mut ratchet = DoubleRatchet::new(
        &root_chain,
        our_secret,
        our_public,
        Some(their_public),
        is_initiator,
        100,
    );

    // Limpiamos claves temporales de la pila
    drop(session_key);
    root_chain.zeroize();

    // Preparamos los prefijos AAD para enviar y recibir
    // send_aad = "yo->peer", recv_aad = "peer->yo"
    let send_aad = frame_aad_prefix(&transcript, session_mgr.my_peer_id(), peer_id);
    let recv_aad = frame_aad_prefix(&transcript, peer_id, session_mgr.my_peer_id());

    // Separamos el stream en reader + writer (necesario para
    // tokio::select! que requiere &mut separados)
    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    // Canal para recibir mensajes a enviar desde SessionManager
    let (msg_tx, mut msg_rx) = mpsc::channel::<Vec<u8>>(256);
    let cancel_notify = Arc::new(Notify::new());

    // Direccion para reconexion: usamos el puerto de escucha del peer,
    // no el puerto efimero de la conexion TCP
    let session_addr = PeerAddr {
        ip: peer_addr.ip,
        port: their_listen_port,
    };
    let session_handle = crate::session::SessionHandle {
        peer_id,
        peer_addr: session_addr,
        sender: msg_tx,
        connected_since: Instant::now(),
        last_message: Instant::now(),
        cancel_notify: cancel_notify.clone(),
    };

    // ── Registro de sesion ─────────────────────────────────────────────

    if let Err(e) = session_mgr.register_session(session_handle) {
        if e == "duplicate session" {
            return Ok(());
        }
        session_mgr.system_msg(&format!("session registration failed: {e}"));
        return Err(e.into());
    }

    // ── Notificaciones post-conexion ───────────────────────────────────

    // Si hay otros peers, avisarles que este peer se unio
    if session_mgr.peer_count() > 1 {
        let join_msg = ChatMessage {
            peer_id,
            text: String::new(),
            timestamp: 0,
            flags: FLAG_SYSTEM_JOIN,
        };
        if let Ok(data) = serde_json::to_vec(&join_msg) {
            session_mgr.broadcast_except(&data, &peer_id);
        }
    }

    // Notificar en la TUI local
    {
        session_mgr.system_msg(&format!("connected {peer_id}"));
    }

    // Enviar nuestro display name al nuevo peer
    if let Some(name) = session_mgr.my_display_name() {
        eprintln!("[sesame] sending display name '{name}' to {peer_id}");
        let dn_msg = ChatMessage {
            peer_id: session_mgr.my_peer_id(),
            text: name,
            timestamp: 0,
            flags: FLAG_SYSTEM_DISPLAY_NAME,
        };
        if let Ok(data) = serde_json::to_vec(&dn_msg) {
            if let Some(sender) = session_mgr.get_sender(&peer_id) {
                let _ = sender.try_send(data);
            }
        }
    }

    // Si somos initiator, pedimos la lista de peers conocidos (mesh discovery)
    if is_initiator {
        let req = ChatMessage {
            peer_id,
            text: String::new(),
            timestamp: 0,
            flags: FLAG_PEER_LIST_REQ,
        };
        if let Ok(data) = serde_json::to_vec(&req) {
            let encrypted = ratchet.encrypt(&data, &send_aad);
            let frame = encode_ratchet_frame(encrypted);
            let padded = apply_padding(&frame);
            let _ = write_frame(&mut writer, &padded).await;
        }
    }

    // ── Loop principal de mensajes ────────────────────────────────────

    let mut cancel_rx = session_mgr.cancel_rx();
    let mut dummy_timer = tokio::time::interval(crate::obfuscate::dummy_interval());
    dummy_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    dummy_timer.tick().await;

    // Deteccion de conexion perdida via fallos de escritura dummy
    let max_dummy_failures: usize = 3;
    let mut consecutive_dummy_failures: usize = 0;

    loop {
        tokio::select! {
            // ── Branch 1: tenemos un mensaje para enviar ────────────
            data = msg_rx.recv() => {
                let data = match data {
                    Some(d) => d,
                    None => break,
                };

                let encrypted = ratchet.encrypt(&data, &send_aad);
                let frame = encode_ratchet_frame(encrypted);

                let padded = apply_padding(&frame);
                if write_frame(&mut writer, &padded).await.is_err() {
                    break;
                }
                consecutive_dummy_failures = 0;
            }

            // ── Branch 2: recibimos un frame ────────────────────────
            result = read_frame(&mut reader) => {
                let padded = match result {
                    Ok(f) => f,
                    Err(_) => break,
                };

                // Removemos el padding (relleno de tamaño fijo)
                let unpadded = match remove_padding(&padded) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Decodificamos el frame del ratchet
                let received = match decode_ratchet_frame(unpadded) {
                    Some(frame) => frame,
                    None => continue,
                };

                // Desciframos con el Double Ratchet
                let plaintext = match ratchet.decrypt(&received, &recv_aad) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Validamos tamaño maximo del JSON
                if plaintext.len() > MAX_JSON_SIZE {
                    session_mgr.system_msg(&format!("oversized json from {peer_id}, dropping"));
                    continue;
                }

                // Deserializamos el mensaje JSON
                let msg: ChatMessage = match serde_json::from_slice(&plaintext) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                session_mgr.update_last_message(&peer_id);

                // Procesamos segun el tipo (flag) del mensaje
                match msg.flags {
                    FLAG_DUMMY => continue, // mensaje dummy, lo ignoramos

                    FLAG_PEER_LIST_REQ => {
                        // Nos piden nuestra lista de peers conectados
                        let addrs = session_mgr.list_peer_addresses(&peer_id);
                        let resp = ChatMessage {
                            peer_id,
                            text: serde_json::to_string(&addrs).unwrap_or_default(),
                            timestamp: 0,
                            flags: FLAG_PEER_LIST_RES,
                        };
                        if let Ok(data) = serde_json::to_vec(&resp) {
                            let encrypted = ratchet.encrypt(&data, &send_aad);
                            let frame = encode_ratchet_frame(encrypted);
                            let padded = apply_padding(&frame);
                            let _ = write_frame(&mut writer, &padded).await;
                        }
                    }

                    FLAG_PEER_LIST_RES => {
                        // Recibimos una lista de peers para descubrir
                        if msg.text.len() > MAX_JSON_SIZE {
                            continue;
                        }
                        let addrs: Vec<PeerAddr> = serde_json::from_str(&msg.text).unwrap_or_default();
                        for addr in addrs {
                            if addr == session_mgr.my_listen_addr {
                                continue; // no conectarse a uno mismo
                            }
                            if session_mgr.is_connected_to_addr(&addr) {
                                continue; // ya conectado
                            }
                            session_mgr.send_discovered(&addr); // enviar al discovery channel
                        }
                    }

                    FLAG_SYSTEM_JOIN | FLAG_SYSTEM_LEAVE => {
                        let _ = session_mgr.message_tx.try_send((peer_id, msg));
                    }

                    FLAG_SYSTEM_DISPLAY_NAME => {
                        let _ = session_mgr.message_tx.try_send((peer_id, msg));
                    }

                    FLAG_REAL => {
                        let _ = session_mgr.message_tx.try_send((peer_id, msg));
                    }

                    _ => continue,
                }
            }

            // ── Branch 3: timer de mensajes dummy ───────────────────
            _ = dummy_timer.tick() => {
                let dummy_msg = ChatMessage {
                    peer_id,
                    text: String::new(),
                    timestamp: 0,
                    flags: FLAG_DUMMY,
                };
                if let Ok(data) = serde_json::to_vec(&dummy_msg) {
                    let encrypted = ratchet.encrypt(&data, &send_aad);
                    let frame = encode_ratchet_frame(encrypted);
                    let padded = apply_padding(&frame);
                    if write_frame(&mut writer, &padded).await.is_err() {
                        consecutive_dummy_failures += 1;
                        // Si fallan 3 mensajes dummy seguidos, asumimos
                        // que la conexion se perdio y salimos del loop
                        // para que el sistema de reconexion intente de nuevo
                        if consecutive_dummy_failures >= max_dummy_failures {
                            session_mgr.system_msg(&format!("connection lost to {peer_id}, reconnecting..."));
                            break;
                        }
                    } else {
                        consecutive_dummy_failures = 0;
                    }
                }
                // Reseteamos el timer con un nuevo intervalo aleatorio
                let interval = crate::obfuscate::dummy_interval();
                dummy_timer = tokio::time::interval(interval);
                dummy_timer.tick().await;
            }

            // ── Branch 4: cancelacion global (panic) ────────────────
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break;
                }
            }

            // ── Branch 5: cancelacion local (disconnect_peer) ───────
            _ = cancel_notify.notified() => {
                break;
            }
        }
    }

    // ── Limpieza al salir ──────────────────────────────────────────────

    // Avisar a los demas peers que este peer se fue
    {
        let leave_msg = ChatMessage {
            peer_id,
            text: String::new(),
            timestamp: 0,
            flags: FLAG_SYSTEM_LEAVE,
        };
        session_mgr.broadcast_except(&serde_json::to_vec(&leave_msg).unwrap_or_default(), &peer_id);
    }

    session_mgr.remove_session(&peer_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::EncryptedFrame;

    /// Verifica que encode/decode de frames del ratchet funciona
    /// correctamente cuando el frame incluye clave publica DH.
    #[test]
    fn ratchet_frame_round_trips_with_dh_public_key() {
        let dh_public_key = PublicKey::from([9u8; 32]);
        let encrypted = EncryptedFrame {
            nonce: [1u8; 12],
            msg_number: 7,
            dh_epoch: 8,
            ciphertext: vec![2, 3, 4, 5],
            tag: [6u8; 16],
            dh_public_key: Some(dh_public_key),
        };

        let encoded = encode_ratchet_frame(encrypted);
        let decoded = decode_ratchet_frame(&encoded).expect("valid DH frame");

        assert_eq!(decoded.nonce, [1u8; 12]);
        assert_eq!(decoded.msg_number, 7);
        assert_eq!(decoded.dh_epoch, 8);
        assert_eq!(decoded.ciphertext, vec![2, 3, 4, 5]);
        assert_eq!(decoded.tag, [6u8; 16]);
        assert_eq!(decoded.dh_public_key.unwrap().as_bytes(), dh_public_key.as_bytes());
    }

    /// Verifica que decode rechaza frames con flags desconocidos.
    #[test]
    fn ratchet_frame_rejects_unknown_flags() {
        let encrypted = EncryptedFrame {
            nonce: [1u8; 12],
            msg_number: 0,
            dh_epoch: 0,
            ciphertext: vec![2, 3],
            tag: [4u8; 16],
            dh_public_key: None,
        };
        let mut encoded = encode_ratchet_frame(encrypted);
        encoded[1] = 0x80; // flag desconocido

        assert!(decode_ratchet_frame(&encoded).is_none());
    }

    /// Verifica que decode rechaza frames con version desconocida.
    #[test]
    fn ratchet_frame_rejects_unknown_version() {
        let encrypted = EncryptedFrame {
            nonce: [1u8; 12],
            msg_number: 0,
            dh_epoch: 0,
            ciphertext: vec![2, 3],
            tag: [4u8; 16],
            dh_public_key: None,
        };
        let mut encoded = encode_ratchet_frame(encrypted);
        encoded[0] = FRAME_VERSION + 1; // version desconocida

        assert!(decode_ratchet_frame(&encoded).is_none());
    }
}
