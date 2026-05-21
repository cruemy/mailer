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

const MAX_JSON_SIZE: usize = 1024 * 64; // 64 KB
const MAX_CONCURRENT_HANDSHAKES: usize = 4;
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const FRAME_VERSION: u8 = 1;
const FRAME_FLAG_DH_PUB: u8 = 1;

fn handshake_limiter() -> &'static Semaphore {
    static LIMITER: OnceLock<Semaphore> = OnceLock::new();
    LIMITER.get_or_init(|| Semaphore::new(MAX_CONCURRENT_HANDSHAKES))
}

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

fn decode_ratchet_frame(frame: &[u8]) -> Option<ReceivedFrame> {
    if frame.len() < 1 + 1 + 8 + 8 + 12 + 16 {
        return None;
    }

    let version = frame[0];
    if version != FRAME_VERSION {
        return None;
    }

    let flags = frame[1];
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

fn frame_aad_prefix(transcript: &[u8; 32], sender: PeerId, receiver: PeerId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + 32 + 32);
    aad.push(FRAME_VERSION);
    aad.extend_from_slice(transcript);
    aad.extend_from_slice(&sender.0);
    aad.extend_from_slice(&receiver.0);
    aad
}

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

#[allow(clippy::too_many_arguments)]
async fn run_peer_session(
    mut tls_stream: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    peer_id: PeerId,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    is_initiator: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _handshake_permit = handshake_limiter().acquire().await?;
    let role = if is_initiator {
        AuthRole::Initiator
    } else {
        AuthRole::Responder
    };

    let tls_exporter = crate::tls::export_transcript_key(&tls_stream)?;

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

    let our_secret = LockedDhSecret::generate();
    let our_public = our_secret.public_key();

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
    let transcript = session_transcript(
        is_initiator,
        &tls_exporter,
        session_mgr.my_peer_id(),
        peer_id,
        our_public,
        their_public,
    );
    let mut root_chain = [0u8; 32];
    crate::crypto::hkdf_expand_with_salt(
        session_key.as_bytes(),
        &crate::crypto::sha256_many(&[shared_secret.as_bytes(), &transcript]),
        b"sesame-root-v1",
        &mut root_chain,
    );

    let mut ratchet = DoubleRatchet::new(
        &root_chain,
        our_secret,
        our_public,
        Some(their_public),
        is_initiator,
        100,
    );

    drop(session_key);
    root_chain.zeroize();
    let send_aad = frame_aad_prefix(&transcript, session_mgr.my_peer_id(), peer_id);
    let recv_aad = frame_aad_prefix(&transcript, peer_id, session_mgr.my_peer_id());

    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    let (msg_tx, mut msg_rx) = mpsc::channel::<Vec<u8>>(256);
    let cancel_notify = Arc::new(Notify::new());

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

    if let Err(e) = session_mgr.register_session(session_handle) {
        if e == "duplicate session" {
            return Ok(());
        }
        session_mgr.system_msg(&format!("session registration failed: {e}"));
        return Err(e.into());
    }

    // Broadcast SYSTEM_JOIN to all other peers
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

    // Notify local TUI
    {
        session_mgr.system_msg(&format!("connected {peer_id}"));
    }

    // Send our display name
    if let Some(name) = session_mgr.my_display_name() {
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

    // If initiator → request peer list from this peer
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

    let mut cancel_rx = session_mgr.cancel_rx();
    let mut dummy_timer = tokio::time::interval(crate::obfuscate::dummy_interval());
    dummy_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    dummy_timer.tick().await;

    let max_dummy_failures: usize = 3;
    let mut consecutive_dummy_failures: usize = 0;

    loop {
        tokio::select! {
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
            result = read_frame(&mut reader) => {
                let padded = match result {
                    Ok(f) => f,
                    Err(_) => break,
                };

                let unpadded = match remove_padding(&padded) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let received = match decode_ratchet_frame(unpadded) {
                    Some(frame) => frame,
                    None => continue,
                };

                let plaintext = match ratchet.decrypt(&received, &recv_aad) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if plaintext.len() > MAX_JSON_SIZE {
                    session_mgr.system_msg(&format!("oversized json from {peer_id}, dropping"));
                    continue;
                }
                let msg: ChatMessage = match serde_json::from_slice(&plaintext) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                session_mgr.update_last_message(&peer_id);

                match msg.flags {
                    FLAG_DUMMY => continue,
                    FLAG_PEER_LIST_REQ => {
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
                        if msg.text.len() > MAX_JSON_SIZE {
                            continue;
                        }
                        let addrs: Vec<PeerAddr> = serde_json::from_str(&msg.text).unwrap_or_default();
                        for addr in addrs {
                            if addr == session_mgr.my_listen_addr {
                                continue;
                            }
                            if session_mgr.is_connected_to_addr(&addr) {
                                continue;
                            }
                            session_mgr.send_discovered(&addr);
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
                        if consecutive_dummy_failures >= max_dummy_failures {
                            session_mgr.system_msg(&format!("connection lost to {peer_id}, reconnecting..."));
                            break;
                        }
                    } else {
                        consecutive_dummy_failures = 0;
                    }
                }
                let interval = crate::obfuscate::dummy_interval();
                dummy_timer = tokio::time::interval(interval);
                dummy_timer.tick().await;
            }
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break;
                }
            }
            _ = cancel_notify.notified() => {
                break;
            }
        }
    }

    // Peer disconnected — broadcast SYSTEM_LEAVE
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

    // "disconnected" is not sent here — remove_session handles
    // SYSTEM_ALONE broadcast if no peers remain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::EncryptedFrame;

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
        encoded[1] = 0x80;

        assert!(decode_ratchet_frame(&encoded).is_none());
    }

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
        encoded[0] = FRAME_VERSION + 1;

        assert!(decode_ratchet_frame(&encoded).is_none());
    }
}
