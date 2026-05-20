use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::auth::{perform_handshake, AuthRole};
use crate::protocol::{apply_padding, read_frame, remove_padding, write_frame};
use crate::ratchet::{DoubleRatchet, ReceivedFrame};
use crate::session::SessionManager;
use crate::types::{
    ChatMessage, PeerAddr, PeerId, FLAG_DUMMY, FLAG_PEER_LIST_REQ, FLAG_PEER_LIST_RES,
    FLAG_REAL, FLAG_SYSTEM_JOIN, FLAG_SYSTEM_LEAVE,
};

const MAX_JSON_SIZE: usize = 1024 * 64; // 64 KB

pub async fn connect_peer(
    addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    connector: tokio_rustls::TlsConnector,
) {
    match tokio::net::TcpStream::connect(addr.to_string()).await {
        Ok(stream) => {
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
    _peer_id: PeerId,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    is_initiator: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let phrase = session_mgr.phrase();
    let role = if is_initiator {
        AuthRole::Initiator
    } else {
        AuthRole::Responder
    };

    let auth = perform_handshake(&mut tls_stream, &phrase, role).await?;
    let mut session_key = auth.session_key;

    let mut rng = rand::rngs::OsRng;
    let our_secret = EphemeralSecret::random_from_rng(&mut rng);
    let our_public = PublicKey::from(&our_secret);

    let mut their_pub_bytes = [0u8; 32];
    let mut our_pub_bytes = [0u8; 32];
    our_pub_bytes.copy_from_slice(our_public.as_bytes());

    if is_initiator {
        tls_stream.write_all(&our_pub_bytes).await?;
        tls_stream.read_exact(&mut their_pub_bytes).await?;
    } else {
        tls_stream.read_exact(&mut their_pub_bytes).await?;
        tls_stream.write_all(&our_pub_bytes).await?;
    }

    let their_public = PublicKey::from(their_pub_bytes);
    let root_chain = crate::crypto::hkdf_derive(&session_key, b"sesame-root");

    let mut ratchet = DoubleRatchet::new(
        &root_chain,
        our_secret,
        our_public,
        Some(their_public),
        is_initiator,
        100,
    );

    session_key.zeroize();

    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    let (msg_tx, mut msg_rx) = mpsc::channel::<Vec<u8>>(256);

    let peer_id = auth.peer_id;
    let session_handle = crate::session::SessionHandle {
        peer_id,
        peer_addr: peer_addr.clone(),
        sender: msg_tx,
        connected_since: Instant::now(),
        last_message: Instant::now(),
    };

    if let Err(e) = session_mgr.register_session(session_handle) {
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
        let connected_msg = ChatMessage {
            peer_id,
            text: format!("connected {peer_id}"),
            timestamp: 0,
            flags: FLAG_REAL,
        };
        let _ = session_mgr
            .message_tx
            .try_send((peer_id, connected_msg));
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
            let encrypted = ratchet.encrypt(&data);
            let mut frame = Vec::new();
            frame.extend_from_slice(&encrypted.nonce);
            frame.extend_from_slice(&encrypted.ciphertext);
            frame.extend_from_slice(&encrypted.tag);
            if let Some(dh_pub) = &encrypted.dh_public_key {
                frame.push(1);
                frame.extend_from_slice(dh_pub.as_bytes());
            } else {
                frame.push(0);
            }
            let padded = apply_padding(&frame);
            let _ = write_frame(&mut writer, &padded).await;
        }
    }

    let mut dummy_timer = tokio::time::interval(crate::obfuscate::dummy_interval());
    dummy_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    dummy_timer.tick().await;

    loop {
        tokio::select! {
            data = msg_rx.recv() => {
                let data = match data {
                    Some(d) => d,
                    None => break,
                };

                let encrypted = ratchet.encrypt(&data);
                let mut frame = Vec::new();
                frame.extend_from_slice(&encrypted.nonce);
                frame.extend_from_slice(&encrypted.ciphertext);
                frame.extend_from_slice(&encrypted.tag);

                if let Some(dh_pub) = &encrypted.dh_public_key {
                    frame.push(1);
                    frame.extend_from_slice(dh_pub.as_bytes());
                } else {
                    frame.push(0);
                }

                let padded = apply_padding(&frame);
                if write_frame(&mut writer, &padded).await.is_err() {
                    break;
                }
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

                let unpadded_len = unpadded.len();
                if unpadded_len < 12 + 16 + 1 {
                    continue;
                }

                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&unpadded[..12]);

                let has_dh_pub = unpadded[unpadded_len - 1] == 1;
                let tag_end = unpadded_len - 1;
                let tag_start = tag_end - 16;
                let ct_end = tag_start;

                let mut tag = [0u8; 16];
                tag.copy_from_slice(&unpadded[tag_start..tag_end]);

                let ciphertext = unpadded[12..ct_end].to_vec();

                let dh_public_key = if has_dh_pub {
                    let dh_start = tag_end + 1;
                    let dh_end = dh_start + 32;
                    if dh_end > unpadded_len {
                        continue;
                    }
                    let mut dh_bytes = [0u8; 32];
                    dh_bytes.copy_from_slice(&unpadded[dh_start..dh_end]);
                    Some(PublicKey::from(dh_bytes))
                } else {
                    None
                };

                let received = ReceivedFrame {
                    nonce,
                    ciphertext,
                    tag,
                    dh_public_key,
                };

                let plaintext = match ratchet.decrypt(&received) {
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
                            let encrypted = ratchet.encrypt(&data);
                            let mut frame = Vec::new();
                            frame.extend_from_slice(&encrypted.nonce);
                            frame.extend_from_slice(&encrypted.ciphertext);
                            frame.extend_from_slice(&encrypted.tag);
                            if let Some(dh_pub) = &encrypted.dh_public_key {
                                frame.push(1);
                                frame.extend_from_slice(dh_pub.as_bytes());
                            } else {
                                frame.push(0);
                            }
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
                    let encrypted = ratchet.encrypt(&data);
                    let mut frame = Vec::new();
                    frame.extend_from_slice(&encrypted.nonce);
                    frame.extend_from_slice(&encrypted.ciphertext);
                    frame.extend_from_slice(&encrypted.tag);
                    frame.push(0);
                    let padded = apply_padding(&frame);
                    let _ = write_frame(&mut writer, &padded).await;
                }
                let interval = crate::obfuscate::dummy_interval();
                dummy_timer = tokio::time::interval(interval);
                dummy_timer.tick().await;
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

    {
        let disconnected_msg = ChatMessage {
            peer_id,
            text: format!("disconnected {peer_id}"),
            timestamp: 0,
            flags: FLAG_REAL,
        };
        let _ = session_mgr
            .message_tx
            .try_send((peer_id, disconnected_msg));
    }

    Ok(())
}
