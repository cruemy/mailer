use tokio::io::{AsyncReadExt, AsyncWriteExt};

use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::crypto::{derive_key, sha256_many, LockedKey};
use crate::types::PeerId;

#[derive(Clone, Copy)]
pub enum AuthRole {
    Initiator,
    Responder,
}

pub struct AuthResult {
    pub session_key: LockedKey,
    pub _our_salt: [u8; 32],
    pub _their_salt: [u8; 32],
}

pub async fn perform_handshake<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    phrase: &[u8],
    role: AuthRole,
    our_peer_id: PeerId,
    their_peer_id: PeerId,
    tls_exporter: &[u8; 32],
) -> Result<AuthResult, Box<dyn std::error::Error>> {
    let our_salt = crate::crypto::generate_random_bytes::<32>();
    let mut their_salt = [0u8; 32];

    match role {
        AuthRole::Initiator => {
            stream.write_all(&our_salt).await?;
            stream.read_exact(&mut their_salt).await?;
        }
        AuthRole::Responder => {
            stream.read_exact(&mut their_salt).await?;
            stream.write_all(&our_salt).await?;
        }
    }

    let password_key = derive_key(phrase, &our_salt, &their_salt)?;
    let pake_key = perform_pake(
        stream,
        role,
        password_key.as_bytes(),
        our_peer_id,
        their_peer_id,
    )
    .await?;
    let session_key = LockedKey::new(sha256_many(&[
        &pake_key,
        tls_exporter,
        &our_salt,
        &their_salt,
        &our_peer_id.0,
        &their_peer_id.0,
    ]));
    let initiator_proof = auth_proof(
        session_key.as_bytes(),
        b"initiator",
        role,
        &our_salt,
        &their_salt,
        our_peer_id,
        their_peer_id,
        tls_exporter,
    );
    let responder_proof = auth_proof(
        session_key.as_bytes(),
        b"responder",
        role,
        &our_salt,
        &their_salt,
        our_peer_id,
        their_peer_id,
        tls_exporter,
    );

    match role {
        AuthRole::Initiator => {
            stream.write_all(&initiator_proof).await?;

            let mut response = [0u8; 32];
            stream.read_exact(&mut response).await?;
            if response != responder_proof {
                return Err("authentication failed: responder challenge mismatch".into());
            }
        }
        AuthRole::Responder => {
            let mut challenge = [0u8; 32];
            stream.read_exact(&mut challenge).await?;
            if challenge != initiator_proof {
                return Err("authentication failed: initiator challenge mismatch".into());
            }

            stream.write_all(&responder_proof).await?;
        }
    }

    Ok(AuthResult {
        session_key,
        _our_salt: our_salt,
        _their_salt: their_salt,
    })
}

async fn perform_pake<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    role: AuthRole,
    password_key: &[u8; 32],
    our_peer_id: PeerId,
    their_peer_id: PeerId,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (initiator_id, responder_id) = match role {
        AuthRole::Initiator => (our_peer_id, their_peer_id),
        AuthRole::Responder => (their_peer_id, our_peer_id),
    };
    let password = Password::new(password_key);
    let initiator_identity = Identity::new(&initiator_id.0);
    let responder_identity = Identity::new(&responder_id.0);

    let key = match role {
        AuthRole::Initiator => {
            let (state, outbound) = Spake2::<Ed25519Group>::start_a(
                &password,
                &initiator_identity,
                &responder_identity,
            );
            write_pake_msg(stream, outbound.as_slice()).await?;
            let inbound = read_pake_msg(stream).await?;
            state.finish(&inbound).map_err(|e| format!("PAKE failed: {e:?}"))?
        }
        AuthRole::Responder => {
            let inbound = read_pake_msg(stream).await?;
            let (state, outbound) = Spake2::<Ed25519Group>::start_b(
                &password,
                &initiator_identity,
                &responder_identity,
            );
            write_pake_msg(stream, outbound.as_slice()).await?;
            state.finish(&inbound).map_err(|e| format!("PAKE failed: {e:?}"))?
        }
    };

    Ok(key)
}

async fn write_pake_msg<S: AsyncWriteExt + Unpin>(stream: &mut S, msg: &[u8]) -> std::io::Result<()> {
    let len: u16 = msg
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "PAKE message too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await
}

async fn read_pake_msg<S: AsyncReadExt + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid PAKE message size",
        ));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    Ok(msg)
}

fn auth_proof(
    session_key: &[u8; 32],
    direction: &[u8],
    role: AuthRole,
    our_salt: &[u8; 32],
    their_salt: &[u8; 32],
    our_peer_id: PeerId,
    their_peer_id: PeerId,
    tls_exporter: &[u8; 32],
) -> [u8; 32] {
    let (initiator_peer, responder_peer, initiator_salt, responder_salt) = match role {
        AuthRole::Initiator => (our_peer_id, their_peer_id, our_salt, their_salt),
        AuthRole::Responder => (their_peer_id, our_peer_id, their_salt, our_salt),
    };

    let mut hasher = Sha256::new();
    hasher.update(b"sesame-auth-v1");
    hasher.update(direction);
    hasher.update(tls_exporter);
    hasher.update(session_key);
    hasher.update(initiator_peer.0);
    hasher.update(responder_peer.0);
    hasher.update(initiator_salt);
    hasher.update(responder_salt);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_proof_is_role_symmetric_and_directional() {
        let session_key = [7u8; 32];
        let initiator_salt = [1u8; 32];
        let responder_salt = [2u8; 32];
        let initiator_id = PeerId([3u8; 32]);
        let responder_id = PeerId([4u8; 32]);
        let tls_exporter = [5u8; 32];

        let initiator_view = auth_proof(
            &session_key,
            b"initiator",
            AuthRole::Initiator,
            &initiator_salt,
            &responder_salt,
            initiator_id,
            responder_id,
            &tls_exporter,
        );
        let responder_view = auth_proof(
            &session_key,
            b"initiator",
            AuthRole::Responder,
            &responder_salt,
            &initiator_salt,
            responder_id,
            initiator_id,
            &tls_exporter,
        );
        let responder_proof = auth_proof(
            &session_key,
            b"responder",
            AuthRole::Responder,
            &responder_salt,
            &initiator_salt,
            responder_id,
            initiator_id,
            &tls_exporter,
        );

        assert_eq!(initiator_view, responder_view);
        assert_ne!(initiator_view, responder_proof);
    }

}
