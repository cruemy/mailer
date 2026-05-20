use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{derive_key, sha256_two};

pub enum AuthRole {
    Initiator,
    Responder,
}

pub struct AuthResult {
    pub session_key: [u8; 32],
    pub _our_salt: [u8; 32],
    pub _their_salt: [u8; 32],
    pub peer_id: super::types::PeerId,
}

pub async fn perform_handshake<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    phrase: &str,
    role: AuthRole,
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

    let session_key = derive_key(phrase, &our_salt, &their_salt)?;

    match role {
        AuthRole::Initiator => {
            let challenge = sha256_two(&session_key, b"initiator");
            stream.write_all(&challenge).await?;

            let mut response = [0u8; 32];
            stream.read_exact(&mut response).await?;
            let expected = sha256_two(&session_key, b"responder");
            if response != expected {
                return Err("authentication failed: responder challenge mismatch".into());
            }
        }
        AuthRole::Responder => {
            let mut challenge = [0u8; 32];
            stream.read_exact(&mut challenge).await?;
            let expected = sha256_two(&session_key, b"initiator");
            if challenge != expected {
                return Err("authentication failed: initiator challenge mismatch".into());
            }

            let response = sha256_two(&session_key, b"responder");
            stream.write_all(&response).await?;
        }
    }

    let peer_id_bytes = match role {
        AuthRole::Initiator => &their_salt,
        AuthRole::Responder => &our_salt,
    };
    let peer_id = crate::types::PeerId(*peer_id_bytes);

    Ok(AuthResult {
        session_key,
        _our_salt: our_salt,
        _their_salt: their_salt,
        peer_id,
    })
}
