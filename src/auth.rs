use tokio::io::{AsyncReadExt, AsyncWriteExt};

use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::crypto::{LockedKey, derive_key, sha256_many};
use crate::types::PeerId;

// ═══════════════════════════════════════════════════════════════════════════
// HANDSHAKE DE AUTENTICACION NEGABLE (SPAKE2 PAKE)
// ═══════════════════════════════════════════════════════════════════════════
// Despues del handshake TLS, los peers hacen un PAKE (Password-Authenticated
// Key Exchange) usando SPAKE2. Esto prueba que ambos conocen la frase de
// paso SIN revelar la frase a un observador ni al otro peer.
//
// "Autenticacion negable" significa que no queda evidencia criptografica
// de que la comunicacion ocurrio. Cualquiera de los dos pudo haber
// generado los mismos mensajes, asi que no hay "prueba" de la conversacion.
// ═══════════════════════════════════════════════════════════════════════════

/// Define que rol juega este peer en el handshake.
///
/// `Initiator`
/// El que INICIA la conexion (el que hace `connect()`).
/// Envia primero su salt, luego su mensaje SPAKE2.
///
/// `Responder`
/// El que ACEPTA la conexion (el listener).
/// Recibe primero, luego responde.
///
/// Por que importa el orden
/// Porque SPAKE2 necesita saber quien es "A" (initiator) y quien es
/// "B" (responder) para calcular las claves correctamente. Si ambos
/// hicieran el mismo calculo, obtendrian claves diferentes.
#[derive(Clone, Copy)]
pub enum AuthRole {
    Initiator,
    Responder,
}

/// Resultado del handshake de autenticacion.
///
/// Campos
/// * `session_key` — la clave de sesion final (32 bytes) que se usara
///   como input para la root chain del Double Ratchet
/// * `_our_salt` — nuestro salt (guardado por si hace falta, no se usa
///   actualmente despues del handshake)
/// * `_their_salt` — el salt del otro peer (idem)
pub struct AuthResult {
    pub session_key: LockedKey,
    pub _our_salt: [u8; 32],
    pub _their_salt: [u8; 32],
}

/// Ejecuta el handshake completo de autenticacion sobre un stream TLS.
///
/// Que hace paso a paso
/// 1. Intercambia salts de 32 bytes (para Argon2)
/// 2. Deriva una clave de la frase usando Argon2id con ambos salts
/// 3. Ejecuta SPAKE2 (PAKE) para obtener un secreto compartido
/// 4. Mezcla todo (PAKE key + TLS exporter + salts + PeerIDs) para
///    obtener la session_key final
/// 5. Prueba de autenticacion mutua: cada peer envia un hash
///    que solo el otro puede verificar si tiene la misma session_key
///
/// Parametros
/// * `stream` — stream TLS sobre TCP (AsyncRead + AsyncWrite)
/// * `phrase` — la frase de paso compartida
/// * `role` — Initiator o Responder
/// * `our_peer_id` — nuestro PeerId (del certificado TLS)
/// * `their_peer_id` — el PeerId del otro peer (del certificado TLS)
/// * `tls_exporter` — 32 bytes exportados del handshake TLS
///   (keying material export). Ancla la autenticacion a la sesion TLS.
///
/// Por que tantos parametros
/// Cada uno contribuye a una capa diferente de seguridad:
/// - phrase + salts -> Argon2 -> resistencia a fuerza bruta
/// - PAKE -> prueba de conocimiento de la frase sin revelarla
/// - TLS exporter -> ata la autenticacion a la sesion TLS (previene
///   ataques MITM donde el atacante esta en el medio del TCP)
/// - PeerIDs -> asegura que cada peer tiene la identidad correcta
///
/// Devuelve
/// `AuthResult` con la session_key, o error si algo falla.
///
/// Errores posibles
/// - Timeout (manejado por el caller)
/// - Falla de SPAKE2 (frase incorrecta)
/// - Falla de prueba de autenticacion (misma causa)
/// - Error de I/O (desconexion durante handshake)
pub async fn perform_handshake<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    phrase: &[u8],
    role: AuthRole,
    our_peer_id: PeerId,
    their_peer_id: PeerId,
    tls_exporter: &[u8; 32],
) -> Result<AuthResult, Box<dyn std::error::Error>> {
    // Paso 1: generar nuestro salt y recibir el del otro
    let our_salt = crate::crypto::generate_random_bytes::<32>();
    let mut their_salt = [0u8; 32];

    // El initiator envia primero su salt, el responder espera
    // (esto sincroniza el intercambio)
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

    // Paso 2: derivar clave de la frase con Argon2 usando ambos salts
    let password_key = derive_key(phrase, &our_salt, &their_salt)?;

    // Paso 3: ejecutar SPAKE2 (PAKE) sobre el stream
    let pake_key = perform_pake(
        stream,
        role,
        password_key.as_bytes(),
        our_peer_id,
        their_peer_id,
    )
    .await?;

    // Paso 4: mezclar todo en la session_key final
    // Ordenamos PeerIDs y salts para que ambos peers obtengan el mismo hash
    let (peer_a, peer_b) = if our_peer_id.0 < their_peer_id.0 {
        (our_peer_id, their_peer_id)
    } else {
        (their_peer_id, our_peer_id)
    };
    let (salt_a, salt_b) = if our_salt < their_salt {
        (&our_salt[..], &their_salt[..])
    } else {
        (&their_salt[..], &our_salt[..])
    };
    let session_key = LockedKey::new(sha256_many(&[
        &pake_key,
        tls_exporter,
        salt_a,
        salt_b,
        &peer_a.0,
        &peer_b.0,
    ]));

    // Paso 5: prueba de autenticacion mutua
    // Cada peer calcula lo que el OTRO deberia enviar y verifica
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
            // Envio mi prueba de initiator y espero la del responder
            stream.write_all(&initiator_proof).await?;

            let mut response = [0u8; 32];
            stream.read_exact(&mut response).await?;
            if response != responder_proof {
                return Err("authentication failed: responder challenge mismatch".into());
            }
        }
        AuthRole::Responder => {
            // Espero la prueba del initiator y la verifico
            let mut challenge = [0u8; 32];
            stream.read_exact(&mut challenge).await?;
            if challenge != initiator_proof {
                return Err("authentication failed: initiator challenge mismatch".into());
            }

            // Envio mi prueba de responder
            stream.write_all(&responder_proof).await?;
        }
    }

    Ok(AuthResult {
        session_key,
        _our_salt: our_salt,
        _their_salt: their_salt,
    })
}

/// Ejecuta el intercambio SPAKE2 (PAKE) sobre el stream.
///
/// SPAKE2 es un algoritmo de "Password-Authenticated Key Exchange".
/// Permite que dos partes que comparten una contraseña (la frase)
/// establezcan una clave secreta compartida sin revelar la contraseña
/// a nadie que este escuchando la red.
///
/// Como funciona (simplificado)
/// 1. El initiator genera un mensaje criptografico que "esconde" la
///    contraseña dentro de una operacion matematica en curva eliptica
/// 2. El responder hace lo mismo
/// 3. Cada uno usa el mensaje del otro + su conocimiento de la
///    contraseña para calcular el mismo secreto compartido
///
/// Si un atacante intercepta los mensajes, no puede recuperar la
/// contraseña ni el secreto compartido.
///
/// Parametros
/// * `stream` — stream para enviar/recibir los mensajes SPAKE2
/// * `role` — quien inicia (A) y quien responde (B)
/// * `password_key` — la clave derivada de la frase (32 bytes)
/// * `our_peer_id` / `their_peer_id` — identidades de ambos peers
async fn perform_pake<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    role: AuthRole,
    password_key: &[u8; 32],
    our_peer_id: PeerId,
    their_peer_id: PeerId,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Determinamos quien es A (initiator) y B (responder) para SPAKE2
    let (initiator_id, responder_id) = match role {
        AuthRole::Initiator => (our_peer_id, their_peer_id),
        AuthRole::Responder => (their_peer_id, our_peer_id),
    };
    let password = Password::new(password_key);
    let initiator_identity = Identity::new(&initiator_id.0);
    let responder_identity = Identity::new(&responder_id.0);

    let key = match role {
        AuthRole::Initiator => {
            // start_a() = soy el initiator A
            let (state, outbound) = Spake2::<Ed25519Group>::start_a(
                &password,
                &initiator_identity,
                &responder_identity,
            );
            write_pake_msg(stream, outbound.as_slice()).await?;
            let inbound = read_pake_msg(stream).await?;
            state
                .finish(&inbound)
                .map_err(|e| format!("PAKE failed: {e:?}"))?
        }
        AuthRole::Responder => {
            // start_b() = soy el responder B
            let inbound = read_pake_msg(stream).await?;
            let (state, outbound) = Spake2::<Ed25519Group>::start_b(
                &password,
                &initiator_identity,
                &responder_identity,
            );
            write_pake_msg(stream, outbound.as_slice()).await?;
            state
                .finish(&inbound)
                .map_err(|e| format!("PAKE failed: {e:?}"))?
        }
    };

    Ok(key)
}

/// Envia un mensaje PAKE al stream.
///
/// Formato: [2 bytes: longitud en big-endian] + [datos del mensaje]
///
/// Por que longitud prefijada
/// Porque el stream es un flujo continuo de bytes. Sin saber donde
/// termina un mensaje y empieza el otro, no podriamos separarlos.
/// Con 2 bytes de longitud tenemos hasta 65535 bytes por mensaje PAKE.
async fn write_pake_msg<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    msg: &[u8],
) -> std::io::Result<()> {
    let len: u16 = msg.len().try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "PAKE message too large")
    })?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await
}

/// Lee un mensaje PAKE del stream.
///
/// Lee 2 bytes de longitud, luego esa cantidad de bytes de datos.
async fn read_pake_msg<S: AsyncReadExt + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    // Validacion de seguridad: PAKE messages are small (< 256 bytes)
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

/// Calcula una "prueba de autenticacion" de 32 bytes.
///
/// Es un hash SHA-256 que demuestra que quien lo envio conoce la
/// session_key y todos los parametros del handshake. Se usa para
/// la verificacion mutua al final del handshake.
///
/// Por que no es suficiente SPAKE2 solo
/// SPAKE2 asegura que ambos conocen la frase. Pero la session_key
/// final mezcla TAMBIEN el TLS exporter (unique key material de la
/// sesion TLS). Esta prueba verifica que el otro peer tambien tiene
/// el mismo TLS exporter -> esta en la misma sesion TLS -> no hay MITM.
///
/// Parametros
/// * `session_key` — la clave de sesion ya calculada
/// * `direction` — b"initiator" o b"responder" (para diferenciar las pruebas)
/// * `role` — nuestro rol (necesario para ordenar los parametros)
/// * `our_salt` / `their_salt` — salts intercambiados
/// * `our_peer_id` / `their_peer_id` — identidades
/// * `tls_exporter` — material exportado de TLS
///
/// Devuelve
/// 32 bytes: SHA-256 de todos los parametros en orden canonico.
#[allow(clippy::too_many_arguments)]
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
    // Orden canonico: siempre ponemos al initiator primero
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

    /// Verifica que `auth_proof` es simetrica: el initiator y el responder
    /// calculan el MISMO valor para la prueba "initiator" (solo que cada
    /// uno ordena los parametros desde su perspectiva). Y que la prueba
    /// "initiator" es DIFERENTE de la prueba "responder".
    #[test]
    fn auth_proof_is_role_symmetric_and_directional() {
        let session_key = [7u8; 32];
        let initiator_salt = [1u8; 32];
        let responder_salt = [2u8; 32];
        let initiator_id = PeerId([3u8; 32]);
        let responder_id = PeerId([4u8; 32]);
        let tls_exporter = [5u8; 32];

        // El initiator calcula la prueba "initiator" desde su perspectiva
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
        // El responder calcula la prueba "initiator" desde SU perspectiva
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
        // Deberia dar el mismo hash
        assert_eq!(initiator_view, responder_view);
        // Pero la prueba "responder" es diferente
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
        assert_ne!(initiator_view, responder_proof);
    }
}
