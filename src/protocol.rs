use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ═══════════════════════════════════════════════════════════════════════════
// FORMATO DE FRAMES EN LA RED (lectura/escritura + padding)
// ═══════════════════════════════════════════════════════════════════════════
// Este archivo maneja como se envian y reciben los datos a traves de la
// conexion TCP/TLS. Cada "frame" tiene:
//
//   [4 bytes: longitud del frame en big-endian] [N bytes: contenido del frame]
//
// Ademas se aplica "padding" (relleno) para que todos los frames tengan
// un tamaño uniforme (1400 bytes). Esto evita que un atacante pueda
// deducir informacion por el tamaño de los mensajes.
// ═══════════════════════════════════════════════════════════════════════════

/// Tamaño del bloque de padding en bytes.
///
/// 1400 bytes es un tamaño comun que cabe en un solo paquete TCP
/// sin fragmentacion (MTU tipico = 1500, menos headers IP/TCP).
///
/// Por que 1400 y no 1500
/// Porque hay que dejar espacio para:
/// - Header IP (20 bytes)
/// - Header TCP (20 bytes)
/// - Header TLS (variable, ~50 bytes)
/// - Header de nuestro frame (4 bytes de longitud + 2 de padding)
/// Con 1400 nos aseguramos que quepa todo sin fragmentar.
pub const PADDING_BLOCK: usize = 1400;

/// Tamaño maximo de un frame entrante (10 MB).
///
/// Si alguien envia un frame mas grande que esto, lo rechazamos.
/// Es una medida de seguridad contra ataques de memoria (enviar
/// gigantes de datos para agotar la RAM).
pub const MAX_FRAME_SIZE: usize = 1024 * 1024 * 10; // 10 MB

/// Lee un frame completo del stream.
///
/// Formato
/// [4 bytes: longitud en big-endian] + [datos del frame]
///
/// Parametros
/// * `reader` — cualquier cosa que implemente AsyncRead (TlsStream, TcpStream, etc.)
///
/// Devuelve
/// Los bytes del frame (sin los 4 bytes de longitud), o error si:
/// - La longitud supera MAX_FRAME_SIZE
/// - Error de I/O (desconexion, timeout)
/// - EOF prematuro (el stream se cerro antes de completar la lectura)
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; frame_len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Escribe un frame completo al stream.
///
/// Formato
/// [4 bytes: longitud en big-endian] + [datos]
///
/// Parametros
/// * `writer` — cualquier cosa que implemente AsyncWrite
/// * `data` — los bytes a enviar
///
/// Por que flush al final
/// Para asegurarnos de que los datos se envian inmediatamente y no
/// quedan en un buffer interno del OS. Sin flush, el mensaje podria
/// demorarse indefinidamente.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Anade padding a un payload para que su tamaño sea multiplo de PADDING_BLOCK.
///
/// Formato del resultado
/// [2 bytes: longitud real del payload] + [payload] + [ceros de relleno]
///
/// Ejemplo
/// Si el payload mide 100 bytes y PADDING_BLOCK = 1400:
/// - Total con header: 100 + 2 = 102
/// - Redondeamos a multiplo de 1400: 1400
/// - Resultado: [0, 100] + [100 bytes de payload] + [1298 bytes de ceros]
///
/// Por que es necesario
/// Sin padding, un atacante que mire el trafico puede deducir:
/// - Longitud del mensaje (texto corto = "que haces?", largo = respuesta larga)
/// - Si se estan enviando mensajes dummy (que son siempre del mismo tamaño)
///
/// Con padding uniforme, todos los paquetes se ven iguales.
///
/// Seguridad
/// Esto NO cifra el contenido (eso lo hace el Double Ratchet). Esto solo
/// oculta el tamaño de los mensajes a nivel de red ("traffic analysis").
///
/// Parametros
/// * `payload` — los datos a enviar (ya cifrados por el ratchet)
///
/// Devuelve
/// Un Vec<u8> con el padding ya aplicado.
pub fn apply_padding(payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    assert!(
        payload_len <= u16::MAX as usize,
        "payload too large for padding header"
    );
    let frame_len = payload_len + 2;
    let total_padded = ((frame_len + PADDING_BLOCK - 1) / PADDING_BLOCK) * PADDING_BLOCK;
    let padded_len = std::cmp::max(PADDING_BLOCK, total_padded);

    let mut frame = Vec::with_capacity(padded_len);
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.resize(padded_len, 0);
    frame
}

/// Remueve el padding de un frame recibido.
///
/// Que hace
/// 1. Lee los primeros 2 bytes (longitud real del payload)
/// 2. Extrae solo esa cantidad de bytes
/// 3. Descarta el resto (los ceros de relleno)
///
/// Parametros
/// * `frame` — el frame completo con padding
///
/// Devuelve
/// El payload original (slice del frame), o error si:
/// - El frame es muy chico (< 2 bytes)
/// - La longitud declarada excede el tamaño del frame
pub fn remove_padding(frame: &[u8]) -> std::io::Result<&[u8]> {
    if frame.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too small for padding header",
        ));
    }
    let payload_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let end = 2 + payload_len;
    if end > frame.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "payload length exceeds frame size",
        ));
    }
    Ok(&frame[2..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifica que el padding/remove_padding funciona para varios
    /// tamaños de payload, incluyendo casos borde como 0, 1, y
    /// justo alrededor del tamaño de bloque.
    #[test]
    fn padding_round_trips_varied_lengths() {
        for len in [0, 1, 32, 1398, 1399, 1400, 4096] {
            let payload = vec![7u8; len];
            let padded = apply_padding(&payload);
            // El resultado debe ser multiplo de PADDING_BLOCK
            assert_eq!(padded.len() % PADDING_BLOCK, 0);
            // Al remover, debemos recuperar el payload original exacto
            assert_eq!(remove_padding(&padded).unwrap(), payload.as_slice());
        }
    }

    /// Verifica que si el frame esta truncado (tiene menos bytes de los
    /// que declara en el header), remove_padding da error.
    #[test]
    fn padding_rejects_truncated_payload() {
        let frame = [0, 10, 1, 2, 3];
        assert!(remove_padding(&frame).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn padding_roundtrip_any_payload(payload in proptest::collection::vec(any::<u8>(), 0..10000)) {
            let padded = apply_padding(&payload);
            let recovered = remove_padding(&padded).unwrap();
            prop_assert_eq!(recovered, &payload[..]);
        }
    }
}
