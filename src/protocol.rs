use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PADDING_BLOCK: usize = 1400;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024 * 10; // 10 MB

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

pub fn apply_padding(payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let total_padded = ((payload_len + PADDING_BLOCK - 1) / PADDING_BLOCK) * PADDING_BLOCK;
    let padded_len = std::cmp::max(PADDING_BLOCK, total_padded);

    let mut frame = Vec::with_capacity(padded_len);
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.resize(padded_len, 0);
    frame
}

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
