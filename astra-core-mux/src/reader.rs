use tokio::io::{AsyncRead, AsyncReadExt};

/// PacketReader reads a single complete packet from a mux frame data stream.
/// Corresponds to Go's `mux.PacketReader`.
pub struct PacketReader<R> {
    reader: R,
    eof: bool,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub fn new(reader: R) -> Self {
        PacketReader { reader, eof: false }
    }

    /// Read one complete packet: 2-byte length prefix + data.
    /// Returns None when the single packet has been read (EOF semantics).
    pub async fn read_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.eof {
            return Ok(None);
        }

        let mut len_buf = [0u8; 2];
        self.reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("read packet len: {}", e))?;

        let packet_len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; packet_len];
        self.reader
            .read_exact(&mut data)
            .await
            .map_err(|e| format!("read packet data: {}", e))?;

        self.eof = true;
        Ok(Some(data))
    }
}

/// StreamReader reads stream data from a mux frame data stream.
/// Each mux data frame contains one chunk with a 2-byte size prefix.
/// Corresponds to Go's `mux.StreamReader` (PlainChunkSizeParser).
pub struct StreamReader<R> {
    reader: R,
}

impl<R: AsyncRead + Unpin> StreamReader<R> {
    pub fn new(reader: R) -> Self {
        StreamReader { reader }
    }

    /// Read one chunk: 2-byte length prefix + data.
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut len_buf = [0u8; 2];
        match self.reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(format!("read chunk len: {}", e)),
        }

        let chunk_len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; chunk_len];
        self.reader
            .read_exact(&mut data)
            .await
            .map_err(|e| format!("read chunk data: {}", e))?;

        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_packet_reader_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(&(5u16).to_be_bytes()); // length prefix
        data.extend_from_slice(b"hello"); // packet data

        let mut reader = PacketReader::new(data.as_slice());
        let packet = reader.read_packet().await.unwrap();
        assert_eq!(packet, Some(b"hello".to_vec()));

        let again = reader.read_packet().await.unwrap();
        assert!(again.is_none());
    }

    #[tokio::test]
    async fn test_stream_reader_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(&(5u16).to_be_bytes()); // chunk length
        data.extend_from_slice(b"hello");

        let mut reader = StreamReader::new(data.as_slice());
        let chunk = reader.read_chunk().await.unwrap();
        assert_eq!(chunk, Some(b"hello".to_vec()));

        let again = reader.read_chunk().await.unwrap();
        assert!(again.is_none());
    }
}
