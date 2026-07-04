use astra_core_net::Destination;
use tokio::io::AsyncWrite;

use crate::frame::{FrameMetadata, FrameOption, SessionStatus};

/// Mux writer that wraps an async writer and sends frames for a single session.
/// Corresponds to Go's `mux.Writer`.
pub struct MuxWriter<W> {
    writer: W,
    session_id: u16,
    followup: bool,
    target: Option<Destination>,
}

impl<W: AsyncWrite + Unpin> MuxWriter<W> {
    pub fn new(writer: W, session_id: u16, target: Option<Destination>) -> Self {
        MuxWriter {
            writer,
            session_id,
            followup: false,
            target,
        }
    }

    /// Create a response writer (no target, starts in followup mode).
    pub fn new_response(writer: W, session_id: u16) -> Self {
        MuxWriter {
            writer,
            session_id,
            followup: true,
            target: None,
        }
    }

    fn next_meta(&mut self, is_data: bool) -> FrameMetadata {
        let status = if self.followup {
            SessionStatus::Keep
        } else {
            self.followup = true;
            SessionStatus::New
        };

        let mut meta = FrameMetadata::new(self.session_id, status);
        if is_data {
            meta.option.set(FrameOption::DATA);
        }
        if !self.followup {
            meta.target = self.target.clone();
        }
        meta
    }

    /// Write metadata-only frame (no data).
    pub async fn write_meta_only(&mut self) -> Result<(), String> {
        let meta = self.next_meta(false);
        crate::frame::write_frame(&mut self.writer, &meta, None).await
    }

    /// Write a data frame.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), String> {
        let meta = self.next_meta(true);
        crate::frame::write_frame(&mut self.writer, &meta, Some(data)).await
    }

    /// Close the session with an End frame.
    pub async fn close(&mut self, has_error: bool) -> Result<(), String> {
        let mut meta = FrameMetadata::new(self.session_id, SessionStatus::End);
        if has_error {
            meta.option.set(FrameOption::ERROR);
        }
        crate::frame::write_frame(&mut self.writer, &meta, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_writer_write_meta_only() {
        let mut buf = Vec::new();
        let mut writer = MuxWriter::new(&mut buf, 1, None);
        writer.write_meta_only().await.unwrap();
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn test_writer_write_data() {
        let mut buf = Vec::new();
        let mut writer = MuxWriter::new(&mut buf, 1, None);
        writer.write_data(b"hello").await.unwrap();
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn test_writer_close() {
        let mut buf = Vec::new();
        let mut writer = MuxWriter::new(&mut buf, 1, None);
        writer.close(false).await.unwrap();
        assert!(!buf.is_empty());

        // Parse the frame to verify it's an End frame
        let mut cursor = buf.as_slice();
        let (meta, _) = crate::frame::read_frame(&mut cursor).await.unwrap();
        assert_eq!(meta.status, SessionStatus::End);
    }
}
