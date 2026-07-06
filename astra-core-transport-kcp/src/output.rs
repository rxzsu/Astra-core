use bytes::BytesMut;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use crate::segment::Segment;

pub async fn write_segment<W: AsyncWrite + Unpin>(
    writer: &mut W,
    seg: &Segment,
) -> std::io::Result<()> {
    let mut buf = BytesMut::with_capacity(256);
    match seg {
        Segment::Data(s) => s.serialize(&mut buf),
        Segment::Ack(s) => s.serialize(&mut buf),
        Segment::CmdOnly(s) => s.serialize(&mut buf),
    }
    writer.write_all(&buf).await
}
