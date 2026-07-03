use std::io::{self, Read};

use crate::buffer::Buffer;
use crate::multi_buffer::MultiBuffer;
use crate::reader::{PacketReader, SingleReader};
use crate::writer::SequentialWriter;

pub trait Reader {
    fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer>;
}

pub trait Writer {
    fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()>;
}

pub fn new_reader(r: impl Read + 'static) -> Box<dyn Reader> {
    Box::new(SingleReader::new(r))
}

#[allow(dead_code)]
pub fn new_packet_reader(r: impl Read + 'static) -> Box<dyn Reader> {
    Box::new(PacketReader::new(r))
}

pub fn new_writer(w: impl io::Write + 'static) -> Box<dyn Writer> {
    Box::new(SequentialWriter::new(w))
}

pub fn write_all_bytes(writer: &mut dyn io::Write, payload: &[u8]) -> io::Result<()> {
    writer.write_all(payload)
}

pub(crate) fn read_one_buffer(r: &mut dyn Read) -> io::Result<Option<Buffer>> {
    let mut buf = Buffer::new();
    let writable = buf.writable_mut();
    match r.read(writable) {
        Ok(0) => Ok(None),
        Ok(n) => {
            buf.set_end(n);
            Ok(Some(buf))
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(Some(Buffer::new())),
        Err(e) => Err(e),
    }
}
