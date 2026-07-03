use std::io;
use std::time::Duration;

use crate::io::{Reader, Writer};

pub struct CopyOptions {
    update_activity: Option<Box<dyn Fn()>>,
    size_counter: Option<Box<dyn FnMut(u64)>>,
    max_chunk_size: usize,
}

impl Default for CopyOptions {
    fn default() -> Self {
        CopyOptions {
            update_activity: None,
            size_counter: None,
            max_chunk_size: 64 * 1024,
        }
    }
}

impl CopyOptions {
    pub fn with_activity(mut self, cb: impl Fn() + 'static) -> Self {
        self.update_activity = Some(Box::new(cb));
        self
    }

    pub fn with_count(mut self, cb: impl FnMut(u64) + 'static) -> Self {
        self.size_counter = Some(Box::new(cb));
        self
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size;
        self
    }
}

pub fn copy(reader: &mut dyn Reader, writer: &mut dyn Writer) -> io::Result<u64> {
    copy_with_opts(reader, writer, &mut CopyOptions::default())
}

pub fn copy_with_opts(
    reader: &mut dyn Reader,
    writer: &mut dyn Writer,
    opts: &mut CopyOptions,
) -> io::Result<u64> {
    let mut total: u64 = 0;
    loop {
        let mb = reader.read_multi_buffer()?;
        if mb.is_empty() {
            break;
        }
        let len = mb.len() as u64;
        total += len;
        writer.write_multi_buffer(mb)?;
        if let Some(ref cb) = opts.update_activity {
            (cb)();
        }
        if let Some(ref mut cb) = opts.size_counter {
            (cb)(len);
        }
    }
    Ok(total)
}

pub fn copy_once_timeout(
    reader: &mut dyn Reader,
    writer: &mut dyn Writer,
    _timeout: Duration,
) -> io::Result<u64> {
    let mb = reader.read_multi_buffer()?;
    if mb.is_empty() {
        return Ok(0);
    }
    let len = mb.len() as u64;
    writer.write_multi_buffer(mb)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::buffer::{Buffer, SIZE};
    use crate::multi_buffer::MultiBuffer;

    #[test]
    fn test_buffer_basic() {
        let mut buf = Buffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.available(), SIZE);

        let data = b"hello";
        let dst = buf.extend(data.len());
        dst.copy_from_slice(data);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.slice(), data);

        let mut out = [0u8; 5];
        let rn = buf.read(&mut out).unwrap();
        assert_eq!(rn, 5);
        assert_eq!(&out, data);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_multi_buffer() {
        let mut mb = MultiBuffer::new();
        assert!(mb.is_empty());

        mb.push_back(Buffer::from_slice(b"hello "));
        mb.push_back(Buffer::from_slice(b"world"));

        assert_eq!(mb.len(), 11);

        let mut data = [0u8; 11];
        mb.copy_bytes(&mut data);
        assert_eq!(&data, b"hello world");
    }
}
