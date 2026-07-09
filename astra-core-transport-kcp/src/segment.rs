use bytes::{Bytes, BytesMut};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Ack = 0,
    Data = 1,
    Terminate = 2,
    Ping = 3,
}

impl Command {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ack),
            1 => Some(Self::Data),
            2 => Some(Self::Terminate),
            3 => Some(Self::Ping),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentOption(pub u8);

impl SegmentOption {
    pub const CLOSE: SegmentOption = SegmentOption(1);

    pub fn contains_close(&self) -> bool {
        self.0 & 1 != 0
    }
}

impl From<u8> for SegmentOption {
    fn from(b: u8) -> Self {
        Self(b)
    }
}

pub const DATA_SEGMENT_OVERHEAD: usize = 18;

#[derive(Clone)]
pub struct DataSegment {
    pub conv: u16,
    pub option: SegmentOption,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Bytes,
    pub timeout: u32,
    pub transmit: u32,
}

impl DataSegment {
    pub fn byte_size(&self) -> usize {
        2 + 1 + 1 + 4 + 4 + 4 + 2 + self.payload.len()
    }

    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.conv.to_be_bytes());
        buf.extend_from_slice(&[Command::Data as u8, self.option.0]);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.number.to_be_bytes());
        buf.extend_from_slice(&self.sending_next.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
    }

    pub fn parse(conv: u16, opt: SegmentOption, data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 15 {
            return None;
        }
        let timestamp = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let number = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let sending_next = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let payload_len = u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize;
        let data = &data[2..];
        if data.len() < payload_len {
            return None;
        }
        let payload = Bytes::copy_from_slice(&data[..payload_len]);
        let remaining = &data[payload_len..];
        Some((
            Self {
                conv,
                option: opt,
                timestamp,
                number,
                sending_next,
                payload,
                timeout: 0,
                transmit: 0,
            },
            remaining,
        ))
    }
}

#[derive(Clone)]
pub struct AckSegment {
    pub conv: u16,
    pub option: SegmentOption,
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub number_list: Vec<u32>,
    pub limit: usize,
}

const ACK_NUMBER_LIMIT: usize = 128;

impl AckSegment {
    pub fn new(limit: usize) -> Self {
        let limit = limit.max(1).min(ACK_NUMBER_LIMIT);
        Self {
            conv: 0,
            option: SegmentOption(0),
            receiving_window: 0,
            receiving_next: 0,
            timestamp: 0,
            number_list: Vec::with_capacity(limit),
            limit,
        }
    }

    pub fn put_timestamp(&mut self, timestamp: u32) {
        if timestamp.wrapping_sub(self.timestamp) < 0x7FFFFFFF {
            self.timestamp = timestamp;
        }
    }

    pub fn put_number(&mut self, number: u32) {
        self.number_list.push(number);
    }

    pub fn is_full(&self) -> bool {
        self.number_list.len() == self.limit
    }

    pub fn is_empty(&self) -> bool {
        self.number_list.is_empty()
    }

    pub fn byte_size(&self) -> usize {
        2 + 1 + 1 + 4 + 4 + 4 + 1 + self.number_list.len() * 4
    }

    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.conv.to_be_bytes());
        buf.extend_from_slice(&[Command::Ack as u8, self.option.0]);
        buf.extend_from_slice(&self.receiving_window.to_be_bytes());
        buf.extend_from_slice(&self.receiving_next.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&[self.number_list.len() as u8]);
        for &n in &self.number_list {
            buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn parse(conv: u16, opt: SegmentOption, data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 13 {
            return None;
        }
        let receiving_window = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let receiving_next = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let timestamp = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let count = data[0] as usize;
        let data = &data[1..];
        if data.len() < count * 4 {
            return None;
        }
        let mut seg = Self::new(128);
        seg.conv = conv;
        seg.option = opt;
        seg.receiving_window = receiving_window;
        seg.receiving_next = receiving_next;
        seg.timestamp = timestamp;
        for i in 0..count {
            let n = u32::from_be_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap());
            seg.put_number(n);
        }
        let remaining = &data[count * 4..];
        Some((seg, remaining))
    }
}

#[derive(Clone)]
pub struct CmdOnlySegment {
    pub conv: u16,
    pub cmd: Command,
    pub option: SegmentOption,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

impl CmdOnlySegment {
    pub fn new(cmd: Command) -> Self {
        Self {
            conv: 0,
            cmd,
            option: SegmentOption(0),
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        }
    }

    pub fn byte_size(&self) -> usize {
        2 + 1 + 1 + 4 + 4 + 4
    }

    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.conv.to_be_bytes());
        buf.extend_from_slice(&[self.cmd as u8, self.option.0]);
        buf.extend_from_slice(&self.sending_next.to_be_bytes());
        buf.extend_from_slice(&self.receiving_next.to_be_bytes());
        buf.extend_from_slice(&self.peer_rto.to_be_bytes());
    }

    pub fn parse(
        conv: u16,
        cmd: Command,
        opt: SegmentOption,
        data: &[u8],
    ) -> Option<(Self, &[u8])> {
        if data.len() < 12 {
            return None;
        }
        let sending_next = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let data = &data[4..];
        let receiving_next = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let data = &data[4..];
        let peer_rto = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let data = &data[4..];
        Some((
            Self {
                conv,
                cmd,
                option: opt,
                sending_next,
                receiving_next,
                peer_rto,
            },
            data,
        ))
    }
}

#[derive(Clone)]
pub enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    CmdOnly(CmdOnlySegment),
}

impl Segment {
    pub fn conv(&self) -> u16 {
        match self {
            Segment::Data(s) => s.conv,
            Segment::Ack(s) => s.conv,
            Segment::CmdOnly(s) => s.conv,
        }
    }
}

pub fn read_segment(data: &[u8]) -> Option<(Segment, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes(data[0..2].try_into().unwrap());
    let data = &data[2..];
    let cmd_byte = data[0];
    let opt = SegmentOption::from(data[1]);
    let data = &data[2..];

    let cmd = Command::from_byte(cmd_byte)?;

    match cmd {
        Command::Data => {
            let (seg, remaining) = DataSegment::parse(conv, opt, data)?;
            Some((Segment::Data(seg), remaining))
        }
        Command::Ack => {
            let (seg, remaining) = AckSegment::parse(conv, opt, data)?;
            Some((Segment::Ack(seg), remaining))
        }
        Command::Terminate | Command::Ping => {
            let (seg, remaining) = CmdOnlySegment::parse(conv, cmd, opt, data)?;
            Some((Segment::CmdOnly(seg), remaining))
        }
    }
}
