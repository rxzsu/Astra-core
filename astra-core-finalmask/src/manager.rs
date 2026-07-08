use crate::mask::{Tcpmask, Udpmask, AsyncReadWrite, UdpPacketConn};

/// Chains multiple TCP masks together.
/// Wraps connections inside-out: the last mask is applied first.
pub struct TcpmaskManager {
    masks: Vec<Box<dyn Tcpmask>>,
}

impl TcpmaskManager {
    pub fn new(masks: Vec<Box<dyn Tcpmask>>) -> Self {
        TcpmaskManager { masks }
    }

    pub fn wrap_client(&self, conn: Box<dyn AsyncReadWrite>) -> Result<Box<dyn AsyncReadWrite>, String> {
        let mut wrapped = conn;
        for mask in self.masks.iter().rev() {
            wrapped = mask.wrap_client(wrapped)?;
        }
        Ok(wrapped)
    }

    pub fn wrap_server(&self, conn: Box<dyn AsyncReadWrite>) -> Result<Box<dyn AsyncReadWrite>, String> {
        let mut wrapped = conn;
        for mask in self.masks.iter().rev() {
            wrapped = mask.wrap_server(wrapped)?;
        }
        Ok(wrapped)
    }
}

/// Chains multiple UDP masks together.
/// Manages header masks (which need special ReadFrom/WriteTo handling).
pub struct UdpmaskManager {
    masks: Vec<Box<dyn Udpmask>>,
}

impl UdpmaskManager {
    pub fn new(masks: Vec<Box<dyn Udpmask>>) -> Self {
        UdpmaskManager { masks }
    }

    pub fn wrap_packet_conn_client(
        &self,
        conn: Box<dyn UdpPacketConn>,
    ) -> Result<Box<dyn UdpPacketConn>, String> {
        let mut wrapped = conn;
        for mask in self.masks.iter().rev() {
            wrapped = mask.wrap_packet_conn_client(wrapped, 0, self.masks.len().saturating_sub(1))?;
        }
        Ok(wrapped)
    }

    pub fn wrap_packet_conn_server(
        &self,
        conn: Box<dyn UdpPacketConn>,
    ) -> Result<Box<dyn UdpPacketConn>, String> {
        let mut wrapped = conn;
        for mask in self.masks.iter().rev() {
            wrapped = mask.wrap_packet_conn_server(wrapped, 0, self.masks.len().saturating_sub(1))?;
        }
        Ok(wrapped)
    }
}
