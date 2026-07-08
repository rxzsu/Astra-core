use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite};

/// TCP mask trait: wraps a TCP connection with obfuscation.
pub trait Tcpmask: Send + Sync {
    fn wrap_client(&self, conn: Box<dyn AsyncReadWrite>) -> Result<Box<dyn AsyncReadWrite>, String>;
    fn wrap_server(&self, conn: Box<dyn AsyncReadWrite>) -> Result<Box<dyn AsyncReadWrite>, String>;
}

/// UDP mask trait: wraps a UDP datagram connection with obfuscation.
pub trait Udpmask: Send + Sync {
    fn wrap_packet_conn_client(
        &self,
        conn: Box<dyn UdpPacketConn>,
        _level: usize,
        _level_count: usize,
    ) -> Result<Box<dyn UdpPacketConn>, String>;
    fn wrap_packet_conn_server(
        &self,
        conn: Box<dyn UdpPacketConn>,
        _level: usize,
        _level_count: usize,
    ) -> Result<Box<dyn UdpPacketConn>, String>;
}

/// Combined AsyncRead + AsyncWrite + Unpin + Send.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// UDP packet connection: send/recv datagrams.
pub trait UdpPacketConn: Send + Sync {
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), String>;
    fn send_to(&self, buf: &[u8], addr: &std::net::SocketAddr) -> Result<usize, String>;
}

/// TCP mask connection marker (for splice detection).
pub trait TcpMaskConn {
    fn raw_conn(&self) -> Option<&dyn AsyncReadWrite>;
    fn splice(&self) -> bool;
}

// ─── Salamander XOR obfuscation ─────────────────────────────────────────────

/// XOR payload with BLAKE2b(PSK || salt). Matches Go's salamander mask.
pub struct SalamanderMask {
    psk: Vec<u8>,
}

impl SalamanderMask {
    pub fn new(password: &str) -> Self {
        SalamanderMask { psk: password.as_bytes().to_vec() }
    }
}

impl Tcpmask for SalamanderMask {
    fn wrap_client(&self, conn: Box<dyn AsyncReadWrite>) -> Result<Box<dyn AsyncReadWrite>, String> {
        Ok(Box::new(SalamanderConn::new(conn, self.psk.clone())))
    }
    fn wrap_server(&self, conn: Box<dyn AsyncReadWrite>) -> Result<Box<dyn AsyncReadWrite>, String> {
        Ok(Box::new(SalamanderConn::new(conn, self.psk.clone())))
    }
}

impl Udpmask for SalamanderMask {
    fn wrap_packet_conn_client(
        &self,
        conn: Box<dyn UdpPacketConn>,
        _level: usize,
        _level_count: usize,
    ) -> Result<Box<dyn UdpPacketConn>, String> {
        Ok(Box::new(SalamanderUdpConn::new(conn, self.psk.clone())))
    }
    fn wrap_packet_conn_server(
        &self,
        conn: Box<dyn UdpPacketConn>,
        _level: usize,
        _level_count: usize,
    ) -> Result<Box<dyn UdpPacketConn>, String> {
        Ok(Box::new(SalamanderUdpConn::new(conn, self.psk.clone())))
    }
}

/// TCP connection wrapper with XOR obfuscation.
pub struct SalamanderConn {
    inner: Box<dyn AsyncReadWrite>,
    psk: Vec<u8>,
}

impl SalamanderConn {
    fn new(inner: Box<dyn AsyncReadWrite>, psk: Vec<u8>) -> Self {
        SalamanderConn { inner, psk }
    }

    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        use blake2::Digest;
        let salt: [u8; 16] = rand::random();
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(&self.psk);
        hasher.update(&salt);
        let key = hasher.finalize();
        let mut out = Vec::with_capacity(16 + data.len());
        out.extend_from_slice(&salt);
        for (i, &b) in data.iter().enumerate() {
            out.push(b ^ key[i % key.len()]);
        }
        out
    }

    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 16 {
            return Err("salamander: data too short".into());
        }
        use blake2::Digest;
        let salt = &data[..16];
        let payload = &data[16..];
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        let key = hasher.finalize();
        Ok(payload.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect())
    }
}

impl tokio::io::AsyncRead for SalamanderConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut tmp = vec![0u8; buf.remaining()];
        let mut tmp_buf = tokio::io::ReadBuf::new(&mut tmp);
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                let n = tmp_buf.filled().len();
                if n == 0 { return Poll::Ready(Ok(())); }
                match this.deobfuscate(&tmp[..n]) {
                    Ok(deobf) => {
                        let len = deobf.len().min(buf.remaining());
                        buf.put_slice(&deobf[..len]);
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => Poll::Ready(Ok(())),
                }
            }
            r => r,
        }
    }
}

impl tokio::io::AsyncWrite for SalamanderConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let obf = this.obfuscate(buf);
        std::pin::Pin::new(&mut this.inner).poll_write(cx, &obf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// UDP connection wrapper with XOR obfuscation.
pub struct SalamanderUdpConn {
    inner: Box<dyn UdpPacketConn>,
    psk: Vec<u8>,
}

impl SalamanderUdpConn {
    fn new(inner: Box<dyn UdpPacketConn>, psk: Vec<u8>) -> Self {
        SalamanderUdpConn { inner, psk }
    }

    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        use blake2::Digest;
        let salt: [u8; 16] = rand::random();
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(&self.psk);
        hasher.update(&salt);
        let key = hasher.finalize();
        let mut out = Vec::with_capacity(16 + data.len());
        out.extend_from_slice(&salt);
        for (i, &b) in data.iter().enumerate() {
            out.push(b ^ key[i % key.len()]);
        }
        out
    }

    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 16 {
            return Err("salamander: data too short".into());
        }
        use blake2::Digest;
        let salt = &data[..16];
        let payload = &data[16..];
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        let key = hasher.finalize();
        Ok(payload.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect())
    }
}

impl UdpPacketConn for SalamanderUdpConn {
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), String> {
        let mut tmp = vec![0u8; buf.len()];
        let (n, addr) = self.inner.recv_from(&mut tmp)?;
        let deobf = self.deobfuscate(&tmp[..n])?;
        let len = deobf.len().min(buf.len());
        buf[..len].copy_from_slice(&deobf[..len]);
        Ok((len, addr))
    }

    fn send_to(&self, buf: &[u8], addr: &std::net::SocketAddr) -> Result<usize, String> {
        let obf = self.obfuscate(buf);
        self.inner.send_to(&obf, addr)
    }
}
