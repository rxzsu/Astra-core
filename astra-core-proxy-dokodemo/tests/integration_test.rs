use std::sync::Arc;

use astra_core_net::{Address, Destination};
use astra_core_proxy::{async_trait, AsyncConn, Dialer, Dispatcher, InboundHandler, OutboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::Link;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestFreedom {
    echo_addr: std::net::SocketAddr,
}

#[async_trait]
impl Dialer for TestFreedom {
    async fn dial(&self, _session: Session, _dest: Destination) -> ProxyResult<Box<dyn AsyncConn>> {
        let stream = TcpStream::connect(self.echo_addr)
            .await
            .map_err(|e| format!("dial: {}", e))?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl OutboundHandler for TestFreedom {
    async fn process(&self, session: Session, link: &mut Link, _dialer: &dyn Dialer) -> ProxyResult<()> {
        let dialer = TestFreedom { echo_addr: self.echo_addr };
        let target = session.outbound.as_ref().map(|o| o.target.clone()).unwrap();
        let mut remote = dialer.dial(session, target).await?;
        let (mut r_reader, mut r_writer) = tokio::io::split(&mut remote);
        let to_remote = tokio::io::copy(&mut link.reader, &mut r_writer);
        let to_client = tokio::io::copy(&mut r_reader, &mut link.writer);
        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_client => r.map(|_| ()),
        }
        .map_err(|e| format!("copy: {}", e))?;
        Ok(())
    }
}

struct TestDispatcher {
    handler: TestFreedom,
}

#[async_trait]
impl Dispatcher for TestDispatcher {
    async fn dispatch(&self, mut session: Session, dest: Destination) -> ProxyResult<Link> {
        let (inbound_link, mut outbound_link) = astra_core_transport::new_link_pair();
        session.outbound = Some(Outbound {
            target: dest.clone(),
            original_target: dest,
            route_target: None,
            tag: String::new(),
        });
        let handler = TestFreedom { echo_addr: self.handler.echo_addr };
        tokio::spawn(async move {
            let _ = handler.process(session, &mut outbound_link, &handler).await;
        });
        Ok(inbound_link)
    }
}

#[tokio::test]
async fn test_dokodemo_to_freedom_echo() {
    // 1. Start echo server
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 { break; }
            s.write_all(&buf[..n]).await.unwrap();
        }
    });

    // 2. Setup dispatcher with test freedom handler
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(TestDispatcher {
        handler: TestFreedom { echo_addr },
    });

    // 3. Dokodemo inbound accepts a connection
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let dokodemo = astra_core_proxy_dokodemo::Handler::new(
        astra_core_proxy_dokodemo::InboundConfig {
            address: Some(Address::Ipv4([127, 0, 0, 1])),
            port: 0,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let session = Session {
            inbound: None,
            outbound: None,
            content: None,
        };
        dokodemo.process(session, conn, dispatcher).await.unwrap();
    });

    // 4. Client connects and does echo test
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    client.write_all(b"hello world").await.unwrap();
    let mut buf = vec![0u8; 11];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello world");

    client.write_all(b"ping").await.unwrap();
    let mut buf = vec![0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    let _ = client.shutdown().await;
}
