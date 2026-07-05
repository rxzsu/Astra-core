use astra_core_net::{Address, Port, TcpDestination};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Dokodemo-style inbound: accept TCP, resolve destination from config.
async fn dokodemo_accept(
    listener: TcpListener,
    target_addr: std::net::SocketAddr,
) {
    let (stream, _) = listener.accept().await.unwrap();

    let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(target_addr.port()));

    // Freedom outbound: dial target, pipe bidirectionally
    let handler = astra_core_proxy_freedom::OutboundHandler::new(
        astra_core_proxy_freedom::OutboundConfig::default(),
    );
    handler.process_async(&dest, stream).await.unwrap();
}

#[tokio::test]
async fn test_dokodemo_to_freedom_echo() {
    // 1. Start echo server (simulates the actual target)
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&buf[..n]).await.unwrap();
        }
    });

    // 2. Start Dokodemo listener (the proxy entry point)
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();

    tokio::spawn(dokodemo_accept(proxy, echo_addr));

    // 3. Connect client -> Dokodemo -> Freedom -> Echo -> back
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
