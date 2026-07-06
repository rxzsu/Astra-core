use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use astra_core_net::Destination;

use crate::config::Config;

pub async fn dial(dest: &Destination, config: &Config) -> Result<TcpStream, String> {
    let addr = format!("{}:{}", dest.address, dest.port.value());
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("httpupgrade dial: connect {}: {}", addr, e))?;

    let host = if config.host.is_empty() {
        addr.as_str()
    } else {
        config.host.as_str()
    };
    let path = config.normalized_path();

    let mut request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-Fetch-Mode: websocket\r\n\
         Sec-Fetch-Dest: empty\r\n\
         Sec-Fetch-Site: same-origin\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-cache\r\n\
         Accept: */*\r\n",
        path, host
    );

    for (key, value) in &config.headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }

    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("httpupgrade dial: write request: {}", e))?;

    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| format!("httpupgrade dial: read status: {}", e))?;

    if !status_line.contains("101") {
        return Err(format!(
            "httpupgrade dial: unexpected status: {}",
            status_line.trim()
        ));
    }

    // read remaining headers
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("httpupgrade dial: read header: {}", e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
    }

    Ok(stream)
}
