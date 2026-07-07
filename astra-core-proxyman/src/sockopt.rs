use astra_core_config::transport::SocketConfig;

/// Applies socket options from Xray's SocketConfig to a TCP stream.
/// Mirrors Go's `transport/internet/tcp/sockopt_*.go` implementations.
#[cfg(target_os = "linux")]
pub fn apply_sockopt_linux(stream: &tokio::net::TcpStream, config: &SocketConfig) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    // Apply MARK (netfilter mark) - SO_MARK
    if config.mark != 0 {
        let mark_val = config.mark as u32;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_val as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
        }
    }

    // TCP congestion control algorithm
    if !config.tcp_congestion.is_empty() {
        let algo_bytes = config.tcp_congestion.as_bytes();
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                algo_bytes.as_ptr() as *const libc::c_void,
                algo_bytes.len() as libc::socklen_t,
            );
        }
    }

    // TCP Fast Open connect
    if config.tcp_fast_open.is_some() {
        let val: i32 = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
    }

    // TCP window clamp
    if config.tcp_window_clamp > 0 {
        let val = config.tcp_window_clamp;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
    }
}

/// Apply TCP keepalive settings (cross-platform via socket2).
pub fn apply_keepalive(stream: &tokio::net::TcpStream, idle: i32, interval: i32) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let sock = unsafe { std::mem::ManuallyDrop::new(socket2::Socket::from_raw_fd(fd)) };
        let mut ka = socket2::TcpKeepalive::new();
        if idle > 0 {
            ka = ka.with_time(std::time::Duration::from_secs(idle as u64));
        }
        if interval > 0 {
            ka = ka.with_interval(std::time::Duration::from_secs(interval as u64));
        }
        let _ = sock.set_tcp_keepalive(&ka);
    }
}
