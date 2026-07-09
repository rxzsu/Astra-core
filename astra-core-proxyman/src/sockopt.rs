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
pub fn apply_keepalive(_stream: &tokio::net::TcpStream, _idle: i32, _interval: i32) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = _stream.as_raw_fd();
        let sock = unsafe { std::mem::ManuallyDrop::new(socket2::Socket::from_raw_fd(fd)) };
        let mut ka = socket2::TcpKeepalive::new();
        if _idle > 0 {
            ka = ka.with_time(std::time::Duration::from_secs(_idle as u64));
        }
        if _interval > 0 {
            ka = ka.with_interval(std::time::Duration::from_secs(_interval as u64));
        }
        let _ = sock.set_tcp_keepalive(&ka);
    }
}

/// Enable tproxy (transparent proxy) on a socket (Linux only).
#[cfg(target_os = "linux")]
pub fn apply_tproxy(stream: &tokio::net::TcpStream, enable: bool) {
    if !enable {
        return;
    }
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let val: i32 = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            19, // IP_TRANSPARENT
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

/// Non-Linux stub for tproxy.
#[cfg(not(target_os = "linux"))]
pub fn apply_tproxy(_stream: &tokio::net::TcpStream, _enable: bool) {}

/// Bind a socket to a specific network interface by name (SO_BINDTODEVICE).
/// Go equivalent: `transport/internet/tcp/sockopt_linux.go` interface binding.
#[cfg(target_os = "linux")]
pub fn bind_to_interface(stream: &tokio::net::TcpStream, iface_name: &str) {
    use std::os::unix::io::AsRawFd;
    if iface_name.is_empty() {
        return;
    }
    let fd = stream.as_raw_fd();
    let name_bytes = iface_name.as_bytes();
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name_bytes.as_ptr() as *const libc::c_void,
            name_bytes.len() as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn bind_to_interface(_stream: &tokio::net::TcpStream, _iface_name: &str) {}
