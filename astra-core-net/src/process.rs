/// Find the process (PID, name, path) that owns a given connection.
/// Go equivalent: `common/net.FindProcess`
///
/// # Arguments
/// * `network` - "tcp" or "udp"
/// * `src_ip` - Source IP address
/// * `src_port` - Source port
/// * `dest_ip` - Destination IP address (may be empty)
/// * `dest_port` - Destination port (may be 0)
pub fn find_process(
    network: &str,
    src_ip: &str,
    src_port: u16,
    _dest_ip: &str,
    _dest_port: u16,
) -> Result<ProcessInfo, String> {
    // Platform-specific implementations
    #[cfg(target_os = "linux")]
    {
        find_process_linux(network, src_ip, src_port)
    }

    #[cfg(target_os = "windows")]
    {
        find_process_windows(network, src_ip, src_port)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (network, src_ip, src_port, dest_ip, dest_port);
        Err("process lookup not supported on this platform".into())
    }
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

// ─── Linux implementation ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn find_process_linux(network: &str, src_ip: &str, src_port: u16) -> Result<ProcessInfo, String> {
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::net::IpAddr;
    use std::path::Path;
    use std::str::FromStr;

    let ip: IpAddr = FromStr::from_str(src_ip).map_err(|e| format!("invalid IP: {}", e))?;

    // Determine proc file based on network and IP version
    let proc_file = match network {
        "tcp" if ip.is_ipv4() => "/proc/net/tcp",
        "tcp" => "/proc/net/tcp6",
        "udp" if ip.is_ipv4() => "/proc/net/udp",
        "udp" => "/proc/net/udp6",
        _ => return Err(format!("unsupported network: {}", network)),
    };

    // Convert source IP and port to /proc/net/* hex format (little-endian)
    let target_hex = format!("{:08X}:{:04X}", ip_to_le_u32(ip), src_port);

    // Search proc file for the connection
    let file = fs::File::open(proc_file).map_err(|e| format!("open {}: {}", proc_file, e))?;
    let reader = BufReader::new(file);
    let mut found_inode: Option<String> = None;

    for line in reader.lines() {
        let line = line.map_err(|e| format!("read {}: {}", proc_file, e))?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if fields[1] == target_hex {
            found_inode = Some(fields[9].to_string());
            break;
        }
    }

    let inode = found_inode.ok_or_else(|| format!("connection not found in {}", proc_file))?;

    // Search /proc/*/fd/ for the inode
    let proc_dir = Path::new("/proc");
    let entries = fs::read_dir(proc_dir).map_err(|e| format!("read /proc: {}", e))?;

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };
        let pid_str = entry.file_name().to_string_lossy().to_string();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let fd_path = format!("/proc/{}/fd", pid_str);
        let fd_dir = match fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_res in fd_dir {
            let fd_entry = match fd_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let link_path = fd_entry.path();
            let link_target = match fs::read_link(&link_path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if link_target.to_string_lossy() == format!("socket:[{}]", inode) {
                let exe_path = format!("/proc/{}/exe", pid_str);
                let abs_path = fs::read_link(&exe_path)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let name = Path::new(&abs_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let pid: u32 = pid_str.parse().unwrap_or(0);
                return Ok(ProcessInfo {
                    pid,
                    name,
                    path: abs_path,
                });
            }
        }
    }

    Err("process not found".into())
}

#[cfg(target_os = "linux")]
fn ip_to_le_u32(ip: std::net::IpAddr) -> u32 {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            u32::from_le_bytes(octets)
        }
        std::net::IpAddr::V6(_) => 0,
    }
}

// ─── Windows implementation ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn find_process_windows(
    _network: &str,
    _src_ip: &str,
    _src_port: u16,
) -> Result<ProcessInfo, String> {
    Err("Windows process lookup not yet implemented".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_process_unsupported_platform() {
        #[cfg(not(target_os = "linux"))]
        {
            let result = find_process("tcp", "127.0.0.1", 8080, "", 0);
            assert!(result.is_err());
        }
    }
}
