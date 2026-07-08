use crate::config::Config;

/// TUN device trait - platform-specific TUN interface.
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    /// Start the TUN device.
    async fn start(&self) -> Result<(), String>;
    /// Get the interface name.
    fn name(&self) -> Result<String, String>;
    /// Get the interface index.
    fn index(&self) -> Result<i32, String>;
    /// Read a raw IP packet from the TUN device.
    fn read_packet(&self) -> Result<Vec<u8>, String>;
    /// Write a raw IP packet to the TUN device.
    fn write_packet(&self, data: &[u8]) -> Result<(), String>;
}

/// Create a platform-specific TUN device.
pub async fn create_tun(config: &Config) -> Result<Box<dyn TunDevice>, String> {
    #[cfg(target_os = "linux")]
    {
        return create_linux_tun(config).await;
    }
    #[cfg(target_os = "windows")]
    {
        return create_windows_tun(config).await;
    }
    #[cfg(target_os = "macos")]
    {
        return create_macos_tun(config).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err("TUN not supported on this platform".into())
    }
}

#[cfg(target_os = "linux")]
async fn create_linux_tun(config: &Config) -> Result<Box<dyn TunDevice>, String> {
    use tun::TunConfiguration;
    let mut tun_config = TunConfiguration::new();
    tun_config.name(&config.name)
        .mtu(config.mtu as i32)
        .up()
        .packet_info(false);
    
    // Use platform_create_async for async support
    let device = tun::create_as_async(&tun_config)
        .map_err(|e| format!("create tun: {}", e))?;
    
    // Set addresses
    for addr in &config.addresses {
        set_address(&config.name, addr)?;
    }
    
    // Bring interface up
    bring_up(&config.name)?;
    
    Ok(Box::new(LinuxTunDevice { device, name: config.name.clone() }))
}

#[cfg(target_os = "linux")]
struct LinuxTunDevice {
    device: std::sync::Mutex<tun::AsyncDevice>,
    name: String,
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TunDevice for LinuxTunDevice {
    async fn start(&self) -> Result<(), String> {
        Ok(())
    }

    fn name(&self) -> Result<String, String> {
        Ok(self.name.clone())
    }

    fn index(&self) -> Result<i32, String> {
        Ok(0)
    }

    fn read_packet(&self) -> Result<Vec<u8>, String> {
        Err("use async read instead".into())
    }

    fn write_packet(&self, _data: &[u8]) -> Result<(), String> {
        Err("use async write instead".into())
    }
}

#[cfg(target_os = "linux")]
fn set_address(ifname: &str, cidr: &str) -> Result<(), String> {
    let (addr_str, prefix_len) = cidr.split_once('/')
        .ok_or_else(|| format!("invalid CIDR: {}", cidr))?;
    let prefix: u8 = prefix_len.parse().map_err(|_| format!("invalid prefix: {}", prefix_len))?;
    use std::process::Command;
    let output = Command::new("ip")
        .args(["addr", "add", cidr, "dev", ifname])
        .output()
        .map_err(|e| format!("ip addr add: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "RTNETLINK answers: File exists" (address already set)
        if !stderr.contains("File exists") {
            return Err(format!("ip addr add failed: {}", stderr));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bring_up(ifname: &str) -> Result<(), String> {
    use std::process::Command;
    let output = Command::new("ip")
        .args(["link", "set", "dev", ifname, "up"])
        .output()
        .map_err(|e| format!("ip link set up: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ip link set up failed: {}", stderr));
    }
    Ok(())
}

// ─── Windows TUN ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn create_windows_tun(_config: &Config) -> Result<Box<dyn TunDevice>, String> {
    Err("Windows TUN not yet implemented".into())
}

// ─── macOS TUN ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn create_macos_tun(_config: &Config) -> Result<Box<dyn TunDevice>, String> {
    Err("macOS TUN not yet implemented".into())
}
