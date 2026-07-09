use crate::config::Config;

/// Fully async TUN device trait.
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    async fn start(&self) -> Result<(), String>;
    fn name(&self) -> Result<String, String>;
    fn index(&self) -> Result<i32, String>;
    /// Read a raw IP packet asynchronously.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, String>;
    /// Write a raw IP packet asynchronously.
    async fn send(&self, buf: &[u8]) -> Result<(), String>;
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

// ─── Linux TUN (fully async via tun::AsyncDevice) ──────────────────────────

#[cfg(target_os = "linux")]
struct LinuxTun {
    device: tun::AsyncDevice,
    name: String,
}

#[cfg(target_os = "linux")]
async fn create_linux_tun(config: &Config) -> Result<Box<dyn TunDevice>, String> {
    use tun::TunConfiguration;
    let mut tun_cfg = TunConfiguration::new();
    tun_cfg
        .name(&config.name)
        .mtu(config.mtu as i32)
        .up()
        .packet_info(false);

    let device = tun::create_as_async(&tun_cfg).map_err(|e| format!("create tun: {}", e))?;

    // Set IP addresses via ip CLI
    for addr in &config.addresses {
        set_address(&config.name, addr)?;
    }
    bring_up(&config.name)?;

    Ok(Box::new(LinuxTun {
        device,
        name: config.name.clone(),
    }))
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TunDevice for LinuxTun {
    async fn start(&self) -> Result<(), String> {
        Ok(())
    }

    fn name(&self) -> Result<String, String> {
        Ok(self.name.clone())
    }

    fn index(&self) -> Result<i32, String> {
        Ok(0)
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.device.recv(buf).await.map_err(|e| e.to_string())
    }

    async fn send(&self, buf: &[u8]) -> Result<(), String> {
        self.device.send(buf).await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn set_address(ifname: &str, cidr: &str) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("ip")
        .args(["addr", "add", cidr, "dev", ifname])
        .output()
        .map_err(|e| format!("ip addr add: {}", e))?;
    if !out.status.success() {
        let s = String::from_utf8_lossy(&out.stderr);
        if !s.contains("File exists") {
            return Err(format!("ip addr add failed: {}", s));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bring_up(ifname: &str) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("ip")
        .args(["link", "set", "dev", ifname, "up"])
        .output()
        .map_err(|e| format!("ip link set up: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "ip link set up failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

// ─── Platform stubs ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn create_windows_tun(_config: &Config) -> Result<Box<dyn TunDevice>, String> {
    Err("Windows TUN not yet implemented".into())
}

#[cfg(target_os = "macos")]
async fn create_macos_tun(_config: &Config) -> Result<Box<dyn TunDevice>, String> {
    Err("macOS TUN not yet implemented".into())
}
