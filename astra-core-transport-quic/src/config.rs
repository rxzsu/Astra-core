/// QUIC transport configuration.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct QuicConfig {
    /// Encryption method (none, aes-128-gcm, chacha20-poly1305).
    pub security: String,
    /// Encryption key.
    pub key: String,
}


impl From<&astra_core_config::transport::QUICConfig> for QuicConfig {
    fn from(cfg: &astra_core_config::transport::QUICConfig) -> Self {
        QuicConfig {
            security: cfg.security.clone(),
            key: cfg.key.clone(),
        }
    }
}
