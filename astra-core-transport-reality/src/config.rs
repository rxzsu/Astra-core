use crate::crypto;

#[derive(Debug, Clone)]
pub struct RealityConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub password: String,
    pub spider_x: String,
    pub allow_insecure: bool,
}

impl RealityConfig {
    pub fn from_transport_config(
        cfg: &astra_core_config::transport::REALITYConfig,
    ) -> Result<Self, String> {
        let public_key = if !cfg.public_key.is_empty() {
            crypto::parse_public_key(&cfg.public_key)?
        } else {
            [0u8; 32]
        };

        let short_id = if !cfg.short_id.is_empty() {
            crypto::parse_short_id(&cfg.short_id)?
        } else {
            [0u8; 8]
        };

        let server_name = if !cfg.server_name.is_empty() {
            cfg.server_name.clone()
        } else {
            String::new()
        };

        let fingerprint = if !cfg.fingerprint.is_empty() {
            cfg.fingerprint.clone()
        } else {
            "chrome".to_string()
        };

        Ok(Self {
            server_name,
            fingerprint,
            public_key,
            short_id,
            password: cfg.password.clone(),
            spider_x: cfg.spider_x.clone(),
            allow_insecure: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub r#type: String,
    pub xver: u64,
}

impl RealityServerConfig {
    pub fn from_transport_config(
        cfg: &astra_core_config::transport::REALITYConfig,
    ) -> Result<Self, String> {
        let private_key = if !cfg.private_key.is_empty() {
            let decoded = hex::decode(&cfg.private_key)
                .map_err(|e| format!("hex decode private_key: {}", e))?;
            if decoded.len() != 32 {
                return Err(format!("private_key must be 32 bytes, got {}", decoded.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            arr
        } else {
            [0u8; 32]
        };

        let mut short_ids = Vec::new();
        for sid_hex in &cfg.short_ids {
            let sid = crate::crypto::parse_short_id(sid_hex)?;
            short_ids.push(sid);
        }

        let dest = cfg
            .dest
            .as_ref()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        Ok(Self {
            dest,
            server_names: cfg.server_names.clone(),
            private_key,
            short_ids,
            r#type: cfg.r#type.clone(),
            xver: cfg.xver,
        })
    }
}
