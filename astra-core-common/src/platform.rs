/// Platform environment flags.
/// Go equivalent: `common/platform`
use std::collections::HashMap;
use std::sync::RwLock;

/// Lazy-loaded environment flag value.
pub struct EnvFlag {
    name: String,
    alt_name: String,
    cached: RwLock<Option<String>>,
}

impl EnvFlag {
    pub fn new(name: &str) -> Self {
        let alt = normalize_env_name(name);
        EnvFlag {
            name: name.to_string(),
            alt_name: alt,
            cached: RwLock::new(None),
        }
    }

    /// Get the value of this flag, checking environment variables.
    /// Caches the result after first read.
    pub fn get(&self, default: &str) -> String {
        let mut cache = self.cached.write().unwrap();
        if let Some(ref val) = *cache {
            return val.clone();
        }
        let val = std::env::var(&self.name)
            .or_else(|_| std::env::var(&self.alt_name))
            .unwrap_or_else(|_| default.to_string());
        *cache = Some(val.clone());
        val
    }
}

lazy_static::lazy_static! {
    static ref FLAGS: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());
}

/// Normalize env name: replace '.' with '_', uppercase.
fn normalize_env_name(name: &str) -> String {
    name.replace('.', "_").to_uppercase()
}

/// Set a platform flag programmatically (for testing).
pub fn set_flag(name: &str, value: &str) {
    FLAGS
        .write()
        .unwrap()
        .insert(name.to_string(), value.to_string());
}

/// Get a platform flag value.
pub fn get_flag(name: &str) -> Option<String> {
    FLAGS.read().unwrap().get(name).cloned()
}

/// Platform constants matching Go's common/platform.
pub const CONFIG_LOCATION: &str = "xray.location.config";
pub const CONFDIR_LOCATION: &str = "xray.location.confdir";
pub const ASSET_LOCATION: &str = "xray.location.asset";
pub const BROWSER_DIALER_ADDR: &str = "xray.browser.dialer";
pub const USE_CONE: &str = "xray.cone.disabled";

/// Check if CONE NAT is enabled (Go: XRAY_USE_CONE env).
pub fn is_cone_nat_enabled() -> bool {
    let flag = EnvFlag::new(USE_CONE);
    flag.get("") != "true"
}

/// Get the config file search paths.
pub fn config_paths() -> Vec<String> {
    let flag = EnvFlag::new(CONFIG_LOCATION);
    let path = flag.get("");
    if path.is_empty() {
        vec![
            "./config.json".into(),
            "./config.yaml".into(),
            "./config.toml".into(),
        ]
    } else {
        vec![path]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_flag_default() {
        let flag = EnvFlag::new("XRAY_TEST_FLAG");
        let val = flag.get("default");
        assert_eq!(val, "default");
    }

    #[test]
    fn test_normalize_env_name() {
        assert_eq!(
            normalize_env_name("xray.location.config"),
            "XRAY_LOCATION_CONFIG"
        );
    }

    #[test]
    fn test_config_paths_default() {
        let paths = config_paths();
        assert!(!paths.is_empty());
    }
}
