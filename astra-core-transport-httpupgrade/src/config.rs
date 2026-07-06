#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub accept_proxy_protocol: bool,
}

impl Config {
    pub fn normalized_path(&self) -> String {
        let p = self.path.as_str();
        if p.is_empty() {
            return "/".into();
        }
        if !p.starts_with('/') {
            return format!("/{}", p);
        }
        p.to_owned()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: String::new(),
            path: "/".into(),
            headers: Vec::new(),
            accept_proxy_protocol: false,
        }
    }
}
