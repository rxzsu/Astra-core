#[derive(Debug, Clone)]
pub struct H2ClientConfig {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct H2ServerConfig {
    pub host: String,
    pub path: String,
}
