use crate::protocol::key_from_password;

#[derive(Debug, Clone)]
pub struct Account {
    pub password: String,
    pub key: [u8; 56],
}

impl Account {
    pub fn new(password: String) -> Self {
        let key = key_from_password(&password);
        Account { password, key }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Fallback {
    pub name: String,   // SNI match
    pub alpn: String,   // ALPN match
    pub path: String,   // HTTP path match (for h2c)
    pub dest: String,   // destination address (host:port)
    pub xver: u64,      // PROXY protocol version (0 = disabled)
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub users: Vec<Account>,
    pub fallbacks: Vec<Fallback>,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub key: [u8; 56],
}

impl ClientConfig {
    pub fn new(server: String, port: u16, password: String) -> Self {
        let key = key_from_password(&password);
        ClientConfig {
            server,
            port,
            password,
            key,
        }
    }
}
