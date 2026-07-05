use crate::protocol::CipherType;

#[derive(Debug, Clone)]
pub struct Account {
    pub cipher_type: CipherType,
    pub password: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub users: Vec<Account>,
    pub network: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub cipher_type: CipherType,
    pub password: String,
    pub key: Vec<u8>,
}
