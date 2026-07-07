pub mod config;
pub mod inbound;
pub mod outbound;
pub mod protocol;

#[cfg(test)]
mod tests {
    use crate::protocol::{key_from_password, read_address, write_address, write_tcp_header, COMMAND_TCP};
    use crate::config::{Account, ClientConfig, ServerConfig};
    use astra_core_net::Address;

    #[test]
    fn test_key_from_password() {
        let key = key_from_password("password123");
        assert_eq!(key.len(), 56);
        // SHA224 of "password123" hex-encoded
        let expected = "3d45597256050bb1e93bd9c10aee4c8716f8774f5a48c995bf0cf860";
        assert_eq!(std::str::from_utf8(&key).unwrap(), expected);
    }

    #[test]
    fn test_write_address_ipv4() {
        let addr = Address::Ipv4([192, 168, 1, 1]);
        let mut buf = Vec::new();
        write_address(&mut buf, &addr);
        assert_eq!(buf, vec![0x01, 192, 168, 1, 1]);
    }

    #[test]
    fn test_write_address_ipv6() {
        let addr = Address::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut buf = Vec::new();
        write_address(&mut buf, &addr);
        assert_eq!(buf.len(), 17);
        assert_eq!(buf[0], 0x04);
    }

    #[test]
    fn test_write_address_domain() {
        let addr = Address::Domain("example.com".into());
        let mut buf = Vec::new();
        write_address(&mut buf, &addr);
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..], b"example.com");
    }

    #[test]
    fn test_read_address_ipv4() {
        let data = [0x01, 10, 0, 0, 1, 0x00, 0x50];
        let (addr, offset) = read_address(&data).unwrap();
        assert_eq!(offset, 7);
        assert_eq!(addr, Address::Ipv4([10, 0, 0, 1]));
    }

    #[test]
    fn test_read_address_domain() {
        let mut data = vec![0x03, 7];
        data.extend_from_slice(b"example");
        data.extend_from_slice(&[0x01, 0xbb]);
        let (addr, offset) = read_address(&data).unwrap();
        assert_eq!(offset, 11);
        assert_eq!(addr, Address::Domain("example".into()));
    }

    #[test]
    fn test_read_address_short_data() {
        assert!(read_address(&[]).is_err());
        assert!(read_address(&[0x01, 1, 2, 3]).is_err());
    }

    #[test]
    fn test_tcp_header_format() {
        let key = key_from_password("test");
        let addr = Address::Ipv4([10, 0, 0, 1]);
        let port = 443u16;
        let hdr = write_tcp_header(&key, &addr, port);
        assert_eq!(&hdr[..56], &key[..]);
        assert_eq!(&hdr[56..58], b"\r\n");
        assert_eq!(hdr[58], COMMAND_TCP);
        assert_eq!(hdr[59], 0x01);
        assert_eq!(&hdr[60..64], &[10, 0, 0, 1]);
        assert_eq!(&hdr[64..66], &443u16.to_be_bytes()[..]);
        assert_eq!(&hdr[66..68], b"\r\n");
    }

    #[test]
    fn test_account_new() {
        let acct = Account::new("mypass".into());
        assert_eq!(acct.password, "mypass");
        assert_ne!(acct.key, [0u8; 56]);
    }

    #[test]
    fn test_client_config_new() {
        let cfg = ClientConfig::new("server.com".into(), 443, "pass".into());
        assert_eq!(cfg.server, "server.com");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.password, "pass");
    }

    #[test]
    fn test_server_config() {
        let users = vec![Account::new("user1".into()), Account::new("user2".into())];
        let cfg = ServerConfig { users: users.clone(), fallbacks: vec![] };
        assert_eq!(cfg.users.len(), 2);
    }
}
