pub mod config;
pub mod inbound;
pub mod outbound;
pub mod protocol;

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use astra_core_net::{Address, Port};
    use crate::protocol::{
        CipherType, password_to_key, write_address, read_address,
        create_aead, aead_chunk_encrypt, aead_chunk_decrypt,
    };

    #[test]
    fn test_cipher_key_sizes() {
        assert_eq!(CipherType::Aes128Gcm.key_size(), 16);
        assert_eq!(CipherType::Aes256Gcm.key_size(), 32);
        assert_eq!(CipherType::Chacha20Poly1305.key_size(), 32);
        assert_eq!(CipherType::XChacha20Poly1305.key_size(), 32);
        assert_eq!(CipherType::None.key_size(), 0);
    }

    #[test]
    fn test_password_to_key_aes256() {
        let key = password_to_key(b"password123", 32);
        assert_eq!(key.len(), 32);
        // first iteration: MD5(password)
        use md5::Digest;
        let first = md5::Md5::digest(b"password123");
        assert_eq!(key[..16], first[..]);
    }

    #[test]
    fn test_password_to_key_aes128() {
        let key = password_to_key(b"testkey", 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_write_read_address_ipv4_roundtrip() {
        let addr = Address::Ipv4([10, 0, 0, 1]);
        let mut buf = BytesMut::new();
        write_address(&mut buf, &addr);
        buf.extend_from_slice(&[0x01, 0xbb]); // port 443
        let (parsed, _) = read_address(&buf).unwrap();
        assert_eq!(parsed.address, addr);
        assert_eq!(parsed.port, Port(443));
    }

    #[test]
    fn test_write_read_address_ipv6_roundtrip() {
        let addr = Address::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        let mut buf = BytesMut::new();
        write_address(&mut buf, &addr);
        buf.extend_from_slice(&[0x00, 0x50]); // port 80
        let (parsed, _) = read_address(&buf).unwrap();
        assert_eq!(parsed.address, addr);
        assert_eq!(parsed.port, Port(80));
    }

    #[test]
    fn test_write_read_address_domain_roundtrip() {
        let addr = Address::Domain("example.com".into());
        let mut buf = BytesMut::new();
        write_address(&mut buf, &addr);
        buf.extend_from_slice(&[0x01, 0xbb]); // port 443
        let (parsed, _) = read_address(&buf).unwrap();
        assert_eq!(parsed.address, addr);
        assert_eq!(parsed.port, Port(443));
    }

    #[test]
    fn test_read_address_invalid() {
        assert!(read_address(&[]).is_err());
        assert!(read_address(&[0x01, 1, 2, 3]).is_err());
        assert!(read_address(&[0x99]).is_err());
    }

    #[test]
    fn test_create_aead_all_types() {
        for ct in &[CipherType::Aes128Gcm, CipherType::Aes256Gcm,
                    CipherType::Chacha20Poly1305, CipherType::XChacha20Poly1305] {
            let key = vec![0u8; ct.key_size()];
            let cipher = create_aead(*ct, &key);
            assert!(cipher.is_ok(), "failed to create {:?}", ct);
        }
        let cipher = create_aead(CipherType::None, &[]);
        assert!(cipher.is_err());
    }

    #[test]
    fn test_aead_chunk_encrypt_decrypt_roundtrip() {
        let key = vec![0xABu8; 16];
        let cipher = create_aead(CipherType::Aes128Gcm, &key).unwrap();
        let plaintext = b"hello shadowsocks";
        let nonce: &[u8] = &[0u8; 12];
        let _size_bytes: &[u8] = &[];
        let encrypted = aead_chunk_encrypt(&cipher, nonce, plaintext, &[]);
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len());
        let decrypted = aead_chunk_decrypt(&cipher, nonce, &encrypted, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_chunk_decrypt_tampered() {
        let key = vec![0xABu8; 16];
        let cipher = create_aead(CipherType::Aes128Gcm, &key).unwrap();
        let nonce: &[u8] = &[0u8; 12];
        let encrypted = aead_chunk_encrypt(&cipher, nonce, b"data", &[]);
        let mut tampered = encrypted.clone();
        if let Some(b) = tampered.last_mut() {
            *b ^= 0xFF;
        }
        assert!(aead_chunk_decrypt(&cipher, nonce, &tampered, &[]).is_err());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = vec![0xCDu8; 32];
        let cipher = create_aead(CipherType::Chacha20Poly1305, &key).unwrap();
        let nonce: &[u8] = &[0u8; 12];
        let data = b"chacha test data";
        let enc = aead_chunk_encrypt(&cipher, nonce, data, &[]);
        let dec = aead_chunk_decrypt(&cipher, nonce, &enc, &[]).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_config_account() {
        let acct = crate::config::Account {
            cipher_type: CipherType::Aes256Gcm,
            password: "mypass".into(),
            key: vec![0u8; 32],
        };
        assert_eq!(acct.password, "mypass");
        assert_eq!(acct.cipher_type, CipherType::Aes256Gcm);
    }
}
