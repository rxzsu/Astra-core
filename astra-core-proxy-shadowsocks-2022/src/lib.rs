//! Shadowsocks 2022 — port of Go `proxy/shadowsocks_2022/`.
//!
//! Uses BLAKE3 key derivation, AEAD chunked TCP, and per-session UDP encryption.

pub mod inbound;
pub mod outbound;
pub mod protocol;
