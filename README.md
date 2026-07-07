# Astra Core

Rust port of [Xray-core](https://github.com/xtls/xray-core) — a modular proxy platform with full protocol support, dynamic routing, and pluggable transports.

## Status

All core protocols and transports from Xray-core are ported. The following is 1:1 ported from Go:

### Proxy Protocols
| Protocol | Status |
|----------|--------|
| Freedom (direct) | ✅ Complete |
| SOCKS (4/4a/5) | ✅ Full auth + UDP ASSOCIATE |
| HTTP CONNECT | ✅ Basic + Proxy-Authorization |
| VLESS | ✅ Inbound/outbound, flows |
| VMess | ✅ AEAD, all security types |
| Shadowsocks | ✅ All ciphers |
| Trojan | ✅ Inbound/outbound |
| Dokodemo (transparent proxy) | ✅ TCP + UDP |
| Blackhole | ✅ Discard traffic |
| DNS | ✅ Forward to upstream |
| Loopback | ✅ Chain back to inbound |
| Reverse (bridge/portal) | ✅ Mux + control protocol |

### Transports
| Transport | Status |
|-----------|--------|
| TCP | ✅ |
| WebSocket | ✅ |
| HTTPUpgrade | ✅ |
| SplitHTTP / XHTTP | ✅ |
| mKCP | ✅ |
| QUIC | ✅ (quinn — Xray has no custom obfuscation, standard RFC 9000 only) |
| gRPC | ✅ (h2 tunnel via tonic) |
| REALITY | ❌ Blocked — requires uTLS browser ClientHello, no Rust equivalent |

### Infrastructure
| Feature | Status |
|---------|--------|
| Router (domain/IP/port/network/protocol/user matchers) | ✅ |
| DNS resolver (UDP nameservers, hosts, Fake DNS) | ✅ |
| Load balancer (round-robin, random) | ✅ |
| Sniffing (TLS SNI, HTTP Host, DNS, BitTorrent) | ✅ |
| Policy system (timeouts, buffer sizes, per-user levels) | ✅ |
| Mux (client/server, framing, session management) | ✅ |
| Observatory (health checks + auto-failover) | ✅ |
| Prometheus metrics (/metrics endpoint) | ✅ |
| Activity timers (idle timeout on connections) | ✅ |
| TCP keepalive + socket options | ✅ |
| TLS (rustls 0.23, server/client) | ✅ |

### Missing / In Progress
| Feature | Status |
|---------|--------|
| REALITY uTLS ClientHello | Blocked — no uTLS in Rust ecosystem |

### Recently Added
| Feature | Status |
|---------|--------|
| GeoIP / GeoSite (geoip.dat, geosite.dat) | ✅ Load `.dat` files via prost protobuf; build routing matchers from `geoip:XX` / `geosite:XX` |
| TCP DNS (tcp:// nameserver) | ✅ RFC 1035 TCP DNS queries with 2-byte length prefix |
| Hysteria protocol | ✅ QUIC-based with Brutal congestion control, password auth, connection pool |

## Architecture

```
astra-core/
├── astra-core-app/         — Builder: wires config → handlers → dispatcher
├── astra-core-app-reverse/ — Reverse proxy (bridge/portal)
├── astra-core-buf/         — Buffer pool, reader/writer utilities
├── astra-core-config/      — Config parsing (serde, JSON)
├── astra-core-crypto/      — AES, ChaCha20, auth, chunk encryption
├── astra-core-dispatcher/  — DefaultDispatcher: routing + DNS + FakeDNS
├── astra-core-dns/         — DNS resolver (UDP, hosts, Fake DNS)
├── astra-core-mux/         — Mux framing, session management
├── astra-core-net/         — Address, Destination, Port, Network
├── astra-core-policy/      — Session/system policies, timeouts
├── astra-core-proto/       — ID, UUID, protocol types
├── astra-core-proxy/       — Core traits (InboundHandler, OutboundHandler, Dispatcher, Dialer)
├── astra-core-proxy-blackhole/     — Discard outbound
├── astra-core-proxy-dns/           — DNS forwarding outbound
├── astra-core-proxy-dokodemo/      — Transparent proxy inbound
├── astra-core-proxy-freedom/       — Direct outbound
├── astra-core-proxy-http/          — HTTP CONNECT inbound/outbound
├── astra-core-proxy-hysteria/      — Hysteria QUIC proxy (Brutal CC)
├── astra-core-proxy-loopback/      — Traffic chaining outbound
├── astra-core-proxy-shadowsocks/   — Shadowsocks inbound/outbound
├── astra-core-proxy-socks/         — SOCKS4/4a/5 inbound/outbound
├── astra-core-proxy-trojan/        — Trojan inbound/outbound
├── astra-core-proxy-vless/         — VLESS inbound/outbound
├── astra-core-proxy-vmess/         — VMess inbound/outbound
├── astra-core-proxyman/   — inbound/outbound managers, transport dispatch
├── astra-core-routing/    — Router, matchers, balancer
├── astra-core-session/    — Session, Inbound, Outbound, Content
├── astra-core-sniffing/   — Protocol detection (TLS/HTTP/DNS/BT)
├── astra-core-transport/  — Link, UdpLink, UdpPacket
├── astra-core-transport-grpc/      — gRPC h2 tunnel
├── astra-core-transport-httpupgrade/— HTTPUpgrade
├── astra-core-transport-kcp/       — mKCP
├── astra-core-transport-quic/      — QUIC (quinn)
├── astra-core-transport-reality/   — REALITY TLS 1.3
├── astra-core-transport-splithttp/ — SplitHTTP / XHTTP
├── astra-core-transport-ws/        — WebSocket
├── astra-core-stats/               — Traffic counters (Counter, Channel, StatsManager)
├── astra-core-app-grpc/            — gRPC API server (HandlerService + StatsService)
├── astra-core-observatory/        — Health checks + balancer auto-failover
├── astra-core-geodata/            — GeoIP / GeoSite .dat loader (prost protobuf)
├── astra-core-metrics/            — Prometheus /metrics endpoint
└── astra-core-main/               — Entrypoint

website/                     — Vue + Tailwind + motion-v landing page
```

## Usage

```bash
cd astra-core
cargo build --release
cargo run -- -config config.json
```

Config follows Xray-core JSON format (see [Xray JSON config docs](https://xtls.github.io/config/)).

## Build

- Rust edition 2024
- Workspace resolver 2
- Minimum supported Rust version: latest stable
- `cargo build` — debug build
- `cargo build --release` — release build
- `cargo test` — run all tests

## License

[MIT](LICENSE)
