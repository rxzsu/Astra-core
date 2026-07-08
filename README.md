# Astra Core

Rust port of [Xray-core](https://github.com/xtls/xray-core) — a modular proxy platform with full protocol support, dynamic routing, and pluggable transports.

## Status

All core protocols and transports from Xray-core are ported ~90%. The following is 1:1 ported from Go:

### Proxy Protocols
| Protocol | Status |
|----------|--------|
| Freedom (direct) | ✅ Fragment, FinalRule, Noise, ProxyProtocol, Splice, DomainStrategy |
| SOCKS (4/4a/5) | ✅ Full auth + UDP ASSOCIATE |
| HTTP CONNECT | ✅ Basic + Proxy-Authorization |
| VLESS | ✅ Inbound/outbound, flows |
| VMess | ✅ AEAD, all security types |
| Shadowsocks | ✅ All ciphers |
| Shadowsocks 2022 | ✅ AEAD chunked + BLAKE3 + relay inbound |
| Trojan | ✅ Inbound/outbound + Fallback (SNI/ALPN/path) |
| Dokodemo (transparent proxy) | ✅ TCP + UDP |
| Blackhole | ✅ Discard traffic |
| DNS | ✅ Forward to upstream |
| Loopback | ✅ Chain back to inbound |
| Reverse (bridge/portal) | ✅ Mux + control protocol |
| WireGuard | ✅ Userspace (boringtun) |
| Hysteria | ✅ QUIC + Brutal CC + auth |

### Transports
| Transport | Status |
|-----------|--------|
| TCP | ✅ |
| WebSocket | ✅ |
| HTTPUpgrade | ✅ |
| SplitHTTP / XHTTP | ✅ |
| mKCP | ✅ |
| QUIC | ✅ (quinn — RFC 9000) |
| gRPC | ✅ (h2 tunnel via tonic) |
| H2 (HTTP/2) | ✅ (h2 crate) |
| REALITY | ❌ Blocked — requires uTLS, no Rust equivalent |

### Infrastructure
| Feature | Status |
|---------|--------|
| Router (domain/IP/port/network/protocol/user/process/attr) | ✅ + ProcessNameMatcher, AttributeMatcher |
| Balancing (Random, RoundRobin, LeastPing, **LeastLoad**) | ✅ LeastLoad with RTT baselines, weights, tolerance |
| WebhookNotifier (routing event webhooks) | ✅ HTTP POST with deduplication |
| DNS (UDP, TCP, DoH, DoQ, h2c, FakeDNS) | ✅ + cache, serveStale, EDNS0, parallel, priority |
| Sniffing (TLS SNI, HTTP Host, DNS, BitTorrent) | ✅ |
| Policy system (timeouts, buffer sizes, per-user levels) | ✅ |
| Mux (client/server, framing, session management) | ✅ |
| Observatory (health checks + auto-failover) | ✅ |
| Prometheus metrics (/metrics endpoint) | ✅ |
| Activity timers (idle timeout on connections) | ✅ |
| Sockopt (mark, tcpCongestion, tcpFastOpen, keepalive, tproxy) | ✅ Linux |
| TLS (rustls 0.23, server/client) | ✅ |

### Recently Added
| Feature | Status |
|---------|--------|
| GeoIP / GeoSite (geoip.dat, geosite.dat) | ✅ Load `.dat` files via prost protobuf |
| DoH / DoQ / h2c DNS | ✅ RFC 8484 / RFC 9250 / h2c |
| EDNS0 Client Subnet | ✅ RFC 7871 (IPv4 /24, IPv6 /96) |
| DNS cache + serveStale | ✅ CacheController with stale TTL |
| Parallel DNS + priority routing | ✅ Concurrent query, `!`/`+` tags |
| StaticHosts proxiedDomain | ✅ Domain replacement chaining |
| YAML / TOML config | ✅ serde_yaml + toml, auto-detect |
| JSON5/JSONC comments | ✅ State machine for `//`, `/* */`, `#` |
| Config override/merge | ✅ Multiple file merging |
| CLI (astra uuid, x25519, wg, tls cert/ping/hash/ech, api ...) | ✅ 30+ CLI commands |
| gRPC reflection | ✅ Service discovery via grpcurl |
| FinalMask traffic obfuscation | ✅ Salamander XOR (TCP + UDP) |
| Browser Dialer | ✅ WebSocket bridge + HTML/JS |
| TUN device | ⚠️ Linux TUN + smoltcp stack, FullCone NAT, ICMP |
| OnlineMap (real-time IP tracking) | ✅ |
| Dependency injection | ✅ Feature registry |
| OverrideBalancer API | ✅ Programmatic balancer override |
| Rule hot-reload (AddRule/RemoveRule) | ✅ gRPC RoutingService |
| gRPC API services | ✅ HandlerService, StatsService, RoutingService, LoggerService |
| send_through (bind to source IP) | ✅ TCP socket bind before connect |
| tproxy (IP_TRANSPARENT) | ✅ Linux transparent proxy |

### Missing / In Progress
| Feature | Status |
|---------|--------|
| REALITY uTLS ClientHello | Blocked — no uTLS in Rust ecosystem |
| Windows/macOS TUN | ❌ Not ported (Linux only) |
| Traditional access/error log system | ❌ Not ported (uses tracing) |

## Architecture

```
astra-core/
├── astra-core-app/            — Builder: wires config → handlers → dispatcher
├── astra-core-app-reverse/    — Reverse proxy (bridge/portal)
├── astra-core-app-grpc/       — gRPC API (HandlerService, StatsService, RoutingService, LoggerService)
├── astra-core-browser-dialer/ — Browser-based HTTP proxy
├── astra-core-buf/            — Buffer pool, reader/writer utilities
├── astra-core-cli/            — CLI binary (astra)
├── astra-core-common/         — Shared utilities (antireplay, cache, retry, drain, ctx, errors, ...)
├── astra-core-config/         — Config parsing (JSON/YAML/TOML, JSON5, merge/override)
├── astra-core-crypto/         — AES, ChaCha20, auth, chunk encryption
├── astra-core-dispatcher/     — DefaultDispatcher: routing + DNS + FakeDNS
├── astra-core-dns/            — DNS resolver (UDP, TCP, DoH, DoQ, h2c, EDNS0, cache)
├── astra-core-finalmask/      — Traffic obfuscation (Salamander XOR)
├── astra-core-geodata/        — GeoIP / GeoSite .dat loader
├── astra-core-metrics/        — Prometheus /metrics endpoint
├── astra-core-mux/            — Mux framing, session management
├── astra-core-net/            — Address, Destination, Port, Network
├── astra-core-observatory/    — Health checks + balancer auto-failover
├── astra-core-policy/         — Session/system policies, timeouts
├── astra-core-proto/          — ID, UUID, protocol types
├── astra-core-proxy/          — Core traits (InboundHandler, OutboundHandler, Dispatcher, Dialer)
├── astra-core-proxy-blackhole/    — Discard outbound
├── astra-core-proxy-dns/          — DNS forwarding outbound
├── astra-core-proxy-dokodemo/     — Transparent proxy inbound
├── astra-core-proxy-freedom/      — Direct outbound
├── astra-core-proxy-http/         — HTTP CONNECT inbound/outbound
├── astra-core-proxy-hysteria/     — Hysteria QUIC proxy
├── astra-core-proxy-loopback/     — Traffic chaining outbound
├── astra-core-proxy-shadowsocks/  — Shadowsocks inbound/outbound
├── astra-core-proxy-shadowsocks-2022/ — SS2022 (AEAD + BLAKE3 + relay)
├── astra-core-proxy-socks/        — SOCKS4/4a/5 inbound/outbound
├── astra-core-proxy-trojan/       — Trojan inbound/outbound + fallback
├── astra-core-proxy-vless/        — VLESS inbound/outbound
├── astra-core-proxy-vmess/        — VMess inbound/outbound
├── astra-core-proxy-wireguard/    — WireGuard userspace
├── astra-core-proxyman/      — inbound/outbound managers, transport dispatch, sockopt
├── astra-core-routing/       — Router, matchers, balancer, webhook
├── astra-core-session/       — Session, Inbound, Outbound, Content
├── astra-core-sniffing/      — Protocol detection (TLS/HTTP/DNS/BT)
├── astra-core-stats/         — Traffic counters + OnlineMap
├── astra-core-transport/     — Link, UdpLink, UdpPacket, tagged, vstream
├── astra-core-transport-grpc/     — gRPC h2 tunnel
├── astra-core-transport-h2/       — HTTP/2 transport
├── astra-core-transport-httpupgrade/ — HTTPUpgrade
├── astra-core-transport-kcp/      — mKCP
├── astra-core-transport-quic/     — QUIC (quinn)
├── astra-core-transport-reality/  — REALITY TLS 1.3
├── astra-core-transport-splithttp/ — SplitHTTP / XHTTP
├── astra-core-transport-ws/       — WebSocket
├── astra-core-tun/            — TUN device + smoltcp IP stack
└── astra-core-main/           — Entrypoint
```

## Usage

```bash
# Run as server
cargo run -- -config config.json

# CLI tool
astra api stats -name "inbound>>>socks>>>traffic>>>downlink"
astra uuid
astra x25519
astra wg
astra tls cert --cn example.com
astra tls ping example.com
astra tls hash --cert cert.pem
astra convert pb -o mix.pb config1.json config2.json
```

Config follows Xray-core JSON format (see [Xray JSON config docs](https://xtls.github.io/config/)) with additional YAML/TOML support.

## Build

- Rust edition 2024
- Workspace resolver v3
- Minimum supported Rust version: latest stable
- `cargo build` — debug build
- `cargo build --release` — release build
- `cargo test` — run all tests
- `cargo clippy` — lint

## License

[MIT](LICENSE)
