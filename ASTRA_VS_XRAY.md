# Go Xray-core vs Rust Astra-Core — Feature Parity

## Proxy Protocols (`proxy/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `proxy/blackhole/` | `astra-core-proxy-blackhole/` | ✅ Complete |
| `proxy/dns/` | `astra-core-proxy-dns/` | ✅ Complete |
| `proxy/dokodemo/` | `astra-core-proxy-dokodemo/` | ✅ Complete |
| `proxy/freedom/` | `astra-core-proxy-freedom/` | ✅ Complete (fragment wired) |
| `proxy/http/` | `astra-core-proxy-http/` | ✅ Complete |
| `proxy/loopback/` | `astra-core-proxy-loopback/` | ✅ Complete |
| `proxy/shadowsocks/` | `astra-core-proxy-shadowsocks/` | ✅ Complete |
| `proxy/shadowsocks_2022/` | `astra-core-proxy-shadowsocks-2022/` | ✅ Complete (AEAD chunked TCP + UDP + BLAKE3) |
| `proxy/socks/` | `astra-core-proxy-socks/` | ✅ Complete |
| `proxy/trojan/` | `astra-core-proxy-trojan/` | ✅ Complete |
| `proxy/vless/` | `astra-core-proxy-vless/` | ✅ Complete |
| `proxy/vmess/` | `astra-core-proxy-vmess/` | ✅ Complete |
| `proxy/wireguard/` | `astra-core-proxy-wireguard/` | ✅ Complete (boringtun noise + UDP tunnel) |
| `proxy/tun/` | — | ❌ Not ported |
| `proxy/hysteria/` | `astra-core-proxy-hysteria/` | ✅ Complete (QUIC transport, Brutal CC, auth) |

## App Layer (`app/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `app/commander/` | `astra-core-app-grpc/` | ✅ HandlerService + StatsService |
| `app/dispatcher/` | `astra-core-dispatcher/` | ✅ Complete |
| `app/dns/` | `astra-core-dns/` | ✅ UDP + TCP (RFC 1035), hosts, Fake DNS |
| `app/log/` | — | ❌ Not ported (uses tracing) |
| `app/metrics/` | `astra-core-metrics/` | ✅ Prometheus /metrics endpoint |
| `app/observatory/` | `astra-core-observatory/` | ✅ TCP probe + balancer failover |
| `app/policy/` | `astra-core-policy/` | ✅ Complete |
| `app/proxyman/` | `astra-core-proxyman/` | ✅ Complete |
| `app/reverse/` | `astra-core-app-reverse/` | ✅ Complete |
| `app/router/` | `astra-core-routing/` | ✅ Complete |
| `app/stats/` | `astra-core-stats/` | ✅ Counter, Channel, StatsManager |
| `app/version/` | built-in | ✅ `--version` flag + platform info |

## Transports (`transport/internet/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `transport/internet/tcp/` | Built-in `tokio::net::TcpStream` | ✅ Complete |
| `transport/internet/ws/` | `astra-core-transport-ws/` | ✅ Complete |
| `transport/internet/httpupgrade/` | `astra-core-transport-httpupgrade/` | ✅ Complete |
| `transport/internet/splithttp/` | `astra-core-transport-splithttp/` | ✅ Complete |
| `transport/internet/kcp/` | `astra-core-transport-kcp/` | ✅ Complete |
| `transport/internet/grpc/` | `astra-core-transport-grpc/` | ✅ Complete |
| `transport/internet/quic/` | `astra-core-transport-quic/` | ✅ Complete (Xray has **no** custom QUIC obfuscation — only standard RFC 9000 + SNI sniffing) |
| `transport/internet/reality/` | `astra-core-transport-reality/` | ❌ Blocked — requires [uTLS](https://github.com/refraction-networking/utls) browser ClientHello. Rust ecosystem has no equivalent. Falls through to camouflage target. |
| `transport/internet/tls/` | `rustls` 0.23 | ✅ Complete |

## Features (`common/`, `features/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `features/routing/` | `astra-core-routing/` | ✅ Complete |
| `features/policy/` | `astra-core-policy/` | ✅ Complete |
| `features/outbound/` | `astra-core-proxyman/outbound.rs` | ✅ Complete |
| `features/stats/` | `astra-core-stats/` | ✅ Counters + channels |
| `common/mux/` | `astra-core-mux/` | ✅ Complete |
| `common/buf/` | `astra-core-buf/` | ✅ Complete |
| `common/net/` | `astra-core-net/` | ✅ Complete |
| `common/protocol/` | `astra-core-proto/` | ✅ Complete |
| `common/session/` | `astra-core-session/` | ✅ Complete |
| `common/signal/` | `astra-core-proxy::timeout::TimeoutConn` | ✅ Timeout wrapper with idle timeout |
| `common/task/` | — (periodic tasks) | ✅ Via `tokio::time::interval` |
| `common/fragment/` | `write_fragmented()` in freedom | ✅ Complete |
| `common/platform/` | — (env flags) | ❌ Not ported |
| `common/geodata/` | `astra-core-geodata/` | ✅ Complete (loads geoip.dat / geosite.dat via prost protobuf; `geoip:XX` / `geosite:XX` expansion in routing rules) |
| `common/geodata/geosite/` | `astra-core-geodata/` | ✅ Complete (DomainType Plain/Regex/Domain/Full mapped to DomainMatcher) |

## Sockopt / Socket Options

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `send_through` (bind to interface) | — | ❌ Not ported |
| `tproxy` (transparent proxy) | — | ❌ Not ported |
| `tcpFastOpen` | `astra-core-proxy` | ✅ `Handler::with_tcp_fast_open()` |
| `tcpKeepAlive` | `astra-core-proxy` | ✅ `Handler::with_keepalive()` |
| `mark` (netfilter mark) | — | ❌ Not ported |
| `interface` (bind to device) | — | ❌ Not ported |
| `acceptProxyProtocol` | — (HTTPUpgrade has it) | ❌ Not ported in all transports |

## Other

| Feature | Status | Notes |
|---|---|---|
| Website / landing page | ✅ | `website/`, Vue + Tailwind + motion-v |
| Config JSON parsing | ✅ | `astra-core-config/`, serde |
| Builder (config → runtime) | ✅ | `astra-core-app/src/builder.rs` |
| Main entrypoint | ✅ | `astra-core-main/` |
| Tests | 180+ passing | 0 warnings |
| CLI flags | ✅ | `-config`, `-test` |

## Legend

- ✅ **Complete** — 1:1 port of Go functionality
- ⚠️ **Partial** — Works but has known gaps
- ❌ **Not ported** — No Rust implementation
