# Go Xray-core vs Rust Astra-Core — Feature Parity

## Proxy Protocols (`proxy/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `proxy/blackhole/` | `astra-core-proxy-blackhole/` | ✅ Complete |
| `proxy/dns/` | `astra-core-proxy-dns/` | ✅ Complete |
| `proxy/dokodemo/` | `astra-core-proxy-dokodemo/` | ✅ Complete |
| `proxy/freedom/` | `astra-core-proxy-freedom/` | ⚠️ Fragment pending |
| `proxy/http/` | `astra-core-proxy-http/` | ✅ Complete |
| `proxy/loopback/` | `astra-core-proxy-loopback/` | ✅ Complete |
| `proxy/shadowsocks/` | `astra-core-proxy-shadowsocks/` | ✅ Complete |
| `proxy/shadowsocks_2022/` | — | ❌ Not ported |
| `proxy/socks/` | `astra-core-proxy-socks/` | ✅ Complete |
| `proxy/trojan/` | `astra-core-proxy-trojan/` | ✅ Complete |
| `proxy/vless/` | `astra-core-proxy-vless/` | ✅ Complete |
| `proxy/vmess/` | `astra-core-proxy-vmess/` | ✅ Complete |
| `proxy/wireguard/` | — | ❌ Not ported |
| `proxy/tun/` | — | ❌ Not ported |
| `proxy/hysteria/` | — | ❌ Not ported |

## App Layer (`app/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `app/commander/` | — | ❌ gRPC management API |
| `app/dispatcher/` | `astra-core-dispatcher/` | ✅ Complete |
| `app/dns/` | `astra-core-dns/` | ⚠️ No TCP DNS, no caching |
| `app/log/` | — | ❌ Not ported (uses tracing) |
| `app/metrics/` | — | ❌ Prometheus metrics |
| `app/observatory/` | — | ❌ Outbound health checks |
| `app/policy/` | `astra-core-policy/` | ✅ Complete |
| `app/proxyman/` | `astra-core-proxyman/` | ✅ Complete |
| `app/reverse/` | `astra-core-app-reverse/` | ✅ Complete |
| `app/router/` | `astra-core-routing/` | ✅ Complete |
| `app/stats/` | — | ❌ Traffic counters |
| `app/version/` | — | ❌ Not ported |

## Transports (`transport/internet/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `transport/internet/tcp/` | Built-in `tokio::net::TcpStream` | ✅ Complete |
| `transport/internet/ws/` | `astra-core-transport-ws/` | ✅ Complete |
| `transport/internet/httpupgrade/` | `astra-core-transport-httpupgrade/` | ✅ Complete |
| `transport/internet/splithttp/` | `astra-core-transport-splithttp/` | ✅ Complete |
| `transport/internet/kcp/` | `astra-core-transport-kcp/` | ✅ Complete |
| `transport/internet/grpc/` | `astra-core-transport-grpc/` | ✅ Complete |
| `transport/internet/quic/` | `astra-core-transport-quic/` | ⚠️ No packet obfuscation |
| `transport/internet/reality/` | `astra-core-transport-reality/` | ⚠️ No uTLS ClientHello |
| `transport/internet/tls/` | `rustls` 0.23 | ✅ Complete |

## Features (`common/`, `features/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `features/routing/` | `astra-core-routing/` | ✅ Complete |
| `features/policy/` | `astra-core-policy/` | ✅ Complete |
| `features/outbound/` | `astra-core-proxyman/outbound.rs` | ✅ Complete |
| `features/stats/` | — | ❌ Not ported |
| `common/mux/` | `astra-core-mux/` | ✅ Complete |
| `common/buf/` | `astra-core-buf/` | ✅ Complete |
| `common/net/` | `astra-core-net/` | ✅ Complete |
| `common/protocol/` | `astra-core-proto/` | ✅ Complete |
| `common/session/` | `astra-core-session/` | ✅ Complete |
| `common/signal/` | — (activity timers) | ⚠️ Not ported |
| `common/task/` | — (periodic tasks) | ✅ Via `tokio::time::interval` |
| `common/fragment/` | `FragmentWriter` in freedom | ⚠️ Struct done, not wired |
| `common/platform/` | — (env flags) | ❌ Not ported |
| `common/geodata/` | — | ❌ Not ported |
| `common/geodata/geosite/` | — | ❌ Not ported |

## Sockopt / Socket Options

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `send_through` (bind to interface) | — | ❌ Not ported |
| `tproxy` (transparent proxy) | — | ❌ Not ported |
| `tcpFastOpen` | — | ❌ Not ported |
| `tcpKeepAlive` | — | ❌ Not ported |
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
| Tests | 150+ passing | 0 warnings |
| CLI flags | ✅ | `-config`, `-test` |

## Legend

- ✅ **Complete** — 1:1 port of Go functionality
- ⚠️ **Partial** — Works but has known gaps
- ❌ **Not ported** — No Rust implementation
