# Go Xray-core vs Rust Astra-Core — Feature Parity

## Proxy Protocols (`proxy/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `proxy/blackhole/` | `astra-core-proxy-blackhole/` | ✅ Complete |
| `proxy/dns/` | `astra-core-proxy-dns/` | ✅ Complete |
| `proxy/dokodemo/` | `astra-core-proxy-dokodemo/` | ⚠️ Partial — FollowRedirect, TPROXY, FakeUDP (Linux), PortMap не портированы |
| `proxy/freedom/` | `astra-core-proxy-freedom/` | ⚠️ Partial — см. Freedom sub-features ниже |
| `proxy/http/` | `astra-core-proxy-http/` | ✅ Complete |
| `proxy/loopback/` | `astra-core-proxy-loopback/` | ✅ Complete |
| `proxy/shadowsocks/` | `astra-core-proxy-shadowsocks/` | ✅ Complete |
| `proxy/shadowsocks_2022/` | `astra-core-proxy-shadowsocks-2022/` | ⚠️ Partial — RelayInbound (multi-hop) не портирован |
| `proxy/socks/` | `astra-core-proxy-socks/` | ⚠️ Partial — UDP over TCP, FullCone NAT, HTTP fallback не портированы |
| `proxy/trojan/` | `astra-core-proxy-trojan/` | ⚠️ Partial — Fallback (SNI/ALPN/path), PROXY protocol v1/v2, REALITY/TLS интеграция не портированы |
| `proxy/vless/` | `astra-core-proxy-vless/` | ✅ Complete |
| `proxy/vmess/` | `astra-core-proxy-vmess/` | ✅ Complete |
| `proxy/wireguard/` | `astra-core-proxy-wireguard/` | ⚠️ Partial — Kernel TUN, gVisor netstack DNS resolver, multi-peer dynamic add/remove, domain resolution strategies не портированы |
| `proxy/tun/` | — | ❌ Not ported — gVisor TCP/IP stack, FullCone NAT, ICMP forwarder, auto-routing, platform-specific TUN |
| `proxy/hysteria/` | `astra-core-proxy-hysteria/` | ⚠️ Partial — Go использует кастомную обфускацию (apernet/quic-go); Rust использует стандартный QUIC (quinn) |

### Freedom sub-features (`proxy/freedom/`)

| Sub-feature | Rust | Status |
|---|---|---|
| Fragment (TLS ClientHello) | `write_fragmented()` | ✅ Complete |
| Noise (случайный UDP шум перед трафиком) | `NoisePacketWriter` | ❌ Not ported |
| ProxyProtocol v1/v2 | — | ❌ Not ported |
| FinalRule (блокировка по IP/CIDR/port с random blackhole delay) | — | ❌ Not ported |
| Splice (zero-copy) | — | ❌ Not ported |
| DomainStrategy (ForceIP/ForceIPv4/ForceIPv6/ForceIPv46/ForceIPv64) | — | ⚠️ Partial — базовая стратегия |
| Default blocking rules (private IPs, loopback, multicast) | — | ❌ Not ported |

## App Layer (`app/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `app/commander/` | `astra-core-app-grpc/` | ⚠️ Partial — gRPC reflection не портирована (см. API команды) |
| `app/dispatcher/` | `astra-core-dispatcher/` | ✅ Complete |
| `app/dns/` | `astra-core-dns/` | ⚠️ Partial — см. DNS sub-features |
| `app/log/` | — | ❌ Not ported (использует tracing) — нет dual access/error лога, file/console/syslog handler'ов |
| `app/metrics/` | `astra-core-metrics/` | ⚠️ Partial — нет per-outbound metrics |
| `app/observatory/` | `astra-core-observatory/` | ⚠️ Partial — Go: HTTP(S) probe (configurable URL, generate_204); Rust: только TCP port probe |
| `app/policy/` | `astra-core-policy/` | ✅ Complete |
| `app/proxyman/` | `astra-core-proxyman/` | ✅ Complete |
| `app/reverse/` | `astra-core-app-reverse/` | ⚠️ Partial — heartbeat, auto-scaling workers не портированы |
| `app/router/` | `astra-core-routing/` | ⚠️ Partial — см. Router sub-features |
| `app/stats/` | `astra-core-stats/` | ⚠️ Partial — см. Stats sub-features |
| `app/version/` | built-in | ✅ `--version` flag + platform info |
| `app/geodata/` | `astra-core-geodata/` | ⚠️ Partial — нет auto-download/update geoip/geosite .dat файлов |

### DNS sub-features (`app/dns/`)

| Sub-feature | Rust | Status |
|---|---|---|
| UDP nameserver | `UdpDnsResolver` | ✅ Complete |
| TCP nameserver (RFC 1035) | `TcpDnsResolver` | ✅ Complete |
| DoH (DNS-over-HTTPS) | — | ❌ Not ported |
| DoQ (DNS-over-QUIC) | — | ❌ Not ported |
| h2c nameserver | — | ❌ Not ported |
| Local (system resolver) | `SimpleDnsResolver` | ✅ Complete |
| FakeDNS | `FakeDnsResolver` | ✅ Complete |
| Cached (serveStale with TTL) | — | ❌ Not ported |
| Domain-based routing with priority (`!+` tags) | — | ❌ Not ported |
| Expected/Unexpected IP filtering | — | ❌ Not ported |
| Client IP (EDNS0) | — | ❌ Not ported |
| DisableFallback / disableFallbackIfMatch | — | ❌ Not ported |
| enableParallelQuery | — | ❌ Not ported |
| StaticHosts with domain replacement (proxiedDomain) | — | ❌ Not ported |

### Router sub-features (`app/router/`)

| Matcher / Feature | Rust | Status |
|---|---|---|
| DomainMatcher | `DomainMatcher` (Exact/Subdomain/Keyword/Regex) | ✅ Complete |
| IPMatcher (source/target/local) | `IpMatcher`, `SourceIpMatcher` | ✅ Complete |
| PortMatcher (source/target/local/vless) | `PortMatcher`, `SourcePortMatcher` | ✅ Complete |
| NetworkMatcher | `NetworkMatcher` | ✅ Complete |
| UserMatcher | `UserMatcher` | ✅ Complete |
| InboundTagMatcher | `InboundTagMatcher` | ✅ Complete |
| ProtocolMatcher | `ProtocolMatcher` | ✅ Complete |
| **ProcessNameMatcher** (по имени процесса, `self/`, `xray/`) | — | ❌ Not ported |
| **AttributeMatcher** (HTTP headers) | — | ❌ Not ported |

| Balancer Strategy | Rust | Status |
|---|---|---|
| RandomStrategy | `BalancerStrategy::Random` | ✅ Complete |
| RoundRobinStrategy | `BalancerStrategy::RoundRobin` | ✅ Complete |
| LeastPingStrategy | `BalancerStrategy::LeastPing` | ✅ Complete |
| **LeastLoadStrategy** (RTT deviation, baselines, expected, tolerance, weights, maxRTT) | — | ❌ Not ported |

| Other Router Features | Rust | Status |
|---|---|---|
| WebhookNotifier (real-time routing event webhooks) | — | ❌ Not ported |
| OverrideBalancer API (set/clear override target) | — | ❌ Not ported |
| Rule hot-reload (AddRule/RemoveRule/ReloadRules) | — | ❌ Not ported |

### Stats sub-features (`app/stats/`)

| Sub-feature | Rust | Status |
|---|---|---|
| Counter (atomic i64) | `Counter` | ✅ Complete |
| Channel (counter + timestamp) | `Channel` | ✅ Complete |
| StatsManager | `StatsManager` | ✅ Complete |
| **OnlineMap** (real-time online IP tracking) | — | ❌ Not ported |

## Transports (`transport/internet/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `transport/internet/tcp/` | Built-in `tokio::net::TcpStream` | ✅ Complete |
| `transport/internet/ws/` | `astra-core-transport-ws/` | ✅ Complete |
| `transport/internet/httpupgrade/` | `astra-core-transport-httpupgrade/` | ✅ Complete |
| `transport/internet/splithttp/` | `astra-core-transport-splithttp/` | ⚠️ Partial — нет browser dialer, xpadding, upload queue |
| `transport/internet/kcp/` | `astra-core-transport-kcp/` | ✅ Complete |
| `transport/internet/grpc/` | `astra-core-transport-grpc/` | ✅ Complete |
| `transport/internet/h2/` | `astra-core-transport-h2/` | ✅ Complete (h2 crate, bidirectional stream, TLS required) |
| `transport/internet/quic/` | `astra-core-transport-quic/` | ✅ Complete |
| `transport/internet/reality/` | `astra-core-transport-reality/` | ❌ Blocked — требует uTLS browser ClientHello, ECH, ML-KEM-768, ML-DSA-65, SpiderX. Falls through to camouflage target. |
| `transport/internet/tls/` | `rustls` 0.23 | ⚠️ Partial — нет uTLS fingerprinting, ECH, certificate pinning, key log writer |
| `transport/internet/hysteria/` | (встроено в `astra-core-proxy-hysteria/`) | ⚠️ Partial — нет обфускации, padding per protocol stage |
| `transport/internet/udp/` | Built-in tokio UDP | ✅ Complete |
| `transport/internet/stat/` | — | ❌ Not ported (CounterConnection wrapper) |
| `transport/internet/browser_dialer/` | — | ❌ Not ported |
| `transport/internet/tagged/` | — | ❌ Not ported |
| `transport/internet/finalmask/` | — | ❌ Not ported (Udpmask/Tcpmask система маскировки) |
| `transport/internet/headers/` | — | ❌ Not ported |
| `transport/internet/domain/` | — | ❌ Not ported |
| `transport/internet/pipe/` | (built-in tokio pipe) | ✅ Через tokio::io::duplex |

## Features (`common/`, `features/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `features/routing/` | `astra-core-routing/` | ✅ Complete |
| `features/policy/` | `astra-core-policy/` | ✅ Complete |
| `features/outbound/` | `astra-core-proxyman/outbound.rs` | ✅ Complete |
| `features/stats/` | `astra-core-stats/` | ⚠️ Partial — нет NoopManager |
| `common/mux/` | `astra-core-mux/` | ✅ Complete |
| `common/buf/` | `astra-core-buf/` | ⚠️ Partial — нет ReadV (scatter/gather), splice-enabled copying, SNI buffering |
| `common/net/` | `astra-core-net/` | ⚠️ Partial — нет process finding (Linux/Android/Windows), system DNS |
| `common/protocol/` | `astra-core-proto/` | ✅ Complete |
| `common/session/` | `astra-core-session/` | ✅ Complete — но нет CanSpliceCopy, Sockopt в сессии |
| `common/signal/` | `astra-core-proxy::timeout::TimeoutConn` | ⚠️ Partial — нет Done/Notifier, CancelAfterInactivity |
| `common/task/` | tokio::time::interval | ⚠️ Partial — нет Periodic task |
| `common/fragment/` | `write_fragmented()` in freedom | ✅ Complete |
| `common/platform/` | — (env flags) | ❌ Not ported — `XRAY_USE_CONE`, `XRAY_USE_SPLICE`, `XRAY_BROWSER_DIALER`, `XRAY_JSON_STRICT` |
| `common/geodata/` | `astra-core-geodata/` | ✅ Complete |
| `common/geodata/geosite/` | `astra-core-geodata/` | ✅ Complete |
| `common/antireplay/` | — | ❌ Not ported |
| `common/bitmask/` | — | ❌ Not ported |
| `common/bytespool/` | `astra-core-buf::pool` | ✅ Complete |
| `common/cache/` | — | ❌ Not ported (generic cache with TTL) |
| `common/cmdarg/` | — | ❌ Not ported |
| `common/ctx/` | — | ❌ Not ported (context ID generation) |
| `common/dice/` | `astra-core-crypto::rand` | ✅ Complete |
| `common/drain/` | — | ❌ Not ported (behavioral drainer) |
| `common/errors/` | — | ❌ Not ported (error chaining with severity) |
| `common/log/` | tracing | ⚠️ Partial — нет access log, severity levels |
| `common/ocsp/` | — | ❌ Not ported |
| `common/peer/` | — | ❌ Not ported |
| `common/reflect/` | — | ❌ Not ported |
| `common/retry/` | — | ❌ Not ported (exponential backoff) |
| `common/serial/` | serde | ✅ Complete |
| `common/singbridge/` | — | ❌ Not ported (sing-box compatibility) |
| `common/type.go` | — | ❌ Not ported |
| `common/units/` | — | ❌ Not ported |
| `common/utils/` | — | ❌ Not ported (TypedSyncMap, HTTP utils) |
| `common/uuid/` | `uuid` crate | ✅ Complete |
| `common/xudp/` | — | ❌ Not ported |

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
| `tcpCongestion` (BBR/CUBIC) | — | ❌ Not ported |
| `VStream` (WS w/ http/1.1 upgrade) | — | ❌ Not ported |
| `sockopt` в session.Context | — | ❌ Not ported |

## CLI Commands (`main/commands/`)

| Go command | Rust | Status |
|---|---|---|
| `xray run` (запуск) | `cargo run -- -config` | ✅ Complete |
| `xray version` | `--version` | ✅ Complete |
| `xray test` | `-test` | ✅ Complete |
| `xray x25519` (X25519 key generation) | — | ❌ Not ported |
| `xray wg` (WireGuard key generation) | — | ❌ Not ported |
| `xray uuid` (UUID generation) | — | ❌ Not ported |
| `xray vlessenc` (VLESS encoding) | — | ❌ Not ported |
| `xray mlkem768` (ML-KEM-768 keygen) | — | ❌ Not ported |
| `xray mldsa65` (ML-DSA-65 keygen) | — | ❌ Not ported |
| `xray curve25519` | — | ❌ Not ported |
| `xray tls cert` | — | ❌ Not ported |
| `xray tls ping` | — | ❌ Not ported |
| `xray tls hash` | — | ❌ Not ported |
| `xray tls ech` (ECH key generation) | — | ❌ Not ported |
| `xray convert protobuf` | — | ❌ Not ported |
| `xray convert json` | — | ❌ Not ported |

## gRPC API Commands (`app/commander/`)

| Go API | Rust | Status |
|---|---|---|
| HandlerService (add/remove/get inbounds/outbounds) | `HandlerSvc` | ✅ Complete |
| StatsService (get/query/sys stats) | `StatsSvc` | ✅ Complete |
| gRPC reflection | — | ❌ Not ported |
| `api stats query/sys/online/get` | — | ❌ Not ported |
| `api inbound user add/remove/count` | — | ❌ Not ported |
| `api inbounds add/list/remove` | — | ❌ Not ported |
| `api outbounds add/list/remove` | — | ❌ Not ported |
| `api rules add/list/remove` | — | ❌ Not ported |
| `api balancer override/info` | — | ❌ Not ported |
| `api source_ip_block` | — | ❌ Not ported |
| `api logger restart` | — | ❌ Not ported |

## Config Parsing (`infra/conf/`)

| Go feature | Rust | Status |
|---|---|---|
| JSON | serde (serde_json) | ✅ Complete |
| YAML | — | ❌ Not ported |
| TOML | — | ❌ Not ported |
| Protobuf | — | ❌ Not ported |
| JSON5/JSONC (Java/Python comments) | — | ❌ Not ported |
| Config override/merge (multiple files) | — | ❌ Not ported |
| Auto-detect format | — | ❌ Not ported |
| Strict JSON mode (`XRAY_JSON_STRICT`) | — | ❌ Not ported |
| Protocol-specific config builders (all proxies) | serde Deserialize | ✅ Complete |

## Other Missing Features

| Feature | Go | Rust | Status |
|---|---|---|---|
| Cone NAT | `XRAY_USE_CONE` env | — | ❌ Not ported |
| IP address masking в логах | half/quarter/full/CIDR | — | ❌ Not ported |
| Browser dialer | WebSocket bridge + embedded HTML server | — | ❌ Not ported |
| Dependency injection | `RequireFeatures`/`OptionalFeatures` | — | ❌ Not ported |
| Splice (zero-copy) везде | `CanSpliceCopy` в сессии | — | ❌ Not ported |
| Sing-box bridge | `common/singbridge/` | — | ❌ Not ported |
| PROXY protocol v1/v2 | поддерживается | — | ❌ Not ported |
| FullCone NAT | в TUN + UDP | — | ❌ Not ported |

## Legend

- ✅ **Complete** — 1:1 port of Go functionality
- ⚠️ **Partial** — Works but has known gaps (see sub-table)
- ❌ **Not ported** — No Rust implementation
