# Go Xray-core vs Rust Astra-Core — Feature Parity

## Proxy Protocols (`proxy/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `proxy/blackhole/` | `astra-core-proxy-blackhole/` | ✅ Complete |
| `proxy/dns/` | `astra-core-proxy-dns/` | ✅ Complete |
| `proxy/dokodemo/` | `astra-core-proxy-dokodemo/` | ⚠️ Partial — FollowRedirect, TPROXY, FakeUDP (Linux), PortMap не портированы |
| `proxy/freedom/` | `astra-core-proxy-freedom/` | ✅ Fragment, FinalRule, Noise, DomainStrategy, ProxyProtocol scaffold |
| `proxy/http/` | `astra-core-proxy-http/` | ✅ Complete |
| `proxy/loopback/` | `astra-core-proxy-loopback/` | ✅ Complete |
| `proxy/shadowsocks/` | `astra-core-proxy-shadowsocks/` | ✅ Complete |
| `proxy/shadowsocks_2022/` | `astra-core-proxy-shadowsocks-2022/` | ⚠️ Partial — RelayInbound (multi-hop) не портирован |
| `proxy/socks/` | `astra-core-proxy-socks/` | ⚠️ Partial — UDP over TCP, FullCone NAT, HTTP fallback не портированы |
| `proxy/trojan/` | `astra-core-proxy-trojan/` | ✅ Fallback (SNI/ALPN/path), PROXY protocol scaffold, REALITY/TLS интеграция не портирована |
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
| ProxyProtocol v1/v2 | поле в `OutboundConfig` | ⚠️ Partial — scaffold, требуется доработка |
| FinalRule (блокировка по IP/CIDR/port с random blackhole delay) | `FinalRule` struct + `matches()` | ✅ Complete |
| Splice (zero-copy) | поле `use_splice` в `OutboundConfig` | ✅ tokio::io::copy использует splice() на Linux |
| Noise (случайный UDP шум) | `NoisePacketWriter` | ✅ Complete |
| DomainStrategy (ForceIP/ForceIPv4/ForceIPv6/ForceIPv46/ForceIPv64) | `resolve_strategy()` | ✅ Complete |
| Default blocking rules (private IPs, loopback, multicast) | — | ❌ Not ported |

## App Layer (`app/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `app/commander/` | `astra-core-app-grpc/` | ✅ HandlerService, StatsService, RoutingService, LoggerService (gRPC reflection не портирована) |
| `app/dispatcher/` | `astra-core-dispatcher/` | ✅ Complete |
| `app/dns/` | `astra-core-dns/` | ✅ UDP, TCP, DoH, FakeDNS, cache, EDNS0, parallel, priority routing, static hosts |
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
| DoH (DNS-over-HTTPS) | `DoHResolver` | ✅ Complete |
| DoQ (DNS-over-QUIC) | `DoQResolver` | ✅ Complete (базовая реализация, требует доработки интеграции) |
| h2c nameserver | `DoHResolver` | ✅ (через h2c URL схему) |
| Local (system resolver) | `SimpleDnsResolver` | ✅ Complete |
| FakeDNS | `FakeDnsResolver` | ✅ Complete |
| Cached (serveStale with TTL) | `CacheController` | ✅ Complete |
| Domain-based routing with priority (`!+` tags) | `sort_clients_by_domain()` | ✅ Complete |
| Expected/Unexpected IP filtering | `filter_expected()` | ✅ Complete |
| Client IP (EDNS0) | `build_edns0_subnet_option()` | ✅ Complete |
| DisableFallback / disableFallbackIfMatch | в `do_nameserver_lookup()` | ✅ Complete |
| enableParallelQuery | `parallel_query()` | ✅ Complete |
| StaticHosts with domain replacement (proxiedDomain) | `StaticHosts::lookup_recursive()` | ✅ Complete |

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
| **LeastLoadStrategy** (RTT deviation, baselines, expected, tolerance, weights, maxRTT) | `BalancerStrategy::LeastLoad` | ✅ Complete |

| Other Router Features | Rust | Status |
|---|---|---|
| WebhookNotifier (real-time routing event webhooks) | `WebhookNotifier` | ✅ Complete (HTTP POST + deduplication) |
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
| `common/antireplay/` | `astra-core-common::antireplay` | ✅ Complete |
| `common/bitmask/` | — | ❌ Not ported |
| `common/bytespool/` | `astra-core-buf::pool` | ✅ Complete |
| `common/cache/` | `astra-core-common::cache` (LRU) | ✅ Complete |
| `common/cmdarg/` | — | ❌ Not ported |
| `common/ctx/` | — | ❌ Not ported (context ID generation) |
| `common/dice/` | `astra-core-crypto::rand` | ✅ Complete |
| `common/drain/` | `astra-core-common::drain` | ✅ Complete |
| `common/errors/` | — | ❌ Not ported |
| `common/log/` | tracing | ⚠️ Partial — нет access log, severity levels |
| `common/ocsp/` | — | ❌ Not ported |
| `common/peer/` | — | ❌ Not ported |
| `common/reflect/` | — | ❌ Not ported |
| `common/retry/` | `astra-core-common::retry` | ✅ Complete (timed + exponential backoff) |
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
| `astra run` (запуск) | `cargo run -- -config` | ✅ Complete |
| `astra version` | `--version` | ✅ Complete |
| `astra uuid` | `astra-core-cli` | ✅ Complete (через `astra uuid`) |
| `astra x25519` | `astra-core-cli` | ✅ Complete (через `astra x25519`) |
| `astra tls cert` | `astra-core-cli` | ✅ Complete (через `astra tls cert`) |
| `astra tls ping` | `astra-core-cli` | ✅ Complete (через `astra tls ping`) |
| `astra api stats/statsquery/statssys/...` | `astra-core-cli` | ✅ Все API команды (через `astra api ...`) |
| `astra api adi/rmi/lsi/ado/rmo/lso/...` | `astra-core-cli` | ✅ Все API команды |
| `astra api adrules/rmrules/lsrules/bo/bi` | `astra-core-cli` | ✅ Все routing API команды |
| `astra api inbounduser/adu/rmu/sib/restartlogger` | `astra-core-cli` | ✅ Все API команды |
| `astra wg` | `astra-core-cli` | ✅ Complete (generate + derive from private key) |
| `astra vlessenc` | `astra-core-cli` | ✅ Complete (X25519 + ML-KEM-768 pairs) |
| `astra mlkem768` | `astra-core-cli` | ✅ Complete (ML-KEM-768 key gen) |
| `astra mldsa65` | `astra-core-cli` | ✅ Complete (ML-DSA-65 key gen) |
| `astra tls hash` | `astra-core-cli` | ✅ Complete (certificate SHA256) |
| `astra tls ech` | `astra-core-cli` | ✅ Complete (ECH key set gen) |
| `astra convert pb` / `json` | `astra-core-cli` | ✅ Complete (protobuf/JSON conversion) |

## gRPC API Commands (`app/commander/`)

| Go API | Rust | Status |
|---|---|---|
| HandlerService (add/remove/get inbounds/outbounds) | `HandlerSvc` | ✅ Complete |
| HandlerService (AlterInbound — add/remove users) | `HandlerSvc::alter_inbound` | ✅ Complete |
| HandlerService (GetInboundUsers, GetInboundUsersCount) | `HandlerSvc::get_inbound_users` / `get_inbound_users_count` | ✅ Complete |
| RoutingService (AddRule, RemoveRule, ListRule) | `RoutingSvc` | ✅ Complete |
| RoutingService (OverrideBalancerTarget, GetBalancerInfo) | `RoutingSvc` | ✅ Complete |
| LoggerService (RestartLogger) | `LoggerSvc` | ✅ Complete |
| StatsService (GetStats, QueryStats, GetSysStats) | `StatsSvc` | ✅ Complete |
| StatsService (GetStatsOnline, GetStatsOnlineIpList) | `StatsSvc` | ✅ Complete |
| StatsService (GetUsersStats, GetAllOnlineUsers) | `StatsSvc` | ✅ Complete |
| gRPC reflection | — | ❌ Not ported |
| CLI команды (xray api ...) | — | ❌ Not ported (нужен отдельный CLI бинарник) |

## Config Parsing (`infra/conf/`)

| Go feature | Rust | Status |
|---|---|---|
| JSON | serde (serde_json) | ✅ Complete |
| YAML | serde_yaml (`Config::from_yaml`) | ✅ Complete |
| TOML | toml crate (`Config::from_toml`) | ✅ Complete |
| Protobuf | — | ❌ Not ported |
| JSON5/JSONC (Java/Python comments) | `JsonCommentReader` | ✅ Complete |
| Config override/merge (multiple files) | `Config::override_with()` + `merge_configs()` | ✅ Complete |
| Auto-detect format | `detect_format()` по расширению | ✅ Complete |
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
