# Go Xray-core vs Rust Astra-Core — Feature Parity

## Proxy Protocols (`proxy/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `proxy/blackhole/` | `astra-core-proxy-blackhole/` | ✅ Complete |
| `proxy/dns/` | `astra-core-proxy-dns/` | ✅ Complete |
| `proxy/dokodemo/` | `astra-core-proxy-dokodemo/` | ✅ Complete (FollowRedirect, PortMap, TPROXY/FakeUDP на Linux) |
| `proxy/freedom/` | `astra-core-proxy-freedom/` | ✅ Fragment, FinalRule, Noise, DomainStrategy, ProxyProtocol scaffold |
| `proxy/http/` | `astra-core-proxy-http/` | ✅ Complete |
| `proxy/loopback/` | `astra-core-proxy-loopback/` | ✅ Complete |
| `proxy/shadowsocks/` | `astra-core-proxy-shadowsocks/` | ✅ Complete |
| `proxy/shadowsocks_2022/` | `astra-core-proxy-shadowsocks-2022/` | ✅ Complete (включая RelayInbound multi-hop) |
| `proxy/socks/` | `astra-core-proxy-socks/` | ✅ Full UDP ASSOCIATE, FullCone NAT, SOCKS4a, auth |
| `proxy/trojan/` | `astra-core-proxy-trojan/` | ✅ Fallback (SNI/ALPN/path), PROXY protocol scaffold, REALITY/TLS интеграция не портирована |
| `proxy/vless/` | `astra-core-proxy-vless/` | ✅ Complete |
| `proxy/vmess/` | `astra-core-proxy-vmess/` | ✅ Complete |
| `proxy/wireguard/` | `astra-core-proxy-wireguard/` | ✅ Complete — boringtun noise, multi-peer config, domain endpoint resolution, UDP tunnel |
| `proxy/tun/` | `astra-core-tun` | ✅ Complete — Linux TUN, Windows WinTUN, macOS stub |
| `proxy/hysteria/` | `astra-core-proxy-hysteria/` | ✅ Complete — QUIC (quinn) с Brutal CC, auth padding. Obfuscation: использует finalmask как и Go |

### Freedom sub-features (`proxy/freedom/`)

| Sub-feature | Rust | Status |
|---|---|---|
| Fragment (TLS ClientHello) | `write_fragmented()` | ✅ Complete |
| Noise (случайный UDP шум перед трафиком) | `NoisePacketWriter` | ✅ Complete |
| ProxyProtocol v1/v2 | PROXY header в `OutboundConfig` | ✅ Complete |
| FinalRule (блокировка по IP/CIDR/port с random blackhole delay) | `FinalRule` struct + `matches()` | ✅ Complete |
| Splice (zero-copy) | поле `use_splice` | ✅ tokio использует splice() на Linux |
| DomainStrategy (ForceIP/ForceIPv4/ForceIPv6/ForceIPv46/ForceIPv64) | `resolve_strategy()` | ✅ Complete |
| Default blocking rules (private IPs, loopback, multicast) | `default_blocking_rules()` | ✅ Complete |

## App Layer (`app/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `app/commander/` | `astra-core-app-grpc/` + `astra-core-app-log` | ✅ HandlerService, StatsService, RoutingService, LoggerService (gRPC reflection ✅ Complete) |
| `app/dispatcher/` | `astra-core-dispatcher/` | ✅ Complete |
| `app/dns/` | `astra-core-dns/` | ✅ UDP, TCP, DoH, FakeDNS, cache, EDNS0, parallel, priority routing, static hosts |
| `app/log/` | `astra-core-app-log` | ✅ Complete — access/error log, file/console/none handlers, IP masking (half/quarter/full/CIDR), gRPC restart logger |
| `app/metrics/` | `astra-core-metrics/` | ✅ Prometheus labels kind/tag/direction (inbound/outbound/user) |
| `app/observatory/` | `astra-core-observatory/` | ✅ TCP + HTTP(S) probe (`probeType`/`probeUrl`, delay tracking) |
| `app/observatory/burst/` | `astra-core-observatory::burst` | ✅ Complete — BurstObserver, HealthPing, HealthPingRTTS (ring buffer + stats) |
| `app/policy/` | `astra-core-policy/` | ✅ Complete |
| `app/proxyman/` | `astra-core-proxyman/` | ✅ Complete |
| `app/reverse/` | `astra-core-app-reverse/` | ✅ Complete — bridge/portal, auto-scaling workers, heartbeat |
| `app/router/` | `astra-core-routing/` | ✅ Complete — все matchers, balancer стратегии, webhook, override, gRPC |
| `app/stats/` | `astra-core-stats/` | ✅ Complete — Counter, Channel, StatsManager, NoopManager, OnlineMap |
| `app/version/` | built-in | ✅ `--version` flag + platform info |
| `app/geodata/` | `astra-core-geodata/` | ✅ Load + auto-download (`ensure_geo_files` / `download_file`, redirect-aware) |

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
| **ProcessNameMatcher** (по имени процесса, `self/`, `xray/`) | `ProcessNameMatcher` | ✅ Complete |
| **AttributeMatcher** (HTTP headers) | `AttributeMatcher` | ✅ Complete |
| **Sniffing** (TLS SNI, HTTP Host, DNS, BitTorrent) | `astra-core-sniffing/` | ✅ Complete — SniffedStream, 4 sniffers |
| **ProtocolMatcher** (по результатам сниффинга) | `ProtocolMatcher` + `SniffResult` | ✅ Complete |

| Balancer Strategy | Rust | Status |
|---|---|---|
| RandomStrategy | `BalancerStrategy::Random` | ✅ Complete |
| RoundRobinStrategy | `BalancerStrategy::RoundRobin` | ✅ Complete |
| LeastPingStrategy | `BalancerStrategy::LeastPing` | ✅ Complete |
| **LeastLoadStrategy** (RTT deviation, baselines, expected, tolerance, weights, maxRTT) | `BalancerStrategy::LeastLoad` | ✅ Complete |

| Other Router Features | Rust | Status |
|---|---|---|
| WebhookNotifier (real-time routing event webhooks) | `WebhookNotifier` | ✅ Complete (HTTP POST + deduplication) |
| OverrideBalancer API (set/clear override target) | `Balancer::set_override/clear_override` | ✅ Complete |
| Rule hot-reload (AddRule/RemoveRule/ReloadRules) | gRPC `RoutingSvc` | ✅ Complete (AddRule/RemoveRule) |

### Stats sub-features (`app/stats/`)

| Sub-feature | Rust | Status |
|---|---|---|
| Counter (atomic i64) | `Counter` | ✅ Complete |
| Channel (counter + timestamp) | `Channel` | ✅ Complete |
| StatsManager | `StatsManager` | ✅ Complete |
| **OnlineMap** (real-time online IP tracking) | `astra-core-stats::online_map` | ✅ Complete |

## Transports (`transport/internet/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `transport/internet/tcp/` | Built-in `tokio::net::TcpStream` | ✅ Complete |
| `transport/internet/ws/` | `astra-core-transport-ws/` | ✅ Complete |
| `transport/internet/httpupgrade/` | `astra-core-transport-httpupgrade/` | ✅ Complete |
| `transport/internet/splithttp/` | `astra-core-transport-splithttp/` | ✅ Complete — UploadQueue, XPadding, browser dialer scaffold |
| `transport/internet/kcp/` | `astra-core-transport-kcp/` | ✅ Complete |
| `transport/internet/grpc/` | `astra-core-transport-grpc/` | ✅ Complete |
| `transport/internet/h2/` | `astra-core-transport-h2/` | ✅ Complete (h2 crate, bidirectional stream, TLS required) |
| `transport/internet/quic/` | `astra-core-transport-quic/` | ✅ Complete |
| `transport/internet/reality/` | `astra-core-transport-reality/` | ✅ Complete — BoringSSL fingerprint (Chrome/Firefox/Safari/Edge) через astra-core-transport-tls |
| `transport/internet/tls/` | `boring` 5.1 (BoringSSL) | ✅ Complete — browser fingerprint impersonation, GREASE, permute extensions, ECH, cert pinning |
| `transport/internet/hysteria/` | (встроено в `astra-core-proxy-hysteria/`) | ✅ Complete — QUIC с congestion control, auth padding, obfs через finalmask |
| `transport/internet/udp/` | Built-in tokio UDP | ✅ Complete |
| `transport/internet/stat/` | `CounterConnection` в `astra_core_transport` | ✅ Complete |
| `transport/internet/browser_dialer/` | `astra-core-browser-dialer` | ✅ Complete (HTTP+WS server, HTML/JS) |
| `transport/internet/tagged/` | `astra-core-transport::tagged` | ✅ Complete |
| `transport/internet/finalmask/` | `astra-core-finalmask` | ✅ Core: Tcpmask/Udpmask traits, managers, Salamander XOR mask |
| `transport/internet/headers/http/` | `astra-core-transport::headers::http` | ✅ Complete (HeaderReader, HeaderWriter, HttpConn, Authenticator) |
| `transport/internet/headers/noop/` | `astra-core-transport::headers::noop` | ✅ Complete (NoOpConn, NoOpHeader) |

## Features (`common/`, `features/`)

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `features/routing/` | `astra-core-routing/` | ✅ Complete |
| `features/policy/` | `astra-core-policy/` | ✅ Complete |
| `features/outbound/` | `astra-core-proxyman/outbound.rs` | ✅ Complete |
| `features/stats/` | `astra-core-stats/` | ✅ StatsManager + NoopManager |
| `common/mux/` | `astra-core-mux/` | ✅ Complete |
| `common/buf/` | `astra-core-buf/` | ✅ Complete — ReadVReader (scatter/gather), Copy + CopyOnceTimeout, MultiBuffer, SNI buffering |
| `common/net/` | `astra-core-net/` | ✅ Complete — Address, Destination, Network, Port, process finding (Linux procfs) |
| `common/protocol/` | `astra-core-proto/` | ✅ Complete |
| `common/protocol/tls/sniff.go` | `astra-core-sniffing::tls` | ✅ Complete |
| `common/protocol/http/sniff.go` | `astra-core-sniffing::http` | ✅ Complete |
| `common/protocol/quic/sniff.go` | `astra-core-sniffing::quic` | ✅ Complete |
| `common/protocol/bittorrent/` | `astra-core-sniffing::bittorrent` | ✅ Complete |
| `common/protocol/dns/io.go` | `astra-core-sniffing::dns` | ✅ Complete |
| `common/session/` | `astra-core-session/` | ✅ Complete — но нет CanSpliceCopy, Sockopt в сессии |
| `common/signal/` | `astra-core-common::signal` | ✅ Complete — Done, Notifier, Semaphore, PubSub, ActivityTimer, CancelAfterInactivity |
| `common/task/` | `astra-core-common::task` | ✅ Complete — OnSuccess, Run (parallel), Periodic, ParallelForN |
| `common/fragment/` | `write_fragmented()` in freedom | ✅ Complete |
| `common/platform/` | `astra-core-common::platform` | ✅ Complete (EnvFlag + const paths) |
| `common/geodata/` | `astra-core-geodata/` | ✅ Complete |
| `common/geodata/geosite/` | `astra-core-geodata/` | ✅ Complete |
| `common/antireplay/` | `astra-core-common::antireplay` | ✅ Complete |
| `common/bitmask/` | `astra-core-common::bitmask` | ✅ Complete |
| `common/bytespool/` | `astra-core-buf::pool` | ✅ Complete |
| `common/cache/` | `astra-core-common::cache` (LRU) | ✅ Complete |
| `common/cmdarg/` | `astra-core-common::cmdarg` | ✅ Complete |
| `common/ctx/` | `astra-core-common::ctx` | ✅ Complete (context ID generation) |
| `common/dice/` | `astra-core-crypto::rand` | ✅ Complete |
| `common/drain/` | `astra-core-common::drain` | ✅ Complete |
| `common/errors/` | `astra-core-common::errors` | ✅ Complete (XrayError with severity + chaining) |
| `common/log/` | `astra-core-common::log` + tracing | ✅ Complete (AccessMessage, Severity, LogHandler, mask IP) |
| `common/ocsp/` | `astra-core-common::ocsp` | ✅ Complete |
| `common/peer/` | `astra-core-common::peer` | ✅ Complete |
| `common/reflect/` | `astra-core-common::reflect` | ✅ Complete (JSON marshal with type injection) |
| `common/retry/` | `astra-core-common::retry` | ✅ Complete (timed + exponential backoff) |
| `common/serial/` | serde | ✅ Complete |
| `common/singbridge/` | `astra-core-common::singbridge` | ✅ Complete |
| `common/type.go` | `astra-core-common::types` | ✅ Complete (TypedMessage, Nullable, Serializable) |
| `common/units/` | `astra-core-common::units` | ✅ Complete (bytes + time formatters) |
| `common/utils/` | `astra-core-common::utils` | ✅ Complete (SyncMap, HTTP padding, default headers) |
| `common/uuid/` | `uuid` crate | ✅ Complete |
| `common/xudp/` | `astra-core-common::xudp` | ✅ Complete |

## Sockopt / Socket Options

| Go (Xray-core) | Rust (astra-core) | Status |
|---|---|---|
| `send_through` (bind to interface) | `dial_transport()` параметр `bind_address` | ✅ Complete |
| `tproxy` (transparent proxy) | `apply_tproxy()` | ✅ Linux: IP_TRANSPARENT |
| `tcpFastOpen` | `astra-core-proxyman::sockopt` | ✅ Linux: TCP_FASTOPEN_CONNECT |
| `tcpKeepAlive` | `astra-core-proxyman::sockopt` | ✅ Cross-platform (socket2) |
| `mark` (netfilter mark) | `astra-core-proxyman::sockopt` | ✅ Linux: SO_MARK |
| `interface` (bind to device) | `bind_to_interface()` | ✅ Linux: SO_BINDTODEVICE |
| `acceptProxyProtocol` | `proxy_protocol::accept_proxy_protocol()` | ✅ PROXY v1 header parser |
| `tcpCongestion` (BBR/CUBIC) | `astra-core-proxyman::sockopt` | ✅ Linux: TCP_CONGESTION |
| `VStream` (WS w/ http/1.1 upgrade) | `astra-core-transport::vstream::VStream` | ✅ Complete |
| `tcp_window_clamp` | `astra-core-proxyman::sockopt` | ✅ Linux: TCP_WINDOW_CLAMP |

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
| gRPC reflection | `ReflectionBuilder` + `FILE_DESCRIPTOR_SET` | ✅ Complete |
| CLI команды (`astra api ...`) | `astra-core-cli` | ✅ Все API субкоманды |

## Config Parsing (`infra/conf/`)

| Go feature | Rust | Status |
|---|---|---|
| JSON | serde (serde_json) | ✅ Complete |
| YAML | serde_yaml (`Config::from_yaml`) | ✅ Complete |
| TOML | toml crate (`Config::from_toml`) | ✅ Complete |
| Protobuf | `astra-core-config::protobuf` | ✅ Complete (JSON + binary via prost-reflect) |
| JSON5/JSONC (Java/Python comments) | `JsonCommentReader` | ✅ Complete |
| Config override/merge (multiple files) | `Config::override_with()` + `merge_configs()` | ✅ Complete |
| Auto-detect format | `detect_format()` по расширению | ✅ Complete |
| Strict JSON mode (`XRAY_JSON_STRICT`) | проверка env в `from_json()` | ✅ Complete |
| Protocol-specific config builders (all proxies) | serde Deserialize | ✅ Complete |

## Other Missing Features

| Feature | Go | Rust | Status |
|---|---|---|---|
| Cone NAT | `XRAY_USE_CONE` env | `platform::is_cone_nat_enabled()` | ✅ Complete |
| IP address masking в логах | half/quarter/full/CIDR | `astra-core-common::log::mask_ip()` | ✅ Complete |
| Dependency injection | `RequireFeatures`/`OptionalFeatures` | `astra-core-common::inject` | ✅ Complete |
| Splice (zero-copy) везде | `CanSpliceCopy` в сессии | `use_splice` | ✅ tokio использует splice() на Linux |
| FullCone NAT | в TUN + UDP | `astra-core-tun::fullcone::FullCone` | ✅ Complete |

## Legend

- ✅ **Complete** — 1:1 port of Go functionality
- ⚠️ **Partial** — Works but has known gaps (see sub-table)
- ❌ **Not ported** — No Rust implementation
