use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use astra_core_config::Config;
use astra_core_config::proxy::{
    DNSOutboundConfig, DokodemoConfig, FreedomConfig, HTTPInboundConfig, HTTPOutboundConfig,
    ShadowsocksInboundConfig, ShadowsocksOutboundConfig, SocksInboundConfig, SocksOutboundConfig,
    TrojanInboundConfig, TrojanOutboundConfig, VLessInboundConfig, VLessOutboundConfig,
    VMessInboundConfig, VMessOutboundConfig,
};
use astra_core_dispatcher::{DefaultDispatcher, DispatchHandler, HandlerProvider};
use astra_core_dns::{
    DnsResolver, DoHResolver, DoQResolver, FakeDnsResolver, NameServer, QueryStrategy,
    SimpleDnsResolver, StaticHosts, TcpDnsResolver, UdpDnsResolver, parse_hosts,
};
use astra_core_geodata::GeoDataManager;
use astra_core_net::{self, Address, Destination, ParseAddress};
use astra_core_proto::{ID, MemoryUser, SecurityType, UUID};
use astra_core_proxy::{InboundHandler, OutboundHandler as OutboundHandlerTrait};
use astra_core_proxy_shadowsocks_2022 as ss2022;
use astra_core_proxy_vless::Validator as VLessValidator;
use astra_core_proxyman::inbound;
use astra_core_proxyman::inbound::AlwaysOnInboundHandler;
use astra_core_proxyman::outbound;
use astra_core_proxyman::outbound::{MuxConfig, TlsConfig};
use astra_core_proxyman::transport;
use astra_core_routing::{
    AttributeMatcher, Balancer, BalancerStrategy, DomainMatcher, DomainStrategy, InboundTagMatcher,
    IpMatcher, NetworkMatcher, PortMatcher, ProcessNameMatcher, ProtocolMatcher, RouteRule, Router,
    SourceIpMatcher, SourcePortMatcher, UserMatcher,
};
use astra_core_stats::StatsManager;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hex;

pub struct AppRuntime {
    pub dispatcher: Arc<DefaultDispatcher>,
    pub inbound_handlers: Vec<AlwaysOnInboundHandler>,
    pub outbound_manager: Arc<outbound::Manager>,
    pub inbound_manager: Arc<inbound::Manager>,
    pub stats_manager: Arc<StatsManager>,
    pub metrics_addr: Option<String>,
}

fn convert_address(config_addr: &astra_core_config::types::Address) -> Address {
    ParseAddress(&config_addr.0)
}

fn parse_destination(redirect: &str) -> Result<Destination, String> {
    astra_core_net::ParseDestination(redirect)
}

fn parse_uuid(s: &str) -> Result<UUID, String> {
    let s = s.trim().replace('-', "");
    let bytes = hex_decode(&s)?;
    if bytes.len() != 16 {
        return Err(format!("invalid UUID length: {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(UUID(arr))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex string length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn parse_endpoint(s: &str) -> Result<(Address, u16), String> {
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!("invalid endpoint: {}", s));
    }
    let port: u16 = parts[0]
        .parse()
        .map_err(|_| format!("invalid port in: {}", s))?;
    let host = parts[1];
    let addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
            std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
        }
    } else {
        Address::Domain(host.to_string())
    };
    Ok((addr, port))
}

fn parse_security(s: &str) -> SecurityType {
    match s {
        "aes-128-gcm" => SecurityType::Aes128Gcm,
        "chacha20-poly1305" => SecurityType::ChaCha20Poly1305,
        "none" | "zero" => SecurityType::Zero,
        _ => SecurityType::Auto,
    }
}

fn parse_ss_cipher_type(
    method: &str,
) -> Result<astra_core_proxy_shadowsocks::protocol::CipherType, String> {
    match method {
        "aes-128-gcm" => Ok(astra_core_proxy_shadowsocks::protocol::CipherType::Aes128Gcm),
        "aes-256-gcm" => Ok(astra_core_proxy_shadowsocks::protocol::CipherType::Aes256Gcm),
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
            Ok(astra_core_proxy_shadowsocks::protocol::CipherType::Chacha20Poly1305)
        }
        "xchacha20-poly1305" | "xchacha20-ietf-poly1305" => {
            Ok(astra_core_proxy_shadowsocks::protocol::CipherType::XChacha20Poly1305)
        }
        "none" => Ok(astra_core_proxy_shadowsocks::protocol::CipherType::None),
        _ => Err(format!("unsupported shadowsocks cipher method: {}", method)),
    }
}

pub fn build_outbound_handler(
    config: &astra_core_config::OutboundDetourConfig,
    dispatcher_cell: astra_core_proxy_loopback::DispatcherCell,
) -> Result<Arc<dyn DispatchHandler>, String> {
    let handler: Arc<dyn OutboundHandlerTrait> = match config.protocol.as_str() {
        "freedom" => {
            let cfg: FreedomConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("freedom config: {}", e))?
                .unwrap_or_default();

            use astra_core_proxy_freedom::{FragmentConfig, parse_packets};
            let fragment = cfg.fragment.as_ref().map(|f| {
                let (pf, pt) = parse_packets(&f.packets);
                let (lmin, lmax) = f
                    .length
                    .as_ref()
                    .map(|r| (r.from as u64, r.to as u64))
                    .unwrap_or((1, 1));
                let (imin, imax) = f
                    .interval
                    .as_ref()
                    .map(|r| (r.from as u64, r.to as u64))
                    .unwrap_or((0, 0));
                FragmentConfig {
                    packets_from: pf,
                    packets_to: pt,
                    length_min: lmin,
                    length_max: lmax,
                    interval_min: imin,
                    interval_max: imax,
                    max_split_min: f.max_split_min.max(1),
                    max_split_max: f.max_split_max.max(1),
                }
            });
            Arc::new(astra_core_proxy_freedom::Handler::new(
                astra_core_proxy_freedom::OutboundConfig {
                    domain_strategy: cfg.domain_strategy,
                    redirect: if cfg.redirect.is_empty() {
                        None
                    } else {
                        Some(parse_destination(&cfg.redirect)?)
                    },
                    fragment,
                    noise: None,
                    final_rules: vec![],
                    proxy_protocol: 0,
                    use_splice: false,
                },
            ))
        }
        "vless" => {
            let cfg: VLessOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("vless config: {}", e))?
                .ok_or_else(|| "vless outbound requires settings".to_string())?;

            let vnext = cfg
                .vnext
                .first()
                .ok_or_else(|| "vless outbound requires at least one vnext".to_string())?;

            let user = vnext
                .users
                .first()
                .ok_or_else(|| "vless outbound requires at least one user in vnext".to_string())?;

            let server_addr = convert_address(&vnext.address);
            let server_dest =
                astra_core_net::TcpDestination(server_addr, astra_core_net::Port(vnext.port));

            Arc::new(astra_core_proxy_vless::OutboundProxyHandler::new(
                server_dest,
                astra_core_proxy_vless::OutboundConfig {
                    flow: user.flow.clone(),
                    seed: None,
                },
            ))
        }
        "vmess" => {
            let cfg: VMessOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("vmess config: {}", e))?
                .ok_or_else(|| "vmess outbound requires settings".to_string())?;

            let vnext = cfg
                .vnext
                .first()
                .ok_or_else(|| "vmess outbound requires at least one vnext".to_string())?;

            let user_cfg = vnext
                .users
                .first()
                .ok_or_else(|| "vmess outbound requires at least one user".to_string())?;

            let uuid = parse_uuid(&user_cfg.id)?;
            let id = ID::new(uuid);
            let security = parse_security(&user_cfg.security);
            let account = Arc::new(astra_core_proxy_vmess::account::MemoryAccount::new(
                id, security, false, false,
            ));
            let user = MemoryUser::new(user_cfg.level, user_cfg.email.clone(), Some(account));

            let server_addr = convert_address(&vnext.address);
            let server_dest = astra_core_net::TcpDestination(
                server_addr.clone(),
                astra_core_net::Port(vnext.port),
            );

            Arc::new(astra_core_proxy_vmess::outbound::Handler::new(
                server_dest,
                astra_core_proxy_vmess::outbound::OutboundConfig {
                    user,
                    address: server_addr,
                    port: astra_core_net::Port(vnext.port),
                },
            ))
        }
        "shadowsocks" => {
            let cfg: ShadowsocksOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("shadowsocks outbound config: {}", e))?
                .ok_or_else(|| "shadowsocks outbound requires settings".to_string())?;

            let cipher_type = parse_ss_cipher_type(&cfg.method)?;
            let key = astra_core_proxy_shadowsocks::protocol::password_to_key(
                cfg.password.as_bytes(),
                cipher_type.key_size(),
            );
            let client_cfg = astra_core_proxy_shadowsocks::config::ClientConfig {
                server: cfg.address.0.clone(),
                port: cfg.port,
                cipher_type,
                password: cfg.password.clone(),
                key,
            };

            Arc::new(astra_core_proxy_shadowsocks::outbound::Handler::new(
                client_cfg,
            ))
        }
        "shadowsocks-2022" => {
            let settings = config
                .settings
                .as_ref()
                .ok_or("ss2022 outbound requires settings")?;
            let addr_str = settings
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let port = settings.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let method = settings
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let key_b64 = settings.get("key").and_then(|v| v.as_str()).unwrap_or("");

            let cipher = ss2022::protocol::CipherType::from_str(method)
                .ok_or_else(|| format!("unsupported ss2022 method: {}", method))?;
            let key_raw = BASE64
                .decode(key_b64.as_bytes())
                .map_err(|e| format!("ss2022 key decode: {}", e))?;
            let key = ss2022::protocol::derive_master_key(&key_raw, cipher.key_size());
            let server_addr = match addr_str.parse::<std::net::IpAddr>() {
                Ok(ip) => match ip {
                    std::net::IpAddr::V4(v4) => astra_core_net::Address::Ipv4(v4.octets()),
                    std::net::IpAddr::V6(v6) => astra_core_net::Address::Ipv6(v6.octets()),
                },
                Err(_) => astra_core_net::Address::Domain(addr_str.to_string()),
            };

            Arc::new(ss2022::outbound::Handler::new(
                server_addr,
                astra_core_net::Port(port),
                cipher,
                key,
            ))
        }
        "trojan" => {
            let cfg: TrojanOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("trojan outbound config: {}", e))?
                .ok_or_else(|| "trojan outbound requires settings".to_string())?;

            let client_cfg = astra_core_proxy_trojan::config::ClientConfig::new(
                cfg.address.0.clone(),
                cfg.port,
                cfg.password.clone(),
            );

            Arc::new(astra_core_proxy_trojan::outbound::Handler::new(client_cfg))
        }
        "socks" => {
            let cfg: SocksOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("socks outbound config: {}", e))?
                .ok_or_else(|| "socks outbound requires settings".to_string())?;

            let client_cfg = astra_core_proxy_socks::outbound::ClientConfig {
                server_address: ParseAddress(&cfg.address.0),
                server_port: astra_core_net::Port(cfg.port),
                username: cfg.user,
                password: cfg.pass,
            };
            Arc::new(astra_core_proxy_socks::outbound::Handler::new(client_cfg))
        }
        "http" => {
            let cfg: HTTPOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("http outbound config: {}", e))?
                .ok_or_else(|| "http outbound requires settings".to_string())?;

            let client_cfg = astra_core_proxy_http::outbound::HttpOutboundConfig {
                server_address: ParseAddress(&cfg.address.0),
                server_port: astra_core_net::Port(cfg.port),
                username: cfg.user,
                password: cfg.pass,
            };
            Arc::new(astra_core_proxy_http::outbound::Handler::new(client_cfg))
        }
        "dns" => {
            let cfg: DNSOutboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("dns outbound config: {}", e))?
                .unwrap_or_default();

            let address = if let Some(ref addr) = cfg.address {
                ParseAddress(&addr.0)
            } else {
                return Err("dns outbound requires address".into());
            };

            Arc::new(astra_core_proxy_dns::Handler::new(address, cfg.port)?)
        }
        "blackhole" => Arc::new(astra_core_proxy_blackhole::Handler::new()),
        "loopback" => {
            let cfg: astra_core_config::proxy::LoopbackConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("loopback config: {}", e))?
                .unwrap_or_default();
            if cfg.inbound_tag.is_empty() {
                return Err("loopback outbound requires inbound_tag".into());
            }
            let handler =
                astra_core_proxy_loopback::Handler::new(cfg.inbound_tag, dispatcher_cell.clone());
            Arc::new(handler)
        }
        "reverse" => {
            let cfg: astra_core_config::ReverseConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("reverse config: {}", e))?
                .unwrap_or_default();
            let portal = cfg
                .portals
                .first()
                .ok_or("reverse outbound requires portal config")?;
            Arc::new(astra_core_app_reverse::PortalHandler::new(
                portal.tag.clone(),
                portal.domain.clone(),
            ))
        }
        "wireguard" => {
            let settings = config
                .settings
                .as_ref()
                .ok_or("wireguard requires settings")?;
            let private_key_b64 = settings
                .get("private_key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let private_key = BASE64
                .decode(private_key_b64.as_bytes())
                .map_err(|e| format!("wg key: {}", e))?;
            if private_key.len() != 32 {
                return Err("wg private key must be 32 bytes".into());
            }
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&private_key);

            let mut peers = Vec::new();
            if let Some(peers_arr) = settings.get("peers").and_then(|v| v.as_array()) {
                for p in peers_arr {
                    let ep = p.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
                    let pubkey_b64 = p.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
                    let pubkey_bytes = BASE64
                        .decode(pubkey_b64.as_bytes())
                        .map_err(|e| format!("wg pubkey: {}", e))?;
                    if pubkey_bytes.len() != 32 {
                        return Err("wg pubkey must be 32 bytes".into());
                    }
                    let mut public_key = [0u8; 32];
                    public_key.copy_from_slice(&pubkey_bytes);

                    let psk_b64 = p
                        .get("pre_shared_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let pre_shared_key = if !psk_b64.is_empty() {
                        let psk_bytes = BASE64
                            .decode(psk_b64.as_bytes())
                            .map_err(|e| format!("wg psk: {}", e))?;
                        if psk_bytes.len() != 32 {
                            return Err("wg psk must be 32 bytes".into());
                        }
                        let mut psk = [0u8; 32];
                        psk.copy_from_slice(&psk_bytes);
                        Some(psk)
                    } else {
                        None
                    };

                    let (ep_addr, ep_port) = parse_endpoint(ep)?;
                    let endpoint = format!("{}:{}", ep_addr, ep_port);
                    peers.push(astra_core_proxy_wireguard::PeerConfig {
                        endpoint,
                        public_key,
                        pre_shared_key,
                        persistent_keepalive: 0,
                        allowed_ips: vec!["0.0.0.0/0".into()],
                    });
                }
            }

            Arc::new(astra_core_proxy_wireguard::Handler::new(
                astra_core_proxy_wireguard::DeviceConfig {
                    private_key: pk_arr,
                    listen_port: 0,
                    peers,
                },
            ))
        }
        "hysteria" => {
            let settings = config
                .settings
                .as_ref()
                .ok_or("hysteria requires settings")?;
            let password = settings
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let up = settings
                .get("up")
                .and_then(|v| v.as_str())
                .unwrap_or("10 mbps")
                .to_string();
            let down = settings
                .get("down")
                .and_then(|v| v.as_str())
                .unwrap_or("10 mbps")
                .to_string();
            let server = settings
                .get("server")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let server_name = settings
                .get("serverName")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let obfs = settings
                .get("obfs")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let config = astra_core_proxy_hysteria::HysteriaConfig {
                server: server.or_else(|| {
                    settings
                        .get("address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                }),
                server_name,
                password,
                up,
                down,
                obfs,
            };
            Arc::new(astra_core_proxy_hysteria::HysteriaOutbound::new(config))
        }
        p => return Err(format!("unsupported outbound protocol: {}", p)),
    };

    let tag = if config.tag.is_empty() {
        format!("out-{}", config.protocol)
    } else {
        config.tag.clone()
    };

    let mut ob_handler = outbound::Handler::new(tag, handler);

    if let Some(ref stream) = config.stream_settings {
        let t = transport::Transport::from_stream_config(stream);
        if !matches!(t, transport::Transport::RawTcp) {
            ob_handler = ob_handler.with_transport(t);
        }

        if stream.security == "tls" {
            if let Some(ref tls_cfg) = stream.tls_settings {
                let server_name = if tls_cfg.server_name.is_empty() {
                    stream
                        .address
                        .as_ref()
                        .map(|a| a.0.clone())
                        .unwrap_or_default()
                } else {
                    tls_cfg.server_name.clone()
                };
                ob_handler = ob_handler.with_tls(TlsConfig {
                    server_name,
                    allow_insecure: tls_cfg.allow_insecure,
                });
            }
        } else if stream.security == "reality"
            && let Some(ref _reality_cfg) = stream.reality_settings
        {
            let server_name = if _reality_cfg.server_name.is_empty() {
                stream
                    .address
                    .as_ref()
                    .map(|a| a.0.clone())
                    .unwrap_or_default()
            } else {
                _reality_cfg.server_name.clone()
            };
            ob_handler = ob_handler.with_reality(outbound::RealityConfig {
                server_name,
                fingerprint: _reality_cfg.fingerprint.clone(),
                public_key: { hex::decode(&_reality_cfg.public_key).unwrap_or_default() },
                short_id: { hex::decode(&_reality_cfg.short_id).unwrap_or_default() },
            });
        }
    }

    if let Some(ref mux_cfg) = config.mux
        && mux_cfg.enabled
    {
        ob_handler = ob_handler.with_mux(MuxConfig {
            enabled: true,
            concurrency: mux_cfg.concurrency,
        });
    }

    Ok(Arc::new(ob_handler))
}

fn get_listen_addr(ib: &astra_core_config::InboundDetourConfig) -> String {
    let port = ib
        .port
        .as_ref()
        .and_then(|p| p.0.first().map(|r| r.from.to_string()))
        .unwrap_or_else(|| "0".to_string());

    if let Some(addr) = &ib.listen {
        format!("{}:{}", addr.0, port)
    } else {
        format!("0.0.0.0:{}", port)
    }
}

pub fn build_inbound_handler(
    config: &astra_core_config::InboundDetourConfig,
) -> Result<AlwaysOnInboundHandler, String> {
    let tag = if config.tag.is_empty() {
        format!("in-{}", config.protocol)
    } else {
        config.tag.clone()
    };

    let proxy: Arc<dyn InboundHandler> = match config.protocol.as_str() {
        "dokodemo-door" => {
            let cfg: DokodemoConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("dokodemo config: {}", e))?
                .unwrap_or_default();

            Arc::new(astra_core_proxy_dokodemo::Handler::new(
                astra_core_proxy_dokodemo::InboundConfig {
                    address: cfg.address.as_ref().map(convert_address),
                    port: cfg.port,
                    follow_redirect: cfg.follow_redirect,
                    user_level: cfg.user_level,
                    port_map: std::collections::HashMap::new(),
                },
            ))
        }
        "vless" => {
            let cfg: VLessInboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("vless inbound config: {}", e))?
                .ok_or_else(|| "vless inbound requires settings".to_string())?;

            let mut validator = astra_core_proxy_vless::MemoryValidator::new();
            for client in &cfg.clients {
                let uuid = parse_uuid(&client.id)?;
                let id = ID::new(uuid);
                let account = Arc::new(astra_core_proxy_vless::MemoryAccount::new(
                    id,
                    client.flow.clone(),
                ));
                let user = MemoryUser::new(client.level, client.email.clone(), Some(account));
                validator
                    .add(user)
                    .map_err(|e| format!("add vless user: {}", e))?;
            }

            let getter: Arc<dyn astra_core_proxy_vless::UserGetter> = Arc::new(validator);
            Arc::new(astra_core_proxy_vless::InboundHandler::new(getter))
        }
        "vmess" => {
            let cfg: VMessInboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("vmess inbound config: {}", e))?
                .ok_or_else(|| "vmess inbound requires settings".to_string())?;

            let mut users = Vec::new();
            for client in &cfg.clients {
                let uuid = parse_uuid(&client.id)?;
                let id = ID::new(uuid);
                let security = parse_security(&client.security);
                let account = Arc::new(astra_core_proxy_vmess::account::MemoryAccount::new(
                    id, security, false, false,
                ));
                users.push(MemoryUser::new(
                    client.level,
                    client.email.clone(),
                    Some(account),
                ));
            }

            Arc::new(astra_core_proxy_vmess::inbound::Handler::new(
                astra_core_proxy_vmess::inbound::InboundConfig { users },
            ))
        }
        "socks" => {
            let cfg: Option<SocksInboundConfig> = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("socks inbound config: {}", e))?;

            let mut socks_cfg = astra_core_proxy_socks::protocol::SocksConfig::default();
            if let Some(c) = cfg {
                socks_cfg.auth_type = if c.auth == "password" {
                    astra_core_proxy_socks::protocol::AuthType::Password
                } else {
                    astra_core_proxy_socks::protocol::AuthType::NoAuth
                };
                for acct in c.accounts {
                    socks_cfg.accounts.insert(acct.user, acct.pass);
                }
                socks_cfg.udp_enabled = c.udp;
                socks_cfg.address = c.ip.map(|a| convert_address(&a));
                socks_cfg.user_level = c.user_level;
            }
            Arc::new(astra_core_proxy_socks::Handler::with_config(socks_cfg))
        }
        "http" => {
            let cfg: Option<HTTPInboundConfig> = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("http inbound config: {}", e))?;

            let mut http_cfg = astra_core_proxy_http::HttpConfig::default();
            if let Some(c) = cfg {
                for acct in c.accounts {
                    http_cfg.accounts.insert(acct.user, acct.pass);
                }
                http_cfg.allow_transparent = c.allow_transparent;
                http_cfg.user_level = c.user_level;
            }
            Arc::new(astra_core_proxy_http::Handler::with_config(http_cfg))
        }
        "shadowsocks" => {
            let cfg: ShadowsocksInboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("shadowsocks inbound config: {}", e))?
                .ok_or_else(|| "shadowsocks inbound requires settings".to_string())?;

            let accounts: Vec<astra_core_proxy_shadowsocks::config::Account> =
                if cfg.users.is_empty() {
                    let method = if cfg.method.is_empty() {
                        "aes-256-gcm"
                    } else {
                        &cfg.method
                    };
                    let cipher_type = parse_ss_cipher_type(method)?;
                    let key = astra_core_proxy_shadowsocks::protocol::password_to_key(
                        cfg.password.as_bytes(),
                        cipher_type.key_size(),
                    );
                    vec![astra_core_proxy_shadowsocks::config::Account {
                        cipher_type,
                        password: cfg.password.clone(),
                        key,
                    }]
                } else {
                    cfg.users
                        .iter()
                        .map(|u| {
                            let method = if u.method.is_empty() {
                                &cfg.method
                            } else {
                                &u.method
                            };
                            let method = if method.is_empty() {
                                "aes-256-gcm"
                            } else {
                                method
                            };
                            let password = if u.password.is_empty() {
                                &cfg.password
                            } else {
                                &u.password
                            };
                            let cipher_type = parse_ss_cipher_type(method)?;
                            let key = astra_core_proxy_shadowsocks::protocol::password_to_key(
                                password.as_bytes(),
                                cipher_type.key_size(),
                            );
                            Ok(astra_core_proxy_shadowsocks::config::Account {
                                cipher_type,
                                password: password.clone(),
                                key,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?
                };

            let server_cfg = astra_core_proxy_shadowsocks::config::ServerConfig {
                users: accounts,
                network: cfg.network.map(|n| n.0).unwrap_or_default(),
            };

            Arc::new(astra_core_proxy_shadowsocks::inbound::Handler::new(
                server_cfg,
            ))
        }
        "shadowsocks-2022" => {
            let settings = config
                .settings
                .as_ref()
                .ok_or("ss2022 inbound requires settings")?;

            // Check for relay config (destinations array)
            if let Some(dests) = settings.get("destinations").and_then(|v| v.as_array()) {
                let method = settings
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2022-blake3-aes-256-gcm");
                let cipher =
                    astra_core_proxy_shadowsocks_2022::protocol::CipherType::from_str(method)
                        .ok_or_else(|| format!("unsupported ss2022 method: {}", method))?;
                use base64::Engine;
                let mut destinations = Vec::new();
                for d in dests {
                    let key_b64 = d.get("key").and_then(|v| v.as_str()).unwrap_or("");
                    let key_raw = base64::engine::general_purpose::STANDARD
                        .decode(key_b64.as_bytes())
                        .map_err(|e| format!("dest key decode: {}", e))?;
                    let key = astra_core_proxy_shadowsocks_2022::protocol::derive_master_key(
                        &key_raw,
                        cipher.key_size(),
                    );
                    let address = d
                        .get("address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let port = d.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    destinations.push(
                        astra_core_proxy_shadowsocks_2022::inbound::RelayDestination {
                            key,
                            address,
                            port,
                            email: d
                                .get("email")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        },
                    );
                }
                Arc::new(
                    astra_core_proxy_shadowsocks_2022::inbound::RelayInbound::new(
                        cipher,
                        destinations,
                    ),
                )
            } else {
                // Single user inbound
                let method = settings
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2022-blake3-aes-256-gcm");
                let key_b64 = settings.get("key").and_then(|v| v.as_str()).unwrap_or("");
                let cipher =
                    astra_core_proxy_shadowsocks_2022::protocol::CipherType::from_str(method)
                        .ok_or_else(|| format!("unsupported ss2022 method: {}", method))?;
                use base64::Engine;
                let key_raw = base64::engine::general_purpose::STANDARD
                    .decode(key_b64.as_bytes())
                    .map_err(|e| format!("ss2022 key decode: {}", e))?;
                let key = astra_core_proxy_shadowsocks_2022::protocol::derive_master_key(
                    &key_raw,
                    cipher.key_size(),
                );
                Arc::new(astra_core_proxy_shadowsocks_2022::inbound::Handler::new(
                    cipher, key,
                ))
            }
        }
        "trojan" => {
            let cfg: TrojanInboundConfig = config
                .settings
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| format!("trojan inbound config: {}", e))?
                .ok_or_else(|| "trojan inbound requires settings".to_string())?;

            let accounts: Vec<astra_core_proxy_trojan::config::Account> = cfg
                .clients
                .iter()
                .map(|c| astra_core_proxy_trojan::config::Account::new(c.password.clone()))
                .collect();

            let fallbacks: Vec<astra_core_proxy_trojan::config::Fallback> = cfg
                .fallbacks
                .iter()
                .map(|f| astra_core_proxy_trojan::config::Fallback {
                    name: f.name.clone(),
                    alpn: f.alpn.clone(),
                    path: f.path.clone(),
                    dest: f
                        .dest
                        .as_ref()
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    xver: f.xver,
                })
                .collect();

            let server_cfg = astra_core_proxy_trojan::config::ServerConfig {
                users: accounts,
                fallbacks,
            };

            Arc::new(astra_core_proxy_trojan::inbound::Handler::new(server_cfg))
        }
        "hysteria" => {
            let password = config
                .settings
                .as_ref()
                .and_then(|s| s.get("password"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let obfs = config
                .settings
                .as_ref()
                .and_then(|s| s.get("obfs"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let in_cfg = astra_core_proxy_hysteria::HysteriaInboundConfig {
                password: password.clone(),
                obfs: obfs.clone(),
            };
            Arc::new(astra_core_proxy_hysteria::HysteriaInbound::new(in_cfg))
        }
        p => return Err(format!("unsupported inbound protocol: {}", p)),
    };

    let listen_addr = get_listen_addr(config);
    let mut handler = AlwaysOnInboundHandler::new(tag, proxy, listen_addr);

    // If hysteria, set up hysteria-specific config
    if config.protocol == "hysteria" {
        let password = config
            .settings
            .as_ref()
            .and_then(|s| s.get("password"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let obfs = config
            .settings
            .as_ref()
            .and_then(|s| s.get("obfs"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        handler = handler.with_hysteria(password, obfs);
    }

    // Determine listen network from protocol config
    if let Some(settings) = config.settings.as_ref() {
        if let Some(network_str) = settings.get("network").and_then(|v| v.as_str()) {
            handler = handler.with_network(astra_core_proxyman::inbound::ListenNetwork::from_str(
                network_str,
            ));
        } else if let Some(networks) = settings.get("network").and_then(|v| v.as_array()) {
            let joined: String = networks
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",");
            if !joined.is_empty() {
                handler = handler.with_network(
                    astra_core_proxyman::inbound::ListenNetwork::from_str(&joined),
                );
            }
        }
    }

    if let Some(ref stream) = config.stream_settings {
        let t = transport::Transport::from_stream_config(stream);
        if !matches!(t, transport::Transport::RawTcp) {
            handler = handler.with_transport(t);
        }

        if (stream.security == "tls" || stream.security == "reality")
            && let Some(ref tls_cfg) = stream.tls_settings
            && let Some(cert) = tls_cfg.certificates.first()
        {
            let cert_data = if !cert.certificate.is_empty() {
                cert.certificate.join("\n").into_bytes()
            } else {
                Vec::new()
            };
            let key_data = if !cert.key.is_empty() {
                cert.key.join("\n").into_bytes()
            } else {
                Vec::new()
            };
            handler = handler.with_tls(inbound::TlsConfig {
                cert_file: if cert.certificate_file.is_empty() {
                    None
                } else {
                    Some(cert.certificate_file.clone())
                },
                key_file: if cert.key_file.is_empty() {
                    None
                } else {
                    Some(cert.key_file.clone())
                },
                cert_data,
                key_data,
            });
        }
    }

    Ok(handler)
}

fn expand_geoip_entry(code: &str, geo: &GeoDataManager) -> Result<Vec<String>, String> {
    let uc = code.to_uppercase();
    if uc == "PRIVATE" {
        return Ok(vec![
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "100.64.0.0/10".into(),
            "fd00::/8".into(),
        ]);
    }
    let entry = geo
        .geoip
        .get(&uc)
        .ok_or_else(|| format!("geoip code not found: {}", code))?;
    let mut cidrs = Vec::with_capacity(entry.cidr.len());
    for c in &entry.cidr {
        if c.ip.len() == 4 {
            cidrs.push(format!(
                "{}.{}.{}.{}/{}",
                c.ip[0], c.ip[1], c.ip[2], c.ip[3], c.prefix
            ));
        } else if c.ip.len() == 16 {
            let ip = std::net::Ipv6Addr::new(
                ((c.ip[0] as u16) << 8) | c.ip[1] as u16,
                ((c.ip[2] as u16) << 8) | c.ip[3] as u16,
                ((c.ip[4] as u16) << 8) | c.ip[5] as u16,
                ((c.ip[6] as u16) << 8) | c.ip[7] as u16,
                ((c.ip[8] as u16) << 8) | c.ip[9] as u16,
                ((c.ip[10] as u16) << 8) | c.ip[11] as u16,
                ((c.ip[12] as u16) << 8) | c.ip[13] as u16,
                ((c.ip[14] as u16) << 8) | c.ip[15] as u16,
            );
            cidrs.push(format!("{ip}/{pfx}", ip = ip, pfx = c.prefix));
        }
    }
    Ok(cidrs)
}

fn expand_geosite_entry(code: &str, geo: &GeoDataManager) -> Result<Vec<String>, String> {
    let uc = code.to_uppercase();
    let site = geo
        .geosite
        .get(&uc)
        .ok_or_else(|| format!("geosite code not found: {}", code))?;
    let mut patterns = Vec::with_capacity(site.domains.len());
    for d in &site.domains {
        let val = &d.value;
        match d.r#type {
            0 | 2 => patterns.push(format!(".{}", val.trim_start_matches('.'))),
            3 => patterns.push(val.clone()),
            1 => patterns.push(format!("regexp:{}", val)),
            _ => patterns.push(format!(".{}", val.trim_start_matches('.'))),
        }
    }
    Ok(patterns)
}

fn build_router(config: &Config, geo: &GeoDataManager) -> Result<Router, String> {
    let routing = config.routing.as_ref();
    let rules_cfg = routing.map(|r| &r.rules).map(Vec::as_slice).unwrap_or(&[]);
    let domain_strategy = routing
        .map(|r| DomainStrategy::from_str(&r.domain_strategy))
        .unwrap_or_default();

    let mut rules: Vec<RouteRule> = Vec::new();
    for (i, rule_cfg) in rules_cfg.iter().enumerate() {
        let tag = format!("rule-{}", i);
        let mut rule = RouteRule::new(
            tag,
            rule_cfg.outbound_tag.clone(),
            rule_cfg.balancer_tag.clone(),
        );

        let domain_list = rule_cfg.domain.as_ref().or(rule_cfg.domains.as_ref());
        if let Some(domains) = domain_list {
            let mut expanded: Vec<String> = Vec::new();
            for d in &domains.0 {
                if let Some(code) = d.strip_prefix("geosite:") {
                    expanded.extend(expand_geosite_entry(code, geo)?);
                } else {
                    expanded.push(d.clone());
                }
            }
            rule.add_condition(Box::new(DomainMatcher::new(&expanded)));
        }

        if let Some(ips) = &rule_cfg.ip {
            let mut expanded: Vec<String> = Vec::new();
            for ip in &ips.0 {
                if let Some(code) = ip.strip_prefix("geoip:") {
                    expanded.extend(expand_geoip_entry(code, geo)?);
                } else {
                    expanded.push(ip.clone());
                }
            }
            rule.add_condition(Box::new(IpMatcher::new(&expanded)?));
        }

        if let Some(ports) = &rule_cfg.port {
            let ranges: Vec<(u16, u16)> = ports.0.iter().map(|r| (r.from, r.to)).collect();
            rule.add_condition(Box::new(PortMatcher::new(&ranges)));
        }

        if let Some(networks) = &rule_cfg.network {
            rule.add_condition(Box::new(NetworkMatcher::new(&networks.0)));
        }

        if let Some(src_ips) = &rule_cfg.source_ip {
            rule.add_condition(Box::new(SourceIpMatcher::new(&src_ips.0)?));
        }

        if let Some(src_ports) = &rule_cfg.source_port {
            let ranges: Vec<(u16, u16)> = src_ports.0.iter().map(|r| (r.from, r.to)).collect();
            rule.add_condition(Box::new(SourcePortMatcher::new(&ranges)));
        }

        if let Some(tags) = &rule_cfg.inbound_tag {
            rule.add_condition(Box::new(InboundTagMatcher::new(&tags.0)));
        }

        if let Some(protocols) = &rule_cfg.protocol {
            rule.add_condition(Box::new(ProtocolMatcher::new(&protocols.0)));
        }

        if let Some(users) = &rule_cfg.user {
            rule.add_condition(Box::new(UserMatcher::new(&users.0)));
        }

        // Process name matching (Go: app/router/config.go BuildCondition)
        if let Some(process_list) = &rule_cfg.process {
            rule.add_condition(Box::new(ProcessNameMatcher::new(&process_list.0)));
        }

        // Attribute matching (Go: app/router/condition.go AttributeMatcher)
        if let Some(attrs) = &rule_cfg.attrs
            && let Some(obj) = attrs.as_object()
        {
            let mut attr_map = std::collections::HashMap::new();
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    attr_map.insert(k.clone(), s.to_string());
                }
            }
            rule.add_condition(Box::new(AttributeMatcher::new(&attr_map)));
        }

        if !rule.conditions.is_empty() {
            rules.push(rule);
        }
    }

    Ok(Router::new(rules, domain_strategy))
}

pub fn build_config(config: &Config) -> Result<AppRuntime, String> {
    let mut geo_manager = GeoDataManager::new();
    if let Some(ref routing) = config.routing {
        if !routing.geoip_dat_path.is_empty() {
            geo_manager
                .load(&routing.geoip_dat_path)
                .map_err(|e| format!("load geoip: {}", e))?;
        }
        if !routing.geosite_dat_path.is_empty() {
            geo_manager
                .load(&routing.geosite_dat_path)
                .map_err(|e| format!("load geosite: {}", e))?;
        }
    }
    let router = Arc::new(build_router(config, &geo_manager)?);

    let dispatcher_cell: astra_core_proxy_loopback::DispatcherCell =
        Arc::new(std::sync::Mutex::new(None));

    let ob_manager = Arc::new(outbound::Manager::new());
    for ob_config in &config.outbounds {
        let handler = build_outbound_handler(ob_config, dispatcher_cell.clone())?;
        let tag = ob_config.tag.clone();
        ob_manager.add_handler(tag, handler);
    }

    struct Provider {
        manager: Arc<outbound::Manager>,
    }
    impl HandlerProvider for Provider {
        fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>> {
            self.manager.get_handler(tag)
        }
        fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
            self.manager.get_default_handler()
        }
    }

    let handler_provider: Arc<dyn HandlerProvider> = Arc::new(Provider {
        manager: ob_manager.clone(),
    });

    let dns_cfg = config.dns.as_ref();
    let hosts = dns_cfg
        .map(|d| parse_hosts(d.hosts.as_ref()))
        .transpose()?
        .unwrap_or(StaticHosts::new());
    let query_strategy = dns_cfg
        .map(|d| QueryStrategy::from_str(&d.query_strategy))
        .unwrap_or_default();
    let disable_cache = dns_cfg.map(|d| d.disable_cache).unwrap_or(false);
    let enable_parallel = dns_cfg.map(|d| d.enable_parallel_query).unwrap_or(false);
    let disable_fallback = dns_cfg.map(|d| d.disable_fallback).unwrap_or(false);
    let disable_fallback_if_match = dns_cfg
        .map(|d| d.disable_fallback_if_match)
        .unwrap_or(false);

    let dns_resolver: Option<Arc<dyn DnsResolver>> = if let Some(dns) = dns_cfg {
        if !dns.servers.is_empty() {
            let mut nameservers = Vec::new();
            let mut use_tcp = false;
            let mut use_doh = false;
            let mut use_doq = false;
            let mut doh_url = String::new();
            let _doq_endpoint = String::new();
            let mut doq_endpoint = String::new();
            for sv in &dns.servers {
                let mut expected_ips = Vec::new();
                for s in &sv.expected_ips.0 {
                    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                        expected_ips.push(ip);
                    }
                }
                let client_ip = sv
                    .client_ip
                    .as_ref()
                    .map(|a| a.0.parse::<std::net::IpAddr>())
                    .transpose()
                    .map_err(|e| format!("invalid client_ip: {}", e))?;
                let raw = sv.address.0.clone();
                let (protocol, addr) = if let Some(rest) = raw.strip_prefix("https://") {
                    use_doh = true;
                    doh_url = format!("https://{}", rest);
                    ("doh".into(), rest.to_string())
                } else if let Some(rest) = raw.strip_prefix("h2c://") {
                    use_doh = true;
                    doh_url = format!("https://{}", rest);
                    ("doh".into(), rest.to_string())
                } else if let Some(rest) = raw.strip_prefix("https+local://") {
                    use_doh = true;
                    doh_url = format!("https://{}", rest);
                    ("doh".into(), rest.to_string())
                } else if let Some(rest) = raw.strip_prefix("quic+local://") {
                    use_doq = true;
                    doq_endpoint = rest.to_string();
                    ("doq".into(), rest.to_string())
                } else if let Some(rest) = raw.strip_prefix("quic+local://") {
                    use_doq = true;
                    doq_endpoint = rest.to_string();
                    ("doq".into(), rest.to_string())
                } else if let Some(rest) = raw.strip_prefix("tcp://") {
                    use_tcp = true;
                    ("tcp".into(), rest.to_string())
                } else if let Some(rest) = raw.strip_prefix("tcp+local://") {
                    use_tcp = true;
                    ("tcp+local".into(), rest.to_string())
                } else {
                    ("udp".into(), raw)
                };
                let port = if sv.port != 0 { sv.port } else { 53 };
                let addr_with_port = if port != 53 || !addr.contains(':') {
                    addr
                } else {
                    addr
                };
                nameservers.push(NameServer {
                    address: if protocol == "doh" || protocol == "doq" {
                        addr_with_port
                    } else {
                        format!("{}:{}", addr_with_port, port)
                    },
                    port,
                    protocol,
                    domains: sv.domains.0.clone(),
                    expected_ips,
                    client_ip,
                    skip_fallback: sv.skip_fallback,
                    tag: sv.tag.clone(),
                    query_strategy: QueryStrategy::from_str(&sv.query_strategy),
                });
            }
            if use_doq {
                Some(Arc::new(DoQResolver::new(
                    doq_endpoint,
                    hosts,
                    query_strategy,
                    disable_cache,
                )) as Arc<dyn DnsResolver>)
            } else if use_doh {
                Some(Arc::new(DoHResolver::new(
                    doh_url,
                    nameservers,
                    hosts,
                    query_strategy,
                    disable_cache,
                )) as Arc<dyn DnsResolver>)
            } else if use_tcp {
                Some(Arc::new(TcpDnsResolver::new(
                    nameservers,
                    hosts,
                    query_strategy,
                    disable_cache,
                    enable_parallel,
                    disable_fallback,
                    disable_fallback_if_match,
                )) as Arc<dyn DnsResolver>)
            } else {
                Some(Arc::new(UdpDnsResolver::new(
                    nameservers,
                    hosts,
                    query_strategy,
                    disable_cache,
                    enable_parallel,
                    disable_fallback,
                    disable_fallback_if_match,
                )) as Arc<dyn DnsResolver>)
            }
        } else {
            Some(Arc::new(SimpleDnsResolver::new(hosts)) as Arc<dyn DnsResolver>)
        }
    } else {
        None
    };

    // Build balancers
    let mut balancers = std::collections::HashMap::new();
    if let Some(ref routing) = config.routing {
        for br in &routing.balancers {
            let strategy = br
                .strategy
                .r#type
                .parse::<BalancerStrategy>()
                .unwrap_or_default();
            let balancer = Balancer::new(
                br.tag.clone(),
                br.selector.0.clone(),
                strategy,
                if br.fallback_tag.is_empty() {
                    None
                } else {
                    Some(br.fallback_tag.clone())
                },
            );
            balancers.insert(br.tag.clone(), balancer);
        }
    }

    // Start observatory if configured — injects alive tracking into each balancer
    if let Some(ref obs_cfg) = config.observatory
        && obs_cfg.enable
        && !obs_cfg.selector.is_empty()
    {
        let alive_tags: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
        for tag in &obs_cfg.selector {
            alive_tags.write().unwrap().insert(tag.clone());
        }

        let interval = if obs_cfg.probe_interval > 0 {
            obs_cfg.probe_interval as u64
        } else {
            10
        };
        let probe = astra_core_observatory::ProbeMethod::from_config(
            &obs_cfg.probe_type,
            obs_cfg.probe_url.as_deref(),
        );

        // Attach alive set to each balancer whose selector overlaps
        for b in balancers.values_mut() {
            if obs_cfg.selector.iter().any(|t| b.selector.contains(t)) {
                *b = b.clone().with_alive(alive_tags.clone());
            }
        }

        let observatory = astra_core_observatory::Observatory::with_probe(
            obs_cfg.selector.clone(),
            alive_tags,
            probe,
            interval,
        );

        observatory.start();
    }

    let mut dispatcher = DefaultDispatcher::new(router, handler_provider);
    if let Some(resolver) = dns_resolver {
        dispatcher = dispatcher.with_dns_resolver(resolver);
    }
    if config.fake_dns.is_some() {
        let fake = Arc::new(FakeDnsResolver::new_default());
        dispatcher = dispatcher.with_fake_dns(fake);
    }
    if !balancers.is_empty() {
        dispatcher = dispatcher.with_balancers(balancers);
    }
    let dispatcher = Arc::new(dispatcher);

    // Inject dispatcher into loopback handlers
    if let Ok(mut guard) = dispatcher_cell.lock() {
        *guard = Some(dispatcher.clone());
    }

    // Initialize reverse proxy bridges
    if let Some(ref rev) = config.reverse {
        for b_cfg in &rev.bridges {
            let _bridge =
                astra_core_app_reverse::Bridge::new(b_cfg.tag.clone(), b_cfg.domain.clone());
            // Bridge will be started when AppRuntime runs
        }
    }

    let mut inbound_handlers = Vec::new();
    for ib_config in &config.inbounds {
        let handler = build_inbound_handler(ib_config)?;
        inbound_handlers.push(handler);
    }

    let stats_manager = Arc::new(StatsManager::new());

    let metrics_addr = if config.stats.is_some() {
        if config
            .api
            .as_ref()
            .map(|a| !a.listen.is_empty())
            .unwrap_or(false)
        {
            // Derive metrics port from API port + 1
            let api_addr = config.api.as_ref().unwrap();
            if let Some(port_end) = api_addr.listen.rfind(':') {
                let base = &api_addr.listen[..port_end + 1];
                if let Ok(port) = api_addr.listen[port_end + 1..].parse::<u16>() {
                    Some(format!("{}{}", base, port + 1))
                } else {
                    Some("0.0.0.0:8080".into())
                }
            } else {
                Some("0.0.0.0:8080".into())
            }
        } else {
            Some("0.0.0.0:8080".into())
        }
    } else {
        None
    };

    Ok(AppRuntime {
        dispatcher,
        inbound_handlers,
        outbound_manager: ob_manager,
        inbound_manager: Arc::new(inbound::Manager::new()),
        stats_manager,
        metrics_addr,
    })
}
