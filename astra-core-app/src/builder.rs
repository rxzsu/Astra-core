use std::sync::Arc;

use astra_core_config::Config;
use hex;
use astra_core_config::proxy::{DokodemoConfig, FreedomConfig, VLessOutboundConfig, VLessInboundConfig, VMessOutboundConfig, VMessInboundConfig, ShadowsocksInboundConfig, ShadowsocksOutboundConfig, SocksInboundConfig, SocksOutboundConfig, HTTPInboundConfig, HTTPOutboundConfig, TrojanInboundConfig, TrojanOutboundConfig, DNSOutboundConfig};
use astra_core_dispatcher::{DefaultDispatcher, DispatchHandler, HandlerProvider};
use astra_core_dns::{DnsResolver, UdpDnsResolver, SimpleDnsResolver, FakeDnsResolver, NameServer, QueryStrategy, parse_hosts};
use astra_core_net::{self, Address, Destination, ParseAddress};
use astra_core_proto::{ID, MemoryUser, SecurityType, UUID};
use astra_core_proxy::{InboundHandler, OutboundHandler as OutboundHandlerTrait};
use astra_core_proxyman::inbound::AlwaysOnInboundHandler;
use astra_core_proxyman::inbound;
use astra_core_proxyman::outbound;
use astra_core_proxyman::outbound::{MuxConfig, TlsConfig};
use astra_core_proxyman::transport;
use astra_core_proxy_vless::Validator as VLessValidator;
use astra_core_routing::{Balancer, BalancerStrategy, DomainStrategy, DomainMatcher, IpMatcher, PortMatcher, InboundTagMatcher,
    ProtocolMatcher, SourceIpMatcher, SourcePortMatcher, UserMatcher, NetworkMatcher,
    RouteRule, Router};

pub struct AppRuntime {
    pub dispatcher: Arc<DefaultDispatcher>,
    pub inbound_handlers: Vec<AlwaysOnInboundHandler>,
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

fn parse_security(s: &str) -> SecurityType {
    match s {
        "aes-128-gcm" => SecurityType::Aes128Gcm,
        "chacha20-poly1305" => SecurityType::ChaCha20Poly1305,
        "none" | "zero" => SecurityType::Zero,
        _ => SecurityType::Auto,
    }
}

fn parse_ss_cipher_type(method: &str) -> Result<astra_core_proxy_shadowsocks::protocol::CipherType, String> {
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

            Arc::new(astra_core_proxy_freedom::Handler::new(
                astra_core_proxy_freedom::OutboundConfig {
                    domain_strategy: cfg.domain_strategy,
                    redirect: if cfg.redirect.is_empty() {
                        None
                    } else {
                        Some(parse_destination(&cfg.redirect)?)
                    },
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

            let vnext = cfg.vnext.first()
                .ok_or_else(|| "vless outbound requires at least one vnext".to_string())?;

            let user = vnext.users.first()
                .ok_or_else(|| "vless outbound requires at least one user in vnext".to_string())?;

            let server_addr = convert_address(&vnext.address);
            let server_dest = astra_core_net::TcpDestination(server_addr, astra_core_net::Port(vnext.port));

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

            let vnext = cfg.vnext.first()
                .ok_or_else(|| "vmess outbound requires at least one vnext".to_string())?;

            let user_cfg = vnext.users.first()
                .ok_or_else(|| "vmess outbound requires at least one user".to_string())?;

            let uuid = parse_uuid(&user_cfg.id)?;
            let id = ID::new(uuid);
            let security = parse_security(&user_cfg.security);
            let account = Arc::new(astra_core_proxy_vmess::account::MemoryAccount::new(id, security, false, false));
            let user = MemoryUser::new(user_cfg.level, user_cfg.email.clone(), Some(account));

            let server_addr = convert_address(&vnext.address);
            let server_dest = astra_core_net::TcpDestination(server_addr.clone(), astra_core_net::Port(vnext.port));

            Arc::new(astra_core_proxy_vmess::outbound::Handler::new(
                server_dest,
                astra_core_proxy_vmess::outbound::OutboundConfig { user, address: server_addr, port: astra_core_net::Port(vnext.port) },
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

            Arc::new(astra_core_proxy_shadowsocks::outbound::Handler::new(client_cfg))
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
        "blackhole" => {
            Arc::new(astra_core_proxy_blackhole::Handler::new())
        }
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
            let handler = astra_core_proxy_loopback::Handler::new(
                cfg.inbound_tag,
                dispatcher_cell.clone(),
            );
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
            let portal = cfg.portals.first().ok_or_else(|| "reverse outbound requires portal config")?;
            Arc::new(astra_core_app_reverse::PortalHandler::new(
                portal.tag.clone(),
                portal.domain.clone(),
            ))
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
                    stream.address.as_ref().map(|a| a.0.clone()).unwrap_or_default()
                } else {
                    tls_cfg.server_name.clone()
                };
                ob_handler = ob_handler.with_tls(TlsConfig { server_name, allow_insecure: tls_cfg.allow_insecure });
            }
        } else if stream.security == "reality" {
            if let Some(ref _reality_cfg) = stream.reality_settings {
                let server_name = if _reality_cfg.server_name.is_empty() {
                    stream.address.as_ref().map(|a| a.0.clone()).unwrap_or_default()
                } else {
                    _reality_cfg.server_name.clone()
                };
                ob_handler = ob_handler.with_reality(outbound::RealityConfig {
                    server_name,
                    fingerprint: _reality_cfg.fingerprint.clone(),
                    public_key: {
                        let decoded = hex::decode(&_reality_cfg.public_key).unwrap_or_default();
                        decoded
                    },
                    short_id: {
                        let decoded = hex::decode(&_reality_cfg.short_id).unwrap_or_default();
                        decoded
                    },
                });
            }
        }
    }

    if let Some(ref mux_cfg) = config.mux {
        if mux_cfg.enabled {
            ob_handler = ob_handler.with_mux(MuxConfig {
                enabled: true,
                concurrency: mux_cfg.concurrency,
            });
        }
    }

    Ok(Arc::new(ob_handler))
}

fn get_listen_addr(ib: &astra_core_config::InboundDetourConfig) -> String {
    let port = ib
        .port
        .as_ref()
        .and_then(|p| {
            p.0.first().map(|r| r.from.to_string())
        })
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
                let account = Arc::new(astra_core_proxy_vless::MemoryAccount::new(id, client.flow.clone()));
                let user = MemoryUser::new(client.level, client.email.clone(), Some(account));
                validator.add(user).map_err(|e| format!("add vless user: {}", e))?;
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
                let account = Arc::new(astra_core_proxy_vmess::account::MemoryAccount::new(id, security, false, false));
                users.push(MemoryUser::new(client.level, client.email.clone(), Some(account)));
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

            let accounts: Vec<astra_core_proxy_shadowsocks::config::Account> = if cfg.users.is_empty() {
                let method = if cfg.method.is_empty() { "aes-256-gcm" } else { &cfg.method };
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
                        let method = if u.method.is_empty() { &cfg.method } else { &u.method };
                        let method = if method.is_empty() { "aes-256-gcm" } else { method };
                        let password = if u.password.is_empty() { &cfg.password } else { &u.password };
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

            Arc::new(astra_core_proxy_shadowsocks::inbound::Handler::new(server_cfg))
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

            let server_cfg = astra_core_proxy_trojan::config::ServerConfig { users: accounts };

            Arc::new(astra_core_proxy_trojan::inbound::Handler::new(server_cfg))
        }
        p => return Err(format!("unsupported inbound protocol: {}", p)),
    };

    let listen_addr = get_listen_addr(config);
    let mut handler = AlwaysOnInboundHandler::new(tag, proxy, listen_addr);

    // Determine listen network from protocol config
    if let Some(settings) = config.settings.as_ref() {
        if let Some(network_str) = settings.get("network").and_then(|v| v.as_str()) {
            handler = handler.with_network(astra_core_proxyman::inbound::ListenNetwork::from_str(network_str));
        } else if let Some(networks) = settings.get("network").and_then(|v| v.as_array()) {
            let joined: String = networks.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",");
            if !joined.is_empty() {
                handler = handler.with_network(astra_core_proxyman::inbound::ListenNetwork::from_str(&joined));
            }
        }
    }

    if let Some(ref stream) = config.stream_settings {
        let t = transport::Transport::from_stream_config(stream);
        if !matches!(t, transport::Transport::RawTcp) {
            handler = handler.with_transport(t);
        }

        if stream.security == "tls" || stream.security == "reality" {
            if let Some(ref tls_cfg) = stream.tls_settings {
                if let Some(cert) = tls_cfg.certificates.first() {
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
                        cert_file: if cert.certificate_file.is_empty() { None } else { Some(cert.certificate_file.clone()) },
                        key_file: if cert.key_file.is_empty() { None } else { Some(cert.key_file.clone()) },
                        cert_data,
                        key_data,
                    });
                }
            }
        }
    }

    Ok(handler)
}

fn build_router(config: &Config) -> Result<Router, String> {
    let routing = config.routing.as_ref();
    let rules_cfg = routing.map(|r| &r.rules).map(Vec::as_slice).unwrap_or(&[]);
    let domain_strategy = routing
        .map(|r| DomainStrategy::from_str(&r.domain_strategy))
        .unwrap_or_default();

    let mut rules: Vec<RouteRule> = Vec::new();
    for (i, rule_cfg) in rules_cfg.iter().enumerate() {
        let tag = format!("rule-{}", i);
        let mut rule = RouteRule::new(tag, rule_cfg.outbound_tag.clone(), rule_cfg.balancer_tag.clone());

        let domain_list = rule_cfg.domain.as_ref().or(rule_cfg.domains.as_ref());
        if let Some(domains) = domain_list {
            rule.add_condition(Box::new(DomainMatcher::new(&domains.0)));
        }

        if let Some(ips) = &rule_cfg.ip {
            rule.add_condition(Box::new(IpMatcher::new(&ips.0)?));
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

        if !rule.conditions.is_empty() {
            rules.push(rule);
        }
    }

    Ok(Router::new(rules, domain_strategy))
}

pub fn build_config(config: &Config) -> Result<AppRuntime, String> {
    let router = Arc::new(build_router(config)?);

    let dispatcher_cell: astra_core_proxy_loopback::DispatcherCell =
        Arc::new(std::sync::Mutex::new(None));

    let mut ob_manager = outbound::Manager::new();
    for ob_config in &config.outbounds {
        let handler = build_outbound_handler(ob_config, dispatcher_cell.clone())?;
        let tag = ob_config.tag.clone();
        ob_manager.add_handler(tag, handler);
    }

    struct Provider {
        manager: outbound::Manager,
    }
    impl HandlerProvider for Provider {
        fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>> {
            self.manager.get_handler(tag).cloned()
        }
        fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
            self.manager.get_default_handler().cloned()
        }
    }

    let handler_provider: Arc<dyn HandlerProvider> = Arc::new(Provider { manager: ob_manager });

    let dns_cfg = config.dns.as_ref();
    let hosts_map = dns_cfg.map(|d| parse_hosts(d.hosts.as_ref())).transpose()?.unwrap_or_default();
    let query_strategy = dns_cfg
        .map(|d| QueryStrategy::from_str(&d.query_strategy))
        .unwrap_or_default();

    let dns_resolver: Option<Arc<dyn DnsResolver>> = if let Some(dns) = dns_cfg {
        if !dns.servers.is_empty() {
            let mut nameservers = Vec::new();
            for sv in &dns.servers {
                let mut expected_ips = Vec::new();
                for s in &sv.expected_ips.0 {
                    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                        expected_ips.push(ip);
                    }
                }
                nameservers.push(NameServer {
                    address: sv.address.0.clone(),
                    port: if sv.port != 0 { sv.port } else { 53 },
                    domains: sv.domains.0.clone(),
                    expected_ips,
                });
            }
            // Use UdpDnsResolver when nameservers are configured
            Some(Arc::new(UdpDnsResolver::new(nameservers, hosts_map, query_strategy)) as Arc<dyn DnsResolver>)
        } else if !hosts_map.is_empty() {
            Some(Arc::new(SimpleDnsResolver::new(hosts_map)) as Arc<dyn DnsResolver>)
        } else {
            None
        }
    } else {
        None
    };

    // Build balancers
    let mut balancers = std::collections::HashMap::new();
    if let Some(ref routing) = config.routing {
        for br in &routing.balancers {
            let strategy = BalancerStrategy::from_str(&br.strategy.r#type);
            balancers.insert(
                br.tag.clone(),
                Balancer::new(
                    br.tag.clone(),
                    br.selector.0.clone(),
                    strategy,
                    if br.fallback_tag.is_empty() { None } else { Some(br.fallback_tag.clone()) },
                ),
            );
        }
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
            let _bridge = astra_core_app_reverse::Bridge::new(
                b_cfg.tag.clone(),
                b_cfg.domain.clone(),
            );
            // Bridge will be started when AppRuntime runs
        }
    }

    let mut inbound_handlers = Vec::new();
    for ib_config in &config.inbounds {
        let handler = build_inbound_handler(ib_config)?;
        inbound_handlers.push(handler);
    }

    Ok(AppRuntime {
        dispatcher,
        inbound_handlers,
    })
}
