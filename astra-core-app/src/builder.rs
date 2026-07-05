use std::sync::Arc;

use astra_core_config::Config;
use astra_core_config::proxy::{DokodemoConfig, FreedomConfig, VLessOutboundConfig, VLessInboundConfig, VMessOutboundConfig, VMessInboundConfig};
use astra_core_dispatcher::{DefaultDispatcher, DispatchHandler, HandlerProvider};
use astra_core_net::{self, Address, Destination, ParseAddress};
use astra_core_proto::{ID, MemoryUser, SecurityType, UUID};
use astra_core_proxy::{InboundHandler, OutboundHandler as OutboundHandlerTrait};
use astra_core_proxyman::inbound::AlwaysOnInboundHandler;
use astra_core_proxyman::outbound;
use astra_core_proxyman::outbound::{MuxConfig, TlsConfig};
use astra_core_proxy_vless::Validator as VLessValidator;
use astra_core_routing::{DomainStrategy, DomainMatcher, IpMatcher, PortMatcher, InboundTagMatcher,
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

pub fn build_outbound_handler(
    config: &astra_core_config::OutboundDetourConfig,
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
        p => return Err(format!("unsupported outbound protocol: {}", p)),
    };

    let tag = if config.tag.is_empty() {
        format!("out-{}", config.protocol)
    } else {
        config.tag.clone()
    };

    let mut ob_handler = outbound::Handler::new(tag, handler);

    if let Some(ref stream) = config.stream_settings {
        if stream.security == "tls" {
            if let Some(ref tls_cfg) = stream.tls_settings {
                let server_name = if tls_cfg.server_name.is_empty() {
                    stream.address.as_ref().map(|a| a.0.clone()).unwrap_or_default()
                } else {
                    tls_cfg.server_name.clone()
                };
                ob_handler = ob_handler.with_tls(TlsConfig { server_name, allow_insecure: tls_cfg.allow_insecure });
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
            Arc::new(astra_core_proxy_socks::Handler::new())
        }
        "http" => {
            Arc::new(astra_core_proxy_http::Handler::new())
        }
        p => return Err(format!("unsupported inbound protocol: {}", p)),
    };

    let listen_addr = get_listen_addr(config);
    Ok(AlwaysOnInboundHandler::new(tag, proxy, listen_addr))
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

    let mut ob_manager = outbound::Manager::new();
    for ob_config in &config.outbounds {
        let handler = build_outbound_handler(ob_config)?;
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
    let dispatcher = Arc::new(DefaultDispatcher::new(router, handler_provider));

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
