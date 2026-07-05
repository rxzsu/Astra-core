use std::sync::Arc;

use astra_core_config::Config;
use astra_core_config::proxy::{DokodemoConfig, FreedomConfig};
use astra_core_dispatcher::{DefaultDispatcher, DispatchHandler, HandlerProvider};
use astra_core_net::{self, Address, Destination, ParseAddress};
use astra_core_proxy::{InboundHandler, OutboundHandler as OutboundHandlerTrait};
use astra_core_proxyman::inbound::AlwaysOnInboundHandler;
use astra_core_proxyman::outbound;
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
        p => return Err(format!("unsupported outbound protocol: {}", p)),
    };

    let tag = if config.tag.is_empty() {
        format!("out-{}", config.protocol)
    } else {
        config.tag.clone()
    };

    Ok(Arc::new(outbound::Handler::new(tag, handler)))
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

        // Domain matcher (supports both "domain" and "domains" fields)
        let domain_list = rule_cfg.domain.as_ref().or(rule_cfg.domains.as_ref());
        if let Some(domains) = domain_list {
            rule.add_condition(Box::new(DomainMatcher::new(&domains.0)));
        }

        // IP matcher
        if let Some(ips) = &rule_cfg.ip {
            rule.add_condition(Box::new(IpMatcher::new(&ips.0)?));
        }

        // Port matcher
        if let Some(ports) = &rule_cfg.port {
            let ranges: Vec<(u16, u16)> = ports.0.iter().map(|r| (r.from, r.to)).collect();
            rule.add_condition(Box::new(PortMatcher::new(&ranges)));
        }

        // Network matcher
        if let Some(networks) = &rule_cfg.network {
            rule.add_condition(Box::new(NetworkMatcher::new(&networks.0)));
        }

        // Source IP matcher
        if let Some(src_ips) = &rule_cfg.source_ip {
            rule.add_condition(Box::new(SourceIpMatcher::new(&src_ips.0)?));
        }

        // Source port matcher
        if let Some(src_ports) = &rule_cfg.source_port {
            let ranges: Vec<(u16, u16)> = src_ports.0.iter().map(|r| (r.from, r.to)).collect();
            rule.add_condition(Box::new(SourcePortMatcher::new(&ranges)));
        }

        // Inbound tag matcher
        if let Some(tags) = &rule_cfg.inbound_tag {
            rule.add_condition(Box::new(InboundTagMatcher::new(&tags.0)));
        }

        // Protocol matcher
        if let Some(protocols) = &rule_cfg.protocol {
            rule.add_condition(Box::new(ProtocolMatcher::new(&protocols.0)));
        }

        // User matcher
        if let Some(users) = &rule_cfg.user {
            rule.add_condition(Box::new(UserMatcher::new(&users.0)));
        }

        // Only add rule if it has at least one condition and a target
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

    // Wrap handler_provider as Arc<dyn HandlerProvider>
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
