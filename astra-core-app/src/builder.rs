use std::sync::Arc;

use astra_core_config::Config;
use astra_core_config::proxy::{DokodemoConfig, FreedomConfig};
use astra_core_dispatcher::{DefaultDispatcher, DispatchHandler, HandlerProvider};
use astra_core_net::{self, Address, Destination, ParseAddress};
use astra_core_proxy::{InboundHandler, OutboundHandler};
use astra_core_proxyman::inbound::AlwaysOnInboundHandler;
use astra_core_proxyman::outbound;
use astra_core_routing::Router;

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
    router: Arc<Router>,
) -> Result<Arc<dyn DispatchHandler>, String> {
    let handler: Arc<dyn OutboundHandler> = match config.protocol.as_str() {
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
                    router: Some(router),
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

pub fn build_config(config: &Config) -> Result<AppRuntime, String> {
    let router = Arc::new(Router::default());

    let mut ob_manager = outbound::Manager::new();
    for ob_config in &config.outbounds {
        let handler = build_outbound_handler(ob_config, router.clone())?;
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
