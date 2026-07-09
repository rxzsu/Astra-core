use std::collections::HashMap;
use std::sync::Arc;

use astra_core_dns::{DnsResolver, FakeDnsResolver};
use astra_core_net::Destination;
use astra_core_proxy::{Dispatcher, ProxyResult, UdpLink, async_trait};
use astra_core_routing::{Balancer, DomainStrategy, Router, RoutingContext};
use astra_core_session::Session;
use astra_core_transport::{Link, new_link_pair, new_udp_link_pair};

use crate::DispatchHandler;

pub struct DefaultDispatcher {
    router: Arc<Router>,
    handler_provider: Arc<dyn HandlerProvider>,
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    fake_dns: Option<Arc<FakeDnsResolver>>,
    balancers: HashMap<String, Balancer>,
}

pub trait HandlerProvider: Send + Sync {
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>>;
    fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>>;
}

impl DefaultDispatcher {
    pub fn new(router: Arc<Router>, handler_provider: Arc<dyn HandlerProvider>) -> Self {
        DefaultDispatcher {
            router,
            handler_provider,
            dns_resolver: None,
            fake_dns: None,
            balancers: HashMap::new(),
        }
    }

    pub fn with_dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    pub fn with_fake_dns(mut self, fake_dns: Arc<FakeDnsResolver>) -> Self {
        self.fake_dns = Some(fake_dns);
        self
    }

    pub fn with_balancers(mut self, balancers: HashMap<String, Balancer>) -> Self {
        self.balancers = balancers;
        self
    }

    fn build_routing_context(session: &Session) -> RoutingContext {
        let mut ctx = RoutingContext::default();
        if let Some(ref ob) = session.outbound {
            ctx.target_domain = ob.target.address.as_domain().map(String::from);
            ctx.target_ip = ob.target.address.as_ip();
            ctx.target_port = ob.target.port.value();
        }
        if let Some(ref ib) = session.inbound {
            ctx.source_ip = ib.source.address.as_ip();
            ctx.source_port = ib.source.port.value();
            ctx.inbound_tag = ib.tag.clone();
        }
        if let Some(ref content) = session.content {
            ctx.protocol = content.protocol.clone();
            ctx.attributes = content.attributes.clone();
        }
        ctx
    }

    /// If the target IP is a fake IP, look up the real domain and set target_domain.
    fn enrich_with_fake_dns(&self, ctx: &mut RoutingContext) {
        let Some(ref fake) = self.fake_dns else {
            return;
        };
        let Some(target_ip) = ctx.target_ip else {
            return;
        };
        if !fake.is_fake_ip(target_ip) {
            return;
        }
        if let Some(domain) = fake.get_domain(target_ip) {
            ctx.target_domain = Some(domain);
            tracing::debug!("fake_dns: {} -> {:?}", target_ip, ctx.target_domain);
        }
    }

    /// Resolve the target domain in the routing context if it's set and not yet resolved.
    async fn resolve_context(&self, ctx: &mut RoutingContext) {
        let Some(ref domain) = ctx.target_domain else {
            return;
        };
        if ctx.target_ip.is_some() {
            return;
        }

        let Some(ref resolver) = self.dns_resolver else {
            return;
        };

        match resolver.resolve(domain).await {
            Ok(ips) => {
                // Use the first IPv4 address, or first address
                let ip = ips.iter().find(|a| a.is_ipv4()).unwrap_or(&ips[0]);
                ctx.target_ip = Some(*ip);
                tracing::debug!("resolved {} -> {}", domain, ip);
            }
            Err(e) => {
                tracing::warn!("dns resolve failed for {}: {}", domain, e);
            }
        }
    }

    /// Pick outbound tag for the given context, updating session if matched.
    /// Resolves balancer tags to the selected outbound tag.
    fn pick_outbound_tag(&self, session: &mut Session, ctx: &RoutingContext) -> String {
        let tag = match self.router.pick_route(ctx) {
            Some(r) => {
                session
                    .outbound
                    .as_mut()
                    .map(|o| o.tag = r.outbound_tag.clone());
                r.outbound_tag
            }
            None => String::new(),
        };

        if tag.is_empty() {
            return tag;
        }

        // If tag matches a balancer, resolve it
        if let Some(balancer) = self.balancers.get(&tag)
            && let Some(selected) = balancer.pick()
        {
            session
                .outbound
                .as_mut()
                .map(|o| o.tag = selected.to_string());
            return selected.to_string();
        }

        tag
    }

    async fn routed_dispatch(
        &self,
        mut session: Session,
        mut outbound_link: Link,
        _dest: &Destination,
    ) -> ProxyResult<()> {
        let mut ctx = Self::build_routing_context(&session);
        self.enrich_with_fake_dns(&mut ctx);
        let strategy = self.router.domain_strategy();

        if strategy == DomainStrategy::IpOnDemand {
            self.resolve_context(&mut ctx).await;
        }

        let mut outbound_tag = self.pick_outbound_tag(&mut session, &ctx);

        if outbound_tag.is_empty() && strategy == DomainStrategy::IpIfNonMatch {
            self.resolve_context(&mut ctx).await;
            outbound_tag = self.pick_outbound_tag(&mut session, &ctx);
        }

        let handler = if !outbound_tag.is_empty() {
            self.handler_provider.get_handler(&outbound_tag)
        } else {
            self.handler_provider.get_default_handler()
        };

        let handler = handler.ok_or_else(|| "no outbound handler available".to_string())?;
        handler.dispatch(session, &mut outbound_link).await
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dispatch(&self, session: Session, dest: Destination) -> ProxyResult<Link> {
        let (inbound_link, outbound_link) = new_link_pair();

        let router = self.router.clone();
        let handler_provider = self.handler_provider.clone();
        let dns_resolver = self.dns_resolver.clone();
        let fake_dns = self.fake_dns.clone();
        let balancers = self.balancers.clone();

        tokio::spawn(async move {
            let dispatcher = DefaultDispatcher {
                router,
                handler_provider,
                dns_resolver,
                fake_dns,
                balancers,
            };
            if let Err(e) = dispatcher
                .routed_dispatch(session, outbound_link, &dest)
                .await
            {
                tracing::error!("dispatch error: {}", e);
            }
        });

        Ok(inbound_link)
    }

    async fn dispatch_udp(&self, session: Session) -> ProxyResult<UdpLink> {
        let (inbound_link, mut outbound_link) = new_udp_link_pair();

        let router = self.router.clone();
        let handler_provider = self.handler_provider.clone();
        let dns_resolver = self.dns_resolver.clone();
        let fake_dns = self.fake_dns.clone();
        let balancers = self.balancers.clone();

        tokio::spawn(async move {
            let handler_provider = handler_provider.clone();
            let dispatcher = DefaultDispatcher {
                router,
                handler_provider: handler_provider.clone(),
                dns_resolver,
                fake_dns,
                balancers,
            };

            let mut session = session;
            let mut ctx = DefaultDispatcher::build_routing_context(&session);
            dispatcher.enrich_with_fake_dns(&mut ctx);
            let strategy = dispatcher.router.domain_strategy();

            if strategy == DomainStrategy::IpOnDemand {
                dispatcher.resolve_context(&mut ctx).await;
            }

            let mut outbound_tag = dispatcher.pick_outbound_tag(&mut session, &ctx);

            if outbound_tag.is_empty() && strategy == DomainStrategy::IpIfNonMatch {
                dispatcher.resolve_context(&mut ctx).await;
                outbound_tag = dispatcher.pick_outbound_tag(&mut session, &ctx);
            }

            let handler = if !outbound_tag.is_empty() {
                handler_provider.get_handler(&outbound_tag)
            } else {
                handler_provider.get_default_handler()
            };

            let handler = match handler {
                Some(h) => h,
                None => {
                    tracing::error!("no outbound handler available for UDP");
                    return;
                }
            };

            if let Err(e) = handler.dispatch_udp(session, &mut outbound_link).await {
                tracing::error!("udp dispatch error: {}", e);
            }
        });

        Ok(inbound_link)
    }

    async fn dispatch_link(
        &self,
        session: Session,
        _dest: Destination,
        link: &mut Link,
    ) -> ProxyResult<()> {
        let mut ctx = Self::build_routing_context(&session);
        self.enrich_with_fake_dns(&mut ctx);
        let strategy = self.router.domain_strategy();

        if strategy == DomainStrategy::IpOnDemand {
            self.resolve_context(&mut ctx).await;
        }

        let mut session = session;
        let mut outbound_tag = self.pick_outbound_tag(&mut session, &ctx);

        if outbound_tag.is_empty() && strategy == DomainStrategy::IpIfNonMatch {
            self.resolve_context(&mut ctx).await;
            outbound_tag = self.pick_outbound_tag(&mut session, &ctx);
        }

        let handler = if !outbound_tag.is_empty() {
            self.handler_provider.get_handler(&outbound_tag)
        } else {
            self.handler_provider.get_default_handler()
        };

        let handler = handler.ok_or_else(|| "no outbound handler available".to_string())?;
        handler.dispatch(session, link).await
    }
}
