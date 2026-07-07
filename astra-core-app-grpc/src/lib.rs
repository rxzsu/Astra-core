use std::sync::Arc;

use tonic::{Request, Response, Status};

use astra_core_proxyman::outbound;
use astra_core_proxy_loopback::DispatcherCell;
use astra_core_stats::StatsManager;

pub mod proto {
    tonic::include_proto!("xray.app.grpc.api");
}

use proto::{
    handler_service_server::{HandlerService, HandlerServiceServer},
    stats_service_server::{StatsService, StatsServiceServer},
    *,
};

/// Configuration for the gRPC API server.
pub struct GrpcApiConfig {
    pub listen_addr: String,
    pub stats_manager: Arc<StatsManager>,
    pub outbound_manager: Arc<outbound::Manager>,
    pub dispatcher_cell: DispatcherCell,
}

/// Start the gRPC API server. Returns a shutdown handle.
pub async fn serve_grpc_api(config: GrpcApiConfig) -> Result<(), Box<dyn std::error::Error>> {
    let addr = config.listen_addr.parse()?;

    let handler_svc = HandlerSvc {
        outbound_manager: config.outbound_manager,
        dispatcher_cell: config.dispatcher_cell,
    };

    let stats_svc = StatsSvc {
        stats_manager: config.stats_manager,
    };

    tonic::transport::Server::builder()
        .add_service(HandlerServiceServer::new(handler_svc))
        .add_service(StatsServiceServer::new(stats_svc))
        .serve(addr)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// HandlerService
// ---------------------------------------------------------------------------

struct HandlerSvc {
    outbound_manager: Arc<outbound::Manager>,
    dispatcher_cell: DispatcherCell,
}

#[tonic::async_trait]
impl HandlerService for HandlerSvc {
    async fn add_inbound(&self, _req: Request<AddInboundRequest>) -> Result<Response<AddInboundResponse>, Status> {
        Err(Status::unimplemented("add inbound not implemented"))
    }

    async fn remove_inbound(&self, _req: Request<RemoveInboundRequest>) -> Result<Response<RemoveInboundResponse>, Status> {
        Err(Status::unimplemented("remove inbound not implemented"))
    }

    async fn add_outbound(&self, req: Request<AddOutboundRequest>) -> Result<Response<AddOutboundResponse>, Status> {
        let config_json = req.into_inner().config;
        let outbound_config: astra_core_config::OutboundDetourConfig =
            serde_json::from_str(&config_json).map_err(|e| Status::invalid_argument(format!("invalid config: {}", e)))?;

        let tag = outbound_config.tag.clone();
        if tag.is_empty() { return Err(Status::invalid_argument("outbound config missing tag")); }

        let handler = astra_core_app::build_outbound_handler(&outbound_config, self.dispatcher_cell.clone())
            .map_err(|e| Status::internal(format!("build outbound: {}", e)))?;

        self.outbound_manager.add_handler(tag, handler);
        Ok(Response::new(AddOutboundResponse {}))
    }

    async fn remove_outbound(&self, req: Request<RemoveOutboundRequest>) -> Result<Response<RemoveOutboundResponse>, Status> {
        let tag = req.into_inner().tag;
        self.outbound_manager.remove_handler(&tag).ok_or_else(|| Status::not_found(format!("outbound {} not found", tag)))?;
        Ok(Response::new(RemoveOutboundResponse {}))
    }

    async fn get_inbounds(&self, _req: Request<GetInboundsRequest>) -> Result<Response<GetInboundsResponse>, Status> {
        Ok(Response::new(GetInboundsResponse { tags: vec![] }))
    }

    async fn get_outbounds(&self, _req: Request<GetOutboundsRequest>) -> Result<Response<GetOutboundsResponse>, Status> {
        let tags = self.outbound_manager.list_handlers();
        Ok(Response::new(GetOutboundsResponse { tags }))
    }
}

// ---------------------------------------------------------------------------
// StatsService
// ---------------------------------------------------------------------------

struct StatsSvc {
    stats_manager: Arc<StatsManager>,
}

#[tonic::async_trait]
impl StatsService for StatsSvc {
    async fn get_stats(&self, req: Request<GetStatsRequest>) -> Result<Response<GetStatsResponse>, Status> {
        let r = req.into_inner();
        if let Some(counter) = self.stats_manager.get_counter(&r.name) {
            let value = if r.reset { counter.reset(); counter.get() } else { counter.get() };
            Ok(Response::new(GetStatsResponse { name: r.name.clone(), value }))
        } else if let Some(ch) = self.stats_manager.get_channel(&r.name) {
            let value = if r.reset { ch.set(0); ch.get() } else { ch.get() };
            Ok(Response::new(GetStatsResponse { name: r.name.clone(), value }))
        } else {
            Err(Status::not_found(format!("stat {} not found", r.name)))
        }
    }

    async fn query_stats(&self, req: Request<QueryStatsRequest>) -> Result<Response<QueryStatsResponse>, Status> {
        let r = req.into_inner();
        let pattern = r.pattern;
        let reset = r.reset;

        let mut stats = Vec::new();
        let is_match = |name: &str| -> bool {
            if pattern.is_empty() || pattern == "*" { return true; }
            let pat = pattern.replace('*', ".*").replace('?', ".");
            regex_lite::Regex::new(&format!("^{}$", pat)).map(|re| re.is_match(name)).unwrap_or(false)
        };

        for counter in self.stats_manager.all_counters() {
            if is_match(counter.name()) {
                let value = if reset { counter.reset(); counter.get() } else { counter.get() };
                stats.push(Stat { name: counter.name().to_string(), value });
            }
        }
        for ch in self.stats_manager.all_channels() {
            if is_match(ch.name()) {
                let value = if reset { ch.set(0); ch.get() } else { ch.get() };
                stats.push(Stat { name: ch.name().to_string(), value });
            }
        }

        Ok(Response::new(QueryStatsResponse { stats }))
    }

    async fn get_sys_stats(&self, _req: Request<GetSysStatsRequest>) -> Result<Response<GetSysStatsResponse>, Status> {
        // Rust doesn't have direct Go-style runtime stats, so provide what we can
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Response::new(GetSysStatsResponse {
            num_goroutine: 0, // not easily accessible in Rust
            num_gc: 0,
            alloc: 0,
            total_alloc: 0,
            sys: Some(SysStats {
                num_goroutine: 0,
                num_gc: 0,
                alloc: 0,
                total_alloc: 0,
                sys: 0,
                mallocs: 0,
                frees: 0,
                live_objects: 0,
                pause_total_ns: 0,
                uptime,
            }),
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            pause_total_ns: 0,
            uptime_seconds: uptime,
        }))
    }
}
