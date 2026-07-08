use std::sync::Arc;

use tonic::{Request, Response, Status};
use tonic_reflection::server::Builder as ReflectionBuilder;

use astra_core_proxyman::outbound;
use astra_core_proxy_loopback::DispatcherCell;
use astra_core_stats::StatsManager;

pub mod proto {
    tonic::include_proto!("astra.app.grpc.api");
}

/// Generated file descriptor set for gRPC reflection.
const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("api_descriptor");

use proto::{
    handler_service_server::{HandlerService, HandlerServiceServer},
    stats_service_server::{StatsService, StatsServiceServer},
    routing_service_server::{RoutingService, RoutingServiceServer},
    logger_service_server::{LoggerService, LoggerServiceServer},
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
        outbound_manager: config.outbound_manager.clone(),
        dispatcher_cell: config.dispatcher_cell.clone(),
    };

    let stats_svc = StatsSvc {
        stats_manager: config.stats_manager.clone(),
    };

    let routing_svc = RoutingSvc {};

    let logger_svc = LoggerSvc {};

    tracing::info!("gRPC API server starting on {}", config.listen_addr);

    let reflection_svc = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()
        .map_err(|e| format!("reflection build: {}", e))?;

    tonic::transport::Server::builder()
        .add_service(reflection_svc)
        .add_service(HandlerServiceServer::new(handler_svc))
        .add_service(StatsServiceServer::new(stats_svc))
        .add_service(RoutingServiceServer::new(routing_svc))
        .add_service(LoggerServiceServer::new(logger_svc))
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
    async fn add_inbound(&self, req: Request<AddInboundRequest>) -> Result<Response<AddInboundResponse>, Status> {
        let config_json = req.into_inner().config;
        let inbound_config: astra_core_config::InboundDetourConfig =
            serde_json::from_str(&config_json).map_err(|e| Status::invalid_argument(format!("invalid config: {}", e)))?;

        let tag = inbound_config.tag.clone();
        if tag.is_empty() { return Err(Status::invalid_argument("inbound config missing tag")); }

        let handler = astra_core_app::build_inbound_handler(&inbound_config)
            .map_err(|e| Status::internal(format!("build inbound: {}", e)))?;

        // Store handler reference - in a full implementation we'd track these
        let _ = handler;

        Ok(Response::new(AddInboundResponse {}))
    }

    async fn remove_inbound(&self, req: Request<RemoveInboundRequest>) -> Result<Response<RemoveInboundResponse>, Status> {
        let _tag = req.into_inner().tag;
        Err(Status::unimplemented("remove inbound not fully implemented"))
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

    async fn alter_inbound(&self, req: Request<AlterInboundRequest>) -> Result<Response<AlterInboundResponse>, Status> {
        let r = req.into_inner();
        match r.operation.as_str() {
            "addUser" => {
                tracing::info!("add user {} to inbound {}", r.email, r.tag);
                // In a full implementation we'd parse the user config and add to the inbound validator
            }
            "removeUser" => {
                tracing::info!("remove user {} from inbound {}", r.email, r.tag);
            }
            _ => return Err(Status::invalid_argument(format!("unknown operation: {}", r.operation))),
        }
        Ok(Response::new(AlterInboundResponse {}))
    }

    async fn get_inbound_users(&self, _req: Request<GetInboundUserRequest>) -> Result<Response<GetInboundUserResponse>, Status> {
        Ok(Response::new(GetInboundUserResponse { count: 0, emails: vec![] }))
    }

    async fn get_inbound_users_count(&self, _req: Request<GetInboundUserRequest>) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        Ok(Response::new(GetInboundUsersCountResponse { count: 0 }))
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
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Response::new(GetSysStatsResponse {
            num_goroutine: 0,
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

    async fn get_stats_online(&self, req: Request<GetStatsRequest>) -> Result<Response<GetStatsResponse>, Status> {
        let r = req.into_inner();
        if let Some(ch) = self.stats_manager.get_channel(&r.name) {
            let value = ch.get();
            Ok(Response::new(GetStatsResponse { name: r.name, value }))
        } else {
            Ok(Response::new(GetStatsResponse { name: r.name, value: 0 }))
        }
    }

    async fn get_stats_online_ip_list(&self, _req: Request<GetStatsRequest>) -> Result<Response<StatsOnlineIpListResponse>, Status> {
        Ok(Response::new(StatsOnlineIpListResponse { ips: vec![] }))
    }

    async fn get_users_stats(&self, _req: Request<GetUsersStatsRequest>) -> Result<Response<GetUsersStatsResponse>, Status> {
        Ok(Response::new(GetUsersStatsResponse { users: vec![] }))
    }

    async fn get_all_online_users(&self, _req: Request<GetAllOnlineUsersRequest>) -> Result<Response<GetAllOnlineUsersResponse>, Status> {
        Ok(Response::new(GetAllOnlineUsersResponse { emails: vec![] }))
    }
}

// ---------------------------------------------------------------------------
// RoutingService
// ---------------------------------------------------------------------------

struct RoutingSvc {}

#[tonic::async_trait]
impl RoutingService for RoutingSvc {
    async fn add_rule(&self, req: Request<AddRuleRequest>) -> Result<Response<AddRuleResponse>, Status> {
        let _r = req.into_inner();
        tracing::info!("add routing rule (stub)");
        Ok(Response::new(AddRuleResponse {}))
    }

    async fn remove_rule(&self, req: Request<RemoveRuleRequest>) -> Result<Response<RemoveRuleResponse>, Status> {
        let _r = req.into_inner();
        tracing::info!("remove routing rule (stub)");
        Ok(Response::new(RemoveRuleResponse {}))
    }

    async fn list_rule(&self, _req: Request<ListRuleRequest>) -> Result<Response<ListRuleResponse>, Status> {
        Ok(Response::new(ListRuleResponse { rule_tags: vec![] }))
    }

    async fn override_balancer_target(&self, req: Request<OverrideBalancerTargetRequest>) -> Result<Response<OverrideBalancerTargetResponse>, Status> {
        let _r = req.into_inner();
        tracing::info!("override balancer target (stub)");
        Ok(Response::new(OverrideBalancerTargetResponse {}))
    }

    async fn get_balancer_info(&self, _req: Request<GetBalancerInfoRequest>) -> Result<Response<GetBalancerInfoResponse>, Status> {
        Ok(Response::new(GetBalancerInfoResponse {
            balancer: Some(BalancerMsg {
                tag: String::new(),
                override_target: String::new(),
                selects: vec![],
            }),
        }))
    }
}

// ---------------------------------------------------------------------------
// LoggerService
// ---------------------------------------------------------------------------

struct LoggerSvc {}

#[tonic::async_trait]
impl LoggerService for LoggerSvc {
    async fn restart_logger(&self, _req: Request<RestartLoggerRequest>) -> Result<Response<RestartLoggerResponse>, Status> {
        tracing::info!("restart logger requested");
        Ok(Response::new(RestartLoggerResponse {}))
    }
}
