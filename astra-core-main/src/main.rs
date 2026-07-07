use std::sync::Arc;
use std::sync::Mutex;

use astra_core_app::build_config;
use astra_core_config::Config;
use astra_core_proxy_loopback::DispatcherCell;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.json".to_string());

    let config_json = match tokio::fs::read_to_string(&config_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to read config file {}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    let config: Config = match Config::from_json(&config_json) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to parse config: {}", e);
            std::process::exit(1);
        }
    };

    tracing::info!(
        "loaded config: {} inbounds, {} outbounds",
        config.inbounds.len(),
        config.outbounds.len()
    );

    let runtime = match build_config(&config) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to build runtime: {}", e);
            std::process::exit(1);
        }
    };

    let dispatcher = runtime.dispatcher.clone();

    for handler in runtime.inbound_handlers.into_iter() {
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = handler.start(dispatcher).await {
                tracing::error!("inbound handler error: {}", e);
            }
        });
    }

    // gRPC API server
    if let Some(ref api_cfg) = config.api {
        if !api_cfg.listen.is_empty() {
            let dispatcher: Arc<dyn astra_core_proxy::Dispatcher> = runtime.dispatcher.clone();
            let cell: DispatcherCell = Arc::new(Mutex::new(Some(dispatcher)));

            let grpc_config = astra_core_app_grpc::GrpcApiConfig {
                listen_addr: api_cfg.listen.clone(),
                stats_manager: runtime.stats_manager.clone(),
                outbound_manager: runtime.outbound_manager.clone(),
                dispatcher_cell: cell,
            };

            tokio::spawn(async move {
                if let Err(e) = astra_core_app_grpc::serve_grpc_api(grpc_config).await {
                    tracing::error!("gRPC API server error: {}", e);
                }
            });

            let services: Vec<&str> = api_cfg.services.iter().map(|s| s.as_str()).collect();
            tracing::info!("gRPC API server listening on {} with services: {:?}", api_cfg.listen, services);
        }
    }

    // Prometheus metrics server
    if let Some(ref metrics_addr) = runtime.metrics_addr {
        let metrics_server = astra_core_metrics::MetricsServer::new(
            runtime.stats_manager.clone(),
            metrics_addr.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = metrics_server.start().await {
                tracing::error!("metrics server error: {}", e);
            }
        });
        tracing::info!("Prometheus metrics on http://{}/metrics", metrics_addr);
    }

    tracing::info!("astra-core started. press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    tracing::info!("shutting down...");
}
