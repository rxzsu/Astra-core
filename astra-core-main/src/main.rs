use astra_core_app::build_config;
use astra_core_config::Config;

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

    tracing::info!("astra-core started. press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    tracing::info!("shutting down...");
}
