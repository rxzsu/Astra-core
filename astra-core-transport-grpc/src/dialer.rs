use std::time::Duration;

use astra_core_net::Destination;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::connection::{HunkConn, MultiHunkConn};
use crate::proto::grpc_service_client::GrpcServiceClient;

/// Configuration for gRPC dialer.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct GrpcDialerConfig {
    pub service_name: String,
    pub multi_mode: bool,
}


async fn connect_channel(dest: &Destination) -> Result<Channel, String> {
    let addr = format!("http://{}:{}", dest.address, dest.port.value());
    let uri: Uri = addr.parse().map_err(|e| format!("invalid uri: {}", e))?;

    let endpoint = Endpoint::from(uri)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10));

    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("grpc connect to {}: {}", addr, e))?;

    Ok(channel)
}

/// Dial a gRPC transport connection (single-stream).
pub async fn dial_grpc(
    dest: &Destination,
    _config: &GrpcDialerConfig,
) -> Result<HunkConn, String> {
    let channel = connect_channel(dest).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(32);

    let mut client = GrpcServiceClient::new(channel);
    let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let response = client
        .tun(request_stream)
        .await
        .map_err(|e| format!("grpc tun: {}", e))?;

    let response_stream = response.into_inner();
    Ok(HunkConn::new(response_stream, tx))
}

/// Dial a gRPC transport connection (multi-stream).
pub async fn dial_grpc_multi(
    dest: &Destination,
    _config: &GrpcDialerConfig,
) -> Result<MultiHunkConn, String> {
    let channel = connect_channel(dest).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(32);

    let mut client = GrpcServiceClient::new(channel);
    let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let response = client
        .tun_multi(request_stream)
        .await
        .map_err(|e| format!("grpc tun_multi: {}", e))?;

    let response_stream = response.into_inner();
    Ok(MultiHunkConn::new(response_stream, tx))
}
