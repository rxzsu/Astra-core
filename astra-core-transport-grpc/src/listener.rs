use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use crate::connection::HunkConn;
use crate::proto::grpc_service_server::{GrpcService, GrpcServiceServer};

/// Callback for handling new gRPC connections.
pub type GrpcConnHandler = Arc<dyn Fn(HunkConn) + Send + Sync>;

/// A shutdown handle returned by `serve_grpc`.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

/// gRPC service implementation that bridges gRPC streams to the connection handler.
pub struct GrpcConnService {
    handler: GrpcConnHandler,
}

#[tonic::async_trait]
impl GrpcService for GrpcConnService {
    type TunStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<crate::proto::Hunk, Status>> + Send>>;

    async fn tun(
        &self,
        req: Request<tonic::Streaming<crate::proto::Hunk>>,
    ) -> Result<Response<Self::TunStream>, Status> {
        let stream = req.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        let conn = HunkConn::new(stream, tx);
        (self.handler)(conn);

        let out_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(out_stream.map(Ok))))
    }

    type TunMultiStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<crate::proto::MultiHunk, Status>> + Send>>;

    async fn tun_multi(
        &self,
        _req: Request<tonic::Streaming<crate::proto::MultiHunk>>,
    ) -> Result<Response<Self::TunMultiStream>, Status> {
        Err(Status::unimplemented(
            "tun_multi not yet supported on server",
        ))
    }
}

/// Start a gRPC listener on the given address.
pub async fn serve_grpc(
    bind_addr: &str,
    handler: GrpcConnHandler,
) -> Result<(std::net::SocketAddr, ShutdownHandle), String> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("bind {}: {}", bind_addr, e))?;

    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("get local addr: {}", e))?;

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let handle = ShutdownHandle {
        flag: shutdown_flag.clone(),
    };

    let grpc_service = GrpcConnService {
        handler: handler.clone(),
    };

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let router = tonic::transport::Server::builder()
            .add_service(GrpcServiceServer::new(grpc_service))
            .serve_with_incoming(incoming);

        if let Err(e) = router.await {
            tracing::error!("gRPC server error: {}", e);
        }
    });

    Ok((local_addr, handle))
}
