pub mod connection;
pub mod dialer;
pub mod listener;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/astra.transport.grpc.encoding.rs"));
}
