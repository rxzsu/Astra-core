pub mod connection;
pub mod dialer;
pub mod listener;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.grpc.encoding.rs"));
}
