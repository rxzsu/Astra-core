//! Xray-core mux protocol implementation.
//!
//! Provides frame encoding/decoding, session management, and reader/writer
//! helpers for multiplexing multiple sessions over a single transport connection.

pub mod client;
pub mod frame;
pub mod reader;
pub mod server;
pub mod session;
pub mod writer;

/// The special address used to identify mux connections (v1.mux.cool:9527).
pub mod wellknown {
    use astra_core_net::destination::TcpDestination;
    use astra_core_net::{Address, Destination, Port};

    pub fn mux_destination() -> Destination {
        TcpDestination(Address::Domain("v1.mux.cool".into()), Port(9527))
    }

    pub fn mux_address() -> Address {
        Address::Domain("v1.mux.cool".into())
    }

    pub fn mux_port() -> Port {
        Port(9527)
    }
}
