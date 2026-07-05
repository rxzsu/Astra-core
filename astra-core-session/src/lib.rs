use std::collections::HashMap;

use astra_core_net::Destination;

#[derive(Clone, Debug)]
pub struct Inbound {
    pub source: Destination,
    pub local: Option<Destination>,
    pub gateway: Option<Destination>,
    pub tag: String,
}

#[derive(Clone, Debug)]
pub struct Outbound {
    pub target: Destination,
    pub original_target: Destination,
    pub route_target: Option<Destination>,
    pub tag: String,
}

#[derive(Clone, Debug, Default)]
pub struct SniffingRequest {
    pub enabled: bool,
    pub metadata_only: bool,
    pub route_only: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Content {
    pub protocol: Option<String>,
    pub sniffing_request: Option<SniffingRequest>,
    pub attributes: HashMap<String, String>,
    pub skip_dns_resolve: bool,
}

#[derive(Clone, Default)]
pub struct Session {
    pub inbound: Option<Inbound>,
    pub outbound: Option<Outbound>,
    pub content: Option<Content>,
}
