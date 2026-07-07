use std::time::Duration;

use clap::{Parser, Subcommand, Args};

use astra_core_app_grpc::proto::{
    handler_service_client::HandlerServiceClient,
    stats_service_client::StatsServiceClient,
    routing_service_client::RoutingServiceClient,
    logger_service_client::LoggerServiceClient,
};

// ─── CLI Root ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[clap(name = "astra", version = "0.1.0")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Call API on a running astra-core instance
    Api(ApiArgs),

    /// Generate a UUID
    Uuid,

    /// Generate a X25519 key pair
    X25519,

    /// TLS certificate utilities
    Tls(TlsArgs),
}

// ─── API Subcommands ─────────────────────────────────────────────────────────

#[derive(Args)]
struct ApiArgs {
    /// API server address
    #[clap(short = 's', long = "server", default_value = "127.0.0.1:8080")]
    server: String,

    /// Connection timeout in seconds
    #[clap(short = 't', long = "timeout", default_value = "3")]
    _timeout: u64,

    /// Output as JSON
    #[clap(long = "json")]
    _json: bool,

    #[clap(subcommand)]
    command: ApiCommands,
}

#[derive(Subcommand)]
enum ApiCommands {
    /// Retrieve statistics by name
    Stats {
        #[clap(long = "name")]
        name: String,
        #[clap(long = "reset")]
        reset: bool,
    },
    /// Query statistics by pattern
    StatsQuery {
        #[clap(long = "pattern", default_value = "")]
        pattern: String,
        #[clap(long = "reset")]
        reset: bool,
    },
    /// Retrieve system statistics
    StatsSys,
    /// Retrieve online session count for a user
    StatsOnline {
        #[clap(long = "email")]
        email: String,
    },
    /// Retrieve online IP list for a user
    StatsOnlineIpList {
        #[clap(long = "email")]
        email: Option<String>,
        #[clap(long = "all")]
        all: bool,
        #[clap(long = "include-traffic")]
        include_traffic: bool,
        #[clap(long = "reset")]
        reset: bool,
    },
    /// Add inbounds from config files
    Adi {
        #[clap(required = true)]
        files: Vec<String>,
    },
    /// Remove inbounds by tag or config
    Rmi {
        #[clap(required = true)]
        tags: Vec<String>,
    },
    /// List inbounds
    Lsi,
    /// Add outbounds from config files
    Ado {
        #[clap(required = true)]
        files: Vec<String>,
    },
    /// Remove outbounds by tag or config
    Rmo {
        #[clap(required = true)]
        tags: Vec<String>,
    },
    /// List outbounds
    Lso,
    /// Get inbound users
    InboundUser {
        #[clap(long = "tag")]
        tag: String,
        #[clap(long = "email")]
        email: Option<String>,
    },
    /// Get inbound user count
    InboundUserCount {
        #[clap(long = "tag")]
        tag: String,
    },
    /// Add users to inbounds from config files
    Adu {
        #[clap(required = true)]
        files: Vec<String>,
    },
    /// Remove users from inbounds
    Rmu {
        #[clap(long = "tag")]
        tag: String,
        #[clap(required = true)]
        emails: Vec<String>,
    },
    /// Add routing rules from config files
    AdRules {
        #[clap(required = true)]
        files: Vec<String>,
        #[clap(long = "append")]
        append: bool,
    },
    /// List routing rules
    LsRules,
    /// Remove routing rules by ruleTag
    RmRules {
        #[clap(required = true)]
        rule_tags: Vec<String>,
    },
    /// Override balancer target
    Bo {
        #[clap(short = 'b', long = "balancer")]
        balancer: String,
        #[clap(short = 'r', long = "remove")]
        remove: bool,
        target: Option<String>,
    },
    /// Get balancer info
    Bi {
        balancer: Option<String>,
    },
    /// Block connections by source IP
    Sib {
        #[clap(long = "outbound")]
        outbound: String,
        #[clap(long = "inbound")]
        inbound: Option<String>,
        #[clap(long = "ruletag", default_value = "sourceIpBlock")]
        rule_tag: String,
        #[clap(long = "reset")]
        reset: bool,
        #[clap(required = true)]
        ips: Vec<String>,
    },
    /// Restart logger
    RestartLogger,
}

// ─── TLS Subcommands ─────────────────────────────────────────────────────────

#[derive(Args)]
struct TlsArgs {
    #[clap(subcommand)]
    command: TlsCommands,
}

#[derive(Subcommand)]
enum TlsCommands {
    /// Generate a self-signed TLS certificate
    Cert {
        #[clap(long = "cn", default_value = "localhost")]
        cn: String,
        #[clap(long = "cert", default_value = "cert.pem")]
        cert_file: String,
        #[clap(long = "key", default_value = "key.pem")]
        key_file: String,
    },
    /// Ping a TLS server
    Ping {
        server: String,
    },
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Uuid => cmd_uuid(),
        Commands::X25519 => cmd_x25519(),
        Commands::Tls(args) => cmd_tls(args).await,
        Commands::Api(args) => cmd_api(args).await,
    }
}

fn cmd_uuid() {
    let id = uuid::Uuid::new_v4();
    println!("{}", id);
}

fn cmd_x25519() {
    let mut private = [0u8; 32];
    getrandom::getrandom(&mut private).unwrap();
    // Clamp per RFC 7748
    let clamped = curve25519_dalek::scalar::clamp_integer(private);
    let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(clamped);
    let public = curve25519_dalek::EdwardsPoint::mul_base(&scalar).to_montgomery().to_bytes();
    println!("Private key: {}", hex::encode(private));
    println!("Public key:  {}", hex::encode(public));
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

async fn cmd_tls(args: TlsArgs) {
    match args.command {
        TlsCommands::Cert { cn, cert_file, key_file } => {
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![cn.clone()]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key_pair).unwrap();
            std::fs::write(&cert_file, cert.pem()).unwrap();
            std::fs::write(&key_file, key_pair.serialize_pem()).unwrap();
            println!("Certificate written to {}", cert_file);
            println!("Private key written to {}", key_file);
        }
        TlsCommands::Ping { server } => {
            use tokio::net::TcpStream;
            use tokio_rustls::TlsConnector;
            use std::sync::Arc;
            use tokio_rustls::rustls::pki_types::{ServerName, DnsName};

            let host = if server.contains(':') {
                server.split(':').next().unwrap_or(&server).to_string()
            } else {
                server.clone()
            };
            let addr = if server.contains(':') { server.clone() } else { format!("{}:443", server) };
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    let config = tokio_rustls::rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();
                    let connector = TlsConnector::from(Arc::new(config));
                    let name = ServerName::DnsName(DnsName::try_from(host.clone()).unwrap());
                    match connector.connect(name, stream).await {
                        Ok(_) => println!("TLS handshake with {} succeeded!", server),
                        Err(e) => eprintln!("TLS handshake failed: {}", e),
                    }
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    }
}

// ─── API ─────────────────────────────────────────────────────────────────────

async fn cmd_api(args: ApiArgs) {
    let addr = format!("http://{}", args.server);

    match &args.command {
        ApiCommands::Stats { name, reset } => {
            let mut client = connect_stats(&addr).await;
            let resp = client.get_stats(tonic::Request::new(
                astra_core_app_grpc::proto::GetStatsRequest {
                    name: name.clone(), reset: *reset,
                },
            )).await;
            print_response(resp);
        }
        ApiCommands::StatsQuery { pattern, reset } => {
            let mut client = connect_stats(&addr).await;
            let resp = client.query_stats(tonic::Request::new(
                astra_core_app_grpc::proto::QueryStatsRequest {
                    pattern: pattern.clone(), reset: *reset,
                },
            )).await;
            print_response(resp);
        }
        ApiCommands::StatsSys => {
            let mut client = connect_stats(&addr).await;
            let resp = client.get_sys_stats(tonic::Request::new(
                astra_core_app_grpc::proto::GetSysStatsRequest {},
            )).await;
            print_response(resp);
        }
        ApiCommands::StatsOnline { email } => {
            let mut client = connect_stats(&addr).await;
            let resp = client.get_stats_online(tonic::Request::new(
                astra_core_app_grpc::proto::GetStatsRequest {
                    name: format!("user>>>{}>>>online", email), reset: false,
                },
            )).await;
            print_response(resp);
        }
        ApiCommands::StatsOnlineIpList { email, all, include_traffic, reset } => {
            let mut client = connect_stats(&addr).await;
            if *all {
                let resp = client.get_users_stats(tonic::Request::new(
                    astra_core_app_grpc::proto::GetUsersStatsRequest {
                        include_traffic: *include_traffic, reset: *reset,
                    },
                )).await;
                print_response(resp);
            } else if let Some(email) = email {
                let resp = client.get_stats_online_ip_list(tonic::Request::new(
                    astra_core_app_grpc::proto::GetStatsRequest {
                        name: format!("user>>>{}>>>online", email), reset: false,
                    },
                )).await;
                print_response(resp);
            }
        }
        ApiCommands::Adi { files } => {
            let mut client = connect_handler(&addr).await;
            for file in files {
                if let Some(config) = load_file(file) {
                    for inbound in &config.inbounds {
                        let json = serde_json::to_string(inbound).unwrap_or_default();
                        let resp = client.add_inbound(tonic::Request::new(
                            astra_core_app_grpc::proto::AddInboundRequest { config: json },
                        )).await;
                        print_response(resp);
                    }
                }
            }
        }
        ApiCommands::Rmi { tags } => {
            let mut client = connect_handler(&addr).await;
            for item in tags {
                if let Some(config) = load_file(item) {
                    for inbound in &config.inbounds {
                        let resp = client.remove_inbound(tonic::Request::new(
                            astra_core_app_grpc::proto::RemoveInboundRequest { tag: inbound.tag.clone() },
                        )).await;
                        print_response(resp);
                    }
                } else {
                    let resp = client.remove_inbound(tonic::Request::new(
                        astra_core_app_grpc::proto::RemoveInboundRequest { tag: item.clone() },
                    )).await;
                    print_response(resp);
                }
            }
        }
        ApiCommands::Lsi => {
            let mut client = connect_handler(&addr).await;
            let resp = client.get_inbounds(tonic::Request::new(
                astra_core_app_grpc::proto::GetInboundsRequest {},
            )).await;
            print_response(resp);
        }
        ApiCommands::Ado { files } => {
            let mut client = connect_handler(&addr).await;
            for file in files {
                if let Some(config) = load_file(file) {
                    for outbound in &config.outbounds {
                        let json = serde_json::to_string(outbound).unwrap_or_default();
                        let resp = client.add_outbound(tonic::Request::new(
                            astra_core_app_grpc::proto::AddOutboundRequest { config: json },
                        )).await;
                        print_response(resp);
                    }
                }
            }
        }
        ApiCommands::Rmo { tags } => {
            let mut client = connect_handler(&addr).await;
            for item in tags {
                if let Some(config) = load_file(item) {
                    for outbound in &config.outbounds {
                        let resp = client.remove_outbound(tonic::Request::new(
                            astra_core_app_grpc::proto::RemoveOutboundRequest { tag: outbound.tag.clone() },
                        )).await;
                        print_response(resp);
                    }
                } else {
                    let resp = client.remove_outbound(tonic::Request::new(
                        astra_core_app_grpc::proto::RemoveOutboundRequest { tag: item.clone() },
                    )).await;
                    print_response(resp);
                }
            }
        }
        ApiCommands::Lso => {
            let mut client = connect_handler(&addr).await;
            let resp = client.get_outbounds(tonic::Request::new(
                astra_core_app_grpc::proto::GetOutboundsRequest {},
            )).await;
            print_response(resp);
        }
        ApiCommands::InboundUser { tag, email } => {
            let mut client = connect_handler(&addr).await;
            let resp = client.get_inbound_users(tonic::Request::new(
                astra_core_app_grpc::proto::GetInboundUserRequest {
                    tag: tag.clone(), email: email.clone().unwrap_or_default(),
                },
            )).await;
            print_response(resp);
        }
        ApiCommands::InboundUserCount { tag } => {
            let mut client = connect_handler(&addr).await;
            let resp = client.get_inbound_users_count(tonic::Request::new(
                astra_core_app_grpc::proto::GetInboundUserRequest {
                    tag: tag.clone(), email: String::new(),
                },
            )).await;
            print_response(resp);
        }
        ApiCommands::Adu { files } => {
            let mut client = connect_handler(&addr).await;
            for file in files {
                if let Some(config) = load_file(file) {
                    for inbound in &config.inbounds {
                        let json = serde_json::to_string(inbound).unwrap_or_default();
                        let resp = client.alter_inbound(tonic::Request::new(
                            astra_core_app_grpc::proto::AlterInboundRequest {
                                tag: inbound.tag.clone(),
                                operation: "addUser".into(),
                                email: String::new(),
                                config: json,
                            },
                        )).await;
                        print_response(resp);
                    }
                }
            }
        }
        ApiCommands::Rmu { tag, emails } => {
            let mut client = connect_handler(&addr).await;
            for email in emails {
                let resp = client.alter_inbound(tonic::Request::new(
                    astra_core_app_grpc::proto::AlterInboundRequest {
                        tag: tag.clone(),
                        operation: "removeUser".into(),
                        email: email.clone(),
                        config: String::new(),
                    },
                )).await;
                print_response(resp);
            }
        }
        ApiCommands::AdRules { files, append } => {
            let mut client = connect_routing(&addr).await;
            for file in files {
                let content = match std::fs::read_to_string(file) {
                    Ok(c) => c,
                    Err(e) => { eprintln!("failed to read {}: {}", file, e); continue; }
                };
                let resp = client.add_rule(tonic::Request::new(
                    astra_core_app_grpc::proto::AddRuleRequest {
                        config: content, should_append: *append,
                    },
                )).await;
                print_response(resp);
            }
        }
        ApiCommands::LsRules => {
            let mut client = connect_routing(&addr).await;
            let resp = client.list_rule(tonic::Request::new(
                astra_core_app_grpc::proto::ListRuleRequest {},
            )).await;
            print_response(resp);
        }
        ApiCommands::RmRules { rule_tags } => {
            let mut client = connect_routing(&addr).await;
            for tag in rule_tags {
                let resp = client.remove_rule(tonic::Request::new(
                    astra_core_app_grpc::proto::RemoveRuleRequest { rule_tag: tag.clone() },
                )).await;
                print_response(resp);
            }
        }
        ApiCommands::Bo { balancer, remove, target } => {
            let mut client = connect_routing(&addr).await;
            let target_str = if *remove { String::new() } else { target.clone().unwrap_or_default() };
            match client.override_balancer_target(tonic::Request::new(
                astra_core_app_grpc::proto::OverrideBalancerTargetRequest {
                    balancer_tag: balancer.clone(), target: target_str,
                },
            )).await {
                Ok(_) => println!("balancer override applied"),
                Err(e) => eprintln!("error: {}", e),
            }
        }
        ApiCommands::Bi { balancer } => {
            let mut client = connect_routing(&addr).await;
            let tag = balancer.clone().unwrap_or_default();
            let resp = client.get_balancer_info(tonic::Request::new(
                astra_core_app_grpc::proto::GetBalancerInfoRequest { tag },
            )).await;
            print_response(resp);
        }
        ApiCommands::Sib { outbound, inbound, rule_tag, reset, ips } => {
            let mut client = connect_routing(&addr).await;
            let json_ips = serde_json::to_string(ips).unwrap_or_default();
            let inbound_tag = inbound.clone().unwrap_or_default();
            let config_json = format!(r#"{{"routing":{{"rules":[{{"ruleTag":"{}","inboundTag":["{}"],"outboundTag":"{}","source":{}}}]}}}}"#,
                rule_tag, inbound_tag, outbound, json_ips);
            if *reset {
                let _ = client.remove_rule(tonic::Request::new(
                    astra_core_app_grpc::proto::RemoveRuleRequest { rule_tag: rule_tag.clone() },
                )).await;
            }
            let resp = client.add_rule(tonic::Request::new(
                astra_core_app_grpc::proto::AddRuleRequest {
                    config: config_json, should_append: true,
                },
            )).await;
            print_response(resp);
        }
        ApiCommands::RestartLogger => {
            let mut client = connect_logger(&addr).await;
            let resp = client.restart_logger(tonic::Request::new(
                astra_core_app_grpc::proto::RestartLoggerRequest {},
            )).await;
            print_response(resp);
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn load_file(path: &str) -> Option<astra_core_config::Config> {
    let content = std::fs::read_to_string(path).ok()?;
    astra_core_config::Config::from_json(&content).ok()
}

fn print_response<T: std::fmt::Debug>(resp: Result<tonic::Response<T>, tonic::Status>) {
    match resp {
        Ok(r) => println!("OK: {:?}", r.get_ref()),
        Err(e) => eprintln!("API error: {}", e),
    }
}

async fn connect_handler(addr: &str) -> HandlerServiceClient<tonic::transport::Channel> {
    HandlerServiceClient::connect(addr.to_string()).await.unwrap_or_else(|e| {
        eprintln!("connect to {}: {}", addr, e); std::process::exit(1);
    })
}

async fn connect_stats(addr: &str) -> StatsServiceClient<tonic::transport::Channel> {
    StatsServiceClient::connect(addr.to_string()).await.unwrap_or_else(|e| {
        eprintln!("connect to {}: {}", addr, e); std::process::exit(1);
    })
}

async fn connect_routing(addr: &str) -> RoutingServiceClient<tonic::transport::Channel> {
    RoutingServiceClient::connect(addr.to_string()).await.unwrap_or_else(|e| {
        eprintln!("connect to {}: {}", addr, e); std::process::exit(1);
    })
}

async fn connect_logger(addr: &str) -> LoggerServiceClient<tonic::transport::Channel> {
    LoggerServiceClient::connect(addr.to_string()).await.unwrap_or_else(|e| {
        eprintln!("connect to {}: {}", addr, e); std::process::exit(1);
    })
}
