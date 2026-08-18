use std::str::FromStr;
use std::sync::Arc;
use log::error;
use log::info;
use log::LevelFilter;
use tokio::select;
use qkd_kme_server::event_subscription::ImportantEventSubscriber;
use qkd_kme_server::qkd_manager::QkdManager;
use qkd_kme_server::config::TransportMode;
use qkd_kme_server::zenoh_transport::ZenohTransport;
use qkd_kme_server::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use qkd_kme_server::routes::inter_kmes_routes::InterKMEsRoutes;
use qkd_kme_server::server::auth_https_server::AuthHttpsServer;
use qkd_kme_server::server::log_http_server::{FilteredLogForwarder, LoggingHttpServer};

/// Target prefix (crate module path) of the log records forwarded to the debugging web interface, on top of the
/// curated [`qkd_kme_server::event_subscription::ImportantEventSubscriber`] notifications.
const ZENOH_RAFT_LOG_TARGET_PREFIX: &str = "qkd_kme_server::zenoh_transport";

#[tokio::main]
async fn main() {
    if std::env::args().len() != 2 {
        eprintln!("Usage: {} <path to json config file>", std::env::args().nth(0).unwrap());
        return;
    }

    let config = match qkd_kme_server::config::Config::from_json_path(&std::env::args().nth(1).unwrap()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config: {}", e);
            return;
        }
    };

    // Created early (before installing the global logger), so that Zenoh/Raft log records can be forwarded to it,
    // in addition to being handled by the curated `ImportantEventSubscriber` notifications below.
    let logging_http_server = config.this_kme_config.debugging_http_interface.as_ref()
        .map(|listen_addr| Arc::new(LoggingHttpServer::new(listen_addr)));

    // Read from config (`log_level`) rather than hardcoded, so verbosity can be changed without a rebuild.
    // Defaults to `Info` (not `simple_logger`'s own default `Trace`, which buries relevant messages under a lot
    // of debug/trace noise) if unset or unparsable. Still overridable via the `RUST_LOG` environment variable.
    let configured_level = config.this_kme_config.log_level.as_deref()
        .map(|level| LevelFilter::from_str(level).unwrap_or_else(|_| {
            eprintln!("Invalid log_level '{}' in config, defaulting to Info", level);
            LevelFilter::Info
        }))
        .unwrap_or(LevelFilter::Info);
    let console_logger = simple_logger::SimpleLogger::new().with_level(configured_level).env();
    let max_level = console_logger.max_level();
    match &logging_http_server {
        Some(logging_http_server) => {
            let forwarder = FilteredLogForwarder::new(
                Box::new(console_logger),
                ZENOH_RAFT_LOG_TARGET_PREFIX,
                configured_level,
                Arc::clone(logging_http_server),
            );
            log::set_boxed_logger(Box::new(forwarder)).unwrap();
        }
        None => {
            log::set_boxed_logger(Box::new(console_logger)).unwrap();
        }
    }
    log::set_max_level(max_level);

    let sae_https_server = AuthHttpsServer::<EtsiSaeQkdRoutesV1>::new(
        &config.this_kme_config.saes_https_interface.listen_address,
        &config.this_kme_config.saes_https_interface.ca_client_cert_path,
        &config.this_kme_config.saes_https_interface.server_cert_path,
        &config.this_kme_config.saes_https_interface.server_key_path
    );

    let inter_kme_https_server = AuthHttpsServer::<InterKMEsRoutes>::new(
        &config.this_kme_config.kmes_https_interface.listen_address,
        &config.this_kme_config.kmes_https_interface.ca_client_cert_path,
        &config.this_kme_config.kmes_https_interface.server_cert_path,
        &config.this_kme_config.kmes_https_interface.server_key_path
    );

    let qkd_manager = QkdManager::from_config(&config).await.unwrap();

    if let Some(logging_http_server) = &logging_http_server {
        qkd_manager.add_important_event_subscriber(Arc::clone(logging_http_server) as Arc<dyn ImportantEventSubscriber>).await.unwrap();
    }

    info!(
        "Startup transport mode: {:?}, zenoh config present: {}",
        config.this_kme_config.transport_mode,
        config.this_kme_config.zenoh_transport.is_some()
    );

    match config.this_kme_config.transport_mode {
        TransportMode::Https => {
            match &logging_http_server {
                Some(logging_http_server) => {
                    select! {
                        x = inter_kme_https_server.run(&qkd_manager) => {
                            error!("Error running inter-KMEs HTTPS server: {:?}", x);
                        },
                        x = sae_https_server.run(&qkd_manager) => {
                            error!("Error running SAEs HTTPS server: {:?}", x);
                        },
                        x = logging_http_server.run() => {
                            error!("Error running logging HTTP server: {:?}", x);
                        }
                    }
                }
                None => {
                    select! {
                        x = inter_kme_https_server.run(&qkd_manager) => {
                            error!("Error running inter-KMEs HTTPS server: {:?}", x);
                        },
                        x = sae_https_server.run(&qkd_manager) => {
                            error!("Error running SAEs HTTPS server: {:?}", x);
                        }
                    }
                }
            }
        }
        TransportMode::ZenohRaft => {
            let mut zenoh_config = config.this_kme_config.zenoh_transport.clone().unwrap_or_default();
            zenoh_config.other_kme_node_ids = config.other_kme_zenoh_node_ids();
            // SAEs still reach their local KME over classical HTTPS (ETSI-014) regardless of the
            // inter-KME transport, so it keeps running here; the classical inter-KME HTTPS server
            // is not started in this mode, since Zenoh replaces that inbound channel (see
            // `zenoh_transport::inter_kme_transport`).
            match &logging_http_server {
                Some(logging_http_server) => {
                    select! {
                        x = sae_https_server.run(&qkd_manager) => {
                            error!("Error running SAEs HTTPS server: {:?}", x);
                        },
                        x = ZenohTransport::start(zenoh_config, (*qkd_manager).clone()) => {
                            if let Err(e) = x {
                                error!("Error running Zenoh transport: {}", e);
                            }
                        },
                        x = logging_http_server.run() => {
                            error!("Error running logging HTTP server: {:?}", x);
                        }
                    }
                }
                None => {
                    select! {
                        x = sae_https_server.run(&qkd_manager) => {
                            error!("Error running SAEs HTTPS server: {:?}", x);
                        },
                        x = ZenohTransport::start(zenoh_config, (*qkd_manager).clone()) => {
                            if let Err(e) = x {
                                error!("Error running Zenoh transport: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}