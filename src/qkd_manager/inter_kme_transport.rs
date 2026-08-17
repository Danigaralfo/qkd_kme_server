//! Abstraction over how this KME reaches out to another KME to activate a set of already
//! QKD-synchronized key-ids for a given SAE pair. Chosen once at startup based on the
//! configured transport mode (classical HTTPS by default, or Zenoh+Raft - see
//! [`crate::zenoh_transport::inter_kme_transport::ZenohInterKmeTransport`]) and installed via
//! [`crate::qkd_manager::QkdManager::set_inter_kme_transport`], so the routing decision lives in
//! exactly one place instead of being scattered across the business logic.

use crate::qkd_manager::http_request_obj;
use crate::qkd_manager::router::QkdRouter;
use crate::qkd_manager::QkdManagerResponse;
use crate::{KmeId, SaeId};
use log::{error, warn};
use sqlx_core::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reaches out to another KME to activate a set of already-synchronized key-ids for a given SAE
/// pair, over whichever transport is configured. Implementations carry no key material: both
/// KMEs already share raw QKD key material out of band, this only carries activation metadata.
pub trait InterKmeTransport: Send + Sync {
    /// Ask `other_kme_id` to activate `key_uuids` for the (`caller_master_sae_id`, `other_sae_id`) SAE pair.
    fn activate_key_on_remote_kme<'a>(
        &'a self,
        caller_master_sae_id: SaeId,
        other_kme_id: KmeId,
        other_sae_id: SaeId,
        key_uuids: Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>>;
}

/// Classical, pre-Phase-6 implementation: activates keys on remote KMEs over mutually
/// authenticated HTTPS, POSTing to their `/keys/activate` endpoint. This is the default
/// transport, and its behavior is unchanged from before the [`InterKmeTransport`] abstraction
/// existed.
#[derive(Clone)]
pub(crate) struct HttpsInterKmeTransport {
    qkd_router: Arc<RwLock<QkdRouter>>,
    other_kme_connections_cache: Arc<RwLock<HashMap<KmeId, reqwest::Client>>>,
}

impl HttpsInterKmeTransport {
    /// Create a new HTTPS-based inter-KME transport, sharing the given classical routing table
    /// and reqwest client cache (also used by [`crate::qkd_manager::key_handler::KeyHandler::add_kme_classical_net_info`]).
    pub(super) fn new(qkd_router: Arc<RwLock<QkdRouter>>, other_kme_connections_cache: Arc<RwLock<HashMap<KmeId, reqwest::Client>>>) -> Self {
        Self { qkd_router, other_kme_connections_cache }
    }
}

impl InterKmeTransport for HttpsInterKmeTransport {
    fn activate_key_on_remote_kme<'a>(
        &'a self,
        caller_master_sae_id: SaeId,
        other_kme_id: KmeId,
        other_sae_id: SaeId,
        key_uuids: Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>> {
        Box::pin(async move {
            let danger_should_ignore_remote_kme_cert = match std::env::var(crate::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE) {
                Ok(val) => val == crate::ACTIVATED_ENV_VARIABLE_VALUE,
                Err(_) => false,
            };

            let req_body = http_request_obj::ActivateKeyRemoteKME {
                key_IDs_list: key_uuids,
                origin_SAE_ID: caller_master_sae_id,
                remote_SAE_ID: other_sae_id,
            };
            let qkd_router = self.qkd_router.read().await;
            let kme_classical_info = match qkd_router.get_classical_connection_info_from_kme_id(other_kme_id) {
                Some(info) => info,
                None => {
                    error!("KME ID not found");
                    return Err(QkdManagerResponse::MissingRemoteKmeConfiguration);
                },
            };

            // check if we already initialized a reqwest client for this KME
            let maybe_client = {
                let cache = self.other_kme_connections_cache.read().await;
                cache.get(&other_kme_id).cloned()
            };
            let kme_client = match maybe_client {
                Some(client) => client.clone(),
                None => {
                    let kme_client_builder = reqwest::Client::builder().identity(kme_classical_info.tls_client_cert_identity.clone());

                    let kme_client_builder = if danger_should_ignore_remote_kme_cert {
                        warn!("Because of {}, remote KME server certificate check is disabled. This is a dangerous setting, it breaks the whole protocol security", crate::DANGER_IGNORE_CERTS_INTER_KME_NETWORK_ENV_VARIABLE);
                        kme_client_builder.danger_accept_invalid_certs(true)
                    } else {
                        log::info!("Remote KME server certificate check is enabled. This is the default setting");
                        kme_client_builder
                    };
                    let kme_client_builder = if kme_classical_info.should_ignore_system_proxy_settings {
                        log::info!("Ignoring system proxy settings for remote KME route");
                        kme_client_builder.no_proxy()
                    } else {
                        log::info!("Using system proxy settings for remote KME route");
                        kme_client_builder
                    };
                    let kme_client = kme_client_builder.build()
                        .map_err(|_| {
                            error!("Error building reqwest client");
                            QkdManagerResponse::Ko
                        })?;
                    self.other_kme_connections_cache.write().await.insert(other_kme_id, kme_client.clone());
                    kme_client
                }
            };

            let response = kme_client.post(&format!("https://{}/keys/activate", kme_classical_info.ip_domain_port))
                .json(&req_body)
                .send().await
                .map_err(|http_error| {
                    error!("Error sending HTTP request: {}", http_error);
                    QkdManagerResponse::RemoteKmeCommunicationError
                })?;

            if response.status() != reqwest::StatusCode::OK {
                error!("Error activating key on other KME");
                return Err(QkdManagerResponse::RemoteKmeAcceptError);
            }

            Ok(())
        })
    }
}
