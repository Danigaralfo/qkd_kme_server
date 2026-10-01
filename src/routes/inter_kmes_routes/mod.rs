//! Describes routes for specific inter KME channels over public network, generally to activate keys on remote KMEs

use std::convert::Infallible;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use rustls_pki_types::CertificateDer;
use crate::MAX_QKD_KEYS_PER_REQUEST;
use crate::qkd_manager::http_request_obj::{ActivateKeyRemoteKME, VoidKeysRemoteKME};
use crate::qkd_manager::QkdManager;
use crate::routes::Routes;

/// Routes for inter KMEs communication over public network
pub struct InterKMEsRoutes {}

impl Routes for InterKMEsRoutes {
    async fn handle_request(req: Request<Incoming>, _client_cert: Option<&CertificateDer<'_>>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_owned();
        match path.as_str() {
            "/keys/activate" => Self::handle_activate(req, qkd_manager).await,
            "/keys/void" => Self::handle_void(req, qkd_manager).await,
            _ => Ok(Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::from(String::from("Not found")))).unwrap()),
        }
    }
}

impl InterKMEsRoutes {
    async fn handle_activate(req: Request<Incoming>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible> {
        let post_body_bytes = match req.into_body().collect().await {
            Ok(bytes) => bytes.to_bytes(),
            Err(_) => {
                return Self::bad_request();
            }
        };

        let key_to_activate_obj: ActivateKeyRemoteKME = match serde_json::from_slice(&post_body_bytes) {
            Ok(request_list_keys_ids) => request_list_keys_ids,
            Err(_) => {
                return Self::bad_request();
            }
        };

        if key_to_activate_obj.key_IDs_list.len() > MAX_QKD_KEYS_PER_REQUEST {
            return Ok(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(format!("Too many keys requested, max is {}", MAX_QKD_KEYS_PER_REQUEST)))).unwrap()
            );
        }

        let response = qkd_manager.activate_key_from_remote(
            key_to_activate_obj.origin_SAE_ID,
            key_to_activate_obj.remote_SAE_ID,
            key_to_activate_obj.key_IDs_list,
            key_to_activate_obj.final_target_kme_id,
            key_to_activate_obj.visited_kme_ids).await;
        match response {
            Ok(_) => Ok(Response::builder().status(StatusCode::OK).body(Full::new(Bytes::from(String::from("OK")))).unwrap()),
            Err(_) => Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(String::from("Cannot activate key")))).unwrap())
        }
    }

    async fn handle_void(req: Request<Incoming>, qkd_manager: QkdManager) -> Result<Response<Full<Bytes>>, Infallible> {
        let post_body_bytes = match req.into_body().collect().await {
            Ok(bytes) => bytes.to_bytes(),
            Err(_) => {
                return Self::bad_request();
            }
        };

        let keys_to_void_obj: VoidKeysRemoteKME = match serde_json::from_slice(&post_body_bytes) {
            Ok(request_list_keys_ids) => request_list_keys_ids,
            Err(_) => {
                return Self::bad_request();
            }
        };

        if keys_to_void_obj.key_IDs_list.len() > MAX_QKD_KEYS_PER_REQUEST {
            return Ok(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(format!("Too many keys requested, max is {}", MAX_QKD_KEYS_PER_REQUEST)))).unwrap()
            );
        }

        let response = qkd_manager.void_keys_from_remote(keys_to_void_obj.key_IDs_list).await;
        match response {
            Ok(_) => Ok(Response::builder().status(StatusCode::OK).body(Full::new(Bytes::from(String::from("OK")))).unwrap()),
            Err(_) => Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(String::from("Cannot void key")))).unwrap())
        }
    }

    fn bad_request() -> Result<Response<Full<Bytes>>, Infallible> {
        Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::from(String::from("Bad request")))).unwrap())
    }
}