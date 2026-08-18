//! Route used by a master SAE to void (permanently delete) already-activated key(s)

use std::convert::{identity, Infallible};
use std::io;
use http_body_util::Full;
use hyper::{body, Request, Response};
use hyper::body::Bytes;
use log::{error, warn};
use crate::{ensure_client_certificate_serial, ensure_sae_id_format_type, io_err};
use crate::qkd_manager::http_request_obj::RequestListKeysIds;
use crate::qkd_manager::QkdManagerResponse;
use crate::routes::request_context::RequestContext;
use crate::routes::sae_zone_routes::EtsiSaeQkdRoutesV1;
use http_body_util::BodyExt;

/// Route to void (permanently delete) key(s) shared with a slave SAE, requested by a master SAE
/// eg `POST /api/v1/keys/{slave SAE id integer}/void_keys`
//
// # Request
// ```json
// {
//     "key_IDs": [
//         {
//             "key_ID": "[key id in UUID format]"
//         },
//         {
//             "key_ID": "[key id in UUID format]"
//         }
//     ]
// }```
//
// # Response
// ```json
// {
//   "message": "OK"
// }
// ```
// # Notes
// The key material is permanently deleted: once voided, a key can no longer be retrieved through
// `enc_keys`/`dec_keys`.
pub(in crate::routes) async fn route_void_keys(rcx: &RequestContext<'_>, req: Request<body::Incoming>, slave_sae_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let request_list_keys_ids = match extract_key_list_from_request(req).await {
        Ok(key_ids) => key_ids,
        Err(e) => {
            warn!("Error extracting key IDs from request: {}", e);
            return EtsiSaeQkdRoutesV1::bad_request();
        }
    };

    // All keys IDs to void
    let keys_uuids: Vec<String> = request_list_keys_ids.key_IDs.iter().map(|key_id| key_id.key_ID.clone()).collect();

    // Ensure the SAE ID is an integer
    let slave_sae_id_i64 = ensure_sae_id_format_type!(slave_sae_id);

    // Check if the client certificate serial is present
    let raw_client_certificate_serial = ensure_client_certificate_serial!(rcx);

    match rcx.qkd_manager.void_qkd_keys(slave_sae_id_i64, &raw_client_certificate_serial, keys_uuids).await.unwrap_or_else(identity) {
        QkdManagerResponse::Ok => {
            Ok(EtsiSaeQkdRoutesV1::json_response_from_str("{\n  \"message\": \"OK\"\n}"))
        }
        QkdManagerResponse::AuthenticationError => {
            EtsiSaeQkdRoutesV1::authentication_error()
        }
        QkdManagerResponse::NotFound => {
            EtsiSaeQkdRoutesV1::not_found()
        }
        QkdManagerResponse::RemoteKmeCommunicationError => {
            EtsiSaeQkdRoutesV1::gateway_timeout()
        }
        QkdManagerResponse::MissingRemoteKmeConfiguration => {
            EtsiSaeQkdRoutesV1::precondition_failed()
        }
        QkdManagerResponse::RemoteKmeAcceptError | QkdManagerResponse::RaftConsensusRejected => {
            EtsiSaeQkdRoutesV1::conflict()
        }
        _ => {
            error!("Error voiding key(s)");
            EtsiSaeQkdRoutesV1::internal_server_error()
        }
    }
}

async fn extract_key_list_from_request(req: Request<body::Incoming>) -> Result<RequestListKeysIds, io::Error> {
    let post_body_bytes = match req.into_body().collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(e) => Err(io_err(format!("Cannot read request body: {}", e).as_str()))?
    };
    match serde_json::from_slice(&post_body_bytes) {
        Ok(request_list_keys_ids) => Ok(request_list_keys_ids),
        Err(e) => Err(io_err(format!("Cannot parse request body as JSON: {}", e).as_str()))
    }
}
