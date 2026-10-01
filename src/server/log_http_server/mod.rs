//! HTTP server for logging important events, in a demonstration purpose (intended to be visited using a web browser)
//! Events are displayed on index HTML page, and retrieved periodically by AJAX requests from /messages

mod logging_message;

use crate::event_subscription::ImportantEventSubscriber;
use crate::server::log_http_server::logging_message::LoggingMessage;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;

/// HTTP logging server struct
#[derive(Debug)]
pub struct LoggingHttpServer {
    /// HTTP listen address, e.g. "0.0.0.0:8080"
    pub listen_addr: String,
    received_log_messages: Arc<RwLock<Vec<LoggingMessage>>>,
}

impl LoggingHttpServer {
    /// Create a new HTTP logging server
    /// # Arguments
    /// * `listen_addr` - The address to listen for HTTP connections, e.g. "0.0.0.0:8080"
    /// # Returns
    /// A new LoggingHttpServer
    pub fn new(listen_addr: &str) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            received_log_messages: Arc::new(RwLock::new(Vec::new())),
        }
    }
    /// Run the HTTP server
    /// # Arguments
    /// * `qkd_manager` - The QKD manager associated with this logging server
    /// # Returns
    /// Never (`!`) in case of success, an io::Error otherwise
    pub async fn run(&self) -> Result<(), io::Error> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;

            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            // `hyper::rt` IO traits.
            let io = TokioIo::new(stream);
            let received_log_messages = Arc::clone(&self.received_log_messages);

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `hello` service
                if let Err(err) = http1::Builder::new()
                    // We could think about passing &self as argument when ! type would be released
                    .serve_connection(io, service_fn(|incoming_request| Self::handle_incoming_request(incoming_request, Arc::clone(&received_log_messages))))
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    /// Called at each incoming request
    async fn handle_incoming_request(request: Request<hyper::body::Incoming>, received_log_messages: Arc<RwLock<Vec<LoggingMessage>>>) -> Result<Response<Full<Bytes>>, Infallible> {
        const INDEX_HTML_RESPONSE: &str = include_str!("index.html");

        let response_obj = match request.uri().path() {
            "/messages" => {
                Self::generate_messages_http_json_response(&received_log_messages).await
            },
            _ => {
                Response::new(Full::new(Bytes::from(INDEX_HTML_RESPONSE.to_string())))
            }
        };
        Ok(response_obj)
    }

    /// Generates JSON array HTTP response containing all received log messages, or HTTP error status if an error occurred
    async fn generate_messages_http_json_response(received_log_messages: &Arc<RwLock<Vec<LoggingMessage>>>) -> Response<Full<Bytes>> {
        let received_log_messages = match received_log_messages.read() {
            Ok(messages) => messages,
            Err(_) => {
                return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Full::new(Bytes::from(String::from("Mutex lock error")))).unwrap();
            }
        };
        let response_str = match serde_json::to_string(received_log_messages.deref()) {
            Ok(response_str) => response_str,
            Err(_) => {
                return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Full::new(Bytes::from(String::from("JSON serialization error")))).unwrap();
            }
        };
        Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(response_str))).unwrap()
    }

    /// Synchronously push a message to be displayed on the HTTP page.
    ///
    /// Unlike [`notify`](ImportantEventSubscriber::notify), this does not return a `Future`, so it can be called
    /// directly from a synchronous context such as a [`log::Log`] implementation (e.g. [`FilteredLogForwarder`]),
    /// which may itself be invoked from within an async task and must not block on a `tokio` lock.
    /// # Arguments
    /// * `message` - The message to be displayed
    pub fn push_message(&self, message: &str) {
        if let Ok(mut received_log_messages) = self.received_log_messages.write() {
            received_log_messages.push(LoggingMessage::new(message));
        }
    }
}

impl ImportantEventSubscriber for LoggingHttpServer {
    /// Add a notification message to be displayed on the HTTP page
    /// # Arguments
    /// * `message` - The message to be displayed
    /// # Returns
    /// Result<(), io::Error> - Ok(()) if the message was successfully added, Err(io::Error) otherwise (mutex lock error)
    fn notify(&self, message: &str) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + '_>> {
        self.push_message(message);
        Box::pin(async move { Ok(()) })
    }
}

/// Wraps another [`log::Log`] implementation (typically the console logger) and additionally forwards a
/// filtered subset of log records - matching a target prefix and a maximum (i.e. least severe) level - to a
/// [`LoggingHttpServer`]. This lets operationally relevant events (e.g. from the Zenoh/Raft transport) show up
/// on the debugging web page, without needing to sift through the full, much more verbose (trace/debug-heavy)
/// console output, and without changing the console output itself.
pub struct FilteredLogForwarder {
    inner: Box<dyn Log>,
    target_prefix: &'static str,
    max_forwarded_level: LevelFilter,
    forward_to: Arc<LoggingHttpServer>,
}

impl FilteredLogForwarder {
    /// Create a new forwarding logger
    /// # Arguments
    /// * `inner` - The wrapped logger, receiving every record unfiltered (e.g. the console logger)
    /// * `target_prefix` - Only records whose target starts with this prefix are forwarded to `forward_to`
    /// * `max_forwarded_level` - Only records at this level or more severe (e.g. `Info`) are forwarded to `forward_to`
    /// * `forward_to` - The logging HTTP server to forward matching records to
    /// # Returns
    /// A new FilteredLogForwarder
    pub fn new(inner: Box<dyn Log>, target_prefix: &'static str, max_forwarded_level: LevelFilter, forward_to: Arc<LoggingHttpServer>) -> Self {
        Self {
            inner,
            target_prefix,
            max_forwarded_level,
            forward_to,
        }
    }
}

impl Log for FilteredLogForwarder {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        self.inner.log(record);
        if record.level() <= self.max_forwarded_level && record.target().starts_with(self.target_prefix) {
            let level_str = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };
            self.forward_to.push_message(&format!("[{}] {}", level_str, record.args()));
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

#[cfg(test)]
mod tests {
    use crate::event_subscription::ImportantEventSubscriber;
    use crate::server::log_http_server::LoggingHttpServer;
    use regex::Regex;
    use serial_test::serial;
    use std::sync::Arc;

    #[tokio::test]
    #[serial]
    async fn test_logging_http_server() {
        const EXPECTED_INDEX_BODY: &'static str = include_str!("index.html");

        let server = Arc::new(LoggingHttpServer::new("127.0.0.1:8080"));
        let server_copy_coroutine = Arc::clone(&server);
        tokio::spawn(async move {
            server_copy_coroutine.run().await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await; // To ensure server task is scheduled before client
        let get_index_response = reqwest::get("http://127.0.0.1:8080").await.unwrap();
        assert_eq!(get_index_response.status(), 200);
        assert_eq!(get_index_response.text().await.unwrap(), EXPECTED_INDEX_BODY);

        let get_messages_response = reqwest::get("http://127.0.0.1:8080/messages").await.unwrap();
        assert_eq!(get_messages_response.status(), 200);
        assert_eq!(get_messages_response.text().await.unwrap(), "[]");

        server.notify("Hello").await.unwrap();
        server.notify("World").await.unwrap();

        let get_messages_response = reqwest::get("http://127.0.0.1:8080/messages").await.unwrap();
        assert_eq!(get_messages_response.status(), 200);
        let check_json_regex = Regex::new(r#"\[\{"message":"Hello","datetime":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"},\{"message":"World","datetime":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"}]"#).unwrap();
        assert!(check_json_regex.is_match(&get_messages_response.text().await.unwrap()));
    }
}