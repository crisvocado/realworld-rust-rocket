use std::collections::HashMap;

use rocket::async_trait;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};

pub mod models;
pub mod sha256;
pub mod trace;
pub mod transport;

pub use models::{ErrorInfo, LogEntry, LogEnvelope, StackFrame, TraceInfo};
pub use trace::parse_traceparent;
pub use transport::{flush, log_entry, set_capture_sink, LogcoreConfig};

/// Rocket fairing for Logcore structured logging.
pub struct LogcoreFairing;

pub fn fairing() -> LogcoreFairing {
    LogcoreFairing
}

#[async_trait]
impl Fairing for LogcoreFairing {
    fn info(&self) -> Info {
        Info {
            name: "Logcore Structured Logging",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        // Parse incoming W3C traceparent header and store in request local_cache
        if let Some(traceparent) = request.headers().get_one("traceparent") {
            if let Some(trace_info) = parse_traceparent(traceparent) {
                request.local_cache(|| Some(trace_info));
            }
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let status = response.status();
        // Forward ERROR and above: 5xx server errors
        if status.class().is_server_error() {
            let trace = request.local_cache(|| None::<TraceInfo>).clone();
            let method = request.method().as_str();
            let uri = request.uri().to_string();
            let msg = format!("HTTP {} {} returned status {}", method, uri, status.code);

            let mut labels = HashMap::new();
            labels.insert("http.method".to_string(), method.to_string());
            labels.insert("http.status_code".to_string(), status.code.to_string());
            labels.insert("http.uri".to_string(), uri);

            let error = ErrorInfo {
                r#type: format!("HttpServerError{}", status.code),
                message: msg.clone(),
                stack: None,
            };

            log_entry("ERROR", &msg, trace, Some(error), Some(labels), None);
        }
    }
}
