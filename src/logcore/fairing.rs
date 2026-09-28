//! Rocket Fairing for automatic trace context extraction and error capture.

use super::types::{ErrorInfo, TraceInfo};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};
use std::collections::HashMap;

pub struct LogcoreFairing;

impl LogcoreFairing {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LogcoreFairing {
    fn default() -> Self {
        Self::new()
    }
}

#[rocket::async_trait]
impl Fairing for LogcoreFairing {
    fn info(&self) -> Info {
        Info {
            name: "Logcore Structured Logging Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        // Extract W3C traceparent header: 00-{trace_id}-{span_id}-{flags}
        if let Some(tp_header) = req.headers().get_one("traceparent") {
            if let Some(trace_info) = parse_traceparent(tp_header) {
                req.local_cache(|| Some(trace_info));
                return;
            }
        }
        req.local_cache(|| None as Option<TraceInfo>);
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let status = res.status();
        if status.code >= 500 {
            let trace = req.local_cache(|| None as Option<TraceInfo>).clone();

            let mut labels = HashMap::new();
            labels.insert("http.method".to_string(), req.method().to_string());
            labels.insert("http.uri".to_string(), req.uri().to_string());
            labels.insert("http.status_code".to_string(), status.code.to_string());

            let message = format!(
                "HTTP {} {} responded with status {}",
                req.method(),
                req.uri().path(),
                status.code
            );

            let error = ErrorInfo {
                error_type: "HttpServerError".to_string(),
                message: format!("HTTP server error {}", status.code),
                stack: None,
            };

            crate::logcore::record_error(
                &message,
                trace,
                Some(error),
                Some(labels),
                None,
            );
        }
    }
}

/// Parse a W3C traceparent header according to the specification.
/// Format: `version(2 hex)-trace_id(32 hex)-parent_id(16 hex)-flags(2 hex)`
pub fn parse_traceparent(header: &str) -> Option<TraceInfo> {
    let parts: Vec<&str> = header.trim().split('-').collect();
    if parts.len() == 4 && parts[0] == "00" && parts[1].len() == 32 && parts[2].len() == 16 {
        let flags = u8::from_str_radix(parts[3], 16).unwrap_or(0);
        let sampled = (flags & 0x01) == 1;
        Some(TraceInfo {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            sampled: Some(sampled),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_traceparent() {
        let header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let trace = parse_traceparent(header).unwrap();
        assert_eq!(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(trace.span_id, "00f067aa0ba902b7");
        assert_eq!(trace.sampled, Some(true));
    }
}
