use super::transport::{build_entry, ensure_worker_started, flush_sync, record_entry};
use super::types::{ErrorInfo, Severity, StackFrame, TraceContext};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Build, Data, Request, Response, Rocket};
use std::collections::HashMap;

pub struct LogcoreFairing;

impl Drop for LogcoreFairing {
    fn drop(&mut self) {
        flush_sync();
    }
}

#[rocket::async_trait]
impl Fairing for LogcoreFairing {
    fn info(&self) -> Info {
        Info {
            name: "Logcore Structured Logging",
            kind: Kind::Ignite | Kind::Request | Kind::Response,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> Result<Rocket<Build>, Rocket<Build>> {
        ensure_worker_started();
        Ok(rocket)
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        let trace_context = extract_or_generate_trace(req);
        req.local_cache(|| trace_context);
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let trace_context: &TraceContext = req.local_cache(|| extract_or_generate_trace(req));

        let flags = if trace_context.sampled { "01" } else { "00" };
        let traceparent_value = format!(
            "00-{}-{}-{}",
            trace_context.trace_id, trace_context.span_id, flags
        );
        res.set_header(Header::new("traceparent", traceparent_value));

        let status = res.status();
        if status.code >= 500 {
            let method = req.method().as_str().to_string();
            let uri = req.uri().to_string();
            let route_name = req
                .route()
                .and_then(|r| r.name.as_ref().map(|n| n.to_string()))
                .unwrap_or_else(|| "unknown".to_string());
            let route_uri = req
                .route()
                .map(|r| r.uri.to_string())
                .unwrap_or_else(|| uri.clone());

            let message = format!("HTTP {} {} returned status {}", method, uri, status.code);

            let mut labels = HashMap::new();
            labels.insert("http.method".to_string(), method.clone());
            labels.insert("http.status_code".to_string(), status.code.to_string());
            labels.insert("http.route".to_string(), route_uri);

            let client_ip = req.client_ip().map(|ip| ip.to_string());
            let context = serde_json::json!({
                "http": {
                    "method": method,
                    "uri": uri,
                    "status_code": status.code,
                    "client_ip": client_ip,
                }
            });

            let error = ErrorInfo {
                error_type: "HttpServerError".to_string(),
                message: format!("Internal server error with status code {}", status.code),
                stack: vec![StackFrame {
                    function: route_name,
                    file: "src/lib.rs".to_string(),
                    line: 1,
                    column: 0,
                    in_app: true,
                }],
            };

            if let Some(entry) = build_entry(
                Severity::Error,
                &message,
                Some(error),
                Some(trace_context.clone()),
                Some(labels),
                Some(context),
            ) {
                record_entry(entry);
            }
        }
    }
}

fn extract_or_generate_trace(req: &Request<'_>) -> TraceContext {
    if let Some(header_val) = req.headers().get_one("traceparent") {
        if let Some(parsed) = parse_traceparent(header_val) {
            return parsed;
        }
    }

    generate_trace_context()
}

fn parse_traceparent(header: &str) -> Option<TraceContext> {
    let parts: Vec<&str> = header.trim().split('-').collect();
    if parts.len() >= 4 {
        let trace_id = parts[1];
        let span_id = parts[2];
        let flags = parts[3];

        if trace_id.len() == 32
            && trace_id.chars().all(|c| c.is_ascii_hexdigit())
            && span_id.len() == 16
            && span_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            let flags_val = u8::from_str_radix(flags, 16).unwrap_or(1);
            let sampled = (flags_val & 0x01) != 0;

            return Some(TraceContext {
                trace_id: trace_id.to_lowercase(),
                span_id: span_id.to_lowercase(),
                sampled,
            });
        }
    }
    None
}

fn generate_trace_context() -> TraceContext {
    let mut trace_bytes = [0u8; 16];
    let mut span_bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut trace_bytes);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut span_bytes);

    let trace_id: String = trace_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let span_id: String = span_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    TraceContext {
        trace_id,
        span_id,
        sampled: true,
    }
}
