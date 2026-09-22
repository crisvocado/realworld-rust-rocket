use crate::logcore::entry::{parse_traceparent, ErrorInfo, LogEntry, StackFrame, TraceContext};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Build, Data, Request, Response, Rocket};
use std::sync::atomic::{AtomicBool, Ordering};

pub struct ErrorLogged(pub AtomicBool);

pub struct LogcoreFairing;

pub fn fairing() -> LogcoreFairing {
    LogcoreFairing
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
        crate::logcore::init();
        Ok(rocket)
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        if let Some(traceparent) = req.headers().get_one("traceparent") {
            if let Some(trace) = parse_traceparent(traceparent) {
                req.local_cache(|| Some(trace));
            }
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let status = res.status();
        if status.code >= 500 {
            let path = req.uri().path().as_str();

            // Self-exclusion: do not instrument logcore's own transport endpoint
            if path.starts_with("/v1/logs") {
                return;
            }

            let error_logged = req.local_cache(|| ErrorLogged(AtomicBool::new(false)));
            if error_logged.0.swap(true, Ordering::SeqCst) {
                return;
            }

            let trace: Option<TraceContext> = req.local_cache(|| None).clone();
            let method = req.method().as_str();

            let mut context_map = serde_json::Map::new();
            let mut http_map = serde_json::Map::new();
            http_map.insert(
                "method".to_string(),
                serde_json::Value::String(method.to_string()),
            );
            http_map.insert(
                "path".to_string(),
                serde_json::Value::String(path.to_string()),
            );
            http_map.insert(
                "status".to_string(),
                serde_json::Value::Number(serde_json::Number::from(status.code)),
            );
            if let Some(client_ip) = req.client_ip() {
                http_map.insert(
                    "client_ip".to_string(),
                    serde_json::Value::String(client_ip.to_string()),
                );
            }
            context_map.insert("http".to_string(), serde_json::Value::Object(http_map));

            let error = ErrorInfo {
                error_type: format!("HttpError{}", status.code),
                message: format!("HTTP response error with status {}", status.code),
                stack: vec![StackFrame {
                    function: format!("{} {}", method, path),
                    file: "routes".to_string(),
                    line: 1,
                    column: 0,
                    in_app: true,
                }],
            };

            let entry = LogEntry::new(
                "ERROR",
                format!("HTTP {} {} returned status {}", method, path, status.code),
                trace,
                Some(error),
                None,
                Some(serde_json::Value::Object(context_map)),
            );

            crate::logcore::log_entry(entry);
        }
    }
}
