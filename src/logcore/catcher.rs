use crate::logcore::entry::{ErrorInfo, LogEntry, StackFrame, TraceContext};
use crate::logcore::fairing::ErrorLogged;
use rocket::http::Status;
use rocket::serde::json::{json, Value};
use rocket::Request;
use std::sync::atomic::{AtomicBool, Ordering};

#[catch(500)]
pub fn internal_error_catcher(req: &Request<'_>) -> Value {
    let error_logged = req.local_cache(|| ErrorLogged(AtomicBool::new(false)));
    if !error_logged.0.swap(true, Ordering::SeqCst) {
        let trace: Option<TraceContext> = req.local_cache(|| None).clone();
        let path = req.uri().path().as_str();
        let method = req.method().as_str();

        let error = ErrorInfo {
            error_type: "InternalServerError".to_string(),
            message: format!("Internal server error handling {} {}", method, path),
            stack: vec![StackFrame {
                function: format!("{} {}", method, path),
                file: "handler".to_string(),
                line: 1,
                column: 0,
                in_app: true,
            }],
        };

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
            serde_json::Value::Number(serde_json::Number::from(500)),
        );
        context_map.insert("http".to_string(), serde_json::Value::Object(http_map));

        let entry = LogEntry::new(
            "ERROR",
            format!("Internal server error handling {} {}", method, path),
            trace,
            Some(error),
            None,
            Some(serde_json::Value::Object(context_map)),
        );

        crate::logcore::log_entry(entry);
    }

    json!({
        "status": "error",
        "reason": "Internal server error."
    })
}

#[catch(default)]
pub fn default_catcher(status: Status, req: &Request<'_>) -> Value {
    if status.code >= 500 {
        let error_logged = req.local_cache(|| ErrorLogged(AtomicBool::new(false)));
        if !error_logged.0.swap(true, Ordering::SeqCst) {
            let trace: Option<TraceContext> = req.local_cache(|| None).clone();
            let path = req.uri().path().as_str();
            let method = req.method().as_str();

            let error = ErrorInfo {
                error_type: format!("HttpStatus{}", status.code),
                message: format!("HTTP error {} handling {} {}", status.code, method, path),
                stack: vec![StackFrame {
                    function: format!("{} {}", method, path),
                    file: "handler".to_string(),
                    line: 1,
                    column: 0,
                    in_app: true,
                }],
            };

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
            context_map.insert("http".to_string(), serde_json::Value::Object(http_map));

            let entry = LogEntry::new(
                "ERROR",
                format!("HTTP {} error handling {} {}", status.code, method, path),
                trace,
                Some(error),
                None,
                Some(serde_json::Value::Object(context_map)),
            );

            crate::logcore::log_entry(entry);
        }
    }

    json!({
        "status": "error",
        "reason": status.reason().unwrap_or("An error occurred")
    })
}
