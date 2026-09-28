//! Logcore structured logging integration for Rocket.
//!
//! Provides automatic fairing-based HTTP instrumentation, trace propagation,
//! and non-blocking delivery of ERROR+ events to logcore gateway.

pub mod client;
pub mod fairing;
pub mod sha256;
pub mod types;

pub use fairing::{parse_traceparent, LogcoreFairing};
pub use types::{ErrorInfo, LogcoreEntry, RequestEnvelope, StackFrame, TraceInfo};

use chrono::Utc;
use client::get_client;
use sha256::compute_insert_id;
use std::collections::HashMap;

/// Create a new Logcore fairing to attach to the Rocket instance.
pub fn fairing() -> LogcoreFairing {
    LogcoreFairing::new()
}

/// Construct a standardized LogcoreEntry conforming to wire_shape and golden_entry.
pub fn build_entry(
    message: &str,
    severity: &str,
    trace: Option<TraceInfo>,
    error: Option<ErrorInfo>,
    labels: Option<HashMap<String, String>>,
    context: Option<serde_json::Value>,
) -> LogcoreEntry {
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let service = std::env::var("LOGCORE_SERVICE").unwrap_or_else(|_| "realworld".to_string());
    let env_name = std::env::var("LOGCORE_ENV").unwrap_or_else(|_| "dev".to_string());
    let insert_id = compute_insert_id(&timestamp, &service, severity, message, context.as_ref());

    LogcoreEntry {
        timestamp,
        severity: severity.to_uppercase(),
        message: message.to_string(),
        service: Some(service),
        env: Some(env_name),
        insert_id: Some(insert_id),
        trace,
        error,
        labels,
        context,
    }
}

/// Record an ERROR-level log entry to logcore.
pub fn record_error(
    message: &str,
    trace: Option<TraceInfo>,
    error: Option<ErrorInfo>,
    labels: Option<HashMap<String, String>>,
    context: Option<serde_json::Value>,
) {
    let entry = build_entry(message, "ERROR", trace, error, labels, context);
    get_client().enqueue(entry);
}

/// Flush any buffered log entries immediately.
pub fn flush() {
    get_client().flush();
}
