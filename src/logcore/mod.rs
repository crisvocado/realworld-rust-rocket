pub mod crypto;
pub mod fairing;
pub mod transport;
pub mod types;

pub use fairing::LogcoreFairing;
pub use types::{ErrorInfo, LogcoreEntry, LogcoreEnvelope, Severity, StackFrame, TraceContext};

use std::collections::HashMap;

/// Create a Rocket Fairing for Logcore structured logging.
pub fn fairing() -> LogcoreFairing {
    LogcoreFairing
}

/// Log an error with structured context to Logcore.
pub fn log_error(
    message: &str,
    error: Option<ErrorInfo>,
    trace: Option<TraceContext>,
    labels: Option<HashMap<String, String>>,
    context: Option<serde_json::Value>,
) {
    if let Some(entry) = transport::build_entry(
        Severity::Error,
        message,
        error,
        trace,
        labels,
        context,
    ) {
        transport::record_entry(entry);
    }
}

/// Helper used by `logcore_probe` binary to emit a verifiable error entry.
pub fn probe_error() {
    let error = ErrorInfo {
        error_type: "LogcoreProbeError".to_string(),
        message: "Logcore probe error for validation".to_string(),
        stack: vec![StackFrame {
            function: "probe_error".to_string(),
            file: "src/bin/logcore_probe.rs".to_string(),
            line: 1,
            column: 1,
            in_app: true,
        }],
    };

    let mut labels = HashMap::new();
    labels.insert("probe".to_string(), "true".to_string());

    let context = serde_json::json!({
        "probe": {
            "source": "logcore_probe",
            "status": "testing"
        }
    });

    let trace = TraceContext {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        sampled: true,
    };

    if let Some(entry) = transport::build_entry(
        Severity::Error,
        "Logcore probe test event",
        Some(error),
        Some(trace),
        Some(labels),
        Some(context),
    ) {
        if let Ok(json_str) = serde_json::to_string(&entry) {
            println!("{}", json_str);
        }
        transport::record_entry(entry);
        transport::flush_sync();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logcore_entry_structure() {
        let error = ErrorInfo {
            error_type: "TypeError".to_string(),
            message: "Cannot read properties of undefined (reading 'total')".to_string(),
            stack: vec![
                StackFrame {
                    function: "checkout".to_string(),
                    file: "https://app.example.com/assets/index-a1b2c3.js".to_string(),
                    line: 1,
                    column: 48213,
                    in_app: true,
                },
                StackFrame {
                    function: "<anon>".to_string(),
                    file: "https://cdn.example.com/vendor.js".to_string(),
                    line: 1,
                    column: 9042,
                    in_app: false,
                },
            ],
        };

        let trace = TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            sampled: true,
        };

        let entry = transport::build_entry(
            Severity::Error,
            "checkout failed",
            Some(error),
            Some(trace),
            None,
            None,
        )
        .expect("entry must be built");

        assert_eq!(entry.severity, "ERROR");
        assert_eq!(entry.message, "checkout failed");
        assert_eq!(entry.insert_id.len(), 32);
        assert!(entry.insert_id.chars().all(|c| c.is_ascii_hexdigit()));

        let json_val = serde_json::to_value(&entry).unwrap();
        assert_eq!(json_val["severity"], "ERROR");
        assert_eq!(json_val["message"], "checkout failed");
        assert_eq!(json_val["trace"]["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(json_val["trace"]["spanId"], "00f067aa0ba902b7");
        assert_eq!(json_val["trace"]["sampled"], true);
        assert_eq!(json_val["error"]["type"], "TypeError");
        assert_eq!(
            json_val["error"]["message"],
            "Cannot read properties of undefined (reading 'total')"
        );
        assert_eq!(json_val["error"]["stack"][0]["function"], "checkout");
        assert_eq!(
            json_val["error"]["stack"][0]["file"],
            "https://app.example.com/assets/index-a1b2c3.js"
        );
        assert_eq!(json_val["error"]["stack"][0]["line"], 1);
        assert_eq!(json_val["error"]["stack"][0]["column"], 48213);
        assert_eq!(json_val["error"]["stack"][0]["inApp"], true);
        assert_eq!(json_val["error"]["stack"][1]["inApp"], false);
    }
}
