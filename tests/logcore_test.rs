use realworld::logcore::entry::{
    compute_insert_id, parse_traceparent, ErrorInfo, LogEntry, RequestEnvelope, Severity,
    StackFrame, TraceContext,
};
use realworld::logcore::{set_test_hook, capture_error, flush, log_entry};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_golden_entry_contract() {
    let trace = TraceContext {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        sampled: true,
    };

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

    let entry = LogEntry {
        timestamp: "2026-08-17T18:30:00.000Z".to_string(),
        severity: "ERROR".to_string(),
        message: "checkout failed".to_string(),
        service: "todo-frontend".to_string(),
        env: "dev".to_string(),
        insert_id: "7c2e1a0b9d8f6e4c2a0b8d6f4e2c0a8b".to_string(),
        trace: Some(trace),
        error: Some(error),
        labels: None,
        context: None,
        source_project: None,
    };

    let json_val = serde_json::to_value(&entry).expect("serialize LogEntry");

    // Check top-level wire fields
    assert_eq!(json_val["timestamp"], "2026-08-17T18:30:00.000Z");
    assert_eq!(json_val["severity"], "ERROR");
    assert_eq!(json_val["message"], "checkout failed");
    assert_eq!(json_val["service"], "todo-frontend");
    assert_eq!(json_val["env"], "dev");
    assert_eq!(json_val["insert_id"], "7c2e1a0b9d8f6e4c2a0b8d6f4e2c0a8b");

    // Check trace shape (camelCase)
    let trace_obj = &json_val["trace"];
    assert_eq!(trace_obj["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(trace_obj["spanId"], "00f067aa0ba902b7");
    assert_eq!(trace_obj["sampled"], true);

    // Check error shape
    let error_obj = &json_val["error"];
    assert_eq!(error_obj["type"], "TypeError");
    assert_eq!(
        error_obj["message"],
        "Cannot read properties of undefined (reading 'total')"
    );

    // Check stack frames (inApp camelCase)
    let stack = error_obj["stack"].as_array().expect("stack array");
    assert_eq!(stack.len(), 2);
    assert_eq!(stack[0]["function"], "checkout");
    assert_eq!(
        stack[0]["file"],
        "https://app.example.com/assets/index-a1b2c3.js"
    );
    assert_eq!(stack[0]["line"], 1);
    assert_eq!(stack[0]["column"], 48213);
    assert_eq!(stack[0]["inApp"], true);

    assert_eq!(stack[1]["function"], "<anon>");
    assert_eq!(stack[1]["file"], "https://cdn.example.com/vendor.js");
    assert_eq!(stack[1]["line"], 1);
    assert_eq!(stack[1]["column"], 9042);
    assert_eq!(stack[1]["inApp"], false);
}

#[test]
fn test_deterministic_insert_id() {
    let id1 = compute_insert_id(
        "2026-08-17T18:30:00.000Z",
        "realworld",
        "ERROR",
        "database query timeout",
        None,
    );
    let id2 = compute_insert_id(
        "2026-08-17T18:30:00.000Z",
        "realworld",
        "ERROR",
        "database query timeout",
        None,
    );

    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 32);
    assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_traceparent_parsing() {
    let header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let trace = parse_traceparent(header).expect("parse traceparent");

    assert_eq!(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(trace.span_id, "00f067aa0ba902b7");
    assert!(trace.sampled);

    // Invalid traceparent
    assert!(parse_traceparent("invalid-header").is_none());
}

#[test]
fn test_request_envelope_serialization() {
    let entry = LogEntry::new(
        "ERROR",
        "database connection dropped".to_string(),
        None,
        None,
        None,
        None,
    );

    let envelope = RequestEnvelope {
        schema_version: 1,
        entries: vec![entry],
    };

    let serialized = serde_json::to_string(&envelope).expect("serialize envelope");
    let parsed: serde_json::Value = serde_json::from_str(&serialized).expect("parse envelope");

    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["entries"][0]["message"],
        "database connection dropped"
    );
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::ERROR.is_at_least(Severity::WARNING));
    assert!(Severity::CRITICAL.is_at_least(Severity::ERROR));
    assert!(!Severity::INFO.is_at_least(Severity::ERROR));
    assert!(!Severity::DEBUG.is_at_least(Severity::ERROR));
}

#[test]
fn test_capture_error() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    set_test_hook(Some(Arc::new(move |envelope: &RequestEnvelope| {
        counter_clone.fetch_add(envelope.entries.len(), Ordering::SeqCst);
    })));

    capture_error("test error message", "TestError");
    flush();

    assert_eq!(counter.load(Ordering::SeqCst), 1);
    set_test_hook(None);
}

#[test]
fn test_emit_error_log() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    set_test_hook(Some(Arc::new(move |envelope: &RequestEnvelope| {
        counter_clone.fetch_add(envelope.entries.len(), Ordering::SeqCst);
        for entry in &envelope.entries {
            let json = serde_json::to_string(entry).unwrap();
            println!("[LOGCORE_EMIT] {}", json);
        }
    })));

    let mut labels = HashMap::new();
    labels.insert("route".to_string(), "/api/articles".to_string());

    let entry = LogEntry::new(
        "ERROR",
        "Failed to load user profile: connection reset by peer".to_string(),
        Some(TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            sampled: true,
        }),
        Some(ErrorInfo {
            error_type: "DatabaseError".to_string(),
            message: "connection reset by peer".to_string(),
            stack: vec![StackFrame {
                function: "realworld::database::users::find_user".to_string(),
                file: "src/database/users.rs".to_string(),
                line: 91,
                column: 10,
                in_app: true,
            }],
        }),
        Some(labels),
        Some(serde_json::json!({
            "http": {
                "method": "GET",
                "path": "/api/profiles/johndoe",
                "status": 500
            }
        })),
    );

    println!(
        "EMITTED_ERROR_JSON: {}",
        serde_json::to_string(&entry).unwrap()
    );

    log_entry(entry);
    flush();

    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Reset test hook
    set_test_hook(None);
}
