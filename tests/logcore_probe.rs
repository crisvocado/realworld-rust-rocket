use realworld::logcore::{
    build_entry, parse_traceparent, ErrorInfo, RequestEnvelope, StackFrame, TraceInfo,
};
use std::collections::HashMap;

#[test]
fn test_logcore_emission_and_contract() {
    let trace = TraceInfo {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        sampled: Some(true),
    };

    let error = ErrorInfo {
        error_type: "DatabaseError".to_string(),
        message: "Connection refused".to_string(),
        stack: Some(vec![
            StackFrame {
                function: "login_user".to_string(),
                file: "src/database/users.rs".to_string(),
                line: 67,
                column: Some(10),
                in_app: true,
            },
            StackFrame {
                function: "post_users_login".to_string(),
                file: "src/routes/users.rs".to_string(),
                line: 79,
                column: Some(5),
                in_app: true,
            },
        ]),
    };

    let mut labels = HashMap::new();
    labels.insert("route".to_string(), "/api/users/login".to_string());
    labels.insert("status".to_string(), "500".to_string());

    let entry = build_entry(
        "login attempt failed: database error",
        "ERROR",
        Some(trace),
        Some(error),
        Some(labels),
        None,
    );

    let json_output = serde_json::to_string(&entry).expect("failed to serialize LogcoreEntry");

    // Print the emitted JSON entry to stdout for Phase 5 verification and capture
    println!("{}", json_output);

    // Assert entry complies with contract
    assert_eq!(entry.severity, "ERROR");
    assert!(entry.insert_id.is_some());
    let insert_id = entry.insert_id.as_ref().unwrap();
    assert_eq!(insert_id.len(), 32);
    assert!(insert_id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));

    // Verify envelope serialization
    let envelope = RequestEnvelope {
        schema_version: 1,
        entries: vec![entry],
    };
    let envelope_json = serde_json::to_string(&envelope).expect("failed to serialize RequestEnvelope");
    assert!(envelope_json.contains("\"schema_version\":1"));
}

#[test]
fn test_traceparent_parsing() {
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let parsed = parse_traceparent(tp).expect("traceparent should parse");
    assert_eq!(parsed.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(parsed.span_id, "00f067aa0ba902b7");
    assert_eq!(parsed.sampled, Some(true));
}
