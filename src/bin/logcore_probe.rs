use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use realworld::logcore::{self, ErrorInfo, StackFrame, TraceInfo};

fn main() {
    let captured = Arc::new(Mutex::new(None::<String>));
    let captured_clone = Arc::clone(&captured);

    // 1. Install capture sink on the Logcore transport adapter
    logcore::set_capture_sink(move |payload: &str| {
        let mut lock = captured_clone.lock().unwrap();
        *lock = Some(payload.to_string());
    });

    // 2. Exercise the logging integration by emitting an ERROR event
    let mut labels = HashMap::new();
    labels.insert("probe".to_string(), "true".to_string());
    labels.insert("integration".to_string(), "logcore".to_string());

    let trace = TraceInfo {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: Some("00f067aa0ba902b7".to_string()),
        sampled: Some(true),
    };

    let error = ErrorInfo {
        r#type: "IntegrationProbeError".to_string(),
        message: "logcore integration probe error verification".to_string(),
        stack: Some(vec![StackFrame {
            function: "main".to_string(),
            file: Some("src/bin/logcore_probe.rs".to_string()),
            line: Some(25),
            column: None,
            in_app: Some(true),
        }]),
    };

    // Emit the error through logcore transport
    logcore::log_entry(
        "ERROR",
        "logcore integration probe error verification",
        Some(trace),
        Some(error),
        Some(labels),
        None,
    );

    // 3. Flush the transport queue
    logcore::flush();

    // 4. Output the complete HTTP request envelope unchanged
    let lock = captured.lock().unwrap();
    if let Some(ref payload) = *lock {
        println!("{}", payload);
    } else {
        eprintln!("Error: No log entry was captured during probe run");
        std::process::exit(1);
    }
}
