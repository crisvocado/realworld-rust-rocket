use dotenv::dotenv;
use realworld::logcore::{self, LogcoreError, LogcoreStackFrame};

fn main() {
    dotenv().ok();

    let stack = vec![LogcoreStackFrame {
        function: "main".to_string(),
        file: "src/bin/logcore_probe.rs".to_string(),
        line: 16,
        column: 5,
        in_app: true,
    }];

    let error = LogcoreError {
        error_type: "ProbeError".to_string(),
        message: "Intentional error triggered by logcore_probe".to_string(),
        stack,
    };

    let entry = logcore::build_entry(
        "ERROR",
        "Logcore probe test error event",
        None,
        Some(error),
        None,
        None,
    );

    let json = serde_json::to_string(&entry).expect("failed to serialize probe entry");
    println!("{}", json);

    // Also enqueue and flush to test the transport pipeline
    logcore::log_entry(entry);
    logcore::flush();
}
