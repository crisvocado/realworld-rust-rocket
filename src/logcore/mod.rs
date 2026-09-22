pub mod catcher;
pub mod entry;
pub mod fairing;
pub mod panic_hook;
pub mod transport;

pub use catcher::{default_catcher, internal_error_catcher};
pub use entry::{ErrorInfo, LogEntry, RequestEnvelope, Severity, StackFrame, TraceContext};
pub use fairing::{fairing, LogcoreFairing};
pub use transport::{get_config, set_test_hook, Config, TestHook};

/// Initialize logcore panic hooks and transport worker.
pub fn init() {
    panic_hook::install();
    let _ = transport::get_transport();
}

/// Enqueue a structured log entry for transport delivery.
pub fn log_entry(entry: LogEntry) {
    transport::get_transport().enqueue(entry);
}

/// Helper to log an error with message and error type.
pub fn capture_error(message: impl Into<String>, error_type: impl Into<String>) {
    let msg = message.into();
    let err_type = error_type.into();
    let error = ErrorInfo {
        error_type: err_type,
        message: msg.clone(),
        stack: vec![],
    };
    let entry = LogEntry::new("ERROR", msg, None, Some(error), None, None);
    log_entry(entry);
}

/// Flush all buffered entries synchronously.
pub fn flush() {
    transport::get_transport().flush();
}

/// Return the standard Rocket catchers for logcore integration.
pub fn catchers() -> Vec<rocket::Catcher> {
    rocket::catchers![internal_error_catcher, default_catcher]
}
