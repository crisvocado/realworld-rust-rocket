use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Logcore envelope for batch HTTP ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcoreEnvelope {
    pub schema_version: u32,
    pub entries: Vec<LogcoreEntry>,
}

/// A single structured log entry adhering to logcore wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcoreEntry {
    pub timestamp: String,
    pub severity: String,
    pub message: String,
    pub service: String,
    pub env: String,
    pub insert_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// W3C distributed trace context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "spanId")]
    pub span_id: String,
    pub sampled: bool,
}

/// Structured error details including parsed stack frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
    pub stack: Vec<StackFrame>,
}

/// A parsed frame in the error stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub function: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    #[serde(rename = "inApp")]
    pub in_app: bool,
}

/// Log severity level floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Debug = 10,
    Info = 20,
    Warn = 30,
    Error = 40,
    Critical = 50,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "DEBUG" => Severity::Debug,
            "INFO" => Severity::Info,
            "WARN" | "WARNING" => Severity::Warn,
            "CRITICAL" | "FATAL" => Severity::Critical,
            _ => Severity::Error,
        }
    }
}
