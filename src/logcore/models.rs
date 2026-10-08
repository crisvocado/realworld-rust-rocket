use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEnvelope {
    pub schema_version: u32,
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub severity: String,
    pub message: String,
    pub service: String,
    pub env: String,
    pub insert_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInfo {
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "spanId", skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub r#type: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<Vec<StackFrame>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(rename = "inApp", skip_serializing_if = "Option::is_none")]
    pub in_app: Option<bool>,
}
