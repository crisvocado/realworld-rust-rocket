use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels supported by logcore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::DEBUG => "DEBUG",
            Severity::INFO => "INFO",
            Severity::WARNING => "WARNING",
            Severity::ERROR => "ERROR",
            Severity::CRITICAL => "CRITICAL",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DEBUG" => Severity::DEBUG,
            "INFO" => Severity::INFO,
            "WARN" | "WARNING" => Severity::WARNING,
            "CRITICAL" | "FATAL" => Severity::CRITICAL,
            _ => Severity::ERROR,
        }
    }

    pub fn is_at_least(&self, min: Severity) -> bool {
        *self >= min
    }
}

/// A parsed stack frame conforming to logcore's frame schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StackFrame {
    pub function: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    #[serde(rename = "inApp")]
    pub in_app: bool,
}

/// Detailed error payload with parsed stack frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorInfo {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub stack: Vec<StackFrame>,
}

/// W3C Trace Context representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceContext {
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "spanId")]
    pub span_id: String,
    pub sampled: bool,
}

/// Single structured log entry matching logcore wire_shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_project: Option<String>,
}

/// Top-level HTTP request envelope sent to /v1/logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestEnvelope {
    pub schema_version: u32,
    pub entries: Vec<LogEntry>,
}

/// Standalone, dependency-free FIPS 180-4 SHA-256 implementation.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, part) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([part[0], part[1], part[2], part[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    let bytes = sha256(data);
    let mut s = String::with_capacity(64);
    for b in &bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Compute deterministic 32-character hex insert_id for deduplication.
pub fn compute_insert_id(
    timestamp: &str,
    service: &str,
    severity: &str,
    message: &str,
    context: Option<&serde_json::Value>,
) -> String {
    let context_str = match context {
        Some(c) => serde_json::to_string(c).unwrap_or_default(),
        None => String::new(),
    };
    let payload = format!("{}|{}|{}|{}|{}", timestamp, service, severity, message, context_str);
    let hash = sha256_hex(payload.as_bytes());
    hash[..32].to_string()
}

/// Parse W3C traceparent header: 00-{trace_id}-{span_id}-{flags}
pub fn parse_traceparent(header: &str) -> Option<TraceContext> {
    let parts: Vec<&str> = header.trim().split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    let version = parts[0];
    let trace_id = parts[1];
    let span_id = parts[2];
    let flags = parts[3];

    // Check expected lengths and non-zero format
    if version.len() != 2 || trace_id.len() != 32 || span_id.len() != 16 || flags.len() != 2 {
        return None;
    }
    if trace_id.chars().all(|c| c == '0') || span_id.chars().all(|c| c == '0') {
        return None;
    }

    let flags_val = u8::from_str_radix(flags, 16).unwrap_or(0);
    let sampled = (flags_val & 0x01) == 1;

    Some(TraceContext {
        trace_id: trace_id.to_string(),
        span_id: span_id.to_string(),
        sampled,
    })
}

/// Clamp message length to <= 65536 chars.
pub fn clamp_message(message: &str) -> String {
    if message.len() > 65536 {
        message[..65536].to_string()
    } else {
        message.to_string()
    }
}

/// Clamp labels to <= 32 entries and values to <= 1024 chars.
pub fn clamp_labels(labels: HashMap<String, String>) -> HashMap<String, String> {
    let mut clamped = HashMap::new();
    for (k, v) in labels.into_iter().take(32) {
        let val = if v.len() > 1024 {
            v[..1024].to_string()
        } else {
            v
        };
        clamped.insert(k, val);
    }
    clamped
}

/// Clamp stack frames to <= 50 frames.
pub fn clamp_frames(frames: Vec<StackFrame>) -> Vec<StackFrame> {
    if frames.len() > 50 {
        frames.into_iter().take(50).collect()
    } else {
        frames
    }
}

impl LogEntry {
    /// Construct a new LogEntry populated with environment defaults and deterministic insert_id.
    pub fn new(
        severity: &str,
        message: String,
        trace: Option<TraceContext>,
        error: Option<ErrorInfo>,
        labels: Option<HashMap<String, String>>,
        context: Option<serde_json::Value>,
    ) -> Self {
        let config = crate::logcore::get_config();
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let service = config.service;
        let env = config.env;
        let clamped_message = clamp_message(&message);
        let insert_id = compute_insert_id(
            &timestamp,
            &service,
            severity,
            &clamped_message,
            context.as_ref(),
        );

        let clamped_error = error.map(|mut err| {
            err.stack = clamp_frames(err.stack);
            err
        });

        let clamped_labels = labels.map(clamp_labels);

        Self {
            timestamp,
            severity: severity.to_uppercase(),
            message: clamped_message,
            service,
            env,
            insert_id,
            trace,
            error: clamped_error,
            labels: clamped_labels,
            context,
            source_project: None,
        }
    }
}
