use chrono::Utc;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Default Logcore endpoint URL
pub const DEFAULT_ENDPOINT: &str = "https://logcore-dev-352942961463.us-east4.run.app";

/// Service configuration for Logcore
#[derive(Debug, Clone)]
pub struct LogcoreConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub enabled: bool,
    pub service: String,
    pub env: String,
    pub min_severity: String,
}

impl LogcoreConfig {
    pub fn from_env() -> Self {
        let endpoint = env::var("LOGCORE_URL")
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
            .trim_end_matches('/')
            .to_string();

        let api_key = env::var("LOGCORE_KEY")
            .or_else(|_| env::var("LOGCORE_API_KEY"))
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());

        let enabled_env = env::var("LOGCORE_ENABLED").ok();
        let enabled = match enabled_env.as_deref() {
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on") => true,
            Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("off") => false,
            _ => api_key.is_some() || cfg!(test),
        };

        let raw_service = env::var("LOGCORE_SERVICE").unwrap_or_else(|_| "realworld".to_string());
        let service = normalize_service(&raw_service);

        let raw_env = env::var("LOGCORE_ENV")
            .or_else(|_| env::var("ROCKET_ENV"))
            .unwrap_or_else(|_| "dev".to_string());
        let env_str = normalize_env(&raw_env);

        let min_severity = env::var("LOGCORE_MIN_SEVERITY")
            .unwrap_or_else(|_| "ERROR".to_string())
            .to_uppercase();

        Self {
            endpoint,
            api_key,
            enabled,
            service,
            env: env_str,
            min_severity,
        }
    }
}

/// Request envelope wrapper sent to Logcore gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcoreEnvelope {
    pub schema_version: u32,
    pub entries: Vec<LogcoreEntry>,
}

/// Single structured log entry conforming to Logcore wire shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcoreEntry {
    pub timestamp: String,
    pub severity: String,
    pub message: String,
    pub service: String,
    pub env: String,
    pub insert_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<LogcoreTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LogcoreError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Distributed trace metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogcoreTrace {
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "spanId")]
    pub span_id: String,
    pub sampled: bool,
}

/// Structured error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcoreError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub stack: Vec<LogcoreStackFrame>,
}

/// Parsed stack frame (innermost frame first)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcoreStackFrame {
    pub function: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    #[serde(rename = "inApp")]
    pub in_app: bool,
}

/// Normalize environment name according to allowed enums: prod, staging, dev, test, local
pub fn normalize_env(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    match lower.as_str() {
        "prod" | "production" => "prod".to_string(),
        "staging" | "stage" => "staging".to_string(),
        "test" | "testing" => "test".to_string(),
        "local" => "local".to_string(),
        _ => "dev".to_string(),
    }
}

/// Normalize service name to match ^[a-z0-9][a-z0-9._-]{0,62}$
pub fn normalize_service(raw: &str) -> String {
    let mut clean: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .collect();

    if clean.is_empty() || !clean.chars().next().unwrap().is_ascii_alphanumeric() {
        clean = "realworld".to_string();
    }
    if clean.len() > 63 {
        clean.truncate(63);
    }
    clean
}

/// Standard SHA-256 implementation (FIPS 180-4) with zero dependencies
pub fn sha256(data: &[u8]) -> String {
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

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
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

    let mut out = String::with_capacity(64);
    for val in h.iter() {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:08x}", val);
    }
    out
}

/// Compute deterministic 32-character insert_id
pub fn compute_insert_id(
    timestamp: &str,
    service: &str,
    severity: &str,
    message: &str,
    context: Option<&serde_json::Value>,
) -> String {
    let ctx_str = match context {
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
        None => String::new(),
    };
    let payload = format!("{}|{}|{}|{}|{}", timestamp, service, severity, message, ctx_str);
    let hash = sha256(payload.as_bytes());
    hash[..32].to_string()
}

/// Parse incoming W3C traceparent header: 00-{trace_id}-{span_id}-{flags}
pub fn parse_traceparent(header_val: &str) -> Option<LogcoreTrace> {
    let parts: Vec<&str> = header_val.trim().split('-').collect();
    if parts.len() == 4 {
        let version = parts[0];
        let trace_id = parts[1];
        let span_id = parts[2];
        let flags = parts[3];
        if (version == "00" || version.len() == 2)
            && trace_id.len() == 32
            && span_id.len() == 16
            && flags.len() == 2
        {
            let flag_val = u8::from_str_radix(flags, 16).unwrap_or(0);
            return Some(LogcoreTrace {
                trace_id: trace_id.to_string(),
                span_id: span_id.to_string(),
                sampled: (flag_val & 0x01) != 0,
            });
        }
    }
    None
}

/// Clamps message length to <= 65536 characters
pub fn clamp_message(msg: &str) -> String {
    if msg.len() > 65536 {
        msg[..65536].to_string()
    } else {
        msg.to_string()
    }
}

/// Clamps labels to <= 32 items with keys/values <= 1024 characters
pub fn clamp_labels(labels: HashMap<String, String>) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for (k, v) in labels.into_iter().take(32) {
        let key = if k.len() > 1024 { k[..1024].to_string() } else { k };
        let val = if v.len() > 1024 { v[..1024].to_string() } else { v };
        result.insert(key, val);
    }
    result
}

/// Clamps error stack frames to <= 50
pub fn clamp_frames(mut frames: Vec<LogcoreStackFrame>) -> Vec<LogcoreStackFrame> {
    if frames.len() > 50 {
        frames.truncate(50);
    }
    frames
}

/// Global client state managing queue and background dispatcher
struct LogcoreClient {
    config: LogcoreConfig,
    queue: Mutex<Vec<LogcoreEntry>>,
    consecutive_failures: AtomicUsize,
    is_running: AtomicBool,
}

static CLIENT: OnceLock<Arc<LogcoreClient>> = OnceLock::new();

fn get_or_init_client() -> &'static Arc<LogcoreClient> {
    CLIENT.get_or_init(|| {
        let config = LogcoreConfig::from_env();
        let client = Arc::new(LogcoreClient {
            config,
            queue: Mutex::new(Vec::new()),
            consecutive_failures: AtomicUsize::new(0),
            is_running: AtomicBool::new(true),
        });

        let worker_client = Arc::clone(&client);
        thread::spawn(move || {
            worker_loop(worker_client);
        });

        client
    })
}

/// Background worker loop that periodically flushes buffered logs
fn worker_loop(client: Arc<LogcoreClient>) {
    let mut last_flush = Instant::now();
    while client.is_running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(200));

        let should_flush = {
            if let Ok(q) = client.queue.lock() {
                q.len() >= 20 || (last_flush.elapsed() >= Duration::from_secs(5) && !q.is_empty())
            } else {
                false
            }
        };

        if should_flush {
            flush_internal(&client);
            last_flush = Instant::now();
        }
    }
    // Final drain on exit
    flush_internal(&client);
}

/// Sends HTTP request with JSON payload via curl subprocess (0 external dependencies)
fn send_http_request(url: &str, api_key: Option<&str>, json_payload: &str) -> Result<(u16, String), String> {
    let mut cmd = std::process::Command::new("curl");
    cmd.arg("-s")
        .arg("-S")
        .arg("-w")
        .arg("\n%{http_code}")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json");

    if let Some(key) = api_key {
        if !key.is_empty() {
            cmd.arg("-H").arg(format!("x-api-key: {}", key));
        }
    }

    cmd.arg("--data-binary")
        .arg(json_payload)
        .arg(url);

    let output = cmd.output().map_err(|e| format!("Failed to execute curl: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(format!("curl process failed: {}", stderr));
    }

    let trimmed = stdout.trim_end();
    if let Some(idx) = trimmed.rfind('\n') {
        let (body, status_str) = trimmed.split_at(idx);
        let status_str = status_str.trim_start();
        let status_code = status_str.parse::<u16>().unwrap_or(0);
        Ok((status_code, body.to_string()))
    } else {
        let status_code = trimmed.parse::<u16>().unwrap_or(0);
        Ok((status_code, String::new()))
    }
}

/// Dispatches a batch with exponential backoff retries and circuit breaking
fn dispatch_batch(client: &LogcoreClient, batch: Vec<LogcoreEntry>) {
    if batch.is_empty() {
        return;
    }

    // Circuit breaker check (10 consecutive failures)
    if client.consecutive_failures.load(Ordering::Relaxed) >= 10 {
        eprintln!("[logcore] Circuit breaker open; dropping batch of {} entries", batch.len());
        return;
    }

    let url = format!("{}/v1/logs", client.config.endpoint);
    let envelope = LogcoreEnvelope {
        schema_version: 1,
        entries: batch,
    };

    let json_body = match serde_json::to_string(&envelope) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[logcore] Failed to serialize batch: {}", e);
            return;
        }
    };

    let mut attempt = 0;
    let max_retries = 3;

    loop {
        let result = send_http_request(&url, client.config.api_key.as_deref(), &json_body);

        match result {
            Ok((status, body)) => {
                if (200..=299).contains(&status) {
                    // Success!
                    client.consecutive_failures.store(0, Ordering::Relaxed);
                    return;
                } else if status == 429 || (500..=599).contains(&status) {
                    // Retriable server error or rate limit
                    attempt += 1;
                    if attempt > max_retries {
                        eprintln!(
                            "[logcore] Exhausted retries for batch (status {}): {}",
                            status, body
                        );
                        client.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    let delay = Duration::from_millis(250 * (1 << attempt));
                    thread::sleep(delay);
                } else {
                    // 4xx Permanent client error - do NOT retry, echo server reason
                    eprintln!(
                        "[logcore] Permanent failure sending batch (HTTP {}): {}",
                        status, body
                    );
                    client.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
            Err(err) => {
                // Network failure
                attempt += 1;
                if attempt > max_retries {
                    eprintln!("[logcore] Network error after retries: {}", err);
                    client.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let delay = Duration::from_millis(250 * (1 << attempt));
                thread::sleep(delay);
            }
        }
    }
}

/// Flushes buffered entries from the queue in batches of up to 200
fn flush_internal(client: &LogcoreClient) {
    loop {
        let batch: Vec<LogcoreEntry> = {
            if let Ok(mut q) = client.queue.lock() {
                if q.is_empty() {
                    break;
                }
                let take_count = q.len().min(200);
                q.drain(..take_count).collect()
            } else {
                break;
            }
        };

        if batch.is_empty() {
            break;
        }

        dispatch_batch(client, batch);
    }
}

/// Builds a LogcoreEntry from given inputs and current config
pub fn build_entry(
    severity: &str,
    message: &str,
    trace: Option<LogcoreTrace>,
    error: Option<LogcoreError>,
    labels: Option<HashMap<String, String>>,
    context: Option<serde_json::Value>,
) -> LogcoreEntry {
    let client = get_or_init_client();
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let clamped_msg = clamp_message(message);
    let clamped_labels = labels.map(clamp_labels);
    let clamped_error = error.map(|mut err| {
        err.stack = clamp_frames(err.stack);
        err
    });

    let insert_id = compute_insert_id(
        &timestamp,
        &client.config.service,
        severity,
        &clamped_msg,
        context.as_ref(),
    );

    LogcoreEntry {
        timestamp,
        severity: severity.to_uppercase(),
        message: clamped_msg,
        service: client.config.service.clone(),
        env: client.config.env.clone(),
        insert_id,
        source_project: None,
        trace,
        error: clamped_error,
        labels: clamped_labels,
        context,
    }
}

/// Internal entry creation and queueing logic
fn log_entry_internal(
    severity: &str,
    message: &str,
    trace: Option<LogcoreTrace>,
    error: Option<LogcoreError>,
    labels: Option<HashMap<String, String>>,
    context: Option<serde_json::Value>,
) {
    let client = get_or_init_client();
    if !client.config.enabled {
        return;
    }

    let entry = build_entry(severity, message, trace, error, labels, context);

    if let Ok(mut q) = client.queue.lock() {
        // Buffer capacity cap of 1000 - drop oldest if full
        if q.len() >= 1000 {
            q.remove(0);
        }
        q.push(entry);
    }
}

/// Public API to record an ERROR level message
pub fn error(message: &str) {
    log_entry_internal("ERROR", message, None, None, None, None);
}

/// Public API to record an ERROR level message with custom context
pub fn error_with_context(message: &str, context: serde_json::Value) {
    log_entry_internal("ERROR", message, None, None, None, Some(context));
}

/// Public API to record an ERROR level message with error details
pub fn error_with_error(message: &str, error_type: &str, error_message: &str) {
    let err = LogcoreError {
        error_type: error_type.to_string(),
        message: error_message.to_string(),
        stack: Vec::new(),
    };
    log_entry_internal("ERROR", message, None, Some(err), None, None);
}

/// Public API to enqueue a complete LogcoreEntry
pub fn log_entry(entry: LogcoreEntry) {
    let client = get_or_init_client();
    if !client.config.enabled {
        return;
    }
    if let Ok(mut q) = client.queue.lock() {
        if q.len() >= 1000 {
            q.remove(0);
        }
        q.push(entry);
    }
}

/// Explicit flush of all buffered log entries
pub fn flush() {
    let client = get_or_init_client();
    flush_internal(client);
}

/// Create a new Logcore Fairing
pub fn fairing() -> LogcoreFairing {
    LogcoreFairing::new()
}

/// Rocket Fairing integrating Logcore structured error logging and trace capture
pub struct LogcoreFairing;

impl LogcoreFairing {
    pub fn new() -> Self {
        // Ensure client background worker is initialized
        let _ = get_or_init_client();
        Self
    }
}

impl Default for LogcoreFairing {
    fn default() -> Self {
        Self::new()
    }
}

#[rocket::async_trait]
impl Fairing for LogcoreFairing {
    fn info(&self) -> Info {
        Info {
            name: "Logcore Structured Logger",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        if let Some(tp_val) = req.headers().get_one("traceparent") {
            if let Some(trace) = parse_traceparent(tp_val) {
                req.local_cache(|| Some(trace));
            }
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let status = res.status();
        if status.code >= 500 {
            let trace = req.local_cache(|| None::<LogcoreTrace>).clone();
            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();
            let status_code = status.code;

            let mut context = serde_json::Map::new();
            let mut http_info = serde_json::Map::new();
            http_info.insert("method".to_string(), serde_json::Value::String(method.clone()));
            http_info.insert("path".to_string(), serde_json::Value::String(path.clone()));
            http_info.insert("status".to_string(), serde_json::Value::Number(status_code.into()));
            if let Some(client_ip) = req.client_ip() {
                http_info.insert("client_ip".to_string(), serde_json::Value::String(client_ip.to_string()));
            }
            context.insert("http".to_string(), serde_json::Value::Object(http_info));

            let message = format!("HTTP {} {} returned status {}", method, path, status_code);
            let error = LogcoreError {
                error_type: "HttpError".to_string(),
                message: format!("HTTP {} {}", status_code, status.reason().unwrap_or("Server Error")),
                stack: Vec::new(),
            };

            log_entry_internal(
                "ERROR",
                &message,
                trace,
                Some(error),
                None,
                Some(serde_json::Value::Object(context)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello_world() {
        assert_eq!(
            sha256(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_insert_id_format() {
        let insert_id = compute_insert_id(
            "2026-08-17T18:30:00.000Z",
            "realworld",
            "ERROR",
            "checkout failed",
            None,
        );
        assert_eq!(insert_id.len(), 32);
        assert!(insert_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_traceparent_parsing() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let parsed = parse_traceparent(tp).expect("failed to parse traceparent");
        assert_eq!(parsed.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(parsed.span_id, "00f067aa0ba902b7");
        assert!(parsed.sampled);
    }

    #[test]
    fn test_golden_entry_serialization() {
        let entry = LogcoreEntry {
            timestamp: "2026-08-17T18:30:00.000Z".to_string(),
            severity: "ERROR".to_string(),
            message: "checkout failed".to_string(),
            service: "todo-frontend".to_string(),
            env: "dev".to_string(),
            insert_id: "7c2e1a0b9d8f6e4c2a0b8d6f4e2c0a8b".to_string(),
            source_project: None,
            trace: Some(LogcoreTrace {
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
                span_id: "00f067aa0ba902b7".to_string(),
                sampled: true,
            }),
            error: Some(LogcoreError {
                error_type: "TypeError".to_string(),
                message: "Cannot read properties of undefined (reading 'total')".to_string(),
                stack: vec![
                    LogcoreStackFrame {
                        function: "checkout".to_string(),
                        file: "https://app.example.com/assets/index-a1b2c3.js".to_string(),
                        line: 1,
                        column: 48213,
                        in_app: true,
                    },
                    LogcoreStackFrame {
                        function: "<anon>".to_string(),
                        file: "https://cdn.example.com/vendor.js".to_string(),
                        line: 1,
                        column: 9042,
                        in_app: false,
                    },
                ],
            }),
            labels: None,
            context: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["timestamp"], "2026-08-17T18:30:00.000Z");
        assert_eq!(value["severity"], "ERROR");
        assert_eq!(value["message"], "checkout failed");
        assert_eq!(value["service"], "todo-frontend");
        assert_eq!(value["env"], "dev");
        assert_eq!(value["insert_id"], "7c2e1a0b9d8f6e4c2a0b8d6f4e2c0a8b");
        assert_eq!(value["trace"]["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(value["trace"]["spanId"], "00f067aa0ba902b7");
        assert_eq!(value["trace"]["sampled"], true);
        assert_eq!(value["error"]["type"], "TypeError");
        assert_eq!(value["error"]["stack"][0]["function"], "checkout");
        assert_eq!(value["error"]["stack"][0]["inApp"], true);
        assert_eq!(value["error"]["stack"][1]["inApp"], false);
        assert!(value.get("source_project").is_none());
    }
}
