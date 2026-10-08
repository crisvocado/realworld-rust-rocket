use std::collections::{HashMap, VecDeque};
use std::env;
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use crate::logcore::models::{ErrorInfo, LogEntry, LogEnvelope, TraceInfo};
use crate::logcore::sha256::sha256_hex;

const DEFAULT_ENDPOINT: &str = "https://logcore-dev-352942961463.us-east4.run.app";
const MAX_BUFFER_CAP: usize = 1000;
const MAX_BATCH_SIZE: usize = 200;
const BATCH_FLUSH_THRESHOLD: usize = 20;
const CIRCUIT_BREAKER_LIMIT: u32 = 10;
const MAX_MESSAGE_CHARS: usize = 65536;
const MAX_LABELS: usize = 32;
const MAX_LABEL_VALUE_CHARS: usize = 1024;
const MAX_STACK_FRAMES: usize = 50;

#[derive(Debug, Clone)]
pub struct LogcoreConfig {
    pub enabled: bool,
    pub url: String,
    pub key: Option<String>,
    pub service: String,
    pub env: String,
    pub min_severity: String,
}

impl LogcoreConfig {
    pub fn from_env() -> Self {
        let enabled_raw = env::var("LOGCORE_ENABLED").unwrap_or_else(|_| "true".to_string());
        let enabled = !matches!(
            enabled_raw.to_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        );

        let url = env::var("LOGCORE_URL")
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
            .trim_end_matches('/')
            .to_string();

        let key = env::var("LOGCORE_KEY").ok();
        let service = env::var("LOGCORE_SERVICE").unwrap_or_else(|_| "realworld".to_string());
        let env_val = env::var("LOGCORE_ENV").unwrap_or_else(|_| "dev".to_string());
        let min_severity =
            env::var("LOGCORE_MIN_SEVERITY").unwrap_or_else(|_| "ERROR".to_string());

        Self {
            enabled,
            url,
            key,
            service,
            env: env_val,
            min_severity,
        }
    }
}

pub type CaptureSink = Arc<dyn Fn(&str) + Send + Sync + 'static>;

struct TransportState {
    config: LogcoreConfig,
    buffer: VecDeque<LogEntry>,
    consecutive_failures: u32,
    capture_sink: Option<CaptureSink>,
}

static mut TRANSPORT: Option<Mutex<TransportState>> = None;
static INIT_ONCE: Once = Once::new();

fn get_transport() -> &'static Mutex<TransportState> {
    INIT_ONCE.call_once(|| {
        let state = TransportState {
            config: LogcoreConfig::from_env(),
            buffer: VecDeque::with_capacity(MAX_BUFFER_CAP),
            consecutive_failures: 0,
            capture_sink: None,
        };
        unsafe {
            TRANSPORT = Some(Mutex::new(state));
        }
    });
    unsafe { TRANSPORT.as_ref().unwrap() }
}

/// Sets a capture sink for testing and emission probe verification.
pub fn set_capture_sink<F>(sink: F)
where
    F: Fn(&str) + Send + Sync + 'static,
{
    let transport = get_transport();
    let mut state = transport.lock().unwrap();
    state.capture_sink = Some(Arc::new(sink));
}

/// Severity ranking
fn severity_rank(sev: &str) -> u32 {
    match sev.to_uppercase().as_str() {
        "DEBUG" => 0,
        "INFO" => 1,
        "NOTICE" => 2,
        "WARNING" => 3,
        "ERROR" => 4,
        "CRITICAL" => 5,
        "ALERT" => 6,
        "EMERGENCY" => 7,
        _ => 4,
    }
}

/// Clamps message, labels and error stack according to Logcore limits.
fn sanitize_entry(
    severity: &str,
    message: &str,
    trace: Option<TraceInfo>,
    error: Option<ErrorInfo>,
    labels: Option<HashMap<String, String>>,
    context: Option<Value>,
    service: &str,
    env: &str,
) -> LogEntry {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Clamp message
    let clamped_message: String = message.chars().take(MAX_MESSAGE_CHARS).collect();
    let safe_message = if clamped_message.is_empty() {
        "unknown error".to_string()
    } else {
        clamped_message
    };

    // Clamp labels
    let clamped_labels = labels.map(|lbls| {
        lbls.into_iter()
            .take(MAX_LABELS)
            .map(|(k, v)| {
                let clamped_v: String = v.chars().take(MAX_LABEL_VALUE_CHARS).collect();
                (k, clamped_v)
            })
            .collect()
    });

    // Clamp error stack
    let clamped_error = error.map(|mut err| {
        if let Some(stack) = err.stack {
            err.stack = Some(stack.into_iter().take(MAX_STACK_FRAMES).collect());
        }
        err
    });

    // Compute deterministic insert_id
    let ctx_str = context.as_ref().map(|c| c.to_string()).unwrap_or_default();
    let hash_input = format!(
        "{}|{}|{}|{}|{}",
        now, service, severity, safe_message, ctx_str
    );
    let hash = sha256_hex(hash_input.as_bytes());
    let insert_id = hash[..32].to_string();

    LogEntry {
        timestamp: now,
        severity: severity.to_uppercase(),
        message: safe_message,
        service: service.to_string(),
        env: env.to_string(),
        insert_id,
        trace,
        error: clamped_error,
        labels: clamped_labels,
        context,
    }
}

/// Log an entry through Logcore transport.
pub fn log_entry(
    severity: &str,
    message: &str,
    trace: Option<TraceInfo>,
    error: Option<ErrorInfo>,
    labels: Option<HashMap<String, String>>,
    context: Option<Value>,
) {
    let transport = get_transport();
    let mut state = transport.lock().unwrap();

    // Check severity floor
    if severity_rank(severity) < severity_rank(&state.config.min_severity) {
        return;
    }

    // Check if enabled (probe/capture sink overrides disabled state)
    if !state.config.enabled && state.capture_sink.is_none() {
        return;
    }

    let service = state.config.service.clone();
    let env_name = state.config.env.clone();

    let entry = sanitize_entry(
        severity, message, trace, error, labels, context, &service, &env_name,
    );

    // Buffer management: drop oldest if buffer is full
    if state.buffer.len() >= MAX_BUFFER_CAP {
        state.buffer.pop_front();
    }
    state.buffer.push_back(entry);

    if state.buffer.len() >= BATCH_FLUSH_THRESHOLD {
        drop(state);
        flush();
    }
}

/// Flushes buffered log entries.
pub fn flush() {
    let transport = get_transport();
    let mut state = transport.lock().unwrap();

    if state.buffer.is_empty() {
        return;
    }

    // Circuit breaker check
    if state.consecutive_failures >= CIRCUIT_BREAKER_LIMIT && state.capture_sink.is_none() {
        state.buffer.clear();
        return;
    }

    let batch_size = std::cmp::min(state.buffer.len(), MAX_BATCH_SIZE);
    let mut batch = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        if let Some(entry) = state.buffer.pop_front() {
            batch.push(entry);
        }
    }

    let envelope = LogEnvelope {
        schema_version: 1,
        entries: batch,
    };

    let serialized = match serde_json::to_string(&envelope) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("logcore: failed to serialize log envelope: {}", err);
            return;
        }
    };

    // If capture sink is installed, deliver directly to capture sink
    if let Some(ref sink) = state.capture_sink {
        sink(&serialized);
        state.consecutive_failures = 0;
        return;
    }

    // HTTP delivery
    let url = format!("{}/v1/logs", state.config.url);
    let key = state.config.key.clone();

    // Self-exclusion check: don't log recursive requests
    if url.is_empty() {
        return;
    }

    // Perform delivery with retry
    let success = send_with_retry(&url, key.as_deref(), &serialized);
    if success {
        state.consecutive_failures = 0;
    } else {
        state.consecutive_failures += 1;
        if state.consecutive_failures >= CIRCUIT_BREAKER_LIMIT {
            eprintln!("logcore: circuit breaker tripped after 10 consecutive failures. Clearing buffer.");
            state.buffer.clear();
        }
    }
}

/// Sends HTTP POST request with exponential retry for 5xx/429/network errors.
fn send_with_retry(url: &str, api_key: Option<&str>, payload: &str) -> bool {
    let attempts = 4; // Initial + up to 3 retries
    for attempt in 0..attempts {
        if attempt > 0 {
            let backoff_ms = 250 * (1 << attempt);
            thread::sleep(Duration::from_millis(backoff_ms));
        }

        match perform_http_post(url, api_key, payload) {
            Ok(status_code) => {
                if status_code >= 200 && status_code < 300 {
                    return true;
                } else if status_code == 429 || status_code >= 500 {
                    // Retry on 429 or 5xx
                    continue;
                } else if status_code >= 400 && status_code < 500 {
                    // Permanent 4xx rejection: do not retry, echo server reason
                    eprintln!(
                        "logcore: permanent rejection HTTP {} for endpoint {}",
                        status_code, url
                    );
                    return false;
                }
            }
            Err(err) => {
                // Network error: retry
                if attempt == attempts - 1 {
                    eprintln!("logcore: delivery failed after {} attempts: {}", attempts, err);
                }
            }
        }
    }
    false
}

/// Lightweight HTTP client using standard library TcpStream for zero extra runtime dependencies.
fn perform_http_post(url: &str, api_key: Option<&str>, payload: &str) -> Result<u16, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let parsed_url = parse_http_url(url)?;

    let host_header = if parsed_url.port == 80 || parsed_url.port == 443 {
        parsed_url.host.clone()
    } else {
        format!("{}:{}", parsed_url.host, parsed_url.port)
    };

    let mut request_headers = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        parsed_url.path,
        host_header,
        payload.len()
    );

    if let Some(key) = api_key {
        request_headers.push_str(&format!("x-api-key: {}\r\n", key));
    }
    request_headers.push_str("\r\n");

    let address = format!("{}:{}", parsed_url.host, parsed_url.port);
    let mut stream = TcpStream::connect_timeout(
        &address
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("Connection error: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout error: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout error: {}", e))?;

    stream
        .write_all(request_headers.as_bytes())
        .map_err(|e| format!("Write headers error: {}", e))?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("Write body error: {}", e))?;
    stream.flush().map_err(|e| format!("Flush error: {}", e))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("Read response error: {}", e))?;

    let response_str = String::from_utf8_lossy(&response);
    let first_line = response_str.lines().next().unwrap_or_default();
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        if let Ok(code) = parts[1].parse::<u16>() {
            return Ok(code);
        }
    }

    Err(format!("Could not parse HTTP response: {}", first_line))
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Result<ParsedUrl, String> {
    let without_scheme = if let Some(stripped) = url.strip_prefix("http://") {
        (stripped, 80)
    } else if let Some(stripped) = url.strip_prefix("https://") {
        (stripped, 443)
    } else {
        (url, 80)
    };

    let (host_port, path) = match without_scheme.0.find('/') {
        Some(idx) => (&without_scheme.0[..idx], &without_scheme.0[idx..]),
        None => (without_scheme.0, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let port_str = &host_port[idx + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid port in url: {}", url))?;
            (&host_port[..idx], port)
        }
        None => (host_port, without_scheme.1),
    };

    Ok(ParsedUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}
