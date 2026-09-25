use super::crypto::sha256_hex;
use super::types::{ErrorInfo, LogcoreEnvelope, LogcoreEntry, Severity, TraceContext};
use chrono::Utc;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

const MAX_BUFFER_SIZE: usize = 1000;
const MAX_BATCH_SIZE: usize = 200;
const BATCH_FLUSH_THRESHOLD: usize = 20;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_CONSECUTIVE_FAILURES: usize = 10;
const MAX_MESSAGE_LEN: usize = 65536;
const MAX_LABELS: usize = 32;
const MAX_LABEL_LEN: usize = 1024;
const MAX_STACK_FRAMES: usize = 50;

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub endpoint: String,
    pub api_key: String,
    pub service: String,
    pub env: String,
    pub min_severity: Severity,
}

impl Config {
    pub fn from_env() -> Self {
        let endpoint = env::var("LOGCORE_URL")
            .unwrap_or_else(|_| "https://logcore-dev-352942961463.us-east4.run.app".to_string())
            .trim()
            .trim_end_matches('/')
            .to_string();

        let api_key = env::var("LOGCORE_KEY").unwrap_or_default().trim().to_string();

        let enabled = match env::var("LOGCORE_ENABLED") {
            Ok(v) => {
                let v = v.trim().to_lowercase();
                v == "true" || v == "1" || v == "yes"
            }
            Err(_) => true,
        };

        let raw_service = env::var("LOGCORE_SERVICE").unwrap_or_else(|_| "realworld".to_string());
        let service = sanitize_service_name(&raw_service);

        let raw_env = env::var("LOGCORE_ENV").unwrap_or_else(|_| "dev".to_string());
        let env_name = sanitize_env_name(&raw_env);

        let min_severity = match env::var("LOGCORE_MIN_SEVERITY") {
            Ok(v) => Severity::from_str_loose(&v),
            Err(_) => Severity::Error,
        };

        Self {
            enabled,
            endpoint,
            api_key,
            service,
            env: env_name,
            min_severity,
        }
    }
}

fn sanitize_service_name(name: &str) -> String {
    let lower = name.trim().to_lowercase();
    let sanitized: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .take(63)
        .collect();

    if sanitized.is_empty() {
        "realworld".to_string()
    } else {
        sanitized
    }
}

fn sanitize_env_name(env_str: &str) -> String {
    match env_str.trim().to_lowercase().as_str() {
        "prod" | "production" => "prod".to_string(),
        "staging" => "staging".to_string(),
        "test" => "test".to_string(),
        "local" => "local".to_string(),
        _ => "dev".to_string(),
    }
}

struct State {
    config: Config,
    buffer: VecDeque<LogcoreEntry>,
    consecutive_failures: usize,
    last_flush: Instant,
}

static INIT_ONCE: Once = Once::new();
static WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<Option<State>> = Mutex::new(None);

fn get_or_init_state() -> &'static Mutex<Option<State>> {
    INIT_ONCE.call_once(|| {
        let config = Config::from_env();
        let mut lock = STATE.lock().unwrap();
        *lock = Some(State {
            config,
            buffer: VecDeque::with_capacity(MAX_BUFFER_SIZE),
            consecutive_failures: 0,
            last_flush: Instant::now(),
        });
    });
    &STATE
}

/// Start background flush worker thread if not already started.
pub fn ensure_worker_started() {
    get_or_init_state();

    if !WORKER_RUNNING.swap(true, Ordering::SeqCst) {
        thread::spawn(|| {
            loop {
                thread::sleep(Duration::from_millis(500));

                let should_flush = {
                    let lock = get_or_init_state().lock().unwrap();
                    if let Some(ref state) = *lock {
                        state.buffer.len() >= BATCH_FLUSH_THRESHOLD
                            || (!state.buffer.is_empty()
                                && state.last_flush.elapsed() >= FLUSH_INTERVAL)
                    } else {
                        false
                    }
                };

                if should_flush {
                    flush_batch();
                }
            }
        });
    }
}

/// Create a LogcoreEntry applying all clamping and deterministic insert_id generation rules.
pub fn build_entry(
    severity: Severity,
    message: &str,
    mut error: Option<ErrorInfo>,
    trace: Option<TraceContext>,
    labels: Option<HashMap<String, String>>,
    context: Option<serde_json::Value>,
) -> Option<LogcoreEntry> {
    let state_lock = get_or_init_state().lock().unwrap();
    let state = state_lock.as_ref()?;

    if !state.config.enabled || severity < state.config.min_severity {
        return None;
    }

    // Message clamp: <= 65,536 characters
    let clamped_message = if message.chars().count() > MAX_MESSAGE_LEN {
        message.chars().take(MAX_MESSAGE_LEN).collect()
    } else {
        message.to_string()
    };

    // Stack clamp: <= 50 frames
    if let Some(ref mut err) = error {
        if err.stack.len() > MAX_STACK_FRAMES {
            err.stack.truncate(MAX_STACK_FRAMES);
        }
    }

    // Labels clamp: <= 32 labels of <= 1024 characters
    let clamped_labels = labels.map(|map| {
        map.into_iter()
            .take(MAX_LABELS)
            .map(|(k, v)| {
                let k_clamp: String = if k.chars().count() > MAX_LABEL_LEN {
                    k.chars().take(MAX_LABEL_LEN).collect()
                } else {
                    k
                };
                let v_clamp: String = if v.chars().count() > MAX_LABEL_LEN {
                    v.chars().take(MAX_LABEL_LEN).collect()
                } else {
                    v
                };
                (k_clamp, v_clamp)
            })
            .collect()
    });

    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let service = state.config.service.clone();
    let env_name = state.config.env.clone();
    let canonical_context = context
        .as_ref()
        .and_then(|c| serde_json::to_string(c).ok())
        .unwrap_or_default();

    // Deterministic insert_id: sha256(timestamp | service | severity | message | canonical_json(context))[:32]
    let id_payload = format!(
        "{}|{}|{}|{}|{}",
        timestamp,
        service,
        severity.as_str(),
        clamped_message,
        canonical_context
    );
    let hash = sha256_hex(id_payload.as_bytes());
    let insert_id = hash[..32].to_string();

    Some(LogcoreEntry {
        timestamp,
        severity: severity.as_str().to_string(),
        message: clamped_message,
        service,
        env: env_name,
        insert_id,
        trace,
        error,
        labels: clamped_labels,
        context,
    })
}

/// Enqueue an entry into the transport buffer.
pub fn record_entry(entry: LogcoreEntry) {
    ensure_worker_started();

    let mut lock = get_or_init_state().lock().unwrap();
    if let Some(ref mut state) = *lock {
        // Circuit breaker check
        if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            state.buffer.clear();
            return;
        }

        // Drop oldest if buffer full
        if state.buffer.len() >= MAX_BUFFER_SIZE {
            state.buffer.pop_front();
        }
        state.buffer.push_back(entry);
    }
}

/// Internal batch flusher. Takes up to MAX_BATCH_SIZE entries and sends them via HTTP.
fn flush_batch() {
    let (batch, config) = {
        let mut lock = get_or_init_state().lock().unwrap();
        let state = match lock.as_mut() {
            Some(s) => s,
            None => return,
        };

        state.last_flush = Instant::now();

        if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            state.buffer.clear();
            return;
        }

        let count = std::cmp::min(state.buffer.len(), MAX_BATCH_SIZE);
        if count == 0 {
            return;
        }

        let mut batch = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(entry) = state.buffer.pop_front() {
                batch.push(entry);
            }
        }
        (batch, state.config.clone())
    };

    if batch.is_empty() {
        return;
    }

    let success = send_payload_with_retries(&config, &batch);

    let mut lock = get_or_init_state().lock().unwrap();
    if let Some(ref mut state) = *lock {
        if success {
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures += 1;
            if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                eprintln!(
                    "logcore: circuit breaker tripped after {} consecutive failures; discarding buffer",
                    state.consecutive_failures
                );
                state.buffer.clear();
            }
        }
    }
}

/// Send payload via HTTP POST with exponential backoff retries.
fn send_payload_with_retries(config: &Config, entries: &[LogcoreEntry]) -> bool {
    if !config.enabled || config.api_key.is_empty() {
        return true;
    }

    let envelope = LogcoreEnvelope {
        schema_version: 1,
        entries: entries.to_vec(),
    };

    let body = match serde_json::to_string(&envelope) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("logcore: failed to serialize envelope: {}", e);
            return false;
        }
    };

    let url = format!("{}/v1/logs", config.endpoint);

    // Retries: up to 3 retries with exponential backoff (250ms, 500ms, 1000ms)
    let backoffs = [
        Duration::from_millis(0),
        Duration::from_millis(250),
        Duration::from_millis(500),
        Duration::from_millis(1000),
    ];

    for (attempt, delay) in backoffs.iter().enumerate() {
        if attempt > 0 {
            thread::sleep(*delay);
        }

        let output = Command::new("curl")
            .arg("-s")
            .arg("-S")
            .arg("-w")
            .arg("\n%{http_code}")
            .arg("-X")
            .arg("POST")
            .arg(&url)
            .arg("-H")
            .arg(format!("x-api-key: {}", config.api_key))
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("--data-binary")
            .arg(&body)
            .arg("--max-time")
            .arg("10")
            .output();

        match output {
            Ok(out) => {
                let stdout_str = String::from_utf8_lossy(&out.stdout);
                let lines: Vec<&str> = stdout_str.trim_end().lines().collect();
                let status_code_str = lines.last().unwrap_or(&"0");
                let status_code: u16 = status_code_str.parse().unwrap_or(0);
                let response_body = if lines.len() > 1 {
                    lines[..lines.len() - 1].join("\n")
                } else {
                    String::new()
                };

                if status_code >= 200 && status_code < 300 {
                    return true;
                } else if status_code == 429 || status_code >= 500 {
                    // Transient failure, retry
                    continue;
                } else if status_code >= 400 && status_code < 500 {
                    // Permanent rejection (e.g. 400, 422, 401)
                    eprintln!(
                        "logcore permanent rejection ({}): {}",
                        status_code, response_body
                    );
                    return false;
                } else {
                    // Network or unknown status, retry
                    continue;
                }
            }
            Err(err) => {
                // Command execution failed, retry
                if attempt == backoffs.len() - 1 {
                    eprintln!("logcore: http delivery failed after retries: {}", err);
                }
                continue;
            }
        }
    }

    false
}

/// Synchronously flush all buffered log entries. Called on shutdown and by probe.
pub fn flush_sync() {
    let mut iterations = 0;
    while iterations < 10 {
        let has_more = {
            let lock = get_or_init_state().lock().unwrap();
            lock.as_ref().map(|s| !s.buffer.is_empty()).unwrap_or(false)
        };

        if !has_more {
            break;
        }

        flush_batch();
        iterations += 1;
    }
}
