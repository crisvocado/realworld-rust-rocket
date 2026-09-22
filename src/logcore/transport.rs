use crate::logcore::entry::{LogEntry, RequestEnvelope, Severity};
use std::collections::VecDeque;
use std::env;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Configuration for logcore client and transport.
#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub url: String,
    pub key: String,
    pub service: String,
    pub env: String,
    pub min_severity: Severity,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    pub fn from_env() -> Self {
        let key = env::var("LOGCORE_KEY").unwrap_or_default();
        let enabled = match env::var("LOGCORE_ENABLED") {
            Ok(v) => {
                let s = v.trim().to_lowercase();
                s != "false" && s != "0" && s != "no"
            }
            Err(_) => !key.is_empty(),
        };

        let url = env::var("LOGCORE_URL")
            .unwrap_or_else(|_| "https://logcore-dev-352942961463.us-east4.run.app".to_string());

        let service_raw = env::var("LOGCORE_SERVICE").unwrap_or_else(|_| "realworld".to_string());
        let service = sanitize_service_name(&service_raw);

        let env_raw = env::var("LOGCORE_ENV").unwrap_or_else(|_| "dev".to_string());
        let env_name = normalize_env(&env_raw);

        let min_sev_raw = env::var("LOGCORE_MIN_SEVERITY").unwrap_or_else(|_| "ERROR".to_string());
        let min_severity = Severity::from_str(&min_sev_raw);

        Self {
            enabled,
            url,
            key,
            service,
            env: env_name,
            min_severity,
        }
    }
}

fn sanitize_service_name(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    let sanitized: String = lower
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = sanitized.trim_matches(|c| c == '.' || c == '_' || c == '-');
    if trimmed.is_empty() {
        "realworld".to_string()
    } else if trimmed.len() > 63 {
        trimmed[..63].to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_env(raw: &str) -> String {
    match raw.trim().to_lowercase().as_str() {
        "production" | "prod" => "prod".to_string(),
        "staging" | "stage" => "staging".to_string(),
        "test" | "testing" => "test".to_string(),
        "local" => "local".to_string(),
        _ => "dev".to_string(),
    }
}

pub type TestHook = Arc<dyn Fn(&RequestEnvelope) + Send + Sync>;

struct SharedState {
    buffer: VecDeque<LogEntry>,
    consecutive_failures: usize,
    shutdown: bool,
    flush_requested: bool,
    test_hook: Option<TestHook>,
}

pub struct Transport {
    config: Config,
    state: Arc<(Mutex<SharedState>, Condvar)>,
    initialized: AtomicBool,
}

static mut TRANSPORT: Option<Transport> = None;
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

pub fn get_transport() -> &'static Transport {
    unsafe {
        INIT_ONCE.call_once(|| {
            let config = Config::from_env();
            let state = Arc::new((
                Mutex::new(SharedState {
                    buffer: VecDeque::with_capacity(1000),
                    consecutive_failures: 0,
                    shutdown: false,
                    flush_requested: false,
                    test_hook: None,
                }),
                Condvar::new(),
            ));

            let transport = Transport {
                config,
                state,
                initialized: AtomicBool::new(false),
            };

            transport.start_worker();
            TRANSPORT = Some(transport);
        });

        TRANSPORT.as_ref().unwrap()
    }
}

pub fn get_config() -> Config {
    get_transport().config.clone()
}

pub fn set_test_hook(hook: Option<TestHook>) {
    let transport = get_transport();
    let (lock, _) = &*transport.state;
    let mut state = lock.lock().unwrap();
    state.test_hook = hook;
}

impl Transport {
    fn start_worker(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return;
        }

        let state_clone = Arc::clone(&self.state);
        let config = self.config.clone();

        thread::Builder::new()
            .name("logcore-transport".into())
            .spawn(move || {
                worker_loop(state_clone, config);
            })
            .ok();
    }

    /// Enqueue a log entry without blocking the caller.
    pub fn enqueue(&self, entry: LogEntry) {
        let entry_sev = Severity::from_str(&entry.severity);
        if !entry_sev.is_at_least(self.config.min_severity) {
            return;
        }

        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();

        // Circuit breaker: after 10 consecutive failures, empty buffer and drop
        if state.consecutive_failures >= 10 {
            state.buffer.clear();
            return;
        }

        // Buffer cap: 1000 items, drop oldest on overflow
        if state.buffer.len() >= 1000 {
            state.buffer.pop_front();
        }

        state.buffer.push_back(entry);

        // Wake worker if batch size threshold reached
        if state.buffer.len() >= 20 {
            cvar.notify_one();
        }
    }

    /// Flush all buffered entries synchronously (e.g. during shutdown).
    pub fn flush(&self) {
        let (lock, cvar) = &*self.state;
        {
            let mut state = lock.lock().unwrap();
            state.flush_requested = true;
            cvar.notify_one();
        }

        // Wait briefly for worker to drain
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(1500) {
            let state = lock.lock().unwrap();
            if state.buffer.is_empty() {
                break;
            }
            drop(state);
            thread::sleep(Duration::from_millis(50));
        }
    }
}

fn worker_loop(state_arc: Arc<(Mutex<SharedState>, Condvar)>, config: Config) {
    let (lock, cvar) = &*state_arc;
    let mut last_flush = Instant::now();

    loop {
        let mut state = lock.lock().unwrap();

        // Wait up to 5s or until notified
        let wait_time = Duration::from_secs(5).saturating_sub(last_flush.elapsed());
        if state.buffer.len() < 20 && !state.shutdown && !state.flush_requested {
            state = cvar.wait_timeout(state, wait_time).unwrap().0;
        }

        state.flush_requested = false;

        if state.buffer.is_empty() {
            if state.shutdown {
                break;
            }
            last_flush = Instant::now();
            continue;
        }

        // Drain up to 200 entries for batch delivery
        let batch_size = state.buffer.len().min(200);
        let entries: Vec<LogEntry> = state.buffer.drain(0..batch_size).collect();
        let test_hook = state.test_hook.clone();
        drop(state);

        let envelope = RequestEnvelope {
            schema_version: 1,
            entries,
        };

        // If test hook is installed, dispatch to test hook
        if let Some(ref hook) = test_hook {
            hook(&envelope);
            last_flush = Instant::now();
            continue;
        }

        // Deliver via HTTP if enabled
        if config.enabled && !config.key.is_empty() {
            let success = deliver_batch_with_retry(&envelope, &config);
            let mut state = lock.lock().unwrap();
            if success {
                state.consecutive_failures = 0;
            } else {
                state.consecutive_failures += 1;
                if state.consecutive_failures >= 10 {
                    state.buffer.clear();
                    eprintln!("[logcore] Circuit breaker tripped after 10 consecutive failures. Dropping buffer.");
                }
            }
        }

        last_flush = Instant::now();
    }
}

fn deliver_batch_with_retry(envelope: &RequestEnvelope, config: &Config) -> bool {
    let body = match serde_json::to_string(envelope) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[logcore] Failed to serialize request envelope: {}", e);
            return false;
        }
    };

    let url = config.url.trim_end_matches('/');
    let api_key = &config.key;

    for attempt in 0..3 {
        if attempt > 0 {
            // Exponential backoff: 2^attempt * 250ms (250ms, 500ms, 1000ms)
            let backoff_ms = (1 << attempt) * 250;
            thread::sleep(Duration::from_millis(backoff_ms));
        }

        match execute_curl_post(url, api_key, &body) {
            Ok((status_code, resp_body)) => {
                if (200..=299).contains(&status_code) {
                    return true;
                } else if status_code == 429 || status_code >= 500 {
                    // Transient error, retry
                    continue;
                } else {
                    // Permanent 4xx error (400, 401, 403, 422, etc.)
                    // Echo server reason to stderr and do not retry
                    eprintln!(
                        "[logcore] Permanent rejection (HTTP {}): {}",
                        status_code, resp_body
                    );
                    return false;
                }
            }
            Err(err) => {
                // Network error, retry
                if attempt == 2 {
                    eprintln!("[logcore] Network delivery failed after 3 attempts: {}", err);
                }
            }
        }
    }

    false
}

fn execute_curl_post(url: &str, api_key: &str, body: &str) -> Result<(u16, String), String> {
    let full_url = format!("{}/v1/logs", url);
    let mut child = Command::new("curl")
        .arg("-s")
        .arg("-S")
        .arg("--max-time")
        .arg("10")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg(format!("x-api-key: {}", api_key))
        .arg("--data-binary")
        .arg("@-")
        .arg("-w")
        .arg("\n%{http_code}")
        .arg(&full_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body.as_bytes());
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for curl: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<&str> = stdout.lines().collect();
    let status_code_str = lines.pop().unwrap_or("0");
    let status_code: u16 = status_code_str.trim().parse().unwrap_or(0);
    let resp_body = lines.join("\n");

    if !output.status.success() && status_code == 0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl error: {}", stderr));
    }

    Ok((status_code, resp_body))
}
