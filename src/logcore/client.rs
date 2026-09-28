//! Logcore HTTP transport client with background batching, retries, circuit breaker, and clamps.

use super::types::{LogcoreEntry, RequestEnvelope};
use std::collections::VecDeque;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

const MAX_BUFFER_CAPACITY: usize = 1000;
const BATCH_FLUSH_SIZE: usize = 20;
const MAX_BATCH_SIZE: usize = 200;
const FLUSH_INTERVAL_SECS: u64 = 5;
const MAX_RETRIES: u32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 10;
const MAX_MESSAGE_LEN: usize = 65536;
const MAX_LABELS_COUNT: usize = 32;
const MAX_LABEL_LEN: usize = 1024;
const MAX_STACK_FRAMES: usize = 50;

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub api_key: String,
    pub enabled: bool,
    pub service: String,
    pub env: String,
    pub min_severity: String,
}

impl Config {
    pub fn from_env() -> Self {
        let url = env::var("LOGCORE_URL")
            .unwrap_or_else(|_| "https://logcore-dev-352942961463.us-east4.run.app".to_string());
        let api_key = env::var("LOGCORE_KEY").unwrap_or_default();
        let enabled_str = env::var("LOGCORE_ENABLED").unwrap_or_else(|_| "true".to_string());
        let enabled = !enabled_str.eq_ignore_ascii_case("false")
            && enabled_str != "0"
            && !api_key.is_empty();

        let service = env::var("LOGCORE_SERVICE").unwrap_or_else(|_| "realworld".to_string());
        let env_name = env::var("LOGCORE_ENV").unwrap_or_else(|_| "dev".to_string());
        let min_severity = env::var("LOGCORE_MIN_SEVERITY").unwrap_or_else(|_| "ERROR".to_string());

        Self {
            url,
            api_key,
            enabled,
            service,
            env: env_name,
            min_severity,
        }
    }
}

pub struct LogcoreClient {
    config: Config,
    queue: Arc<Mutex<VecDeque<LogcoreEntry>>>,
    condvar: Arc<Condvar>,
    shutdown: Arc<AtomicBool>,
    consecutive_failures: Arc<AtomicU32>,
}

static mut GLOBAL_CLIENT: Option<LogcoreClient> = None;
static INIT_ONCE: Once = Once::new();

pub fn get_client() -> &'static LogcoreClient {
    unsafe {
        INIT_ONCE.call_once(|| {
            GLOBAL_CLIENT = Some(LogcoreClient::new(Config::from_env()));
        });
        GLOBAL_CLIENT.as_ref().unwrap()
    }
}

impl LogcoreClient {
    pub fn new(config: Config) -> Self {
        let queue = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BUFFER_CAPACITY)));
        let condvar = Arc::new(Condvar::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let consecutive_failures = Arc::new(AtomicU32::new(0));

        let client = Self {
            config: config.clone(),
            queue: queue.clone(),
            condvar: condvar.clone(),
            shutdown: shutdown.clone(),
            consecutive_failures: consecutive_failures.clone(),
        };

        if config.enabled {
            let q = queue;
            let cv = condvar;
            let sd = shutdown;
            let cf = consecutive_failures;
            let cfg = config;

            thread::Builder::new()
                .name("logcore-worker".to_string())
                .spawn(move || {
                    worker_loop(cfg, q, cv, sd, cf);
                })
                .ok();
        }

        client
    }

    /// Enqueue a log entry for delivery off the calling thread.
    pub fn enqueue(&self, mut entry: LogcoreEntry) {
        // Enforce severity floor
        if !self.is_severity_allowed(&entry.severity) {
            return;
        }

        // Apply field clamps
        clamp_entry(&mut entry);

        // Fill defaults if missing
        if entry.service.is_none() {
            entry.service = Some(self.config.service.clone());
        }
        if entry.env.is_none() {
            entry.env = Some(self.config.env.clone());
        }

        if let Ok(mut q) = self.queue.lock() {
            // Buffer capacity cap: drop oldest if buffer is full
            while q.len() >= MAX_BUFFER_CAPACITY {
                q.pop_front();
            }
            q.push_back(entry);
            let len = q.len();
            if len >= BATCH_FLUSH_SIZE {
                self.condvar.notify_one();
            }
        }
    }

    /// Flush all queued entries immediately (used during graceful shutdown or tests).
    pub fn flush(&self) {
        let mut entries = Vec::new();
        if let Ok(mut q) = self.queue.lock() {
            while let Some(item) = q.pop_front() {
                entries.push(item);
                if entries.len() >= MAX_BATCH_SIZE {
                    break;
                }
            }
        }

        if !entries.is_empty() && self.config.enabled {
            let _ = send_batch(&self.config, entries, &self.consecutive_failures);
        }
    }

    fn is_severity_allowed(&self, severity: &str) -> bool {
        let level_score = |s: &str| match s.to_uppercase().as_str() {
            "TRACE" | "DEBUG" => 10,
            "INFO" => 20,
            "WARN" | "WARNING" => 30,
            "ERROR" => 40,
            "FATAL" | "CRITICAL" => 50,
            _ => 40,
        };
        level_score(severity) >= level_score(&self.config.min_severity)
    }
}

impl Drop for LogcoreClient {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.condvar.notify_all();
        self.flush();
    }
}

fn worker_loop(
    config: Config,
    queue: Arc<Mutex<VecDeque<LogcoreEntry>>>,
    condvar: Arc<Condvar>,
    shutdown: Arc<AtomicBool>,
    consecutive_failures: Arc<AtomicU32>,
) {
    let mut last_flush = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        let mut batch = Vec::new();

        if let Ok(mut q) = queue.lock() {
            let should_flush_time = last_flush.elapsed() >= Duration::from_secs(FLUSH_INTERVAL_SECS);
            let has_enough_items = q.len() >= BATCH_FLUSH_SIZE;

            if !has_enough_items && !should_flush_time && !q.is_empty() {
                let remaining = Duration::from_secs(FLUSH_INTERVAL_SECS)
                    .saturating_sub(last_flush.elapsed());
                if let Ok((lock, _)) = condvar.wait_timeout(q, remaining) {
                    q = lock;
                } else {
                    continue;
                }
            } else if q.is_empty() {
                if let Ok((lock, _)) = condvar.wait_timeout(q, Duration::from_secs(FLUSH_INTERVAL_SECS)) {
                    q = lock;
                } else {
                    continue;
                }
            }

            while let Some(item) = q.pop_front() {
                batch.push(item);
                if batch.len() >= MAX_BATCH_SIZE {
                    break;
                }
            }
        }

        if !batch.is_empty() {
            last_flush = Instant::now();
            let _ = send_batch(&config, batch, &consecutive_failures);
        }
    }
}

fn clamp_entry(entry: &mut LogcoreEntry) {
    // Message clamp
    if entry.message.len() > MAX_MESSAGE_LEN {
        entry.message.truncate(MAX_MESSAGE_LEN - 3);
        entry.message.push_str("...");
    }

    // Labels clamp
    if let Some(labels) = &mut entry.labels {
        if labels.len() > MAX_LABELS_COUNT {
            let keys_to_remove: Vec<String> = labels.keys().skip(MAX_LABELS_COUNT).cloned().collect();
            for k in keys_to_remove {
                labels.remove(&k);
            }
        }
        for (_, val) in labels.iter_mut() {
            if val.len() > MAX_LABEL_LEN {
                val.truncate(MAX_LABEL_LEN);
            }
        }
    }

    // Stack frames clamp
    if let Some(error) = &mut entry.error {
        if let Some(stack) = &mut error.stack {
            if stack.len() > MAX_STACK_FRAMES {
                stack.truncate(MAX_STACK_FRAMES);
            }
        }
    }
}

fn send_batch(
    config: &Config,
    entries: Vec<LogcoreEntry>,
    consecutive_failures: &AtomicU32,
) -> Result<(), ()> {
    if entries.is_empty() || config.api_key.is_empty() {
        return Ok(());
    }

    // Circuit breaker check
    if consecutive_failures.load(Ordering::Relaxed) >= CIRCUIT_BREAKER_THRESHOLD {
        eprintln!("[logcore] circuit breaker open: discarding batch due to consecutive delivery failures");
        return Err(());
    }

    let envelope = RequestEnvelope {
        schema_version: 1,
        entries,
    };

    let payload = match serde_json::to_string(&envelope) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[logcore] failed to serialize envelope: {}", e);
            return Err(());
        }
    };

    let mut attempt = 0;
    loop {
        match post_envelope(&config.url, &config.api_key, &payload) {
            Ok(status) if (200..300).contains(&status) => {
                consecutive_failures.store(0, Ordering::Relaxed);
                return Ok(());
            }
            Ok(status) if status == 429 || status >= 500 => {
                // Retryable server or rate limit error
                attempt += 1;
                if attempt > MAX_RETRIES {
                    consecutive_failures.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[logcore] delivery failed after retries: HTTP {}", status);
                    return Err(());
                }
                let backoff_ms = 250 * (1 << (attempt - 1));
                thread::sleep(Duration::from_millis(backoff_ms));
            }
            Ok(status) => {
                // Permanent 4xx client error: do NOT retry, log reason to stderr
                consecutive_failures.fetch_add(1, Ordering::Relaxed);
                eprintln!("[logcore] batch rejected by gateway: HTTP {}", status);
                return Err(());
            }
            Err(err) => {
                // Network / transport error: retry
                attempt += 1;
                if attempt > MAX_RETRIES {
                    consecutive_failures.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[logcore] transport error after retries: {}", err);
                    return Err(());
                }
                let backoff_ms = 250 * (1 << (attempt - 1));
                thread::sleep(Duration::from_millis(backoff_ms));
            }
        }
    }
}

/// Send raw HTTP POST request to endpoint. Supports HTTPS via OpenSSL or plain HTTP via TCP.
pub fn post_envelope(endpoint_url: &str, api_key: &str, payload: &str) -> Result<u16, String> {
    let (is_https, host, port, path) = parse_url(endpoint_url)?;

    let request_path = if path.is_empty() || path == "/" {
        "/v1/logs"
    } else if path.ends_with("/v1/logs") {
        &path
    } else {
        "/v1/logs"
    };

    let http_request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: logcore-rust/1.0\r\n\
         Content-Type: application/json\r\n\
         x-api-key: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        request_path,
        host,
        api_key,
        payload.len(),
        payload
    );

    if is_https {
        send_https_openssl(&host, port, &http_request)
    } else {
        send_http_plain(&host, port, &http_request)
    }
}

fn parse_url(url: &str) -> Result<(bool, String, u16, String), String> {
    let (is_https, rest) = if let Some(stripped) = url.strip_prefix("https://") {
        (true, stripped)
    } else if let Some(stripped) = url.strip_prefix("http://") {
        (false, stripped)
    } else {
        (true, url)
    };

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/v1/logs".to_string()),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let h = &host_port[..idx];
            let p = host_port[idx + 1..]
                .parse::<u16>()
                .map_err(|e| format!("Invalid port in url: {}", e))?;
            (h.to_string(), p)
        }
        None => (host_port.to_string(), if is_https { 443 } else { 80 }),
    };

    Ok((is_https, host, port, path))
}

fn send_https_openssl(host: &str, port: u16, http_request: &str) -> Result<u16, String> {
    let target = format!("{}:{}", host, port);

    let mut child = Command::new("openssl")
        .args(&[
            "s_client",
            "-connect",
            &target,
            "-servername",
            host,
            "-ign_eof",
            "-quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn openssl s_client: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(http_request.as_bytes())
            .map_err(|e| format!("failed to write to openssl stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait on openssl: {}", e))?;

    let response_str = String::from_utf8_lossy(&output.stdout);
    parse_http_status(&response_str)
}

fn send_http_plain(host: &str, port: u16, http_request: &str) -> Result<u16, String> {
    let target = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&target)
        .map_err(|e| format!("failed to connect to {}: {}", target, e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    stream
        .write_all(http_request.as_bytes())
        .map_err(|e| format!("failed to write HTTP request: {}", e))?;

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .map_err(|e| format!("failed to read HTTP response: {}", e))?;

    let response_str = String::from_utf8_lossy(&response_buf);
    parse_http_status(&response_str)
}

fn parse_http_status(response: &str) -> Result<u16, String> {
    for line in response.lines() {
        if line.starts_with("HTTP/1.") || line.starts_with("HTTP/2") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].parse::<u16>() {
                    return Ok(code);
                }
            }
        }
    }
    Err("Could not parse HTTP status code from response".to_string())
}
