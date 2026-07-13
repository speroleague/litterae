use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub argon2: Argon2Config,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default)]
    pub jmap: JmapConfig,
    #[serde(default)]
    pub submission: SubmissionConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub antispam: AntispamConfig,
    #[serde(default)]
    pub antivirus: AntivirusConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Primary domain this instance serves mail for.
    pub domain: String,
}

/// Inbound SMTP listener config (spec §8.1). TLS is always opportunistic
/// (STARTTLS) -- port 25 must never require it (spec §0 guardrails); if no
/// cert/key is configured, STARTTLS simply isn't advertised.
#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    #[serde(default = "default_smtp_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_smtp_max_message_size")]
    pub max_message_size: usize,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

fn default_smtp_listen_addr() -> String {
    "0.0.0.0:25".to_string()
}
fn default_smtp_max_message_size() -> usize {
    25 * 1024 * 1024
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_smtp_listen_addr(),
            max_message_size: default_smtp_max_message_size(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// HTTP listener config for the JMAP API (session resource, method-call
/// endpoint, SSE push) -- meant to run over TLS in production (spec §8.4).
/// Set `tls_cert_path`/`tls_key_path` to terminate TLS in-process, or leave
/// both unset to bind plaintext and terminate TLS at a reverse proxy
/// instead; the plaintext dev default (localhost-only) supports either.
#[derive(Debug, Clone, Deserialize)]
pub struct JmapConfig {
    #[serde(default = "default_jmap_listen_addr")]
    pub listen_addr: String,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

fn default_jmap_listen_addr() -> String {
    "127.0.0.1:8620".to_string()
}

impl Default for JmapConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_jmap_listen_addr(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Submission (587 STARTTLS / 465 implicit TLS) listener config. Unlike
/// inbound port 25, TLS is mandatory here -- both listeners refuse to
/// authenticate a session that isn't encrypted, so `tls_cert_path`/
/// `tls_key_path` are required for submission to function at all.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmissionConfig {
    #[serde(default = "default_submission_starttls_addr")]
    pub listen_addr_starttls: String,
    #[serde(default = "default_submission_implicit_addr")]
    pub listen_addr_implicit: String,
    #[serde(default = "default_smtp_max_message_size")]
    pub max_message_size: usize,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

fn default_submission_starttls_addr() -> String {
    "0.0.0.0:587".to_string()
}
fn default_submission_implicit_addr() -> String {
    "0.0.0.0:465".to_string()
}

impl Default for SubmissionConfig {
    fn default() -> Self {
        Self {
            listen_addr_starttls: default_submission_starttls_addr(),
            listen_addr_implicit: default_submission_implicit_addr(),
            max_message_size: default_smtp_max_message_size(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Bootstrap credentials for the first admin account, applied once on
/// startup if no admin exists yet in storage -- omit once you've logged in
/// and changed the password; re-adding this section after that point has
/// no effect (bootstrap only ever fires once, never resets an existing
/// admin's password).
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Localhost-only by default -- the admin API is meaningfully more
    /// sensitive than JMAP (it can create/delete mailboxes and domains),
    /// so exposing it beyond localhost is an explicit opt-in via config
    /// or a reverse proxy, not the default.
    #[serde(default = "default_admin_listen_addr")]
    pub listen_addr: String,
    /// Same in-process-vs-reverse-proxy choice as `JmapConfig` -- admin is
    /// the more sensitive of the two, so this matters even more once it's
    /// exposed beyond localhost.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

fn default_admin_listen_addr() -> String {
    "127.0.0.1:8621".to_string()
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            listen_addr: default_admin_listen_addr(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl AdminConfig {
    pub fn bootstrap_credentials(&self) -> Option<(&str, &str)> {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }
}

/// Optional rspamd integration for inbound spam scoring (spec §8.1). An
/// unset endpoint means scanning is skipped entirely -- no network calls
/// -- the same off-unless-configured idiom as TLS cert/key pairs above.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AntispamConfig {
    /// `/path/to/rspamd.sock` for a Unix socket, or `host:port` for TCP
    /// (rspamd's *normal* worker, e.g. `127.0.0.1:11333` -- not the
    /// controller port).
    pub endpoint: Option<String>,
}

impl AntispamConfig {
    pub fn is_enabled(&self) -> bool {
        self.endpoint.is_some()
    }
}

/// Optional clamd (ClamAV) integration for inbound malware scanning.
/// Same off-unless-configured idiom as `AntispamConfig`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AntivirusConfig {
    /// `/path/to/clamd.ctl` for a Unix socket, or `host:port` for TCP
    /// (clamd's `TCPSocket`, e.g. `127.0.0.1:3310`).
    pub endpoint: Option<String>,
}

impl AntivirusConfig {
    pub fn is_enabled(&self) -> bool {
        self.endpoint.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Directory containing content-addressed blobs.
    pub blob_dir: PathBuf,
    /// Path to the SQLite metadata database.
    pub sqlite_path: PathBuf,
}

/// Argon2id parameters for the unlock KDF (spec §3.5).
/// Floor: m = 64 MiB, t = 3, p = 4. Tune upward toward ~0.5-1.0s wall clock
/// for the target host; these are config keys, not hardcoded.
#[derive(Debug, Clone, Deserialize)]
pub struct Argon2Config {
    #[serde(default = "default_m_cost_kib")]
    pub m_cost_kib: u32,
    #[serde(default = "default_t_cost")]
    pub t_cost: u32,
    #[serde(default = "default_p_cost")]
    pub p_cost: u32,
}

fn default_m_cost_kib() -> u32 {
    64 * 1024
}
fn default_t_cost() -> u32 {
    3
}
fn default_p_cost() -> u32 {
    4
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost_kib: default_m_cost_kib(),
            t_cost: default_t_cost(),
            p_cost: default_p_cost(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        toml::from_str(&raw).map_err(|e| Error::Config(e.to_string()))
    }
}
