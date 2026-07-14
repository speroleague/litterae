//! Content scanning for inbound mail (spec §8.1): spam scoring via a
//! locally-running rspamd, malware scanning via clamd. Both are optional
//! and independently skipped (zero network calls) if not configured, and
//! both fail *open* on a connect/timeout/protocol error -- a crashed
//! scanner degrades to "content unscanned," not "inbound mail stops."
//! That's a deliberate availability-over-strictness choice for a
//! single-operator server; see `Scanner::scan`'s doc comment.

pub mod clamav;
pub mod endpoint;
pub mod rspamd;

use std::net::IpAddr;
use std::time::Duration;

use common::config::{AntispamConfig, AntivirusConfig};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Scanner {
    rspamd: Option<rspamd::RspamdClient>,
    clamav: Option<clamav::ClamavClient>,
    timeout: Duration,
}

pub struct ScanRequest<'a> {
    pub remote_ip: IpAddr,
    pub helo: &'a str,
    pub mail_from: &'a str,
    pub rcpt_to: &'a [String],
    pub raw_message: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// rspamd add-header/rewrite-subject: deliver, but route to Junk.
    Spam { reason: String },
    /// rspamd soft-reject/greylist: SMTP 4xx, sender should retry later.
    Defer { reason: String },
    /// rspamd reject, OR any ClamAV `FOUND`: SMTP 5xx, never delivered.
    Reject { reason: String },
}

pub struct ScanResult {
    pub verdict: Verdict,
    /// Fail-open events worth a warn-log + audit entry even though the
    /// message was still let through unscored by that backend.
    pub warnings: Vec<String>,
    /// rspamd's raw score, independent of `verdict` -- e.g. still `Some`
    /// for a `Clean`/`NoAction` message, so a client can show "scored
    /// 1.2/6.0" even when nothing enforcement-worthy happened. `None` if
    /// rspamd isn't configured or was unreachable this message.
    pub spam_score: Option<f64>,
    /// `Some(true)` = clamd scanned and found nothing, `Some(false)` =
    /// clamd found something (mirrors a `Reject` verdict in that case),
    /// `None` = not configured or unreachable this message.
    pub av_clean: Option<bool>,
}

impl Scanner {
    pub fn new(rspamd: Option<rspamd::RspamdClient>, clamav: Option<clamav::ClamavClient>) -> Self {
        Self { rspamd, clamav, timeout: DEFAULT_TIMEOUT }
    }

    pub fn from_config(antispam: &AntispamConfig, antivirus: &AntivirusConfig) -> Self {
        Self::new(
            antispam.endpoint.as_deref().map(rspamd::RspamdClient::new),
            antivirus.endpoint.as_deref().map(clamav::ClamavClient::new),
        )
    }

    /// Overrides the default per-backend timeout (used by tests to avoid
    /// waiting out the real default against an unreachable scanner; also
    /// available to any future caller that wants a tighter/looser bound
    /// than `DEFAULT_TIMEOUT`).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Runs both configured scanners concurrently (they're independent
    /// classifiers over the same bytes) and combines their verdicts:
    /// ClamAV `Found` always wins outright; otherwise rspamd's own
    /// `action` field drives the outcome (litterae doesn't re-implement
    /// threshold logic -- rspamd already decided what its score means).
    /// A backend that's unreachable or times out contributes a warning
    /// and is treated as absent for this message, never as a rejection.
    pub async fn scan(&self, req: &ScanRequest<'_>) -> ScanResult {
        let (rspamd_result, clamav_result) = tokio::join!(self.run_rspamd(req), self.run_clamav(req.raw_message));

        let mut warnings = Vec::new();

        let av_clean = match &clamav_result {
            Some(Ok(clamav::ClamavVerdict::Clean)) => Some(true),
            Some(Ok(clamav::ClamavVerdict::Found(_))) => Some(false),
            Some(Err(e)) => {
                warnings.push(format!("clamav unreachable: {e}"));
                None
            }
            None => None,
        };

        if let Some(Ok(clamav::ClamavVerdict::Found(sig))) = &clamav_result {
            return ScanResult {
                verdict: Verdict::Reject { reason: format!("malware detected: {sig}") },
                warnings,
                spam_score: None,
                av_clean,
            };
        }

        let rspamd_verdict = match rspamd_result {
            Some(Ok(v)) => Some(v),
            Some(Err(e)) => {
                warnings.push(format!("rspamd unreachable: {e}"));
                None
            }
            None => None,
        };
        let spam_score = rspamd_verdict.as_ref().map(|v| v.score);

        let verdict = match rspamd_verdict {
            None => Verdict::Clean,
            Some(v) => match v.action {
                rspamd::RspamdAction::Reject => Verdict::Reject {
                    reason: format!("rspamd reject (score {:.1}/{:.1})", v.score, v.required_score),
                },
                rspamd::RspamdAction::SoftReject | rspamd::RspamdAction::Greylist => Verdict::Defer {
                    reason: format!("rspamd {:?} (score {:.1}/{:.1})", v.action, v.score, v.required_score),
                },
                rspamd::RspamdAction::AddHeader | rspamd::RspamdAction::RewriteSubject => Verdict::Spam {
                    reason: format!("rspamd {:?} (score {:.1}/{:.1})", v.action, v.score, v.required_score),
                },
                rspamd::RspamdAction::NoAction => Verdict::Clean,
                rspamd::RspamdAction::Unknown(ref s) => {
                    warnings.push(format!("rspamd: unrecognized action {s:?}, treating as no action"));
                    Verdict::Clean
                }
            },
        };

        ScanResult { verdict, warnings, spam_score, av_clean }
    }

    async fn run_rspamd(&self, req: &ScanRequest<'_>) -> Option<common::Result<rspamd::RspamdVerdict>> {
        let client = self.rspamd.as_ref()?;
        let check_req = rspamd::CheckRequest {
            remote_ip: req.remote_ip,
            helo: req.helo,
            mail_from: req.mail_from,
            rcpt_to: req.rcpt_to,
            raw_message: req.raw_message,
        };
        Some(match tokio::time::timeout(self.timeout, client.check(&check_req)).await {
            Ok(r) => r,
            Err(_) => Err(common::Error::Network("rspamd check timed out".into())),
        })
    }

    async fn run_clamav(&self, raw: &[u8]) -> Option<common::Result<clamav::ClamavVerdict>> {
        let client = self.clamav.as_ref()?;
        Some(match tokio::time::timeout(self.timeout, client.scan(raw)).await {
            Ok(r) => r,
            Err(_) => Err(common::Error::Network("clamd scan timed out".into())),
        })
    }
}
