//! The outbound worker: claims due recipients, connects to their MX,
//! sends, classifies the result, and commits the next state. One
//! connection per (message, destination domain) -- recipients of the same
//! message at the same domain share a connection; different domains (even
//! for the same message) get separate connections.
//!
//! DSNs are generated per recipient as it reaches a terminal failure,
//! rather than batched across an entire message's recipient set -- a
//! message that fails to two different domains at two different times
//! produces two DSN emails, not one combined one. Combining them would
//! need to wait until every recipient of a message is terminal, which
//! trades correctness (a fast bounce staying fast) for tidiness.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mail_send::smtp::message::Parameters;
use mail_send::{SmtpClient, SmtpClientBuilder};
use rusqlite::OptionalExtension;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use auth::AuthStore;
use delivery::{AuthResults, InboundEnvelope, RecipientAccount};
use dns::Resolver;
use store::{BlobStore, MetadataStore, ROLE_DRAFTS, ROLE_SENT};

use crate::backoff::{next_delay_secs, DELAYED_DSN_THRESHOLD_SECS};
use crate::classify::{classify_connect_failure, classify_send_result, Outcome};
use crate::dsn::{build_dsn, DsnAction, DsnInput, FailedRecipient};
use crate::scheduled::{ScheduledKind, StoredScheduledEvent};
use crate::schema::QueueStore;
use crate::types::RcptState;

/// JMAP keyword hiding a message until its snooze fires (spec §8.6) --
/// defined here rather than in `store` (cf. `store::KEYWORD_DRAFT`) since
/// only this worker and `jmap::api::email_set` ever touch it.
pub const KEYWORD_SNOOZED: &str = "$snoozed";
/// Set when a `followup_nudge` fires with no reply seen in the thread.
pub const KEYWORD_NUDGE: &str = "$nudge";

const BATCH_SIZE: i64 = 100;
const IDLE_FLOOR: Duration = Duration::from_secs(30);
const LEASE_TTL_SECS: i64 = 300;
const COOLDOWN_SECS: u64 = 60;
const WORKER_ID: &str = "worker-1";

pub struct Worker {
    queue: QueueStore,
    blobs: BlobStore,
    metadata: MetadataStore,
    auth_store: AuthStore,
    audit: Arc<audit::AuditStore>,
    resolver: Resolver,
    hostname: String,
    cooldowns: Mutex<HashMap<String, Instant>>,
    notifier: Arc<common::changes::ChangeNotifier>,
}

#[derive(Debug, Clone)]
struct ClaimedRcpt {
    id: i64,
    rcpt_to: String,
    domain: String,
    dsn_notify: String,
    attempts: i64,
    delayed_dsn_sent: bool,
}

struct OutboundRow {
    id: i64,
    message_blob: String,
    envelope_from: String,
    is_dsn: bool,
    created_at: i64,
    expires_at: i64,
    account_id: i64,
}

enum Connected {
    Tls(Box<SmtpClient<TlsStream<TcpStream>>>),
    Plain(SmtpClient<TcpStream>),
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue: QueueStore,
        blobs: BlobStore,
        metadata: MetadataStore,
        auth_store: AuthStore,
        audit: Arc<audit::AuditStore>,
        resolver: Resolver,
        hostname: String,
        notifier: Arc<common::changes::ChangeNotifier>,
    ) -> Self {
        Self {
            queue,
            blobs,
            metadata,
            auth_store,
            audit,
            resolver,
            hostname,
            cooldowns: Mutex::new(HashMap::new()),
            notifier,
        }
    }

    pub async fn run(&self) {
        loop {
            self.reap_stale_claims();
            self.expire_overdue();
            self.fire_due_scheduled_events();

            let claimed = self.claim_batch(now_unix(), BATCH_SIZE);
            if claimed.is_empty() {
                tokio::time::sleep(IDLE_FLOOR).await;
                continue;
            }

            let mut units: HashMap<(i64, String), Vec<ClaimedRcpt>> = HashMap::new();
            for (outbound_id, rcpt) in claimed {
                units
                    .entry((outbound_id, rcpt.domain.clone()))
                    .or_default()
                    .push(rcpt);
            }

            for ((outbound_id, domain), rcpts) in units {
                if self.is_cooling_down(&domain) {
                    self.release_to_ready(&rcpts);
                    continue;
                }
                self.send_unit(outbound_id, &domain, &rcpts).await;
            }
        }
    }

    fn claim_batch(&self, now: i64, limit: i64) -> Vec<(i64, ClaimedRcpt)> {
        let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "UPDATE outbound_rcpt SET state = 'claimed', claimed_by = ?1, claimed_at = ?2
                 WHERE id IN (
                    SELECT id FROM outbound_rcpt
                    WHERE state IN ('ready', 'deferred') AND next_attempt_at <= ?2
                    ORDER BY next_attempt_at
                    LIMIT ?3
                 )
                 RETURNING id, outbound_id, rcpt_to, domain, dsn_notify, attempts, delayed_dsn_sent",
            )
            .expect("valid SQL");
        let rows = stmt
            .query_map(rusqlite::params![WORKER_ID, now, limit], |row| {
                let outbound_id: i64 = row.get(1)?;
                Ok((
                    outbound_id,
                    ClaimedRcpt {
                        id: row.get(0)?,
                        rcpt_to: row.get(2)?,
                        domain: row.get(3)?,
                        dsn_notify: row.get(4)?,
                        attempts: row.get(5)?,
                        delayed_dsn_sent: row.get::<_, i64>(6)? != 0,
                    },
                ))
            })
            .expect("valid query");
        rows.filter_map(|r| r.ok()).collect()
    }

    fn reap_stale_claims(&self) {
        let now = now_unix();
        let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
        let _ = conn.execute(
            "UPDATE outbound_rcpt SET state = 'ready', claimed_by = NULL
             WHERE state = 'claimed' AND claimed_at < ?1",
            (now - LEASE_TTL_SECS,),
        );
    }

    fn expire_overdue(&self) {
        let now = now_unix();
        let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
        let _ = conn.execute(
            "UPDATE outbound_rcpt SET state = 'expired'
             WHERE state IN ('ready', 'deferred')
             AND outbound_id IN (SELECT id FROM outbound WHERE expires_at < ?1)",
            (now,),
        );
    }

    /// A.6 step 2: cheap, done inline in the main loop rather than farmed
    /// out to the send-task pool -- neither snooze-resurface nor
    /// followup-nudge touches the network.
    fn fire_due_scheduled_events(&self) {
        let due = match self.queue.due_scheduled_events(now_unix()) {
            Ok(due) => due,
            Err(e) => {
                tracing::error!(error = %e, "failed to load due scheduled events");
                return;
            }
        };
        for ev in due {
            match ScheduledKind::from_db_str(&ev.kind) {
                Some(ScheduledKind::SnoozeResurface) => self.fire_snooze_resurface(&ev),
                Some(ScheduledKind::FollowupNudge) => self.fire_followup_nudge(&ev),
                // "remind" has no v1 UI hooked up to create it yet, and an
                // unrecognized kind shouldn't loop forever re-firing --
                // both just get marked fired with no side effect.
                _ => {
                    let _ = self.queue.mark_event_fired(ev.id);
                }
            }
        }
    }

    fn scheduled_message_row_id(ev: &StoredScheduledEvent) -> Option<i64> {
        ev.payload.as_deref()?.strip_prefix('m')?.parse().ok()
    }

    /// Clears the hiding keyword and pushes an SSE nudge -- resurfacing is
    /// exactly "the message was hidden until now" per spec §8.6, so there's
    /// nothing else to reverse.
    fn fire_snooze_resurface(&self, ev: &StoredScheduledEvent) {
        if let Some(row_id) = Self::scheduled_message_row_id(ev) {
            if let Ok(Some(msg)) = self.metadata.get_message(row_id) {
                let kept: Vec<&str> = msg
                    .keywords
                    .split(',')
                    .filter(|k| !k.is_empty() && *k != KEYWORD_SNOOZED)
                    .collect();
                let _ = self
                    .metadata
                    .update_message(row_id, None, Some(&kept.join(",")));
                self.notifier.notify(ev.account_id);
            }
        }
        let _ = self.queue.mark_event_fired(ev.id);
    }

    /// "Nudge if no reply by T" (spec A.9): reads only thread *metadata*
    /// (mailbox membership, not bodies), so this works correctly even
    /// while the account is locked. A message landing in the thread
    /// afterward that isn't in Sent/Drafts counts as a reply; anything
    /// else (including the account replying to itself) silently cancels
    /// the nudge rather than firing it.
    fn fire_followup_nudge(&self, ev: &StoredScheduledEvent) {
        // Sourced from the event row rather than the loaded message's own
        // `thread_id` -- keeps the check correct even if the anchor
        // message itself were later moved, which `thread_id`'s doc
        // comment in the schema is there for.
        let Some(thread_id) = ev.thread_id.as_deref().and_then(|t| t.parse::<i64>().ok()) else {
            let _ = self.queue.mark_event_fired(ev.id);
            return;
        };
        if let Some(row_id) = Self::scheduled_message_row_id(ev) {
            if let Ok(Some(msg)) = self.metadata.get_message(row_id) {
                let sent = self.metadata.ensure_mailbox(ev.account_id, ROLE_SENT).ok();
                let drafts = self.metadata.ensure_mailbox(ev.account_id, ROLE_DRAFTS).ok();
                let replied = self
                    .metadata
                    .messages_in_thread(ev.account_id, thread_id)
                    .unwrap_or_default()
                    .into_iter()
                    .any(|m| {
                        m.id != row_id
                            && sent.as_ref().is_none_or(|mb| m.mailbox_id != mb.id)
                            && drafts.as_ref().is_none_or(|mb| m.mailbox_id != mb.id)
                    });
                if replied {
                    let _ = self.queue.mark_event_cancelled(ev.id);
                    return;
                }
                if !msg.keywords.split(',').any(|k| k == KEYWORD_NUDGE) {
                    let mut kept: Vec<&str> =
                        msg.keywords.split(',').filter(|k| !k.is_empty()).collect();
                    kept.push(KEYWORD_NUDGE);
                    let _ = self
                        .metadata
                        .update_message(row_id, None, Some(&kept.join(",")));
                }
                self.notifier.notify(ev.account_id);
            }
        }
        let _ = self.queue.mark_event_fired(ev.id);
    }

    fn release_to_ready(&self, rcpts: &[ClaimedRcpt]) {
        let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
        for rcpt in rcpts {
            let _ = conn.execute(
                "UPDATE outbound_rcpt SET state = 'ready', claimed_by = NULL WHERE id = ?1",
                (rcpt.id,),
            );
        }
    }

    fn is_cooling_down(&self, domain: &str) -> bool {
        let cooldowns = self.cooldowns.lock().expect("cooldown mutex poisoned");
        cooldowns
            .get(domain)
            .is_some_and(|until| Instant::now() < *until)
    }

    fn set_cooldown(&self, domain: &str) {
        let mut cooldowns = self.cooldowns.lock().expect("cooldown mutex poisoned");
        cooldowns.insert(
            domain.to_string(),
            Instant::now() + Duration::from_secs(COOLDOWN_SECS),
        );
    }

    fn load_outbound(&self, outbound_id: i64) -> Option<OutboundRow> {
        let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
        conn.query_row(
            "SELECT message_blob, envelope_from, is_dsn, created_at, expires_at, account_id
             FROM outbound WHERE id = ?1",
            (outbound_id,),
            |row| {
                Ok(OutboundRow {
                    id: outbound_id,
                    message_blob: row.get(0)?,
                    envelope_from: row.get(1)?,
                    is_dsn: row.get::<_, i64>(2)? != 0,
                    created_at: row.get(3)?,
                    expires_at: row.get(4)?,
                    account_id: row.get(5)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    async fn send_unit(&self, outbound_id: i64, domain: &str, rcpts: &[ClaimedRcpt]) {
        let Some(outbound) = self.load_outbound(outbound_id) else {
            return;
        };
        let raw = match self.blobs.read(&outbound.message_blob) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(error = %e, outbound_id, "failed to read queued message blob");
                for rcpt in rcpts {
                    self.finalize(
                        rcpt,
                        &outbound,
                        Outcome::Transient {
                            code: None,
                            status: None,
                            detail: "local storage error".into(),
                        },
                    );
                }
                return;
            }
        };

        let mx_records = match self.resolver.resolve_mx(domain).await {
            Ok(records) => records,
            Err(e) => {
                for rcpt in rcpts {
                    self.finalize(
                        rcpt,
                        &outbound,
                        classify_connect_failure(e.to_string(), false),
                    );
                }
                return;
            }
        };

        if mx_records.len() == 1 && mx_records[0].exchange == "." {
            for rcpt in rcpts {
                self.finalize(
                    rcpt,
                    &outbound,
                    classify_connect_failure(
                        "domain publishes a null MX (RFC 7505): does not accept mail".into(),
                        true,
                    ),
                );
            }
            return;
        }

        let Some(connected) = self.connect_opportunistic(&mx_records).await else {
            self.set_cooldown(domain);
            for rcpt in rcpts {
                self.finalize(
                    rcpt,
                    &outbound,
                    classify_connect_failure("could not connect to any MX host".into(), false),
                );
            }
            return;
        };

        let sender = outbound.envelope_from.clone();
        let outcomes = match connected {
            Connected::Tls(client) => run_envelope(*client, &sender, rcpts, &raw).await,
            Connected::Plain(client) => run_envelope(client, &sender, rcpts, &raw).await,
        };
        for (rcpt, outcome) in rcpts.iter().zip(outcomes) {
            self.finalize(rcpt, &outbound, outcome);
        }
    }

    /// Tries each MX in preference order, preferring STARTTLS but falling
    /// back to plaintext when the remote doesn't offer it -- TLS is never
    /// required for outbound delivery, only preferred.
    async fn connect_opportunistic(&self, mx_records: &[dns::MxRecord]) -> Option<Connected> {
        for mx in mx_records {
            let host = mx.exchange.trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            let Ok(builder) = SmtpClientBuilder::new(host.to_string(), 25) else {
                continue;
            };
            let builder = builder.implicit_tls(false).helo_host(self.hostname.clone());
            match builder.connect().await {
                Ok(client) => return Some(Connected::Tls(Box::new(client))),
                Err(mail_send::Error::MissingStartTls) => {
                    if let Ok(client) = builder.connect_plain().await {
                        return Some(Connected::Plain(client));
                    }
                }
                Err(_) => {}
            }
        }
        None
    }

    fn finalize(&self, rcpt: &ClaimedRcpt, outbound: &OutboundRow, outcome: Outcome) {
        let now = now_unix();
        let (state, next_attempt_at, code, status, detail) = match &outcome {
            Outcome::Delivered => (RcptState::Delivered, now, None, None, String::new()),
            Outcome::Permanent {
                code,
                status,
                detail,
            } => (
                RcptState::Failed,
                now,
                *code,
                status.clone(),
                detail.clone(),
            ),
            Outcome::Transient {
                code,
                status,
                detail,
            } => {
                let attempts = rcpt.attempts + 1;
                if now >= outbound.expires_at {
                    (
                        RcptState::Expired,
                        now,
                        *code,
                        status.clone(),
                        detail.clone(),
                    )
                } else {
                    let delay = next_delay_secs(attempts);
                    (
                        RcptState::Deferred,
                        now + delay,
                        *code,
                        status.clone(),
                        detail.clone(),
                    )
                }
            }
        };

        let attempts_increment = !matches!(outcome, Outcome::Delivered);
        {
            let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
            let _ = conn.execute(
                "UPDATE outbound_rcpt
                 SET state = ?1, next_attempt_at = ?2, claimed_by = NULL,
                     attempts = attempts + ?3, last_code = ?4, last_status = ?5, last_detail = ?6
                 WHERE id = ?7",
                rusqlite::params![
                    state.as_str(),
                    next_attempt_at,
                    attempts_increment as i64,
                    code.map(|c| c as i64),
                    status,
                    detail,
                    rcpt.id,
                ],
            );
        }

        if state.is_terminal() {
            let action = match state {
                RcptState::Delivered => "queue.delivered",
                RcptState::Failed => "queue.failed",
                RcptState::Expired => "queue.expired",
                _ => unreachable!("guarded by is_terminal above"),
            };
            let _ = self.audit.log(action, &rcpt.rcpt_to);
        }

        if state.is_terminal() && state != RcptState::Delivered {
            self.maybe_send_dsn(
                rcpt,
                outbound,
                DsnAction::Failed,
                code,
                status.as_deref(),
                &detail,
            );
        } else if state == RcptState::Deferred
            && !rcpt.delayed_dsn_sent
            && rcpt.dsn_notify.contains("DELAY")
            && now - outbound.created_at >= DELAYED_DSN_THRESHOLD_SECS
        {
            self.mark_delayed_dsn_sent(rcpt.id);
            self.maybe_send_dsn(
                rcpt,
                outbound,
                DsnAction::Delayed,
                code,
                status.as_deref(),
                &detail,
            );
        }
        self.cleanup_terminal_message(outbound);
    }

    /// Wipes the plaintext wire-form blob as soon as every recipient has
    /// reached a terminal state. Queue rows remain for metrics and failure
    /// diagnostics, but no message content is retained with them.
    fn cleanup_terminal_message(&self, outbound: &OutboundRow) {
        let no_active_reference = {
            let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
            conn.query_row(
                "SELECT COUNT(*) = 0
                 FROM outbound_rcpt r
                 JOIN outbound o ON o.id = r.outbound_id
                 WHERE o.message_blob = ?1
                   AND r.state NOT IN ('delivered', 'failed', 'expired')",
                (&outbound.message_blob,),
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false)
        };
        if no_active_reference {
            if let Err(e) = self.blobs.remove(&outbound.message_blob) {
                tracing::warn!(error = %e, outbound_id = outbound.id, "failed to remove terminal queue blob");
            }
        }
    }

    fn mark_delayed_dsn_sent(&self, rcpt_id: i64) {
        let conn = self.queue.conn.lock().expect("queue store mutex poisoned");
        let _ = conn.execute(
            "UPDATE outbound_rcpt SET delayed_dsn_sent = 1 WHERE id = ?1",
            (rcpt_id,),
        );
    }

    fn maybe_send_dsn(
        &self,
        rcpt: &ClaimedRcpt,
        outbound: &OutboundRow,
        action: DsnAction,
        code: Option<u16>,
        status: Option<&str>,
        detail: &str,
    ) {
        // Loop guards (never optional): don't DSN a null-sender message,
        // and never DSN a DSN.
        if outbound.envelope_from.is_empty() || outbound.is_dsn || rcpt.dsn_notify == "NEVER" {
            return;
        }

        let status_string = status
            .map(|s| s.to_string())
            .unwrap_or_else(|| code.map(|c| c.to_string()).unwrap_or_default());
        let diagnostic = if detail.is_empty() {
            "delivery failed".to_string()
        } else {
            detail.to_string()
        };
        let failed = [FailedRecipient {
            rcpt_to: &rcpt.rcpt_to,
            action,
            status: (!status_string.is_empty()).then_some(status_string.as_str()),
            diagnostic: &diagnostic,
        }];
        let input = DsnInput {
            reporting_mta: &self.hostname,
            original_envelope_from: &outbound.envelope_from,
            original_subject: None,
            recipients: &failed,
            original_message: None,
        };
        let Ok(dsn_bytes) = build_dsn(&input) else {
            tracing::error!("failed to build DSN");
            return;
        };

        let Ok(Some(account)) = self.auth_store.find_by_id(outbound.account_id) else {
            tracing::error!(
                account_id = outbound.account_id,
                "DSN target account not found"
            );
            return;
        };
        let recipient_account = RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        };
        let envelope = InboundEnvelope {
            mail_from: String::new(),
            rcpt_to: outbound.envelope_from.clone(),
            remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        let auth_results = AuthResults {
            spf: "n/a".into(),
            dkim: "n/a".into(),
            dmarc: "n/a".into(),
        };
        match delivery::deliver(
            &self.blobs,
            &self.metadata,
            &recipient_account,
            &envelope,
            &auth_results,
            &dsn_bytes,
            now_unix(),
            None,
            delivery::ScanMetadata::default(),
        ) {
            Ok(_) => self.notifier.notify(account.id),
            Err(e) => tracing::error!(error = %e, "failed to deliver DSN locally"),
        }
    }
}

/// Runs MAIL FROM / RCPT TO (per recipient) / DATA (once, for whichever
/// recipients were accepted) over an already-connected client, generic
/// over the stream type so it works identically for the STARTTLS and
/// plaintext paths.
async fn run_envelope<T: AsyncRead + AsyncWrite + Unpin>(
    mut client: SmtpClient<T>,
    sender: &str,
    rcpts: &[ClaimedRcpt],
    raw: &[u8],
) -> Vec<Outcome> {
    if let Err(e) = client.mail_from(sender, &Parameters::default()).await {
        let outcome = classify_send_result(&Err(e));
        return rcpts.iter().map(|_| outcome.clone()).collect();
    }

    let mut outcomes: Vec<Option<Outcome>> = vec![None; rcpts.len()];
    let mut accepted = Vec::new();
    for (i, rcpt) in rcpts.iter().enumerate() {
        match client.rcpt_to(&rcpt.rcpt_to, &Parameters::default()).await {
            Ok(()) => accepted.push(i),
            Err(e) => outcomes[i] = Some(classify_send_result(&Err(e))),
        }
    }

    if !accepted.is_empty() {
        let data_result = client.data(raw).await;
        let outcome = classify_send_result(&data_result);
        for i in accepted {
            outcomes[i] = Some(outcome.clone());
        }
    }

    let _ = client.quit().await;

    outcomes
        .into_iter()
        .map(|o| {
            o.unwrap_or(Outcome::Transient {
                code: None,
                status: None,
                detail: "internal: no outcome computed".into(),
            })
        })
        .collect()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NewOutbound;
    use common::config::Argon2Config;

    fn fast_argon2() -> Argon2Config {
        Argon2Config {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn make_worker() -> (Worker, i64) {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let auth_store = AuthStore::open_in_memory().unwrap();
        let account = auth_store
            .provision("alice", "example.com", b"pw", &fast_argon2())
            .unwrap();
        let resolver = Resolver::new().unwrap();
        let audit = Arc::new(audit::AuditStore::open_in_memory().unwrap());
        audit.bootstrap_keys(&[7u8; 32]).unwrap();
        let worker = Worker::new(
            queue,
            blobs,
            metadata,
            auth_store,
            audit,
            resolver,
            "mx.example.com".to_string(),
            Arc::new(common::changes::ChangeNotifier::new()),
        );
        (worker, account.id)
    }

    fn enqueue_test_message(worker: &Worker, account_id: i64, recipients: &[&str]) -> i64 {
        let domain_key = worker.queue.ensure_dkim_key("example.com").unwrap();
        let new = NewOutbound {
            account_id,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n",
            recipients,
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };
        crate::enqueue::enqueue(&worker.queue, &worker.blobs, &domain_key, &new).unwrap()
    }

    #[test]
    fn claim_batch_picks_up_due_ready_rows() {
        let (worker, account_id) = make_worker();
        let outbound_id = enqueue_test_message(&worker, account_id, &["bob@example.net"]);

        let claimed = worker.claim_batch(now_unix(), 10);
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].0, outbound_id);
        assert_eq!(claimed[0].1.rcpt_to, "bob@example.net");

        // A second claim finds nothing left ready (already claimed).
        assert!(worker.claim_batch(now_unix(), 10).is_empty());
    }

    #[test]
    fn reap_stale_claims_returns_expired_leases_to_ready() {
        let (worker, account_id) = make_worker();
        enqueue_test_message(&worker, account_id, &["bob@example.net"]);
        let claimed = worker.claim_batch(now_unix(), 10);
        assert_eq!(claimed.len(), 1);

        // Backdate the claim past the lease TTL.
        {
            let conn = worker.queue.conn.lock().unwrap();
            conn.execute(
                "UPDATE outbound_rcpt SET claimed_at = ?1 WHERE id = ?2",
                (now_unix() - LEASE_TTL_SECS - 10, claimed[0].1.id),
            )
            .unwrap();
        }
        worker.reap_stale_claims();
        let reclaimed = worker.claim_batch(now_unix(), 10);
        assert_eq!(reclaimed.len(), 1, "stale claim should be reapable");
    }

    #[test]
    fn finalize_delivered_marks_row_delivered() {
        let (worker, account_id) = make_worker();
        let outbound_id = enqueue_test_message(&worker, account_id, &["bob@example.net"]);
        let claimed = worker.claim_batch(now_unix(), 10);
        let outbound = worker.load_outbound(outbound_id).unwrap();

        worker.finalize(&claimed[0].1, &outbound, Outcome::Delivered);

        assert!(
            !worker.blobs.exists(&outbound.message_blob),
            "terminal plaintext queue content must be removed"
        );

        let conn = worker.queue.conn.lock().unwrap();
        let state: String = conn
            .query_row(
                "SELECT state FROM outbound_rcpt WHERE id = ?1",
                (claimed[0].1.id,),
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "delivered");
    }

    #[test]
    fn finalize_transient_defers_with_backoff_and_increments_attempts() {
        let (worker, account_id) = make_worker();
        let outbound_id = enqueue_test_message(&worker, account_id, &["bob@example.net"]);
        let claimed = worker.claim_batch(now_unix(), 10);
        let outbound = worker.load_outbound(outbound_id).unwrap();
        let before = now_unix();

        worker.finalize(
            &claimed[0].1,
            &outbound,
            Outcome::Transient {
                code: Some(450),
                status: Some("4.2.2".into()),
                detail: "mailbox full".into(),
            },
        );

        let conn = worker.queue.conn.lock().unwrap();
        let (state, attempts, next_attempt_at): (String, i64, i64) = conn
            .query_row(
                "SELECT state, attempts, next_attempt_at FROM outbound_rcpt WHERE id = ?1",
                (claimed[0].1.id,),
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "deferred");
        assert_eq!(attempts, 1);
        assert!(
            next_attempt_at > before,
            "next attempt should be in the future"
        );
    }

    #[test]
    fn finalize_permanent_failure_marks_failed_and_delivers_dsn_locally() {
        let (worker, account_id) = make_worker();
        let outbound_id = enqueue_test_message(&worker, account_id, &["bob@example.net"]);
        let claimed = worker.claim_batch(now_unix(), 10);
        let outbound = worker.load_outbound(outbound_id).unwrap();

        worker.finalize(
            &claimed[0].1,
            &outbound,
            Outcome::Permanent {
                code: Some(550),
                status: Some("5.1.1".into()),
                detail: "no such user".into(),
            },
        );

        let conn = worker.queue.conn.lock().unwrap();
        let state: String = conn
            .query_row(
                "SELECT state FROM outbound_rcpt WHERE id = ?1",
                (claimed[0].1.id,),
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "failed");
        drop(conn);

        // The DSN was delivered locally into the sender's own mailbox, not
        // routed back out through SMTP.
        let messages = worker.metadata.messages_for_account(account_id).unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn dsn_is_not_generated_for_a_dsn_or_null_sender() {
        let (worker, account_id) = make_worker();
        let domain_key = worker.queue.ensure_dkim_key("example.com").unwrap();
        let new = NewOutbound {
            account_id,
            envelope_from: "", // null sender: this message is itself a DSN
            raw_message: b"From: mailer-daemon@example.com\r\nTo: bob@example.net\r\nSubject: bounce\r\n\r\nx\r\n",
            recipients: &["bob@example.net"],
            is_dsn: true,
            dsn_envid: None,
            dsn_ret: None,
        };
        let outbound_id =
            crate::enqueue::enqueue(&worker.queue, &worker.blobs, &domain_key, &new).unwrap();
        let claimed = worker.claim_batch(now_unix(), 10);
        let outbound = worker.load_outbound(outbound_id).unwrap();

        worker.finalize(
            &claimed[0].1,
            &outbound,
            Outcome::Permanent {
                code: Some(550),
                status: None,
                detail: "no such user".into(),
            },
        );

        assert!(worker
            .metadata
            .messages_for_account(account_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cooldown_expires_after_the_configured_duration() {
        let (worker, _account_id) = make_worker();
        assert!(!worker.is_cooling_down("slow.example"));
        worker.set_cooldown("slow.example");
        assert!(worker.is_cooling_down("slow.example"));
    }

    fn insert_test_message(worker: &Worker, account_id: i64, mailbox_id: i64, thread_id: i64, keywords: &str) -> i64 {
        worker
            .metadata
            .insert_message(&store::NewMessage {
                account_id,
                mailbox_id,
                thread_id,
                blob_hash: "deadbeef",
                dek_wrap: b"wrapped",
                mail_from: "someone@example.net",
                rcpt_to: "alice@example.com",
                remote_ip: "203.0.113.5",
                size_bytes: 10,
                spf_result: "pass",
                dkim_result: "pass",
                dmarc_result: "pass",
                received_at: now_unix(),
                keywords,
                message_id_header: None,
                in_reply_to: None,
                references_header: None,
                subject_hash: None,
                spam_score: None,
                av_clean: None,
            })
            .unwrap()
    }

    #[test]
    fn snooze_resurface_clears_keyword_and_marks_fired() {
        let (worker, account_id) = make_worker();
        let inbox = worker.metadata.ensure_mailbox(account_id, store::ROLE_INBOX).unwrap();
        let msg_id = insert_test_message(&worker, account_id, inbox.id, 1, "$seen,$snoozed");
        let ev_id = worker
            .queue
            .insert_scheduled_event(&crate::scheduled::NewScheduledEvent {
                account_id,
                kind: ScheduledKind::SnoozeResurface,
                fire_at: now_unix() - 10,
                thread_id: Some("1"),
                payload: Some(&format!("m{msg_id}")),
            })
            .unwrap();

        worker.fire_due_scheduled_events();

        let stored = worker.metadata.get_message(msg_id).unwrap().unwrap();
        assert_eq!(stored.keywords, "$seen");
        assert!(worker.queue.due_scheduled_events(now_unix()).unwrap().is_empty());
        assert!(worker
            .queue
            .pending_events_for_account(account_id, ScheduledKind::SnoozeResurface)
            .unwrap()
            .is_empty());
        let _ = ev_id;
    }

    #[test]
    fn followup_nudge_fires_when_no_reply_landed_in_the_thread() {
        let (worker, account_id) = make_worker();
        let sent = worker.metadata.ensure_mailbox(account_id, store::ROLE_SENT).unwrap();
        let msg_id = insert_test_message(&worker, account_id, sent.id, 5, "");
        worker
            .queue
            .insert_scheduled_event(&crate::scheduled::NewScheduledEvent {
                account_id,
                kind: ScheduledKind::FollowupNudge,
                fire_at: now_unix() - 10,
                thread_id: Some("5"),
                payload: Some(&format!("m{msg_id}")),
            })
            .unwrap();

        worker.fire_due_scheduled_events();

        let stored = worker.metadata.get_message(msg_id).unwrap().unwrap();
        assert!(stored.keywords.split(',').any(|k| k == KEYWORD_NUDGE));
        assert!(worker.queue.due_scheduled_events(now_unix()).unwrap().is_empty());
    }

    #[test]
    fn followup_nudge_cancels_silently_when_a_reply_already_landed() {
        let (worker, account_id) = make_worker();
        let sent = worker.metadata.ensure_mailbox(account_id, store::ROLE_SENT).unwrap();
        let inbox = worker.metadata.ensure_mailbox(account_id, store::ROLE_INBOX).unwrap();
        let msg_id = insert_test_message(&worker, account_id, sent.id, 9, "");
        // A later message in the same thread, landing anywhere but
        // Sent/Drafts, counts as a reply.
        insert_test_message(&worker, account_id, inbox.id, 9, "");
        worker
            .queue
            .insert_scheduled_event(&crate::scheduled::NewScheduledEvent {
                account_id,
                kind: ScheduledKind::FollowupNudge,
                fire_at: now_unix() - 10,
                thread_id: Some("9"),
                payload: Some(&format!("m{msg_id}")),
            })
            .unwrap();

        worker.fire_due_scheduled_events();

        let stored = worker.metadata.get_message(msg_id).unwrap().unwrap();
        assert!(!stored.keywords.split(',').any(|k| k == KEYWORD_NUDGE));
        assert!(worker.queue.due_scheduled_events(now_unix()).unwrap().is_empty());
        assert!(worker
            .queue
            .pending_events_for_account(account_id, ScheduledKind::FollowupNudge)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn followup_nudge_ignores_the_accounts_own_later_sent_message() {
        let (worker, account_id) = make_worker();
        let sent = worker.metadata.ensure_mailbox(account_id, store::ROLE_SENT).unwrap();
        let msg_id = insert_test_message(&worker, account_id, sent.id, 3, "");
        // Sending another message into the same thread yourself doesn't
        // count as "they replied."
        insert_test_message(&worker, account_id, sent.id, 3, "");
        worker
            .queue
            .insert_scheduled_event(&crate::scheduled::NewScheduledEvent {
                account_id,
                kind: ScheduledKind::FollowupNudge,
                fire_at: now_unix() - 10,
                thread_id: Some("3"),
                payload: Some(&format!("m{msg_id}")),
            })
            .unwrap();

        worker.fire_due_scheduled_events();

        let stored = worker.metadata.get_message(msg_id).unwrap().unwrap();
        assert!(
            stored.keywords.split(',').any(|k| k == KEYWORD_NUDGE),
            "own later Sent message must not count as a reply"
        );
    }

    /// Drives a scripted plaintext SMTP dialog: greet, accept EHLO, accept
    /// MAIL FROM, accept the first RCPT TO and reject the second, then
    /// accept DATA. Proves `run_envelope`'s partial-success handling (one
    /// recipient delivered, one permanently rejected, in a single
    /// connection) against a real socket, not a mocked trait.
    async fn scripted_smtp_server(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        write_half
            .write_all(b"220 mock.example ESMTP\r\n")
            .await
            .unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap(); // EHLO
        write_half.write_all(b"250 mock.example\r\n").await.unwrap();

        line.clear();
        reader.read_line(&mut line).await.unwrap(); // MAIL FROM
        write_half.write_all(b"250 OK\r\n").await.unwrap();

        line.clear();
        reader.read_line(&mut line).await.unwrap(); // RCPT TO (accepted)
        write_half.write_all(b"250 OK\r\n").await.unwrap();

        line.clear();
        reader.read_line(&mut line).await.unwrap(); // RCPT TO (rejected)
        write_half
            .write_all(b"550 5.1.1 No such user\r\n")
            .await
            .unwrap();

        line.clear();
        reader.read_line(&mut line).await.unwrap(); // DATA
        write_half
            .write_all(b"354 Start mail input\r\n")
            .await
            .unwrap();

        // Drain the message body up to the terminating "."
        loop {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            if line == ".\r\n" {
                break;
            }
        }
        write_half.write_all(b"250 OK: queued\r\n").await.unwrap();

        line.clear();
        reader.read_line(&mut line).await.unwrap(); // QUIT
        write_half.write_all(b"221 Bye\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn run_envelope_handles_partial_recipient_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(scripted_smtp_server(listener));

        let builder = SmtpClientBuilder::new("127.0.0.1".to_string(), addr.port())
            .unwrap()
            .say_ehlo(true)
            .helo_host("sender.example".to_string());
        let client = builder.connect_plain().await.unwrap();

        let rcpts = vec![
            ClaimedRcpt {
                id: 1,
                rcpt_to: "good@example.net".into(),
                domain: "example.net".into(),
                dsn_notify: "FAILURE".into(),
                attempts: 0,
                delayed_dsn_sent: false,
            },
            ClaimedRcpt {
                id: 2,
                rcpt_to: "bad@example.net".into(),
                domain: "example.net".into(),
                dsn_notify: "FAILURE".into(),
                attempts: 0,
                delayed_dsn_sent: false,
            },
        ];

        let outcomes =
            run_envelope(client, "sender@sender.example", &rcpts, b"test body\r\n").await;
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(outcomes[0], Outcome::Delivered));
        assert!(matches!(
            outcomes[1],
            Outcome::Permanent {
                code: Some(550),
                ..
            }
        ));
    }
}
