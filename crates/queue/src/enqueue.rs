//! Accepting a message into the durable queue: DKIM-sign, write the signed
//! MIME to content-addressed storage (same store as inbound blobs, but
//! unencrypted -- this is the signed wire form, analogous to a
//! conventional MTA's plaintext spool, not sealed mailbox content), and
//! insert one `outbound` row plus one `outbound_rcpt` row per recipient.

use std::time::{SystemTime, UNIX_EPOCH};

use store::BlobStore;

use common::{Error, Result};

use crate::backoff::MAX_LIFETIME_SECS;
use crate::dkim::DomainKey;
use crate::schema::{storage_err, QueueStore};
use crate::types::NewOutbound;

/// Rolling window over which per-account send limits below are enforced.
const RATE_LIMIT_WINDOW_SECS: i64 = 3600;
/// A single leaked credential (password or app password) must not be able
/// to blast unbounded mail through the account's DKIM identity -- that
/// burns the whole instance's IP/domain sending reputation, not just the
/// one account's. DSNs (`is_dsn`) are excluded: they're generated locally
/// by the worker, not by an authenticated sender, and are already capped
/// by how many real messages can fail.
pub const MAX_MESSAGES_PER_WINDOW: i64 = 200;
pub const MAX_RECIPIENTS_PER_WINDOW: i64 = 500;

pub fn enqueue(
    queue: &QueueStore,
    blobs: &BlobStore,
    domain_key: &DomainKey,
    new: &NewOutbound,
) -> Result<i64> {
    if (!new.envelope_from.is_empty() && !common::input::valid_email_address(new.envelope_from))
        || new.recipients.is_empty()
        || new.recipients.len() > 100
        || new
            .recipients
            .iter()
            .any(|recipient| !common::input::valid_email_address(recipient))
    {
        return Err(Error::Config("invalid outbound envelope".to_string()));
    }
    let dkim_header = domain_key.sign(new.raw_message)?;
    let mut signed = dkim_header.into_bytes();
    signed.extend_from_slice(new.raw_message);
    let blob_hash = blobs.write(&signed)?;

    let now = now_unix();
    let expires_at = now + MAX_LIFETIME_SECS;

    let conn = queue.conn.lock().expect("queue store mutex poisoned");

    if !new.is_dsn {
        let since = now - RATE_LIMIT_WINDOW_SECS;
        let message_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound WHERE account_id = ?1 AND created_at > ?2 AND is_dsn = 0",
                rusqlite::params![new.account_id, since],
                |r| r.get(0),
            )
            .map_err(storage_err)?;
        if message_count >= MAX_MESSAGES_PER_WINDOW {
            return Err(Error::RateLimited(format!(
                "account has sent {message_count} messages in the last hour (limit {MAX_MESSAGES_PER_WINDOW})"
            )));
        }
        let recipient_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_rcpt
                 JOIN outbound ON outbound.id = outbound_rcpt.outbound_id
                 WHERE outbound.account_id = ?1 AND outbound.created_at > ?2 AND outbound.is_dsn = 0",
                rusqlite::params![new.account_id, since],
                |r| r.get(0),
            )
            .map_err(storage_err)?;
        if recipient_count + new.recipients.len() as i64 > MAX_RECIPIENTS_PER_WINDOW {
            return Err(Error::RateLimited(format!(
                "account has addressed {recipient_count} recipients in the last hour (limit {MAX_RECIPIENTS_PER_WINDOW})"
            )));
        }
    }

    conn.execute(
        "INSERT INTO outbound
            (account_id, message_blob, envelope_from, created_at, expires_at, dsn_envid, dsn_ret, is_dsn)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            new.account_id,
            blob_hash,
            new.envelope_from,
            now,
            expires_at,
            new.dsn_envid,
            new.dsn_ret,
            new.is_dsn as i64,
        ],
    )
    .map_err(storage_err)?;
    let outbound_id = conn.last_insert_rowid();

    for rcpt in new.recipients {
        let domain = rcpt
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(rcpt)
            .to_ascii_lowercase();
        conn.execute(
            "INSERT INTO outbound_rcpt (outbound_id, rcpt_to, domain, next_attempt_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![outbound_id, rcpt, domain, now],
        )
        .map_err(storage_err)?;
    }

    Ok(outbound_id)
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

    #[test]
    fn enqueue_creates_outbound_and_rcpt_rows() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();

        let new = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n",
            recipients: &["bob@example.net", "carol@example.org"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };

        let id = enqueue(&queue, &blobs, &key, &new).unwrap();
        assert!(id > 0);

        let conn = queue.conn.lock().unwrap();
        let rcpt_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_rcpt WHERE outbound_id = ?1",
                (id,),
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rcpt_count, 2);

        let blob_hash: String = conn
            .query_row(
                "SELECT message_blob FROM outbound WHERE id = ?1",
                (id,),
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);
        let stored = blobs.read(&blob_hash).unwrap();
        let stored_text = String::from_utf8(stored).unwrap();
        assert!(stored_text.starts_with("DKIM-Signature:"));
        assert!(stored_text.contains("Subject: hi"));
    }

    fn insert_raw_outbound(queue: &QueueStore, account_id: i64, created_at: i64, is_dsn: bool) {
        let conn = queue.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO outbound
                (account_id, message_blob, envelope_from, created_at, expires_at, is_dsn)
             VALUES (?1, 'deadbeef', 'alice@example.com', ?2, ?2, ?3)",
            rusqlite::params![account_id, created_at, is_dsn as i64],
        )
        .unwrap();
    }

    #[test]
    fn rate_limit_blocks_after_max_messages_in_window() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();
        let now = now_unix();

        for _ in 0..MAX_MESSAGES_PER_WINDOW {
            insert_raw_outbound(&queue, 1, now, false);
        }

        let new = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\n\r\nbody",
            recipients: &["bob@example.net"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };
        let err = enqueue(&queue, &blobs, &key, &new).unwrap_err();
        assert!(matches!(err, Error::RateLimited(_)), "{err:?}");

        // A different account is unaffected by account 1's usage.
        let other = NewOutbound {
            account_id: 2,
            ..new
        };
        assert!(enqueue(&queue, &blobs, &key, &other).is_ok());
    }

    #[test]
    fn rate_limit_ignores_messages_outside_the_window() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();
        let now = now_unix();

        for _ in 0..MAX_MESSAGES_PER_WINDOW {
            insert_raw_outbound(&queue, 1, now - RATE_LIMIT_WINDOW_SECS - 1, false);
        }

        let new = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\n\r\nbody",
            recipients: &["bob@example.net"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };
        assert!(enqueue(&queue, &blobs, &key, &new).is_ok());
    }

    #[test]
    fn rate_limit_blocks_after_max_recipients_in_window() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();

        // Stay under the per-message 100-recipient cap (a separate,
        // pre-existing check) while building up to the per-window total.
        let batches = MAX_RECIPIENTS_PER_WINDOW / 100;
        for batch in 0..batches {
            let recipients: Vec<String> = (0..100)
                .map(|i| format!("r{batch}-{i}@example.net"))
                .collect();
            let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
            let new = NewOutbound {
                account_id: 1,
                envelope_from: "alice@example.com",
                raw_message: b"From: alice@example.com\r\n\r\nbody",
                recipients: &recipient_refs,
                is_dsn: false,
                dsn_envid: None,
                dsn_ret: None,
            };
            enqueue(&queue, &blobs, &key, &new).unwrap();
        }

        let one_more = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\n\r\nbody",
            recipients: &["one-too-many@example.net"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };
        let err = enqueue(&queue, &blobs, &key, &one_more).unwrap_err();
        assert!(matches!(err, Error::RateLimited(_)), "{err:?}");
    }

    #[test]
    fn dsn_messages_are_exempt_from_rate_limit() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();
        let now = now_unix();

        for _ in 0..MAX_MESSAGES_PER_WINDOW {
            insert_raw_outbound(&queue, 1, now, false);
        }

        let new = NewOutbound {
            account_id: 1,
            envelope_from: "",
            raw_message: b"From: mailer-daemon@example.com\r\n\r\nbounce",
            recipients: &["bob@example.net"],
            is_dsn: true,
            dsn_envid: None,
            dsn_ret: None,
        };
        assert!(enqueue(&queue, &blobs, &key, &new).is_ok());
    }

    #[test]
    fn rejects_smtp_command_injection_in_recipient() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();
        let malicious = "victim@example.net>\r\nRSET\r\nMAIL FROM:<spoof@example.org";
        let new = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\n\r\nbody",
            recipients: &[malicious],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };

        assert!(enqueue(&queue, &blobs, &key, &new).is_err());
    }
}
