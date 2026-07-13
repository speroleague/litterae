//! Accepting a message into the durable queue: DKIM-sign, write the signed
//! MIME to content-addressed storage (same store as inbound blobs, but
//! unencrypted -- this is the signed wire form, analogous to a
//! conventional MTA's plaintext spool, not sealed mailbox content), and
//! insert one `outbound` row plus one `outbound_rcpt` row per recipient.

use std::time::{SystemTime, UNIX_EPOCH};

use store::BlobStore;

use common::Result;

use crate::backoff::MAX_LIFETIME_SECS;
use crate::dkim::DomainKey;
use crate::schema::{storage_err, QueueStore};
use crate::types::NewOutbound;

pub fn enqueue(queue: &QueueStore, blobs: &BlobStore, domain_key: &DomainKey, new: &NewOutbound) -> Result<i64> {
    let dkim_header = domain_key.sign(new.raw_message)?;
    let mut signed = dkim_header.into_bytes();
    signed.extend_from_slice(new.raw_message);
    let blob_hash = blobs.write(&signed)?;

    let now = now_unix();
    let expires_at = now + MAX_LIFETIME_SECS;

    let conn = queue.conn.lock().expect("queue store mutex poisoned");
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
        let domain = rcpt.rsplit_once('@').map(|(_, d)| d).unwrap_or(rcpt);
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
            .query_row("SELECT COUNT(*) FROM outbound_rcpt WHERE outbound_id = ?1", (id,), |r| r.get(0))
            .unwrap();
        assert_eq!(rcpt_count, 2);

        let blob_hash: String = conn
            .query_row("SELECT message_blob FROM outbound WHERE id = ?1", (id,), |r| r.get(0))
            .unwrap();
        drop(conn);
        let stored = blobs.read(&blob_hash).unwrap();
        let stored_text = String::from_utf8(stored).unwrap();
        assert!(stored_text.starts_with("DKIM-Signature:"));
        assert!(stored_text.contains("Subject: hi"));
    }
}
