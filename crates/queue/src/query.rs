//! Read access to queue state -- used by tests and will back an eventual
//! admin/status view.

use rusqlite::OptionalExtension;

use common::Result;

use crate::schema::{storage_err, QueueStore};
use crate::types::{OutboundMessage, OutboundRecipient, RcptState};

impl QueueStore {
    pub fn get_outbound(&self, id: i64) -> Result<Option<OutboundMessage>> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        conn.query_row(
            "SELECT id, account_id, message_blob, envelope_from, created_at, expires_at,
                    dsn_envid, dsn_ret, is_dsn
             FROM outbound WHERE id = ?1",
            (id,),
            row_to_outbound,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn recipients_for_outbound(&self, outbound_id: i64) -> Result<Vec<OutboundRecipient>> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, outbound_id, rcpt_to, domain, dsn_notify, state, attempts,
                        next_attempt_at, last_code, last_status, last_detail, delayed_dsn_sent
                 FROM outbound_rcpt WHERE outbound_id = ?1",
            )
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((outbound_id,), row_to_recipient)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage_err)
    }

    /// Recipient counts by state -- the admin area's queue-at-a-glance.
    pub fn metrics(&self) -> Result<QueueMetrics> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        let mut stmt = conn
            .prepare("SELECT state, COUNT(*) FROM outbound_rcpt GROUP BY state")
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage_err)?;

        let mut metrics = QueueMetrics::default();
        for row in rows {
            let (state, count) = row.map_err(storage_err)?;
            match RcptState::from_db_str(&state) {
                RcptState::Ready => metrics.ready += count,
                RcptState::Claimed => metrics.claimed += count,
                RcptState::Deferred => metrics.deferred += count,
                RcptState::Delivered => metrics.delivered += count,
                RcptState::Failed => metrics.failed += count,
                RcptState::Expired => metrics.expired += count,
            }
        }
        Ok(metrics)
    }

    /// The most recent permanently-failed or expired recipients, newest
    /// first -- what actually went wrong, for the admin area to show.
    pub fn recent_failures(&self, limit: i64) -> Result<Vec<OutboundRecipient>> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, outbound_id, rcpt_to, domain, dsn_notify, state, attempts,
                        next_attempt_at, last_code, last_status, last_detail, delayed_dsn_sent
                 FROM outbound_rcpt WHERE state IN ('failed', 'expired')
                 ORDER BY id DESC LIMIT ?1",
            )
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((limit,), row_to_recipient)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage_err)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueMetrics {
    pub ready: i64,
    pub claimed: i64,
    pub deferred: i64,
    pub delivered: i64,
    pub failed: i64,
    pub expired: i64,
}

fn row_to_outbound(row: &rusqlite::Row) -> rusqlite::Result<OutboundMessage> {
    Ok(OutboundMessage {
        id: row.get(0)?,
        account_id: row.get(1)?,
        message_blob: row.get(2)?,
        envelope_from: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        dsn_envid: row.get(6)?,
        dsn_ret: row.get(7)?,
        is_dsn: row.get::<_, i64>(8)? != 0,
    })
}

fn row_to_recipient(row: &rusqlite::Row) -> rusqlite::Result<OutboundRecipient> {
    Ok(OutboundRecipient {
        id: row.get(0)?,
        outbound_id: row.get(1)?,
        rcpt_to: row.get(2)?,
        domain: row.get(3)?,
        dsn_notify: row.get(4)?,
        state: RcptState::from_db_str(&row.get::<_, String>(5)?),
        attempts: row.get(6)?,
        next_attempt_at: row.get(7)?,
        last_code: row.get(8)?,
        last_status: row.get(9)?,
        last_detail: row.get(10)?,
        delayed_dsn_sent: row.get::<_, i64>(11)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enqueue::enqueue;
    use crate::types::NewOutbound;
    use store::BlobStore;

    #[test]
    fn round_trips_outbound_and_recipients() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();

        let new = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n",
            recipients: &["bob@example.net"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };
        let id = enqueue(&queue, &blobs, &key, &new).unwrap();

        let outbound = queue.get_outbound(id).unwrap().expect("row exists");
        assert_eq!(outbound.envelope_from, "alice@example.com");
        assert!(!outbound.is_dsn);

        let rcpts = queue.recipients_for_outbound(id).unwrap();
        assert_eq!(rcpts.len(), 1);
        assert_eq!(rcpts[0].rcpt_to, "bob@example.net");
        assert_eq!(rcpts[0].state, RcptState::Ready);
    }

    #[test]
    fn unknown_id_returns_none() {
        let queue = QueueStore::open_in_memory().unwrap();
        assert!(queue.get_outbound(999).unwrap().is_none());
    }

    #[test]
    fn metrics_counts_by_state() {
        let queue = QueueStore::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let key = queue.ensure_dkim_key("example.com").unwrap();

        let new = NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n",
            recipients: &["bob@example.net", "carol@example.net"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        };
        let id = enqueue(&queue, &blobs, &key, &new).unwrap();
        let rcpts = queue.recipients_for_outbound(id).unwrap();
        {
            let conn = queue.conn.lock().unwrap();
            conn.execute(
                "UPDATE outbound_rcpt SET state = 'failed', last_code = 550, last_detail = 'no such user' WHERE id = ?1",
                (rcpts[0].id,),
            )
            .unwrap();
        }

        let metrics = queue.metrics().unwrap();
        assert_eq!(metrics.ready, 1);
        assert_eq!(metrics.failed, 1);

        let failures = queue.recent_failures(10).unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].last_detail.as_deref(), Some("no such user"));
    }
}
