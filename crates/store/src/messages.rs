//! Inbound message metadata. Only opaque pointers and operationally-
//! necessary envelope data live here in cleartext -- message *content*
//! (body, and until unlocked, header semantics beyond routing) stays
//! inside the sealed blob. Message-ID/In-Reply-To/References are the one
//! exception: they're auto-generated identifiers already visible in
//! transit (DKIM-signed, exchanged with the world), not sensitive prose
//! like Subject/From -- keeping them in the clear is what lets threading
//! work as a metadata join instead of needing plaintext.

use rusqlite::OptionalExtension;

use common::Result;

use crate::metadata::{storage_err, MetadataStore};

/// JMAP keyword tagging a message as spam-routed (spec §8.1 content
/// scanning). Written at insert time by `delivery::deliver`, not
/// retrofitted via `update_message`.
pub const KEYWORD_JUNK: &str = "$junk";

/// Standard JMAP keyword (RFC 8621 §4.1) marking a message as an
/// unsent draft. Set at create time by `jmap`'s compose path, cleared
/// via `update_message` when `EmailSubmission/set` sends it.
pub const KEYWORD_DRAFT: &str = "$draft";

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    id                  INTEGER PRIMARY KEY,
    account_id          INTEGER NOT NULL,
    mailbox_id          INTEGER NOT NULL,
    thread_id           INTEGER NOT NULL,
    blob_hash           TEXT    NOT NULL,
    dek_wrap            BLOB    NOT NULL,
    mail_from           TEXT    NOT NULL,
    rcpt_to             TEXT    NOT NULL,
    remote_ip           TEXT    NOT NULL,
    size_bytes          INTEGER NOT NULL,
    spf_result          TEXT    NOT NULL,
    dkim_result         TEXT    NOT NULL,
    dmarc_result        TEXT    NOT NULL,
    received_at         INTEGER NOT NULL,
    keywords            TEXT    NOT NULL DEFAULT '',
    message_id_header   TEXT,
    in_reply_to         TEXT,
    references_header   TEXT,
    subject_hash        TEXT
);
CREATE INDEX IF NOT EXISTS ix_messages_account ON messages(account_id, received_at);
CREATE INDEX IF NOT EXISTS ix_messages_mailbox ON messages(account_id, mailbox_id, received_at);
CREATE INDEX IF NOT EXISTS ix_messages_thread ON messages(account_id, thread_id);
CREATE INDEX IF NOT EXISTS ix_messages_message_id ON messages(account_id, message_id_header);
CREATE INDEX IF NOT EXISTS ix_messages_subject_hash ON messages(account_id, subject_hash);
"#;

pub struct NewMessage<'a> {
    pub account_id: i64,
    pub mailbox_id: i64,
    pub thread_id: i64,
    pub blob_hash: &'a str,
    pub dek_wrap: &'a [u8],
    pub mail_from: &'a str,
    pub rcpt_to: &'a str,
    pub remote_ip: &'a str,
    pub size_bytes: i64,
    pub spf_result: &'a str,
    pub dkim_result: &'a str,
    pub dmarc_result: &'a str,
    pub received_at: i64,
    pub keywords: &'a str,
    pub message_id_header: Option<&'a str>,
    pub in_reply_to: Option<&'a str>,
    pub references_header: Option<&'a str>,
    pub subject_hash: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub id: i64,
    pub account_id: i64,
    pub mailbox_id: i64,
    pub thread_id: i64,
    pub blob_hash: String,
    pub dek_wrap: Vec<u8>,
    pub mail_from: String,
    pub rcpt_to: String,
    pub remote_ip: String,
    pub size_bytes: i64,
    pub spf_result: String,
    pub dkim_result: String,
    pub dmarc_result: String,
    pub received_at: i64,
    pub keywords: String,
    pub message_id_header: Option<String>,
    pub in_reply_to: Option<String>,
    pub references_header: Option<String>,
    pub subject_hash: Option<String>,
}

const MESSAGE_COLUMNS: &str = "id, account_id, mailbox_id, thread_id, blob_hash, dek_wrap, mail_from, rcpt_to,
     remote_ip, size_bytes, spf_result, dkim_result, dmarc_result, received_at, keywords,
     message_id_header, in_reply_to, references_header, subject_hash";

impl MetadataStore {
    pub fn insert_message(&self, msg: &NewMessage) -> Result<i64> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute(
            "INSERT INTO messages
                (account_id, mailbox_id, thread_id, blob_hash, dek_wrap, mail_from, rcpt_to,
                 remote_ip, size_bytes, spf_result, dkim_result, dmarc_result, received_at,
                 keywords, message_id_header, in_reply_to, references_header, subject_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            rusqlite::params![
                msg.account_id,
                msg.mailbox_id,
                msg.thread_id,
                msg.blob_hash,
                msg.dek_wrap,
                msg.mail_from,
                msg.rcpt_to,
                msg.remote_ip,
                msg.size_bytes,
                msg.spf_result,
                msg.dkim_result,
                msg.dmarc_result,
                msg.received_at,
                msg.keywords,
                msg.message_id_header,
                msg.in_reply_to,
                msg.references_header,
                msg.subject_hash,
            ],
        )
        .map_err(storage_err)?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_message(&self, id: i64) -> Result<Option<StoredMessage>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            &format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE id = ?1"),
            (id,),
            row_to_message,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn messages_for_account(&self, account_id: i64) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages WHERE account_id = ?1 ORDER BY received_at DESC"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id,), row_to_message)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    pub fn messages_in_mailbox(&self, account_id: i64, mailbox_id: i64) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages
                 WHERE account_id = ?1 AND mailbox_id = ?2 ORDER BY received_at DESC"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id, mailbox_id), row_to_message)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    pub fn messages_with_keyword(&self, account_id: i64, keyword: &str) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages
                 WHERE account_id = ?1 AND (',' || keywords || ',') LIKE ?2
                 ORDER BY received_at DESC"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id, format!("%,{keyword},%")), row_to_message)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    /// The inverse of `messages_with_keyword` -- e.g. "unread" (everything
    /// missing `$seen`) spanning every mailbox at once, the same way
    /// `messages_with_keyword` already does for "flagged".
    pub fn messages_without_keyword(&self, account_id: i64, keyword: &str) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages
                 WHERE account_id = ?1 AND NOT ((',' || keywords || ',') LIKE ?2)
                 ORDER BY received_at DESC"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id, format!("%,{keyword},%")), row_to_message)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    pub fn messages_in_thread(&self, account_id: i64, thread_id: i64) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages
                 WHERE account_id = ?1 AND thread_id = ?2 ORDER BY received_at ASC"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id, thread_id), row_to_message)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    /// Updates keywords and/or mailbox (JMAP Email/set). `None` leaves a
    /// field unchanged.
    pub fn update_message(
        &self,
        id: i64,
        mailbox_id: Option<i64>,
        keywords: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        if let Some(mailbox_id) = mailbox_id {
            conn.execute(
                "UPDATE messages SET mailbox_id = ?1 WHERE id = ?2",
                (mailbox_id, id),
            )
            .map_err(storage_err)?;
        }
        if let Some(keywords) = keywords {
            conn.execute(
                "UPDATE messages SET keywords = ?1 WHERE id = ?2",
                (keywords, id),
            )
            .map_err(storage_err)?;
        }
        Ok(())
    }

    pub fn delete_message(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute("DELETE FROM messages WHERE id = ?1", (id,))
            .map_err(storage_err)?;
        Ok(())
    }
}

fn row_to_message(row: &rusqlite::Row) -> rusqlite::Result<StoredMessage> {
    Ok(StoredMessage {
        id: row.get(0)?,
        account_id: row.get(1)?,
        mailbox_id: row.get(2)?,
        thread_id: row.get(3)?,
        blob_hash: row.get(4)?,
        dek_wrap: row.get(5)?,
        mail_from: row.get(6)?,
        rcpt_to: row.get(7)?,
        remote_ip: row.get(8)?,
        size_bytes: row.get(9)?,
        spf_result: row.get(10)?,
        dkim_result: row.get(11)?,
        dmarc_result: row.get(12)?,
        received_at: row.get(13)?,
        keywords: row.get(14)?,
        message_id_header: row.get(15)?,
        in_reply_to: row.get(16)?,
        references_header: row.get(17)?,
        subject_hash: row.get(18)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(account_id: i64) -> NewMessage<'static> {
        NewMessage {
            account_id,
            mailbox_id: 1,
            thread_id: 1,
            blob_hash: "deadbeef",
            dek_wrap: b"wrapped-dek-bytes",
            mail_from: "sender@example.net",
            rcpt_to: "alice@example.com",
            remote_ip: "203.0.113.5",
            size_bytes: 1234,
            spf_result: "pass",
            dkim_result: "pass",
            dmarc_result: "pass",
            received_at: 1_700_000_000,
            keywords: "",
            message_id_header: Some("<1@example.net>"),
            in_reply_to: None,
            references_header: None,
            subject_hash: Some("abc123"),
        }
    }

    #[test]
    fn insert_and_get_round_trip() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_message(&sample(1)).unwrap();
        let stored = store.get_message(id).unwrap().expect("message exists");
        assert_eq!(stored.account_id, 1);
        assert_eq!(stored.blob_hash, "deadbeef");
        assert_eq!(stored.dek_wrap, b"wrapped-dek-bytes");
        assert_eq!(stored.message_id_header.as_deref(), Some("<1@example.net>"));
    }

    #[test]
    fn messages_for_account_filters_and_orders() {
        let store = MetadataStore::open_in_memory().unwrap();
        let mut m1 = sample(1);
        m1.received_at = 100;
        let mut m2 = sample(1);
        m2.received_at = 200;
        let m3 = sample(2);

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();
        store.insert_message(&m3).unwrap();

        let msgs = store.messages_for_account(1).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].received_at, 200); // newest first
        assert_eq!(msgs[1].received_at, 100);
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = MetadataStore::open_in_memory().unwrap();
        assert!(store.get_message(999).unwrap().is_none());
    }

    #[test]
    fn update_message_changes_mailbox_and_keywords() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_message(&sample(1)).unwrap();

        store.update_message(id, Some(2), Some("$seen,$flagged")).unwrap();
        let stored = store.get_message(id).unwrap().unwrap();
        assert_eq!(stored.mailbox_id, 2);
        assert_eq!(stored.keywords, "$seen,$flagged");
    }

    #[test]
    fn messages_with_keyword_matches_exact_tokens_only() {
        let store = MetadataStore::open_in_memory().unwrap();
        let mut flagged = sample(1);
        flagged.keywords = "$seen,$flagged";
        let mut unflagged = sample(1);
        unflagged.keywords = "$seen";
        store.insert_message(&flagged).unwrap();
        store.insert_message(&unflagged).unwrap();

        let results = store.messages_with_keyword(1, "$flagged").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].keywords, "$seen,$flagged");
    }

    #[test]
    fn messages_without_keyword_is_the_exact_inverse() {
        let store = MetadataStore::open_in_memory().unwrap();
        let mut seen = sample(1);
        seen.keywords = "$seen";
        let mut unseen = sample(1);
        unseen.keywords = "";
        store.insert_message(&seen).unwrap();
        let unseen_id = store.insert_message(&unseen).unwrap();

        let results = store.messages_without_keyword(1, "$seen").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, unseen_id);
    }

    #[test]
    fn delete_message_removes_it() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_message(&sample(1)).unwrap();
        store.delete_message(id).unwrap();
        assert!(store.get_message(id).unwrap().is_none());
    }
}
