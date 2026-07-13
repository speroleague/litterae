//! Thread assignment (JMAP `Thread` object, RFC 8621 §3.1). Threading is
//! computed once, at ingest, while the message is briefly plaintext --
//! same principle as any other body-derived classification (spec's
//! auto-file-by-body-keyword rule). The join keys it produces
//! (Message-ID, normalized-subject hash) are auto-generated identifiers,
//! not sensitive prose, so storing them in cleartext metadata doesn't leak
//! anything the message headers don't already show in transit.

use common::Result;

use crate::metadata::{storage_err, MetadataStore};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS threads (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL
);
"#;

/// Inputs for thread matching, already extracted from the plaintext
/// message at ingest.
pub struct ThreadMatch<'a> {
    pub account_id: i64,
    /// Message-IDs referenced by this message's In-Reply-To/References
    /// headers -- candidates to join an existing thread.
    pub reference_ids: &'a [String],
    /// Hash of the normalized subject (Re:/Fwd: stripped, lowercased,
    /// trimmed) -- fallback match when no reference resolves.
    pub subject_hash: Option<&'a str>,
}

impl MetadataStore {
    /// Finds an existing thread to join, or creates a new one.
    pub fn find_or_create_thread(&self, m: &ThreadMatch) -> Result<i64> {
        if let Some(id) = self.thread_by_reference(m.account_id, m.reference_ids)? {
            return Ok(id);
        }
        if let Some(hash) = m.subject_hash {
            if let Some(id) = self.thread_by_subject_hash(m.account_id, hash)? {
                return Ok(id);
            }
        }
        self.create_thread(m.account_id)
    }

    fn thread_by_reference(&self, account_id: i64, reference_ids: &[String]) -> Result<Option<i64>> {
        if reference_ids.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let placeholders = reference_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT thread_id FROM messages
             WHERE account_id = ? AND message_id_header IN ({placeholders})
             LIMIT 1"
        );
        let mut stmt = conn.prepare(&sql).map_err(storage_err)?;
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&account_id];
        for id in reference_ids {
            params.push(id);
        }
        stmt.query_row(params.as_slice(), |row| row.get(0))
            .optional_result()
    }

    fn thread_by_subject_hash(&self, account_id: i64, subject_hash: &str) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            "SELECT thread_id FROM messages
             WHERE account_id = ?1 AND subject_hash = ?2
             ORDER BY received_at DESC LIMIT 1",
            (account_id, subject_hash),
            |row| row.get(0),
        )
        .optional_result()
    }

    fn create_thread(&self, account_id: i64) -> Result<i64> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute("INSERT INTO threads (account_id) VALUES (?1)", (account_id,))
            .map_err(storage_err)?;
        Ok(conn.last_insert_rowid())
    }
}

/// Small helper trait so `.optional_result()` reads naturally at call
/// sites above instead of repeating the match-on-QueryReturnedNoRows
/// dance every time.
trait OptionalResult<T> {
    fn optional_result(self) -> Result<Option<T>>;
}

impl<T> OptionalResult<T> for rusqlite::Result<T> {
    fn optional_result(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(storage_err(e)),
        }
    }
}

/// Normalizes a subject for threading: strips repeated Re:/Fwd:/Fw:
/// prefixes (case-insensitive), trims whitespace, lowercases.
pub fn normalize_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.trim_start();
        let stripped = ["re:", "fwd:", "fw:"].iter().find_map(|prefix| {
            if lower.len() >= prefix.len() && lower[..prefix.len()].eq_ignore_ascii_case(prefix) {
                Some(lower[prefix.len()..].trim_start())
            } else {
                None
            }
        });
        match stripped {
            Some(rest) if rest.len() != s.len() => s = rest,
            _ => break,
        }
    }
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NewMessage;

    fn sample<'a>(account_id: i64, thread_id: i64, message_id: &'a str, subject_hash: &'a str) -> NewMessage<'a> {
        NewMessage {
            account_id,
            mailbox_id: 1,
            thread_id,
            blob_hash: "hash",
            dek_wrap: b"wrap",
            mail_from: "a@example.com",
            rcpt_to: "b@example.com",
            remote_ip: "127.0.0.1",
            size_bytes: 10,
            spf_result: "pass",
            dkim_result: "pass",
            dmarc_result: "pass",
            received_at: 1000,
            keywords: "",
            message_id_header: Some(message_id),
            in_reply_to: None,
            references_header: None,
            subject_hash: Some(subject_hash),
        }
    }

    #[test]
    fn normalizes_reply_and_forward_prefixes() {
        assert_eq!(normalize_subject("Re: Hello"), "hello");
        assert_eq!(normalize_subject("Fwd: Re: Hello"), "hello");
        assert_eq!(normalize_subject("RE: re: Hello"), "hello");
        assert_eq!(normalize_subject("Hello"), "hello");
    }

    #[test]
    fn new_thread_when_nothing_matches() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 1,
                reference_ids: &[],
                subject_hash: None,
            })
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn joins_existing_thread_by_message_id_reference() {
        let store = MetadataStore::open_in_memory().unwrap();
        let thread_id = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 1,
                reference_ids: &[],
                subject_hash: None,
            })
            .unwrap();
        store
            .insert_message(&sample(1, thread_id, "<1@example.com>", "hash-a"))
            .unwrap();

        let joined = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 1,
                reference_ids: &["<1@example.com>".to_string()],
                subject_hash: Some("different-hash"),
            })
            .unwrap();
        assert_eq!(joined, thread_id);
    }

    #[test]
    fn joins_existing_thread_by_subject_hash_fallback() {
        let store = MetadataStore::open_in_memory().unwrap();
        let thread_id = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 1,
                reference_ids: &[],
                subject_hash: None,
            })
            .unwrap();
        store
            .insert_message(&sample(1, thread_id, "<1@example.com>", "same-hash"))
            .unwrap();

        let joined = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 1,
                reference_ids: &["<unrelated@example.com>".to_string()],
                subject_hash: Some("same-hash"),
            })
            .unwrap();
        assert_eq!(joined, thread_id);
    }

    #[test]
    fn different_accounts_never_share_a_thread() {
        let store = MetadataStore::open_in_memory().unwrap();
        let thread_id = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 1,
                reference_ids: &[],
                subject_hash: None,
            })
            .unwrap();
        store
            .insert_message(&sample(1, thread_id, "<1@example.com>", "hash-a"))
            .unwrap();

        let other = store
            .find_or_create_thread(&ThreadMatch {
                account_id: 2,
                reference_ids: &["<1@example.com>".to_string()],
                subject_hash: Some("hash-a"),
            })
            .unwrap();
        assert_ne!(other, thread_id);
    }
}
