//! Session-scoped in-RAM full-text index (SQLite FTS5, `:memory:`). Built
//! lazily on first search after unlock by decrypting every message for the
//! account; dropped with the session on lock. At rest, nothing about
//! message content is ever indexed -- this exists only in the memory of a
//! process that currently holds the account's unwrapped private key.

use rayon::prelude::*;
use rusqlite::Connection;
use std::sync::Mutex;

use store::{BlobStore, MetadataStore};

pub struct SearchIndex {
    conn: Mutex<Option<Connection>>,
}

impl SearchIndex {
    pub fn new() -> Self {
        Self {
            conn: Mutex::new(None),
        }
    }

    /// Returns matching message row ids for `query`, building the index on
    /// first call this session.
    pub fn search(
        &self,
        blobs: &BlobStore,
        metadata: &MetadataStore,
        account_id: i64,
        account_priv: &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
        query: &str,
    ) -> common::Result<Vec<i64>> {
        let mut guard = self.conn.lock().expect("search index mutex poisoned");
        if guard.is_none() {
            *guard = Some(build_index(blobs, metadata, account_id, account_priv)?);
        }
        let conn = guard.as_ref().expect("just built");

        let mut stmt = conn
            .prepare("SELECT message_id FROM docs WHERE docs MATCH ?1 ORDER BY rank")
            .map_err(|e| common::Error::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([fts5_query(query)], |row| row.get::<_, i64>(0))
            .map_err(|e| common::Error::Storage(e.to_string()))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| common::Error::Storage(e.to_string()))
    }
}

impl Default for SearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

fn build_index(
    blobs: &BlobStore,
    metadata: &MetadataStore,
    account_id: i64,
    account_priv: &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
) -> common::Result<Connection> {
    let conn = Connection::open_in_memory().map_err(|e| common::Error::Storage(e.to_string()))?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE docs USING fts5(message_id UNINDEXED, subject, body);",
    )
    .map_err(|e| common::Error::Storage(e.to_string()))?;

    // Decrypting and MIME-parsing each message is independent CPU work --
    // do it in parallel across the blocking pool's threads. The in-memory
    // connection isn't `Sync`, so inserts still happen in one sequential
    // pass afterward.
    let docs: Vec<(i64, String, String)> = metadata
        .messages_for_account(account_id)?
        .par_iter()
        .filter_map(|stored| {
            let raw = delivery::open_message(blobs, stored, account_priv).ok()?; // corrupt/unreadable message shouldn't block the whole index
            let parsed = mail_parser::MessageParser::default().parse(&raw)?;
            let subject = parsed.subject().unwrap_or_default().to_string();
            let body = parsed.body_text(0).unwrap_or_default().to_string();
            Some((stored.id, subject, body))
        })
        .collect();

    for (message_id, subject, body) in docs {
        conn.execute(
            "INSERT INTO docs (message_id, subject, body) VALUES (?1, ?2, ?3)",
            rusqlite::params![message_id, subject, body],
        )
        .map_err(|e| common::Error::Storage(e.to_string()))?;
    }

    Ok(conn)
}

/// FTS5's MATCH syntax treats bare input as a query expression (operators
/// like `-`, `"`, `*` are meaningful); quote each token so free-text search
/// input can't be misinterpreted as FTS5 query syntax. Each quoted token
/// gets a trailing `*` for prefix matching -- FTS5 has no fuzzy/typo
/// tolerance, but exact-whole-token-only search feels badly broken for a
/// live-typing search box (typing "quart" while the message says
/// "Quarterly" would find nothing until the word was finished); prefix
/// matching is the cheap, native fix that covers what users actually
/// expect. `"tok"*` (asterisk immediately after the closing quote, no
/// space) is FTS5's documented syntax for "quoted string as a prefix".
fn fts5_query(query: &str) -> String {
    query
        .split_whitespace()
        .map(|tok| format!("\"{}\"*", tok.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::HpkeKeypair;
    use delivery::{AuthResults, InboundEnvelope, RecipientAccount};

    fn deliver_test_message(
        blobs: &BlobStore,
        metadata: &MetadataStore,
        account_id: i64,
        account_pub: [u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
        subject: &str,
        body: &str,
    ) {
        let raw = format!(
            "From: a@example.com\r\nTo: b@example.com\r\nSubject: {subject}\r\n\r\n{body}\r\n"
        );
        delivery::deliver(
            blobs,
            metadata,
            &RecipientAccount {
                id: account_id,
                account_pub,
                key_id: 1,
            },
            &InboundEnvelope {
                mail_from: "a@example.com".into(),
                rcpt_to: "b@example.com".into(),
                remote_ip: "203.0.113.5".parse().unwrap(),
            },
            &AuthResults {
                spf: "pass".into(),
                dkim: "pass".into(),
                dmarc: "pass".into(),
            },
            raw.as_bytes(),
            1_700_000_000,
            None,
            delivery::ScanMetadata::default(),
        )
        .unwrap();
    }

    #[test]
    fn finds_messages_by_body_and_subject_text() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();

        deliver_test_message(
            &blobs,
            &metadata,
            1,
            account.public,
            "Quarterly report",
            "please review the attached numbers",
        );
        deliver_test_message(
            &blobs,
            &metadata,
            1,
            account.public,
            "Dinner plans",
            "how about pizza tonight",
        );

        let index = SearchIndex::new();
        let hits = index
            .search(&blobs, &metadata, 1, &account.private, "pizza")
            .unwrap();
        assert_eq!(hits.len(), 1);

        let hits2 = index
            .search(&blobs, &metadata, 1, &account.private, "quarterly")
            .unwrap();
        assert_eq!(hits2.len(), 1);

        let hits3 = index
            .search(&blobs, &metadata, 1, &account.private, "nonexistentword")
            .unwrap();
        assert!(hits3.is_empty());
    }

    #[test]
    fn index_is_built_once_and_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        deliver_test_message(
            &blobs,
            &metadata,
            1,
            account.public,
            "First",
            "alpha content",
        );

        let index = SearchIndex::new();
        let hits = index
            .search(&blobs, &metadata, 1, &account.private, "alpha")
            .unwrap();
        assert_eq!(hits.len(), 1);

        // A message delivered after the index was built shouldn't appear
        // until a fresh SearchIndex (i.e. next unlock) is built.
        deliver_test_message(
            &blobs,
            &metadata,
            1,
            account.public,
            "Second",
            "beta content",
        );
        let hits2 = index
            .search(&blobs, &metadata, 1, &account.private, "beta")
            .unwrap();
        assert!(hits2.is_empty());
    }

    #[test]
    fn matches_a_partial_word_as_a_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        deliver_test_message(
            &blobs,
            &metadata,
            1,
            account.public,
            "Quarterly report",
            "numbers inside",
        );

        let index = SearchIndex::new();
        let hits = index
            .search(&blobs, &metadata, 1, &account.private, "quart")
            .unwrap();
        assert_eq!(hits.len(), 1);

        // A prefix that isn't actually a prefix of anything still finds
        // nothing -- this isn't typo-tolerant fuzzy matching, just
        // whole-word-so-far matching.
        let no_hits = index
            .search(&blobs, &metadata, 1, &account.private, "zzznope")
            .unwrap();
        assert!(no_hits.is_empty());
    }

    #[test]
    fn quotes_query_tokens_so_fts5_operators_cannot_break_the_query() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        deliver_test_message(
            &blobs,
            &metadata,
            1,
            account.public,
            "Test",
            "a NOT b situation",
        );

        let index = SearchIndex::new();
        // "NOT" is an FTS5 operator; as free-text search input it must not
        // be treated as one.
        let hits = index
            .search(&blobs, &metadata, 1, &account.private, "NOT")
            .unwrap();
        assert_eq!(hits.len(), 1);
    }
}
