//! SQLite metadata store (spec §7): WAL mode, `synchronous = FULL` because
//! this database records which blobs and key-wraps exist -- durability
//! matters more than the throughput synchronous=NORMAL buys. One file,
//! trivially inspectable.
//!
//! The connection is wrapped in a `Mutex` so `MetadataStore` can be shared
//! (behind an `Arc`) across concurrent async tasks -- at personal/small-tenant
//! scale (spec §1) a brief lock during a synchronous SQLite call is fine;
//! `queue`/`delivery` extend this schema in later phases (spec §11), and a
//! `spawn_blocking` + connection-pool split (spec §9) is the natural next
//! step if that ever becomes a bottleneck.

use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

use common::{Error, Result};

pub(crate) fn storage_err(e: rusqlite::Error) -> Error {
    Error::Storage(e.to_string())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS blob_refs (
    hash        TEXT    PRIMARY KEY,
    ref_count   INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);
"#;

pub struct MetadataStore {
    pub(crate) conn: Mutex<Connection>,
}

impl MetadataStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(storage_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        conn.execute_batch(crate::mailboxes::SCHEMA)
            .map_err(storage_err)?;
        conn.execute_batch(crate::threads::SCHEMA)
            .map_err(storage_err)?;
        conn.execute_batch(crate::messages::SCHEMA)
            .map_err(storage_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        conn.execute_batch(crate::mailboxes::SCHEMA)
            .map_err(storage_err)?;
        conn.execute_batch(crate::threads::SCHEMA)
            .map_err(storage_err)?;
        conn.execute_batch(crate::messages::SCHEMA)
            .map_err(storage_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Increments (or inserts at 1) the refcount for `hash`.
    pub fn incref_blob(&self, hash: &str, now: i64) -> Result<()> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute(
            "INSERT INTO blob_refs (hash, ref_count, created_at) VALUES (?1, 1, ?2)
             ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1",
            (hash, now),
        )
        .map_err(storage_err)?;
        Ok(())
    }

    /// Decrements the refcount for `hash`, returning the count remaining.
    /// Callers should delete the underlying blob once this reaches zero.
    pub fn decref_blob(&self, hash: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute(
            "UPDATE blob_refs SET ref_count = ref_count - 1 WHERE hash = ?1",
            (hash,),
        )
        .map_err(storage_err)?;
        let remaining: i64 = conn
            .query_row(
                "SELECT ref_count FROM blob_refs WHERE hash = ?1",
                (hash,),
                |row| row.get(0),
            )
            .map_err(storage_err)?;
        Ok(remaining)
    }

    pub fn ref_count(&self, hash: &str) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            "SELECT ref_count FROM blob_refs WHERE hash = ?1",
            (hash,),
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(storage_err(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incref_and_decref_round_trip() {
        let store = MetadataStore::open_in_memory().unwrap();
        store.incref_blob("abc123", 1_700_000_000).unwrap();
        assert_eq!(store.ref_count("abc123").unwrap(), Some(1));

        store.incref_blob("abc123", 1_700_000_000).unwrap();
        assert_eq!(store.ref_count("abc123").unwrap(), Some(2));

        let remaining = store.decref_blob("abc123").unwrap();
        assert_eq!(remaining, 1);
        assert_eq!(store.ref_count("abc123").unwrap(), Some(1));
    }

    #[test]
    fn unknown_hash_has_no_refcount() {
        let store = MetadataStore::open_in_memory().unwrap();
        assert_eq!(store.ref_count("nonexistent").unwrap(), None);
    }
}
