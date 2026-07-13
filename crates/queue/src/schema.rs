//! Durable outbound queue state (own SQLite connection, WAL mode --
//! multiple connections to the same file coexist fine, same pattern as
//! `auth::AuthStore`). A crash must never lose track of an in-flight send:
//! every state transition is a committed SQLite write, never memory-only.

use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

use common::{Error, Result};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS outbound (
    id              INTEGER PRIMARY KEY,
    account_id      INTEGER NOT NULL,
    message_blob    TEXT    NOT NULL,
    envelope_from   TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    dsn_envid       TEXT,
    dsn_ret         TEXT,
    is_dsn          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS outbound_rcpt (
    id               INTEGER PRIMARY KEY,
    outbound_id      INTEGER NOT NULL REFERENCES outbound(id) ON DELETE CASCADE,
    rcpt_to          TEXT    NOT NULL,
    domain           TEXT    NOT NULL,
    dsn_notify       TEXT    NOT NULL DEFAULT 'FAILURE',
    state            TEXT    NOT NULL DEFAULT 'ready',
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  INTEGER NOT NULL,
    claimed_by       TEXT,
    claimed_at       INTEGER,
    last_code        INTEGER,
    last_status      TEXT,
    last_detail      TEXT,
    delayed_dsn_sent INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_rcpt_due ON outbound_rcpt(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_rcpt_outbound ON outbound_rcpt(outbound_id);

CREATE TABLE IF NOT EXISTS dkim_keys (
    domain      TEXT PRIMARY KEY,
    selector    TEXT NOT NULL,
    private_der BLOB NOT NULL,
    public_der  BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
"#;

pub(crate) fn storage_err(e: rusqlite::Error) -> Error {
    Error::Storage(e.to_string())
}

pub struct QueueStore {
    pub(crate) conn: Mutex<Connection>,
}

impl QueueStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(storage_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}
