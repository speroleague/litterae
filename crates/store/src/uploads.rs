//! Pending (not-yet-sent) attachment blobs from `POST /jmap/upload`.
//! Referenced by a `u{id}` blobId until `EmailSubmission/set` folds them
//! into a composed message's own sealed blob -- see
//! `crates/jmap/src/compose.rs`. Not cleaned up once consumed or
//! abandoned, same as message blobs: this codebase has no blob GC
//! anywhere yet.

use rusqlite::OptionalExtension;

use common::Result;

use crate::metadata::{storage_err, MetadataStore};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS uploads (
    id              INTEGER PRIMARY KEY,
    account_id      INTEGER NOT NULL,
    blob_hash       TEXT    NOT NULL,
    dek_wrap        BLOB    NOT NULL,
    key_id          INTEGER NOT NULL,
    filename        TEXT    NOT NULL,
    content_type    TEXT    NOT NULL,
    size_bytes      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_uploads_account ON uploads(account_id);
"#;

pub struct NewUpload<'a> {
    pub account_id: i64,
    pub blob_hash: &'a str,
    pub dek_wrap: &'a [u8],
    pub key_id: u16,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size_bytes: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredUpload {
    pub id: i64,
    pub account_id: i64,
    pub blob_hash: String,
    pub dek_wrap: Vec<u8>,
    pub key_id: u16,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub created_at: i64,
}

const UPLOAD_COLUMNS: &str =
    "id, account_id, blob_hash, dek_wrap, key_id, filename, content_type, size_bytes, created_at";

impl MetadataStore {
    pub fn insert_upload(&self, upload: &NewUpload) -> Result<i64> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute(
            "INSERT INTO uploads
                (account_id, blob_hash, dek_wrap, key_id, filename, content_type, size_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                upload.account_id,
                upload.blob_hash,
                upload.dek_wrap,
                upload.key_id,
                upload.filename,
                upload.content_type,
                upload.size_bytes,
                upload.created_at,
            ],
        )
        .map_err(storage_err)?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_upload(&self, id: i64) -> Result<Option<StoredUpload>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            &format!("SELECT {UPLOAD_COLUMNS} FROM uploads WHERE id = ?1"),
            (id,),
            row_to_upload,
        )
        .optional()
        .map_err(storage_err)
    }
}

fn row_to_upload(row: &rusqlite::Row) -> rusqlite::Result<StoredUpload> {
    Ok(StoredUpload {
        id: row.get(0)?,
        account_id: row.get(1)?,
        blob_hash: row.get(2)?,
        dek_wrap: row.get(3)?,
        key_id: row.get::<_, i64>(4)? as u16,
        filename: row.get(5)?,
        content_type: row.get(6)?,
        size_bytes: row.get(7)?,
        created_at: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(account_id: i64) -> NewUpload<'static> {
        NewUpload {
            account_id,
            blob_hash: "deadbeef",
            dek_wrap: b"wrapped-dek-bytes",
            key_id: 1,
            filename: "invoice.pdf",
            content_type: "application/pdf",
            size_bytes: 1234,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn insert_and_get_round_trip() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_upload(&sample(1)).unwrap();
        let stored = store.get_upload(id).unwrap().expect("upload exists");
        assert_eq!(stored.account_id, 1);
        assert_eq!(stored.blob_hash, "deadbeef");
        assert_eq!(stored.filename, "invoice.pdf");
        assert_eq!(stored.content_type, "application/pdf");
        assert_eq!(stored.size_bytes, 1234);
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = MetadataStore::open_in_memory().unwrap();
        assert!(store.get_upload(999_999).unwrap().is_none());
    }
}
