//! Address-book entries. Like `messages.rs`, this module only ever
//! touches opaque bytes -- `sealed` is an AEAD blob the caller already
//! encrypted (see `jmap::contacts`), never plaintext name/email.

use rusqlite::OptionalExtension;

use common::Result;

use crate::metadata::{storage_err, MetadataStore};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL,
    sealed      BLOB    NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_contacts_account ON contacts(account_id);
"#;

#[derive(Debug, Clone, PartialEq)]
pub struct StoredContact {
    pub id: i64,
    pub account_id: i64,
    pub sealed: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

const CONTACT_COLUMNS: &str = "id, account_id, sealed, created_at, updated_at";

impl MetadataStore {
    pub fn insert_contact(&self, account_id: i64, sealed: &[u8], now: i64) -> Result<i64> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute(
            "INSERT INTO contacts (account_id, sealed, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)",
            rusqlite::params![account_id, sealed, now],
        )
        .map_err(storage_err)?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_contact(&self, id: i64) -> Result<Option<StoredContact>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE id = ?1"),
            (id,),
            row_to_contact,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn contacts_for_account(&self, account_id: i64) -> Result<Vec<StoredContact>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {CONTACT_COLUMNS} FROM contacts WHERE account_id = ?1 ORDER BY id ASC"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id,), row_to_contact)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    pub fn update_contact(&self, id: i64, sealed: &[u8], now: i64) -> Result<()> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute(
            "UPDATE contacts SET sealed = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![sealed, now, id],
        )
        .map_err(storage_err)?;
        Ok(())
    }

    pub fn delete_contact(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.execute("DELETE FROM contacts WHERE id = ?1", (id,))
            .map_err(storage_err)?;
        Ok(())
    }
}

fn row_to_contact(row: &rusqlite::Row) -> rusqlite::Result<StoredContact> {
    Ok(StoredContact {
        id: row.get(0)?,
        account_id: row.get(1)?,
        sealed: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_round_trip() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_contact(1, b"sealed-bytes", 1_700_000_000).unwrap();
        let stored = store.get_contact(id).unwrap().expect("contact exists");
        assert_eq!(stored.account_id, 1);
        assert_eq!(stored.sealed, b"sealed-bytes");
        assert_eq!(stored.created_at, 1_700_000_000);
        assert_eq!(stored.updated_at, 1_700_000_000);
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = MetadataStore::open_in_memory().unwrap();
        assert!(store.get_contact(999).unwrap().is_none());
    }

    #[test]
    fn contacts_for_account_filters_by_account() {
        let store = MetadataStore::open_in_memory().unwrap();
        store.insert_contact(1, b"a", 100).unwrap();
        store.insert_contact(1, b"b", 100).unwrap();
        store.insert_contact(2, b"c", 100).unwrap();

        let contacts = store.contacts_for_account(1).unwrap();
        assert_eq!(contacts.len(), 2);
        assert!(contacts.iter().all(|c| c.account_id == 1));
    }

    #[test]
    fn update_contact_changes_sealed_and_updated_at() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_contact(1, b"old", 100).unwrap();
        store.update_contact(id, b"new", 200).unwrap();
        let stored = store.get_contact(id).unwrap().unwrap();
        assert_eq!(stored.sealed, b"new");
        assert_eq!(stored.updated_at, 200);
        assert_eq!(stored.created_at, 100);
    }

    #[test]
    fn delete_contact_removes_it() {
        let store = MetadataStore::open_in_memory().unwrap();
        let id = store.insert_contact(1, b"a", 100).unwrap();
        store.delete_contact(id).unwrap();
        assert!(store.get_contact(id).unwrap().is_none());
    }
}
