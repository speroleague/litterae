//! Mailboxes (JMAP folders). System mailboxes only for now: their names
//! are fixed protocol-level labels ("Inbox", "Archive", ...), not user
//! content, so cleartext is fine -- custom user-named folders would need
//! the sealed name-map treatment custom labels get, and aren't built yet.

use rusqlite::OptionalExtension;

use common::Result;

use crate::metadata::{storage_err, MetadataStore};

pub const ROLE_INBOX: &str = "inbox";
pub const ROLE_ARCHIVE: &str = "archive";
pub const ROLE_TRASH: &str = "trash";
pub const ROLE_SENT: &str = "sent";
pub const ROLE_DRAFTS: &str = "drafts";
pub const ROLE_JUNK: &str = "junk";

const SYSTEM_ROLES: &[(&str, &str)] = &[
    (ROLE_INBOX, "Inbox"),
    (ROLE_ARCHIVE, "Archive"),
    (ROLE_TRASH, "Trash"),
    (ROLE_SENT, "Sent"),
    (ROLE_DRAFTS, "Drafts"),
    (ROLE_JUNK, "Junk"),
];

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mailboxes (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL,
    role        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    UNIQUE(account_id, role)
);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub id: i64,
    pub account_id: i64,
    pub role: String,
    pub name: String,
}

impl MetadataStore {
    /// Returns the account's mailbox for `role`, backfilling any missing
    /// mailboxes from the standard set for this account. Runs the
    /// INSERT OR IGNORE loop unconditionally (not just when the account has
    /// no mailboxes at all) so accounts created before a role was added to
    /// `SYSTEM_ROLES` still pick it up on the next call.
    pub fn ensure_mailbox(&self, account_id: i64, role: &str) -> Result<Mailbox> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        for (role, name) in SYSTEM_ROLES {
            conn.execute(
                "INSERT OR IGNORE INTO mailboxes (account_id, role, name) VALUES (?1, ?2, ?3)",
                (account_id, role, name),
            )
            .map_err(storage_err)?;
        }
        drop(conn);

        self.get_mailbox_by_role(account_id, role)?
            .ok_or_else(|| common::Error::Storage(format!("no such mailbox role: {role}")))
    }

    pub fn get_mailbox_by_role(&self, account_id: i64, role: &str) -> Result<Option<Mailbox>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            "SELECT id, account_id, role, name FROM mailboxes WHERE account_id = ?1 AND role = ?2",
            (account_id, role),
            row_to_mailbox,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn get_mailbox(&self, id: i64) -> Result<Option<Mailbox>> {
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        conn.query_row(
            "SELECT id, account_id, role, name FROM mailboxes WHERE id = ?1",
            (id,),
            row_to_mailbox,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn mailboxes_for_account(&self, account_id: i64) -> Result<Vec<Mailbox>> {
        // Bootstrapping via the inbox role also creates the rest of the
        // standard set, so callers always see a full mailbox list.
        self.ensure_mailbox(account_id, ROLE_INBOX)?;
        let conn = self.conn.lock().expect("metadata store mutex poisoned");
        let mut stmt = conn
            .prepare("SELECT id, account_id, role, name FROM mailboxes WHERE account_id = ?1 ORDER BY id")
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id,), row_to_mailbox)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }
}

fn row_to_mailbox(row: &rusqlite::Row) -> rusqlite::Result<Mailbox> {
    Ok(Mailbox {
        id: row.get(0)?,
        account_id: row.get(1)?,
        role: row.get(2)?,
        name: row.get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_mailbox_bootstraps_full_system_set() {
        let store = MetadataStore::open_in_memory().unwrap();
        let inbox = store.ensure_mailbox(1, ROLE_INBOX).unwrap();
        assert_eq!(inbox.role, ROLE_INBOX);
        assert_eq!(inbox.name, "Inbox");

        let all = store.mailboxes_for_account(1).unwrap();
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn ensure_mailbox_is_idempotent() {
        let store = MetadataStore::open_in_memory().unwrap();
        let first = store.ensure_mailbox(1, ROLE_TRASH).unwrap();
        let second = store.ensure_mailbox(1, ROLE_TRASH).unwrap();
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn mailboxes_are_scoped_per_account() {
        let store = MetadataStore::open_in_memory().unwrap();
        store.ensure_mailbox(1, ROLE_INBOX).unwrap();
        store.ensure_mailbox(2, ROLE_INBOX).unwrap();
        assert_eq!(store.mailboxes_for_account(1).unwrap().len(), 6);
        assert_eq!(store.mailboxes_for_account(2).unwrap().len(), 6);
    }
}
