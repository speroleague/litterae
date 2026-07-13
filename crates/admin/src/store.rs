//! Admin identity and hosted-domain storage. Deliberately separate from
//! `auth::AuthStore` (mailbox accounts): an admin has no mailbox to
//! encrypt, so there's no AMK/HPKE hierarchy here -- just a password
//! check, reusing the same Argon2id primitive (`crypto::derive_pk`) mailbox
//! unlock uses, compared in constant time. This separation is also a
//! hardening property (admin principals never reach mailbox JMAP/mail
//! objects, because they're not the same kind of credential at all).

use rand::RngExt;
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use common::config::Argon2Config;
use common::{Error, Result};
use crypto::{derive_pk, Salt};
use subtle::ConstantTimeEq;

use crate::types::{Admin, Domain};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admins (
    id                      INTEGER PRIMARY KEY,
    username                TEXT    NOT NULL UNIQUE,
    salt                    BLOB    NOT NULL,
    derived_key             BLOB    NOT NULL,
    must_change_password    INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id                      INTEGER PRIMARY KEY,
    name                    TEXT    NOT NULL UNIQUE,
    catch_all_local_part    TEXT,
    verification_token      TEXT,
    verified_at             INTEGER,
    created_at              INTEGER NOT NULL
);
"#;

/// Adds columns introduced after this table's initial release. Additive
/// only, guarded against re-running on a database that already has them --
/// there's no migration framework in this project (every store ships its
/// full schema in one `CREATE TABLE IF NOT EXISTS`, which is a no-op
/// against a table that already exists), so an on-disk `domains` table
/// from before domain verification existed needs this to pick the new
/// columns up. A fresh database already gets them from `SCHEMA` above and
/// this is a no-op for it.
fn migrate_domains_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(domains)")
        .map_err(storage_err)?;
    let existing: Vec<String> = stmt
        .query_map((), |row| row.get::<_, String>(1))
        .map_err(storage_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(storage_err)?;

    if !existing.iter().any(|c| c == "verification_token") {
        conn.execute("ALTER TABLE domains ADD COLUMN verification_token TEXT", ())
            .map_err(storage_err)?;
    }
    if !existing.iter().any(|c| c == "verified_at") {
        conn.execute("ALTER TABLE domains ADD COLUMN verified_at INTEGER", ())
            .map_err(storage_err)?;
    }

    // Domains created before this migration have a NULL token from the
    // ADD COLUMN above (ALTER TABLE has no way to compute a per-row
    // default) -- backfill one so every domain has something to publish,
    // not just ones created after this feature shipped.
    let ids_needing_token: Vec<i64> = conn
        .prepare("SELECT id FROM domains WHERE verification_token IS NULL")
        .map_err(storage_err)?
        .query_map((), |row| row.get(0))
        .map_err(storage_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(storage_err)?;
    for id in ids_needing_token {
        conn.execute(
            "UPDATE domains SET verification_token = ?1 WHERE id = ?2",
            (generate_verification_token(), id),
        )
        .map_err(storage_err)?;
    }
    Ok(())
}

fn storage_err(e: rusqlite::Error) -> Error {
    Error::Storage(e.to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

pub struct AdminStore {
    conn: Mutex<Connection>,
}

struct AdminAuthRow {
    id: i64,
    salt: Vec<u8>,
    derived_key: Vec<u8>,
    must_change_password: i64,
    created_at: i64,
}

impl AdminStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(storage_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        migrate_domains_columns(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        migrate_domains_columns(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn has_admin(&self) -> Result<bool> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM admins", (), |row| row.get(0))
            .map_err(storage_err)?;
        Ok(count > 0)
    }

    /// Creates the first admin, with a forced password change on next
    /// login. A no-op (never overwrites) if an admin already exists --
    /// bootstrap fires once, ever, so leaving `[admin]` in the config
    /// after first startup can't reset a password out from under someone.
    /// Returns the derived password key only when it actually created the
    /// admin, so a caller can use that same moment to bootstrap keys that
    /// wrap under it (e.g. the audit log's encryption key).
    pub fn bootstrap(
        &self,
        username: &str,
        password: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<Option<[u8; 32]>> {
        if self.has_admin()? {
            return Ok(None);
        }
        let salt = Salt::generate();
        let pk = derive_pk(password, &salt, argon2_config).map_err(|e| Error::Crypto(e.to_string()))?;

        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.execute(
            "INSERT INTO admins (username, salt, derived_key, must_change_password, created_at)
             VALUES (?1, ?2, ?3, 1, ?4)",
            rusqlite::params![username, salt.0.as_slice(), pk.as_bytes().as_slice(), now_unix()],
        )
        .map_err(storage_err)?;
        Ok(Some(*pk.as_bytes()))
    }

    /// Verifies a login attempt, returning the admin and their derived
    /// password key on success. Failure (wrong username or wrong password)
    /// is indistinguishable, same as mailbox unlock. The derived key is the
    /// same one that wraps the audit log's encryption key -- callers that
    /// need to read the audit log carry it forward from here, not
    /// re-derive it.
    pub fn verify_login(
        &self,
        username: &str,
        password: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<Option<(Admin, [u8; 32])>> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        let row: Option<AdminAuthRow> = conn
            .query_row(
                "SELECT id, salt, derived_key, must_change_password, created_at FROM admins WHERE username = ?1",
                (username,),
                |row| {
                    Ok(AdminAuthRow {
                        id: row.get(0)?,
                        salt: row.get(1)?,
                        derived_key: row.get(2)?,
                        must_change_password: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(storage_err)?;
        drop(conn);

        let Some(AdminAuthRow {
            id,
            salt: salt_bytes,
            derived_key: stored_derived,
            must_change_password: must_change,
            created_at,
        }) = row
        else {
            return Ok(None);
        };
        let mut salt_arr = [0u8; crypto::kdf::SALT_LEN];
        if salt_bytes.len() != salt_arr.len() {
            return Ok(None);
        }
        salt_arr.copy_from_slice(&salt_bytes);
        let salt = Salt::from_bytes(salt_arr);
        let pk = derive_pk(password, &salt, argon2_config).map_err(|e| Error::Crypto(e.to_string()))?;

        if pk.as_bytes().as_slice().ct_eq(&stored_derived).unwrap_u8() != 1 {
            return Ok(None);
        }
        Ok(Some((
            Admin {
                id,
                username: username.to_string(),
                must_change_password: must_change != 0,
                created_at,
            },
            *pk.as_bytes(),
        )))
    }

    pub fn username_for_id(&self, admin_id: i64) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.query_row(
            "SELECT username FROM admins WHERE id = ?1",
            (admin_id,),
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_err)
    }

    /// Rewraps the admin's password and returns the new derived key, so a
    /// caller can rewrap anything keyed to the old one (the audit log's
    /// encryption key) in the same breath.
    pub fn change_password(
        &self,
        admin_id: i64,
        new_password: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<[u8; 32]> {
        let salt = Salt::generate();
        let pk = derive_pk(new_password, &salt, argon2_config).map_err(|e| Error::Crypto(e.to_string()))?;
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.execute(
            "UPDATE admins SET salt = ?1, derived_key = ?2, must_change_password = 0 WHERE id = ?3",
            rusqlite::params![salt.0.as_slice(), pk.as_bytes().as_slice(), admin_id],
        )
        .map_err(storage_err)?;
        Ok(*pk.as_bytes())
    }

    pub fn list_domains(&self) -> Result<Vec<Domain>> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, name, catch_all_local_part, verification_token, verified_at, created_at \
                 FROM domains ORDER BY name",
            )
            .map_err(storage_err)?;
        let rows = stmt.query_map((), row_to_domain).map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage_err)
    }

    pub fn get_domain(&self, id: i64) -> Result<Option<Domain>> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.query_row(
            "SELECT id, name, catch_all_local_part, verification_token, verified_at, created_at \
             FROM domains WHERE id = ?1",
            (id,),
            row_to_domain,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn get_domain_by_name(&self, name: &str) -> Result<Option<Domain>> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.query_row(
            "SELECT id, name, catch_all_local_part, verification_token, verified_at, created_at \
             FROM domains WHERE name = ?1",
            (name,),
            row_to_domain,
        )
        .optional()
        .map_err(storage_err)
    }

    pub fn create_domain(&self, name: &str, catch_all_local_part: Option<&str>) -> Result<Domain> {
        let created_at = now_unix();
        let verification_token = generate_verification_token();
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.execute(
            "INSERT INTO domains (name, catch_all_local_part, verification_token, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, catch_all_local_part, verification_token, created_at],
        )
        .map_err(storage_err)?;
        Ok(Domain {
            id: conn.last_insert_rowid(),
            name: name.to_string(),
            catch_all_local_part: catch_all_local_part.map(str::to_string),
            verification_token,
            verified_at: None,
            created_at,
        })
    }

    pub fn set_catch_all(&self, domain_id: i64, catch_all_local_part: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.execute(
            "UPDATE domains SET catch_all_local_part = ?1 WHERE id = ?2",
            (catch_all_local_part, domain_id),
        )
        .map_err(storage_err)?;
        Ok(())
    }

    /// Records a successful DNS TXT verification. Advisory only -- nothing
    /// else in litterae reads `verified_at` to gate behavior; it exists
    /// purely so the admin panel can show the operator whether they've
    /// actually published the record they were shown.
    pub fn mark_domain_verified(&self, id: i64, verified_at: i64) -> Result<()> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.execute(
            "UPDATE domains SET verified_at = ?1 WHERE id = ?2",
            (verified_at, id),
        )
        .map_err(storage_err)?;
        Ok(())
    }

    pub fn delete_domain(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("admin store mutex poisoned");
        conn.execute("DELETE FROM domains WHERE id = ?1", (id,))
            .map_err(storage_err)?;
        Ok(())
    }
}

fn generate_verification_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn row_to_domain(row: &rusqlite::Row) -> rusqlite::Result<Domain> {
    Ok(Domain {
        id: row.get(0)?,
        name: row.get(1)?,
        catch_all_local_part: row.get(2)?,
        verification_token: row.get(3)?,
        verified_at: row.get(4)?,
        created_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_config() -> Argon2Config {
        Argon2Config {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn bootstrap_creates_admin_requiring_password_change() {
        let store = AdminStore::open_in_memory().unwrap();
        let cfg = fast_config();
        assert!(!store.has_admin().unwrap());

        store.bootstrap("admin", b"change-me-please", &cfg).unwrap();
        assert!(store.has_admin().unwrap());

        let (admin, _pk) = store.verify_login("admin", b"change-me-please", &cfg).unwrap().unwrap();
        assert!(admin.must_change_password);
    }

    #[test]
    fn bootstrap_is_a_noop_once_an_admin_exists() {
        let store = AdminStore::open_in_memory().unwrap();
        let cfg = fast_config();
        store.bootstrap("admin", b"first-password", &cfg).unwrap();

        // A second bootstrap call (e.g. config left in place after first
        // startup) must not reset the password.
        store.bootstrap("admin", b"second-password", &cfg).unwrap();

        assert!(store.verify_login("admin", b"first-password", &cfg).unwrap().is_some());
        assert!(store.verify_login("admin", b"second-password", &cfg).unwrap().is_none());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let store = AdminStore::open_in_memory().unwrap();
        let cfg = fast_config();
        store.bootstrap("admin", b"correct", &cfg).unwrap();
        assert!(store.verify_login("admin", b"wrong", &cfg).unwrap().is_none());
    }

    #[test]
    fn change_password_clears_must_change_flag() {
        let store = AdminStore::open_in_memory().unwrap();
        let cfg = fast_config();
        store.bootstrap("admin", b"initial", &cfg).unwrap();
        let (admin, _pk) = store.verify_login("admin", b"initial", &cfg).unwrap().unwrap();

        store.change_password(admin.id, b"new-password", &cfg).unwrap();

        assert!(store.verify_login("admin", b"initial", &cfg).unwrap().is_none());
        let (updated, _pk) = store.verify_login("admin", b"new-password", &cfg).unwrap().unwrap();
        assert!(!updated.must_change_password);
    }

    #[test]
    fn domain_crud_and_catch_all() {
        let store = AdminStore::open_in_memory().unwrap();
        let domain = store.create_domain("example.com", None).unwrap();
        assert!(domain.catch_all_local_part.is_none());

        store.set_catch_all(domain.id, Some("catchall")).unwrap();
        let updated = store.get_domain_by_name("example.com").unwrap().unwrap();
        assert_eq!(updated.catch_all_local_part.as_deref(), Some("catchall"));

        store.set_catch_all(domain.id, None).unwrap();
        let cleared = store.get_domain_by_name("example.com").unwrap().unwrap();
        assert!(cleared.catch_all_local_part.is_none());

        assert_eq!(store.list_domains().unwrap().len(), 1);
        store.delete_domain(domain.id).unwrap();
        assert!(store.list_domains().unwrap().is_empty());
    }

    #[test]
    fn duplicate_domain_rejected() {
        let store = AdminStore::open_in_memory().unwrap();
        store.create_domain("example.com", None).unwrap();
        assert!(store.create_domain("example.com", None).is_err());
    }

    #[test]
    fn new_domains_get_a_unique_verification_token_and_start_unverified() {
        let store = AdminStore::open_in_memory().unwrap();
        let a = store.create_domain("a.example.com", None).unwrap();
        let b = store.create_domain("b.example.com", None).unwrap();
        assert!(!a.verification_token.is_empty());
        assert_ne!(a.verification_token, b.verification_token);
        assert!(a.verified_at.is_none());
    }

    #[test]
    fn mark_domain_verified_sets_the_timestamp() {
        let store = AdminStore::open_in_memory().unwrap();
        let domain = store.create_domain("example.com", None).unwrap();
        store.mark_domain_verified(domain.id, 1_700_000_000).unwrap();
        let updated = store.get_domain(domain.id).unwrap().unwrap();
        assert_eq!(updated.verified_at, Some(1_700_000_000));
    }

    #[test]
    fn migration_backfills_tokens_for_domains_predating_verification() {
        // Simulate an on-disk database from before verification_token/
        // verified_at existed: the pre-migration schema, with a domain row
        // inserted the old way (no token column at all).
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE domains (
                id                      INTEGER PRIMARY KEY,
                name                    TEXT    NOT NULL UNIQUE,
                catch_all_local_part    TEXT,
                created_at              INTEGER NOT NULL
            );
            INSERT INTO domains (name, created_at) VALUES ('old.example.com', 1700000000);
            "#,
        )
        .unwrap();

        migrate_domains_columns(&conn).unwrap();

        let token: Option<String> = conn
            .query_row(
                "SELECT verification_token FROM domains WHERE name = 'old.example.com'",
                (),
                |row| row.get(0),
            )
            .unwrap();
        assert!(token.is_some_and(|t| !t.is_empty()));
    }
}
