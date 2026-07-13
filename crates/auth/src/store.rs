//! SQLite-backed account store. Opens its own connection to the shared
//! metadata database (WAL mode lets multiple connections to one file
//! coexist safely); `store::MetadataStore` owns the messages/blob-refs
//! tables, this owns `accounts`.

use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use common::config::Argon2Config;
use common::{Error, Result};
use crypto::{
    derive_pk, unwrap_amk, unwrap_priv_key, wrap_amk, wrap_priv_key, AccountMasterKey,
    HpkeKeypair, Salt,
};
use zeroize::Zeroizing;

use crate::account::Account;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    id                      INTEGER PRIMARY KEY,
    local_part              TEXT    NOT NULL,
    domain                  TEXT    NOT NULL,
    key_id                  INTEGER NOT NULL,
    salt                    BLOB    NOT NULL,
    wrapped_amk             BLOB    NOT NULL,
    account_pub             BLOB    NOT NULL,
    wrapped_account_priv    BLOB    NOT NULL,
    created_at              INTEGER NOT NULL,
    UNIQUE(local_part, domain)
);
"#;

fn storage_err(e: rusqlite::Error) -> Error {
    Error::Storage(e.to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

pub struct AuthStore {
    conn: Mutex<Connection>,
}

/// The AMK and account private key, recovered from a password. Callers hold
/// this only as long as the mailbox is unlocked (spec §3.1, §9).
pub struct UnlockedAccount {
    pub amk: AccountMasterKey,
    pub account_priv: Zeroizing<[u8; crypto::hpke_seal::PRIVATE_KEY_LEN]>,
}

impl AuthStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(storage_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "synchronous", "FULL")
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

    /// Provisions a brand-new account (spec §3.2): mints a random AMK and an
    /// account HPKE keypair, wraps the AMK under the password-derived key
    /// (committing construction) and the account private key under the AMK,
    /// and persists everything. This is the only place account private key
    /// material exists unwrapped, and only transiently.
    pub fn provision(
        &self,
        local_part: &str,
        domain: &str,
        password: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<Account> {
        let salt = Salt::generate();
        let pk =
            derive_pk(password, &salt, argon2_config).map_err(|e| Error::Crypto(e.to_string()))?;
        let amk = AccountMasterKey::generate();
        let wrapped_amk = wrap_amk(&pk, 1, &amk);

        let keypair = HpkeKeypair::generate();
        let wrapped_account_priv = wrap_priv_key(&amk, 1, keypair.private.as_slice());

        let created_at = now_unix();
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "INSERT INTO accounts
                (local_part, domain, key_id, salt, wrapped_amk, account_pub, wrapped_account_priv, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                local_part,
                domain,
                1i64,
                salt.0.as_slice(),
                wrapped_amk,
                keypair.public.as_slice(),
                wrapped_account_priv,
                created_at,
            ],
        )
        .map_err(storage_err)?;
        let id = conn.last_insert_rowid();

        Ok(Account {
            id,
            local_part: local_part.to_string(),
            domain: domain.to_string(),
            key_id: 1,
            salt: salt.0,
            wrapped_amk,
            account_pub: keypair.public,
            wrapped_account_priv,
            created_at,
        })
    }

    /// Looks up an account by its address. Returns `account_pub` in
    /// cleartext along with everything else -- callers on the inbound path
    /// (RCPT TO validation, delivery sealing) never need to unlock.
    pub fn find_by_address(&self, local_part: &str, domain: &str) -> Result<Option<Account>> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.query_row(
            "SELECT id, local_part, domain, key_id, salt, wrapped_amk, account_pub, wrapped_account_priv, created_at
             FROM accounts WHERE local_part = ?1 AND domain = ?2",
            rusqlite::params![local_part, domain],
            row_to_account,
        )
        .optional()
        .map_err(storage_err)
    }

    /// Looks up an account by its numeric id -- used by the outbound queue
    /// to find where to deliver a DSN locally.
    pub fn find_by_id(&self, id: i64) -> Result<Option<Account>> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.query_row(
            "SELECT id, local_part, domain, key_id, salt, wrapped_amk, account_pub, wrapped_account_priv, created_at
             FROM accounts WHERE id = ?1",
            (id,),
            row_to_account,
        )
        .optional()
        .map_err(storage_err)
    }

    /// Lists every account, newest first -- the admin area's account list.
    pub fn list_accounts(&self) -> Result<Vec<Account>> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, local_part, domain, key_id, salt, wrapped_amk, account_pub, wrapped_account_priv, created_at
                 FROM accounts ORDER BY created_at DESC",
            )
            .map_err(storage_err)?;
        let rows = stmt.query_map((), row_to_account).map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage_err)
    }

    /// Lists accounts for one domain -- used to check whether a domain has
    /// any mailboxes before letting an admin remove it.
    pub fn list_accounts_for_domain(&self, domain: &str) -> Result<Vec<Account>> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, local_part, domain, key_id, salt, wrapped_amk, account_pub, wrapped_account_priv, created_at
                 FROM accounts WHERE domain = ?1 ORDER BY local_part",
            )
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((domain,), row_to_account)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage_err)
    }

    pub fn delete_account(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute("DELETE FROM accounts WHERE id = ?1", (id,))
            .map_err(storage_err)?;
        Ok(())
    }

    /// Unlocks an account: derives PK from the password, unwraps the AMK,
    /// then unwraps the account private key. Fails (indistinguishably from a
    /// corrupt wrap) if the password is wrong.
    pub fn unlock(
        &self,
        account: &Account,
        password: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<UnlockedAccount> {
        let salt = Salt::from_bytes(account.salt);
        let pk =
            derive_pk(password, &salt, argon2_config).map_err(|e| Error::Crypto(e.to_string()))?;
        let amk =
            unwrap_amk(&pk, &account.wrapped_amk).map_err(|e| Error::Crypto(e.to_string()))?;
        let priv_bytes = unwrap_priv_key(&amk, &account.wrapped_account_priv)
            .map_err(|e| Error::Crypto(e.to_string()))?;

        let mut account_priv = Zeroizing::new([0u8; crypto::hpke_seal::PRIVATE_KEY_LEN]);
        account_priv.copy_from_slice(&priv_bytes);
        Ok(UnlockedAccount { amk, account_priv })
    }
}

fn row_to_account(row: &rusqlite::Row) -> rusqlite::Result<Account> {
    let salt_blob: Vec<u8> = row.get(4)?;
    let mut salt = [0u8; crypto::kdf::SALT_LEN];
    salt.copy_from_slice(&salt_blob);

    let pub_blob: Vec<u8> = row.get(6)?;
    let mut account_pub = [0u8; crypto::hpke_seal::PUBLIC_KEY_LEN];
    account_pub.copy_from_slice(&pub_blob);

    Ok(Account {
        id: row.get(0)?,
        local_part: row.get(1)?,
        domain: row.get(2)?,
        key_id: row.get::<_, i64>(3)? as u16,
        salt,
        wrapped_amk: row.get(5)?,
        account_pub,
        wrapped_account_priv: row.get(7)?,
        created_at: row.get(8)?,
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
    fn provision_then_find() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"hunter2", &cfg)
            .unwrap();

        let found = store
            .find_by_address("alice", "example.com")
            .unwrap()
            .expect("account should exist");
        assert_eq!(found.id, account.id);
        assert_eq!(found.account_pub, account.account_pub);
        assert_eq!(found.address(), "alice@example.com");

        let by_id = store.find_by_id(account.id).unwrap().expect("account should exist");
        assert_eq!(by_id.address(), "alice@example.com");
        assert!(store.find_by_id(999_999).unwrap().is_none());
    }

    #[test]
    fn unknown_address_not_found() {
        let store = AuthStore::open_in_memory().unwrap();
        assert!(store
            .find_by_address("nobody", "example.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn unlock_with_correct_password_recovers_account_key() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("bob", "example.com", b"correct horse battery staple", &cfg)
            .unwrap();

        let unlocked = store
            .unlock(&account, b"correct horse battery staple", &cfg)
            .unwrap();

        // The recovered private key must actually pair with the cleartext
        // public key stored on the account: seal to account_pub, open with
        // the unlocked private key.
        let sealed = crypto::hpke_seal(&account.account_pub, account.key_id, b"info", b"secret")
            .unwrap();
        let opened = crypto::hpke_open(&unlocked.account_priv, b"info", &sealed).unwrap();
        assert_eq!(&opened[..], b"secret");
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("carol", "example.com", b"right password", &cfg)
            .unwrap();

        assert!(store.unlock(&account, b"wrong password", &cfg).is_err());
    }

    #[test]
    fn duplicate_address_rejected() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        store
            .provision("dave", "example.com", b"pw1", &cfg)
            .unwrap();
        assert!(store
            .provision("dave", "example.com", b"pw2", &cfg)
            .is_err());
    }

    #[test]
    fn list_accounts_returns_everyone() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        store.provision("alice", "example.com", b"pw", &cfg).unwrap();
        store.provision("bob", "other.example", b"pw", &cfg).unwrap();

        let all = store.list_accounts().unwrap();
        assert_eq!(all.len(), 2);

        let just_example_com = store.list_accounts_for_domain("example.com").unwrap();
        assert_eq!(just_example_com.len(), 1);
        assert_eq!(just_example_com[0].local_part, "alice");
    }

    #[test]
    fn delete_account_removes_it() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store.provision("alice", "example.com", b"pw", &cfg).unwrap();

        store.delete_account(account.id).unwrap();
        assert!(store.find_by_id(account.id).unwrap().is_none());
    }
}
