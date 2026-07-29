//! SQLite-backed account store. Opens its own connection to the shared
//! metadata database (WAL mode lets multiple connections to one file
//! coexist safely); `store::MetadataStore` owns the messages/blob-refs
//! tables, this owns `accounts`.

use rand::RngExt;
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use common::config::Argon2Config;
use common::{Error, Result};
use crypto::{
    derive_pk, unwrap_amk, unwrap_priv_key, wrap_amk, wrap_priv_key, AccountMasterKey, HpkeKeypair,
    Salt,
};
use zeroize::Zeroizing;

use crate::account::Account;
use crate::app_password::{AppPasswordScope, AppPasswordSummary};

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

CREATE TABLE IF NOT EXISTS app_passwords (
    id              INTEGER PRIMARY KEY,
    account_id      INTEGER NOT NULL,
    label           TEXT    NOT NULL,
    scope           TEXT    NOT NULL,
    key_id          INTEGER NOT NULL,
    salt            BLOB    NOT NULL,
    wrapped_amk     BLOB    NOT NULL,
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER
);
"#;

/// Adds columns introduced after this table's initial release. Additive
/// only (see `admin::store::migrate_domains_columns` for the same
/// pattern) -- a fresh database already gets this column from `SCHEMA`
/// above and this is a no-op for it.
fn migrate_accounts_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(accounts)")
        .map_err(storage_err)?;
    let existing: Vec<String> = stmt
        .query_map((), |row| row.get::<_, String>(1))
        .map_err(storage_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(storage_err)?;

    if !existing.iter().any(|c| c == "signature_sealed") {
        conn.execute("ALTER TABLE accounts ADD COLUMN signature_sealed BLOB", ())
            .map_err(storage_err)?;
    }
    Ok(())
}

/// 160 bits -- generated, not user-chosen, so this doesn't need Argon2id's
/// margin against a weak-input dictionary attack the way a real password
/// does; it needs to be easy to paste into a client, not memorable.
const APP_PASSWORD_SECRET_LEN: usize = 20;

fn storage_err(e: rusqlite::Error) -> Error {
    Error::Storage(e.to_string())
}

/// Shared tail of `unlock`/`unlock_any`: once an AMK has been recovered by
/// whichever credential matched, unwrapping the account private key is
/// identical regardless of which one it was.
fn finish_unlock(amk: AccountMasterKey, wrapped_account_priv: &[u8]) -> Result<UnlockedAccount> {
    let priv_bytes =
        unwrap_priv_key(&amk, wrapped_account_priv).map_err(|e| Error::Crypto(e.to_string()))?;
    let mut account_priv = Zeroizing::new([0u8; crypto::hpke_seal::PRIVATE_KEY_LEN]);
    account_priv.copy_from_slice(&priv_bytes);
    Ok(UnlockedAccount { amk, account_priv })
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
        migrate_accounts_columns(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        conn.execute_batch(SCHEMA).map_err(storage_err)?;
        migrate_accounts_columns(&conn)?;
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
        if !common::input::valid_local_part(local_part) || !common::input::valid_domain_name(domain)
        {
            return Err(Error::Config("invalid mailbox address".to_string()));
        }
        let domain = domain.to_ascii_lowercase();
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
                &domain,
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
            domain,
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
        let domain = domain.to_ascii_lowercase();
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
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
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
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
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
        finish_unlock(amk, &account.wrapped_account_priv)
    }

    /// Tries the primary password first, then each of the account's app
    /// passwords (spec §8.4) in turn -- a bare credential has no way to say
    /// which slot it belongs to, so this is the only option. Cost is one
    /// Argon2id derivation per candidate tried; fine for the small number
    /// of app passwords a personal account actually has. Returns which
    /// scope matched so the caller (JMAP login vs. submission auth) can
    /// decide whether that scope is allowed on this listener.
    pub fn unlock_any(
        &self,
        account: &Account,
        credential: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<(UnlockedAccount, AppPasswordScope)> {
        if let Ok(unlocked) = self.unlock(account, credential, argon2_config) {
            return Ok((unlocked, AppPasswordScope::Full));
        }

        let candidates: Vec<(i64, Vec<u8>, Vec<u8>, String)> = {
            let conn = self.conn.lock().expect("auth store mutex poisoned");
            let mut stmt = conn
                .prepare(
                    "SELECT id, salt, wrapped_amk, scope FROM app_passwords WHERE account_id = ?1",
                )
                .map_err(storage_err)?;
            let rows = stmt
                .query_map((account.id,), |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .map_err(storage_err)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_err)?
        };

        for (id, salt_bytes, wrapped_amk, scope_str) in candidates {
            if salt_bytes.len() != crypto::kdf::SALT_LEN {
                continue;
            }
            let mut salt_arr = [0u8; crypto::kdf::SALT_LEN];
            salt_arr.copy_from_slice(&salt_bytes);
            let salt = Salt::from_bytes(salt_arr);
            let pk = derive_pk(credential, &salt, argon2_config)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            let Ok(amk) = unwrap_amk(&pk, &wrapped_amk) else {
                continue;
            };
            let scope = AppPasswordScope::parse(&scope_str).unwrap_or(AppPasswordScope::Full);
            let unlocked = finish_unlock(amk, &account.wrapped_account_priv)?;
            self.touch_app_password(id)?;
            return Ok((unlocked, scope));
        }

        Err(Error::Crypto("no matching credential".to_string()))
    }

    /// Mints a new app password: a random, high-entropy secret that
    /// independently wraps the *same* AMK the caller already has open
    /// (spec §3.2) under its own salt/key. Returns the plaintext secret
    /// exactly once -- it is never stored, only its wrap.
    pub fn create_app_password(
        &self,
        account_id: i64,
        amk: &AccountMasterKey,
        label: &str,
        scope: AppPasswordScope,
        argon2_config: &Argon2Config,
    ) -> Result<(AppPasswordSummary, String)> {
        let mut secret_bytes = [0u8; APP_PASSWORD_SECRET_LEN];
        rand::rng().fill(&mut secret_bytes);
        let plaintext = hex::encode(secret_bytes);

        let salt = Salt::generate();
        let pk = derive_pk(plaintext.as_bytes(), &salt, argon2_config)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let wrapped_amk = wrap_amk(&pk, 1, amk);

        let created_at = now_unix();
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "INSERT INTO app_passwords (account_id, label, scope, key_id, salt, wrapped_amk, created_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
            rusqlite::params![
                account_id,
                label,
                scope.as_str(),
                salt.0.as_slice(),
                wrapped_amk,
                created_at
            ],
        )
        .map_err(storage_err)?;
        let id = conn.last_insert_rowid();

        Ok((
            AppPasswordSummary {
                id,
                label: label.to_string(),
                scope,
                created_at,
                last_used_at: None,
            },
            plaintext,
        ))
    }

    pub fn list_app_passwords(&self, account_id: i64) -> Result<Vec<AppPasswordSummary>> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, label, scope, created_at, last_used_at FROM app_passwords \
                 WHERE account_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id,), |row| {
                let scope_str: String = row.get(2)?;
                Ok(AppPasswordSummary {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    scope: AppPasswordScope::parse(&scope_str).unwrap_or(AppPasswordScope::Full),
                    created_at: row.get(3)?,
                    last_used_at: row.get(4)?,
                })
            })
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    /// Scoped to `account_id` so one account can't revoke another's app
    /// password by guessing an id.
    pub fn revoke_app_password(&self, account_id: i64, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "DELETE FROM app_passwords WHERE id = ?1 AND account_id = ?2",
            (id, account_id),
        )
        .map_err(storage_err)?;
        Ok(())
    }

    fn touch_app_password(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "UPDATE app_passwords SET last_used_at = ?1 WHERE id = ?2",
            (now_unix(), id),
        )
        .map_err(storage_err)?;
        Ok(())
    }

    /// Raw sealed signature blob (`crypto::aead_seal`'d under the account's
    /// AMK by the caller -- this store just persists opaque bytes, same
    /// separation as `wrapped_amk`/`wrapped_account_priv`).
    pub fn get_signature_sealed(&self, account_id: i64) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.query_row(
            "SELECT signature_sealed FROM accounts WHERE id = ?1",
            (account_id,),
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .map_err(storage_err)
        .map(Option::flatten)
    }

    /// `None` clears the signature.
    pub fn set_signature_sealed(&self, account_id: i64, sealed: Option<Vec<u8>>) -> Result<()> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "UPDATE accounts SET signature_sealed = ?1 WHERE id = ?2",
            (sealed, account_id),
        )
        .map_err(storage_err)?;
        Ok(())
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

        let by_id = store
            .find_by_id(account.id)
            .unwrap()
            .expect("account should exist");
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
        let sealed =
            crypto::hpke_seal(&account.account_pub, account.key_id, b"info", b"secret").unwrap();
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
        store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        store
            .provision("bob", "other.example", b"pw", &cfg)
            .unwrap();

        let all = store.list_accounts().unwrap();
        assert_eq!(all.len(), 2);

        let just_example_com = store.list_accounts_for_domain("example.com").unwrap();
        assert_eq!(just_example_com.len(), 1);
        assert_eq!(just_example_com[0].local_part, "alice");
    }

    #[test]
    fn signature_defaults_to_none_then_round_trips() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();

        assert_eq!(store.get_signature_sealed(account.id).unwrap(), None);

        store
            .set_signature_sealed(account.id, Some(b"sealed bytes".to_vec()))
            .unwrap();
        assert_eq!(
            store.get_signature_sealed(account.id).unwrap(),
            Some(b"sealed bytes".to_vec())
        );

        store.set_signature_sealed(account.id, None).unwrap();
        assert_eq!(store.get_signature_sealed(account.id).unwrap(), None);
    }

    #[test]
    fn delete_account_removes_it() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();

        store.delete_account(account.id).unwrap();
        assert!(store.find_by_id(account.id).unwrap().is_none());
    }

    #[test]
    fn app_password_unlocks_the_same_amk_as_the_primary_password() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"primary password", &cfg)
            .unwrap();
        let primary = store.unlock(&account, b"primary password", &cfg).unwrap();

        let (summary, plaintext) = store
            .create_app_password(
                account.id,
                &primary.amk,
                "Thunderbird",
                AppPasswordScope::Full,
                &cfg,
            )
            .unwrap();
        assert_eq!(summary.label, "Thunderbird");
        assert_eq!(summary.scope, AppPasswordScope::Full);
        assert!(summary.last_used_at.is_none());

        let (unlocked, scope) = store
            .unlock_any(&account, plaintext.as_bytes(), &cfg)
            .unwrap();
        assert_eq!(scope, AppPasswordScope::Full);
        assert_eq!(unlocked.amk.as_bytes(), primary.amk.as_bytes());
    }

    #[test]
    fn unlock_any_reports_which_scope_matched() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        let primary = store.unlock(&account, b"pw", &cfg).unwrap();
        let (_, plaintext) = store
            .create_app_password(
                account.id,
                &primary.amk,
                "relay",
                AppPasswordScope::Submission,
                &cfg,
            )
            .unwrap();

        let (_, scope) = store
            .unlock_any(&account, plaintext.as_bytes(), &cfg)
            .unwrap();
        assert_eq!(scope, AppPasswordScope::Submission);

        let (_, primary_scope) = store.unlock_any(&account, b"pw", &cfg).unwrap();
        assert_eq!(primary_scope, AppPasswordScope::Full);
    }

    #[test]
    fn unlock_any_fails_closed_for_a_wrong_credential() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        let primary = store.unlock(&account, b"pw", &cfg).unwrap();
        store
            .create_app_password(
                account.id,
                &primary.amk,
                "relay",
                AppPasswordScope::Submission,
                &cfg,
            )
            .unwrap();

        assert!(store.unlock_any(&account, b"nope", &cfg).is_err());
    }

    #[test]
    fn revoked_app_password_no_longer_unlocks() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        let primary = store.unlock(&account, b"pw", &cfg).unwrap();
        let (summary, plaintext) = store
            .create_app_password(
                account.id,
                &primary.amk,
                "old laptop",
                AppPasswordScope::Full,
                &cfg,
            )
            .unwrap();

        store.revoke_app_password(account.id, summary.id).unwrap();

        assert!(store
            .unlock_any(&account, plaintext.as_bytes(), &cfg)
            .is_err());
        assert!(store.list_app_passwords(account.id).unwrap().is_empty());
    }

    #[test]
    fn revoke_is_scoped_to_the_owning_account() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let alice = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        let bob = store.provision("bob", "example.com", b"pw", &cfg).unwrap();
        let alice_unlocked = store.unlock(&alice, b"pw", &cfg).unwrap();
        let (summary, plaintext) = store
            .create_app_password(
                alice.id,
                &alice_unlocked.amk,
                "phone",
                AppPasswordScope::Full,
                &cfg,
            )
            .unwrap();

        // Bob can't revoke Alice's app password by guessing its id.
        store.revoke_app_password(bob.id, summary.id).unwrap();
        assert!(store.unlock_any(&alice, plaintext.as_bytes(), &cfg).is_ok());

        store.revoke_app_password(alice.id, summary.id).unwrap();
        assert!(store
            .unlock_any(&alice, plaintext.as_bytes(), &cfg)
            .is_err());
    }

    #[test]
    fn list_app_passwords_is_scoped_per_account() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let alice = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        let bob = store.provision("bob", "example.com", b"pw", &cfg).unwrap();
        let alice_unlocked = store.unlock(&alice, b"pw", &cfg).unwrap();
        let bob_unlocked = store.unlock(&bob, b"pw", &cfg).unwrap();
        store
            .create_app_password(
                alice.id,
                &alice_unlocked.amk,
                "a",
                AppPasswordScope::Full,
                &cfg,
            )
            .unwrap();
        store
            .create_app_password(bob.id, &bob_unlocked.amk, "b", AppPasswordScope::Full, &cfg)
            .unwrap();

        let alice_list = store.list_app_passwords(alice.id).unwrap();
        assert_eq!(alice_list.len(), 1);
        assert_eq!(alice_list[0].label, "a");
    }

    #[test]
    fn using_an_app_password_records_last_used_at() {
        let store = AuthStore::open_in_memory().unwrap();
        let cfg = fast_config();
        let account = store
            .provision("alice", "example.com", b"pw", &cfg)
            .unwrap();
        let primary = store.unlock(&account, b"pw", &cfg).unwrap();
        let (summary, plaintext) = store
            .create_app_password(
                account.id,
                &primary.amk,
                "phone",
                AppPasswordScope::Full,
                &cfg,
            )
            .unwrap();
        assert!(summary.last_used_at.is_none());

        store
            .unlock_any(&account, plaintext.as_bytes(), &cfg)
            .unwrap();

        let refreshed = store
            .list_app_passwords(account.id)
            .unwrap()
            .into_iter()
            .find(|p| p.id == summary.id)
            .unwrap();
        assert!(refreshed.last_used_at.is_some());
    }
}
