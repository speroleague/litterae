//! Hash-chained, encrypted audit log (spec §6).
//!
//! Two different key roles, deliberately not protected the same way:
//! - `audit_pub`/`audit_priv` (HPKE): seals each entry's detail. `audit_priv`
//!   is wrapped under the operator's password-derived key, so entry
//!   *contents* only become readable after the admin unlocks -- the same
//!   "locked server is a pure producer" shape as account/index keys.
//! - `chain_key` (HMAC) and the Ed25519 head-signing key: kept in the clear.
//!   `log()` is called from code paths that run with no admin session at
//!   all (inbound SMTP, the outbound worker), so these can't require an
//!   unlock. That also means they give tamper-evidence against accidental
//!   corruption or partial edits, not against an attacker who already has
//!   full read/write access to this database -- that stronger guarantee is
//!   the external-anchoring extension point the spec explicitly punts past
//!   v1, not something a same-database key can provide.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};

use common::{Error, Result};
use crypto::hpke_seal::{PRIVATE_KEY_LEN as HPKE_PRIV_LEN, PUBLIC_KEY_LEN as HPKE_PUB_LEN};
use crypto::keyed_hash::{HASH_LEN, KEY_LEN as CHAIN_KEY_LEN};
use crypto::sign::{
    PRIVATE_KEY_LEN as SIGN_PRIV_LEN, PUBLIC_KEY_LEN as SIGN_PUB_LEN, SIGNATURE_LEN,
};
use crypto::{
    committing_open, committing_seal, hpke_open, hpke_seal, keyed_hash, sign, verify, HpkeKeypair,
    SigningKeypair,
};

use crate::types::AuditEntry;

const HPKE_INFO: &[u8] = b"litterae/audit-entry-v1";
/// Re-sign the chain head every this-many entries. Ties "periodically" to
/// log activity rather than a wall-clock timer, so no scheduler is needed.
const SIGN_INTERVAL: i64 = 20;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_keys (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    audit_pub           BLOB    NOT NULL,
    wrapped_audit_priv  BLOB    NOT NULL,
    key_id              INTEGER NOT NULL,
    chain_key           BLOB    NOT NULL,
    sign_pub            BLOB    NOT NULL,
    sign_priv           BLOB    NOT NULL,
    created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    at              INTEGER NOT NULL,
    action          TEXT    NOT NULL,
    commitment      BLOB    NOT NULL,
    prev_hash       BLOB    NOT NULL,
    hash            BLOB    NOT NULL,
    sealed_detail   BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_head_signatures (
    seq         INTEGER NOT NULL,
    hash        BLOB    NOT NULL,
    signature   BLOB    NOT NULL,
    signed_at   INTEGER NOT NULL
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

fn genesis_hash() -> [u8; HASH_LEN] {
    [0u8; HASH_LEN]
}

struct AuditKeys {
    audit_pub: [u8; HPKE_PUB_LEN],
    wrapped_audit_priv: Vec<u8>,
    key_id: u16,
    chain_key: [u8; CHAIN_KEY_LEN],
    sign_pub: [u8; SIGN_PUB_LEN],
    sign_priv: [u8; SIGN_PRIV_LEN],
}

pub struct AuditStore {
    conn: Mutex<Connection>,
}

impl AuditStore {
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

    pub fn has_keys(&self) -> Result<bool> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_keys", (), |row| row.get(0))
            .map_err(storage_err)?;
        Ok(count > 0)
    }

    /// Generates the audit encryption keypair, chain key, and head-signing
    /// keypair once. A no-op if keys already exist, matching
    /// `admin::AdminStore::bootstrap`'s once-ever semantics.
    pub fn bootstrap_keys(&self, wrap_key: &[u8; 32]) -> Result<()> {
        if self.has_keys()? {
            return Ok(());
        }
        let audit_kp = HpkeKeypair::generate();
        let sign_kp = SigningKeypair::generate();
        let mut chain_key = [0u8; CHAIN_KEY_LEN];
        chain_key.copy_from_slice(crypto::random_key_256().as_slice());
        let wrapped_audit_priv = committing_seal(wrap_key, 1, audit_kp.private.as_slice());

        let conn = self.conn.lock().expect("audit store mutex poisoned");
        conn.execute(
            "INSERT INTO audit_keys (id, audit_pub, wrapped_audit_priv, key_id, chain_key, sign_pub, sign_priv, created_at)
             VALUES (1, ?1, ?2, 1, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                audit_kp.public.as_slice(),
                wrapped_audit_priv,
                chain_key.as_slice(),
                sign_kp.public.as_slice(),
                sign_kp.private.as_slice(),
                now_unix(),
            ],
        )
        .map_err(storage_err)?;
        Ok(())
    }

    /// Rewraps `audit_priv` under a new password-derived key (e.g. on admin
    /// password change) -- one small blob, not the log, mirroring the
    /// AMK-rewrap pattern used for mailbox accounts.
    pub fn rewrap_audit_key(&self, old_wrap_key: &[u8; 32], new_wrap_key: &[u8; 32]) -> Result<()> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let (wrapped, key_id): (Vec<u8>, u16) = conn
            .query_row(
                "SELECT wrapped_audit_priv, key_id FROM audit_keys WHERE id = 1",
                (),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage_err)?;
        let priv_bytes =
            committing_open(old_wrap_key, &wrapped).map_err(|e| Error::Crypto(e.to_string()))?;
        let new_key_id = key_id + 1;
        let rewrapped = committing_seal(new_wrap_key, new_key_id, &priv_bytes);
        conn.execute(
            "UPDATE audit_keys SET wrapped_audit_priv = ?1, key_id = ?2 WHERE id = 1",
            rusqlite::params![rewrapped, new_key_id],
        )
        .map_err(storage_err)?;
        Ok(())
    }

    fn load_keys(conn: &Connection) -> Result<AuditKeys> {
        conn.query_row(
            "SELECT audit_pub, wrapped_audit_priv, key_id, chain_key, sign_pub, sign_priv FROM audit_keys WHERE id = 1",
            (),
            |row| {
                let audit_pub: Vec<u8> = row.get(0)?;
                let wrapped_audit_priv: Vec<u8> = row.get(1)?;
                let key_id: i64 = row.get(2)?;
                let chain_key: Vec<u8> = row.get(3)?;
                let sign_pub: Vec<u8> = row.get(4)?;
                let sign_priv: Vec<u8> = row.get(5)?;
                Ok((audit_pub, wrapped_audit_priv, key_id, chain_key, sign_pub, sign_priv))
            },
        )
        .optional()
        .map_err(storage_err)?
        .map(|(audit_pub, wrapped_audit_priv, key_id, chain_key, sign_pub, sign_priv)| {
            let mut audit_pub_arr = [0u8; HPKE_PUB_LEN];
            audit_pub_arr.copy_from_slice(&audit_pub);
            let mut chain_key_arr = [0u8; CHAIN_KEY_LEN];
            chain_key_arr.copy_from_slice(&chain_key);
            let mut sign_pub_arr = [0u8; SIGN_PUB_LEN];
            sign_pub_arr.copy_from_slice(&sign_pub);
            let mut sign_priv_arr = [0u8; SIGN_PRIV_LEN];
            sign_priv_arr.copy_from_slice(&sign_priv);
            AuditKeys {
                audit_pub: audit_pub_arr,
                wrapped_audit_priv,
                key_id: key_id as u16,
                chain_key: chain_key_arr,
                sign_pub: sign_pub_arr,
                sign_priv: sign_priv_arr,
            }
        })
        .ok_or_else(|| Error::Storage("audit keys not bootstrapped".into()))
    }

    /// Appends a tamper-evident entry. `detail` is sealed to `audit_pub` and
    /// unreadable until `read_recent` is called with the matching wrap key.
    /// `action` stays in cleartext (a short label like `"auth.login"`) so
    /// the log can be browsed by category without decrypting -- spec §6
    /// forbids plaintext bodies, not plaintext categories.
    pub fn log(&self, action: &str, detail: &str) -> Result<()> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let keys = Self::load_keys(&conn)?;

        let prev_hash: [u8; HASH_LEN] = conn
            .query_row(
                "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                (),
                |row| {
                    let hash: Vec<u8> = row.get(0)?;
                    Ok(hash)
                },
            )
            .optional()
            .map_err(storage_err)?
            .map(|h| {
                let mut arr = [0u8; HASH_LEN];
                arr.copy_from_slice(&h);
                arr
            })
            .unwrap_or_else(genesis_hash);

        let commitment = keyed_hash(&keys.chain_key, detail.as_bytes());
        let mut chained = Vec::with_capacity(HASH_LEN * 2);
        chained.extend_from_slice(&prev_hash);
        chained.extend_from_slice(&commitment);
        let hash = keyed_hash(&keys.chain_key, &chained);

        let sealed_detail = hpke_seal(&keys.audit_pub, keys.key_id, HPKE_INFO, detail.as_bytes())
            .map_err(|e| Error::Crypto(e.to_string()))?;

        conn.execute(
            "INSERT INTO audit_log (at, action, commitment, prev_hash, hash, sealed_detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                now_unix(),
                action,
                commitment.as_slice(),
                prev_hash.as_slice(),
                hash.as_slice(),
                sealed_detail
            ],
        )
        .map_err(storage_err)?;

        let seq = conn.last_insert_rowid();
        if seq % SIGN_INTERVAL == 0 {
            Self::sign_head_locked(&conn, &keys, seq, &hash)?;
        }
        Ok(())
    }

    fn sign_head_locked(
        conn: &Connection,
        keys: &AuditKeys,
        seq: i64,
        hash: &[u8; HASH_LEN],
    ) -> Result<()> {
        let sign_kp = SigningKeypair::from_private_bytes(keys.sign_priv);
        let message = head_message(seq, hash);
        let signature = sign(&sign_kp, &message);
        conn.execute(
            "INSERT INTO audit_head_signatures (seq, hash, signature, signed_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![seq, hash.as_slice(), signature.as_slice(), now_unix()],
        )
        .map_err(storage_err)?;
        Ok(())
    }

    /// Explicit, wall-clock-triggerable counterpart to the automatic
    /// per-`SIGN_INTERVAL` signing in `log` -- for callers that want to
    /// force a signature (e.g. before an export) regardless of activity.
    pub fn sign_head_now(&self) -> Result<()> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let keys = Self::load_keys(&conn)?;
        let latest: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                (),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_err)?;
        let Some((seq, hash)) = latest else {
            return Ok(());
        };
        let mut hash_arr = [0u8; HASH_LEN];
        hash_arr.copy_from_slice(&hash);
        Self::sign_head_locked(&conn, &keys, seq, &hash_arr)
    }

    /// Walks the chain from genesis, recomputing each link from its stored
    /// commitment. Needs no unlock -- see the module doc for what this does
    /// and doesn't defend against.
    pub fn verify_chain(&self) -> Result<bool> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let keys = Self::load_keys(&conn)?;
        let mut stmt = conn
            .prepare("SELECT commitment, prev_hash, hash FROM audit_log ORDER BY seq ASC")
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((), |row| {
                let commitment: Vec<u8> = row.get(0)?;
                let prev_hash: Vec<u8> = row.get(1)?;
                let hash: Vec<u8> = row.get(2)?;
                Ok((commitment, prev_hash, hash))
            })
            .map_err(storage_err)?;

        let mut expected_prev = genesis_hash();
        for row in rows {
            let (commitment, prev_hash, hash) = row.map_err(storage_err)?;
            if prev_hash != expected_prev {
                return Ok(false);
            }
            let mut chained = Vec::with_capacity(HASH_LEN * 2);
            chained.extend_from_slice(&expected_prev);
            chained.extend_from_slice(&commitment);
            let expected_hash = keyed_hash(&keys.chain_key, &chained);
            if expected_hash.as_slice() != hash.as_slice() {
                return Ok(false);
            }
            expected_prev = expected_hash;
        }
        Ok(true)
    }

    /// Verifies the most recent chain-head signature against the entry it
    /// claims to cover, if one has ever been recorded.
    pub fn verify_latest_signature(&self) -> Result<Option<bool>> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let keys = Self::load_keys(&conn)?;
        let row: Option<(i64, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT seq, hash, signature FROM audit_head_signatures ORDER BY signed_at DESC LIMIT 1",
                (),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_err)?;
        let Some((seq, hash, signature)) = row else {
            return Ok(None);
        };
        let mut hash_arr = [0u8; HASH_LEN];
        hash_arr.copy_from_slice(&hash);
        let mut sig_arr = [0u8; SIGNATURE_LEN];
        sig_arr.copy_from_slice(&signature);
        let message = head_message(seq, &hash_arr);
        Ok(Some(verify(&keys.sign_pub, &message, &sig_arr)))
    }

    /// Unwraps `audit_priv` under `wrap_key` and decrypts the `limit` most
    /// recent entries, newest first.
    pub fn read_recent(&self, wrap_key: &[u8; 32], limit: i64) -> Result<Vec<AuditEntry>> {
        let conn = self.conn.lock().expect("audit store mutex poisoned");
        let keys = Self::load_keys(&conn)?;
        let priv_bytes = committing_open(wrap_key, &keys.wrapped_audit_priv)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut priv_arr = [0u8; HPKE_PRIV_LEN];
        priv_arr.copy_from_slice(&priv_bytes);

        let mut stmt = conn
            .prepare(
                "SELECT seq, at, action, sealed_detail FROM audit_log ORDER BY seq DESC LIMIT ?1",
            )
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((limit,), |row| {
                let seq: i64 = row.get(0)?;
                let at: i64 = row.get(1)?;
                let action: String = row.get(2)?;
                let sealed_detail: Vec<u8> = row.get(3)?;
                Ok((seq, at, action, sealed_detail))
            })
            .map_err(storage_err)?;

        let mut entries = Vec::new();
        for row in rows {
            let (seq, at, action, sealed_detail) = row.map_err(storage_err)?;
            let detail = hpke_open(&priv_arr, HPKE_INFO, &sealed_detail)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            let detail = String::from_utf8(detail.to_vec())
                .map_err(|e| Error::Storage(format!("non-utf8 audit detail: {e}")))?;
            entries.push(AuditEntry {
                seq,
                at,
                action,
                detail,
            });
        }
        Ok(entries)
    }
}

fn head_message(seq: i64, hash: &[u8; HASH_LEN]) -> Vec<u8> {
    let mut message = seq.to_be_bytes().to_vec();
    message.extend_from_slice(hash);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn bootstrap_is_a_noop_once_keys_exist() {
        let store = AuditStore::open_in_memory().unwrap();
        assert!(!store.has_keys().unwrap());
        store.bootstrap_keys(&wrap_key()).unwrap();
        assert!(store.has_keys().unwrap());
        // A second call must not mint a new keypair (would orphan
        // already-sealed entries under the old audit_priv).
        store.bootstrap_keys(&[9u8; 32]).unwrap();
        store.log("test.entry", "hello").unwrap();
        let entries = store.read_recent(&wrap_key(), 10).unwrap();
        assert_eq!(
            entries.len(),
            1,
            "second bootstrap must not have rotated the key"
        );
    }

    #[test]
    fn log_entries_round_trip_and_chain_verifies() {
        let store = AuditStore::open_in_memory().unwrap();
        store.bootstrap_keys(&wrap_key()).unwrap();
        store.log("auth.login", "admin logged in").unwrap();
        store.log("admin.domain_create", "example.com").unwrap();
        store
            .log("admin.account_create", "alice@example.com")
            .unwrap();

        assert!(store.verify_chain().unwrap());

        let entries = store.read_recent(&wrap_key(), 10).unwrap();
        assert_eq!(entries.len(), 3);
        // Newest first.
        assert_eq!(entries[0].action, "admin.account_create");
        assert_eq!(entries[0].detail, "alice@example.com");
        assert_eq!(entries[2].action, "auth.login");
    }

    #[test]
    fn wrong_wrap_key_cannot_read_entries() {
        let store = AuditStore::open_in_memory().unwrap();
        store.bootstrap_keys(&wrap_key()).unwrap();
        store.log("auth.login", "admin logged in").unwrap();
        assert!(store.read_recent(&[0u8; 32], 10).is_err());
    }

    #[test]
    fn tampered_entry_fails_chain_verification() {
        let store = AuditStore::open_in_memory().unwrap();
        store.bootstrap_keys(&wrap_key()).unwrap();
        store.log("auth.login", "admin logged in").unwrap();
        store.log("admin.domain_create", "example.com").unwrap();
        assert!(store.verify_chain().unwrap());

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE audit_log SET commitment = ?1 WHERE seq = 1",
                (vec![0u8; HASH_LEN],),
            )
            .unwrap();
        }
        assert!(!store.verify_chain().unwrap());
    }

    #[test]
    fn head_signature_appears_at_interval_and_verifies() {
        let store = AuditStore::open_in_memory().unwrap();
        store.bootstrap_keys(&wrap_key()).unwrap();
        for i in 0..SIGN_INTERVAL {
            store.log("test.entry", &format!("entry {i}")).unwrap();
        }
        let verified = store.verify_latest_signature().unwrap();
        assert_eq!(verified, Some(true));
    }

    #[test]
    fn sign_head_now_signs_without_waiting_for_interval() {
        let store = AuditStore::open_in_memory().unwrap();
        store.bootstrap_keys(&wrap_key()).unwrap();
        assert_eq!(store.verify_latest_signature().unwrap(), None);
        store.log("test.entry", "one").unwrap();
        store.sign_head_now().unwrap();
        assert_eq!(store.verify_latest_signature().unwrap(), Some(true));
    }

    #[test]
    fn rewrap_audit_key_survives_wrap_key_rotation() {
        let store = AuditStore::open_in_memory().unwrap();
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];
        store.bootstrap_keys(&old_key).unwrap();
        store.log("auth.login", "before rotation").unwrap();

        store.rewrap_audit_key(&old_key, &new_key).unwrap();

        assert!(store.read_recent(&old_key, 10).is_err());
        let entries = store.read_recent(&new_key, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].detail, "before rotation");
    }
}
