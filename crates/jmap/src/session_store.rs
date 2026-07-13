//! In-memory registry mapping a short-lived bearer token to an unlocked
//! account's key material. Nothing here ever touches disk: losing the
//! process loses every open session, which is the point -- the account
//! private key only exists in RAM for as long as someone is actively using
//! it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngExt;
use zeroize::Zeroizing;

use auth::UnlockedAccount;
use crypto::AccountMasterKey;

use crate::search::SearchIndex;

const TOKEN_LEN: usize = 32;

/// The account facts compose (Email/set create, EmailSubmission/set) needs
/// alongside the private key -- all cleartext, all already loaded by the
/// `unlock` handler before the account row goes out of scope, so threading
/// it into the session avoids a repeat `auth_store` lookup on every
/// compose/send call.
#[derive(Clone)]
pub struct SessionIdentity {
    pub account_pub: [u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
    pub key_id: u16,
    pub address: String,
}

struct Session {
    account_id: i64,
    account_priv: Zeroizing<[u8; crypto::hpke_seal::PRIVATE_KEY_LEN]>,
    #[allow(dead_code)] // not read yet -- write-path phases will need it for rewrap operations.
    amk: AccountMasterKey,
    identity: SessionIdentity,
    last_seen: Instant,
    search_index: SearchIndex,
}

pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, Session>>,
    idle_timeout: Duration,
}

impl SessionRegistry {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            idle_timeout,
        }
    }

    /// Registers a freshly-unlocked account and returns its bearer token.
    pub fn create(&self, account_id: i64, unlocked: UnlockedAccount, identity: SessionIdentity) -> String {
        let mut bytes = [0u8; TOKEN_LEN];
        rand::rng().fill(&mut bytes);
        let token = hex::encode(bytes);

        let session = Session {
            account_id,
            account_priv: unlocked.account_priv,
            amk: unlocked.amk,
            identity,
            last_seen: Instant::now(),
            search_index: SearchIndex::new(),
        };
        self.sessions
            .lock()
            .expect("session registry mutex poisoned")
            .insert(token.clone(), session);
        token
    }

    /// Returns the account id for a valid, unexpired token, refreshing its
    /// idle timer.
    pub fn account_id(&self, token: &str) -> Option<i64> {
        let mut sessions = self.sessions.lock().expect("session registry mutex poisoned");
        let session = sessions.get_mut(token)?;
        if session.last_seen.elapsed() > self.idle_timeout {
            sessions.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some(session.account_id)
    }

    /// Runs `f` with the session's account id and private key, refreshing
    /// its idle timer. The key never leaves this call.
    pub fn with_account<T>(
        &self,
        token: &str,
        f: impl FnOnce(i64, &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN]) -> T,
    ) -> Option<T> {
        let mut sessions = self.sessions.lock().expect("session registry mutex poisoned");
        let session = sessions.get_mut(token)?;
        if session.last_seen.elapsed() > self.idle_timeout {
            sessions.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some(f(session.account_id, &session.account_priv))
    }

    /// Runs `f` with the session's account id, private key, search index,
    /// and identity (public key/key_id/address, for compose+send) together
    /// in one locked section -- these can't be composed by calling separate
    /// accessors, since that would lock this registry's mutex twice on one
    /// request.
    pub fn with_session<T>(
        &self,
        token: &str,
        f: impl FnOnce(i64, &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN], &SearchIndex, &SessionIdentity) -> T,
    ) -> Option<T> {
        let mut sessions = self.sessions.lock().expect("session registry mutex poisoned");
        let session = sessions.get_mut(token)?;
        if session.last_seen.elapsed() > self.idle_timeout {
            sessions.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some(f(
            session.account_id,
            &session.account_priv,
            &session.search_index,
            &session.identity,
        ))
    }

    pub fn remove(&self, token: &str) {
        self.sessions
            .lock()
            .expect("session registry mutex poisoned")
            .remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::HpkeKeypair;

    fn sample_unlocked() -> UnlockedAccount {
        let kp = HpkeKeypair::generate();
        UnlockedAccount {
            amk: AccountMasterKey::generate(),
            account_priv: kp.private,
        }
    }

    fn sample_identity() -> SessionIdentity {
        let kp = HpkeKeypair::generate();
        SessionIdentity {
            account_pub: kp.public,
            key_id: 1,
            address: "alice@example.test".to_string(),
        }
    }

    #[test]
    fn create_then_lookup() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(42, sample_unlocked(), sample_identity());
        assert_eq!(reg.account_id(&token), Some(42));
    }

    #[test]
    fn unknown_token_returns_none() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        assert_eq!(reg.account_id("nonexistent"), None);
    }

    #[test]
    fn remove_invalidates_token() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, sample_unlocked(), sample_identity());
        reg.remove(&token);
        assert_eq!(reg.account_id(&token), None);
    }

    #[test]
    fn expired_session_is_evicted() {
        let reg = SessionRegistry::new(Duration::from_millis(1));
        let token = reg.create(1, sample_unlocked(), sample_identity());
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(reg.account_id(&token), None);
    }

    #[test]
    fn with_account_exposes_matching_private_key() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        let unlocked = sample_unlocked();
        let expected_priv = *unlocked.account_priv;
        let token = reg.create(7, unlocked, sample_identity());

        let result = reg.with_account(&token, |account_id, priv_key| {
            assert_eq!(account_id, 7);
            *priv_key
        });
        assert_eq!(result, Some(expected_priv));
    }

    #[test]
    fn with_session_exposes_account_priv_key_and_search_index_together() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        let unlocked = sample_unlocked();
        let expected_priv = *unlocked.account_priv;
        let token = reg.create(9, unlocked, sample_identity());

        let result = reg.with_session(&token, |account_id, priv_key, _search_index, _identity| {
            assert_eq!(account_id, 9);
            *priv_key
        });
        assert_eq!(result, Some(expected_priv));
    }
}
