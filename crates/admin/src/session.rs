//! Admin session tokens. Much simpler than the mailbox `SessionRegistry`
//! in `jmap`, but not entirely free of key material: reading the audit
//! log needs the admin's password-derived key to unwrap `audit_priv`, so
//! each session carries it in RAM for as long as the session lives (the
//! same "drained on lock/logout" shape as an unlocked mailbox's AMK).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngExt;

const TOKEN_LEN: usize = 32;

struct Session {
    admin_id: i64,
    wrap_key: [u8; 32],
    must_change_password: bool,
    /// Set at `create` time from the account's `totp_enabled` flag. While
    /// true, `require_admin` locks out every endpoint except `/admin/mfa/
    /// verify` -- same shape as `must_change_password`'s gate.
    mfa_pending: bool,
    last_seen: Instant,
}

pub struct AdminSessionRegistry {
    sessions: Mutex<HashMap<String, Session>>,
    idle_timeout: Duration,
}

impl AdminSessionRegistry {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            idle_timeout,
        }
    }

    pub fn create(
        &self,
        admin_id: i64,
        wrap_key: [u8; 32],
        must_change_password: bool,
        mfa_pending: bool,
    ) -> String {
        let mut bytes = [0u8; TOKEN_LEN];
        rand::rng().fill(&mut bytes);
        let token = hex::encode(bytes);
        self.sessions
            .lock()
            .expect("admin session registry mutex poisoned")
            .insert(
                token.clone(),
                Session {
                    admin_id,
                    wrap_key,
                    must_change_password,
                    mfa_pending,
                    last_seen: Instant::now(),
                },
            );
        token
    }

    pub fn admin_id(&self, token: &str) -> Option<i64> {
        self.touch(token).map(|s| s.0)
    }

    pub fn wrap_key(&self, token: &str) -> Option<[u8; 32]> {
        self.touch(token).map(|s| s.1)
    }

    pub fn password_change_required(&self, token: &str) -> Option<bool> {
        self.touch(token).map(|s| s.2)
    }

    pub fn mfa_pending(&self, token: &str) -> Option<bool> {
        self.touch(token).map(|s| s.3)
    }

    /// Keeps only the session that performed the password change and moves
    /// it to the new wrap key. Any stolen or forgotten sibling token is
    /// invalid immediately.
    pub fn complete_password_change(
        &self,
        token: &str,
        admin_id: i64,
        new_wrap_key: [u8; 32],
    ) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .expect("admin session registry mutex poisoned");
        let Some(session) = sessions.get_mut(token) else {
            return false;
        };
        if session.admin_id != admin_id {
            return false;
        }
        session.wrap_key = new_wrap_key;
        session.must_change_password = false;
        session.last_seen = Instant::now();
        sessions.retain(|candidate, _| candidate == token);
        true
    }

    /// Clears the MFA gate on this token after a live TOTP or recovery code
    /// has been verified. Unlike password change, this doesn't rotate any
    /// key material, so sibling sessions (if any) are left alone.
    pub fn complete_mfa(&self, token: &str, admin_id: i64) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .expect("admin session registry mutex poisoned");
        let Some(session) = sessions.get_mut(token) else {
            return false;
        };
        if session.admin_id != admin_id {
            return false;
        }
        session.mfa_pending = false;
        session.last_seen = Instant::now();
        true
    }

    fn touch(&self, token: &str) -> Option<(i64, [u8; 32], bool, bool)> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("admin session registry mutex poisoned");
        let session = sessions.get_mut(token)?;
        if session.last_seen.elapsed() > self.idle_timeout {
            sessions.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some((
            session.admin_id,
            session.wrap_key,
            session.must_change_password,
            session.mfa_pending,
        ))
    }

    pub fn remove(&self, token: &str) {
        self.sessions
            .lock()
            .expect("admin session registry mutex poisoned")
            .remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_lookup() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, [0u8; 32], false, false);
        assert_eq!(reg.admin_id(&token), Some(1));
    }

    #[test]
    fn wrap_key_is_recoverable_for_the_session() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, [9u8; 32], false, false);
        assert_eq!(reg.wrap_key(&token), Some([9u8; 32]));
    }

    #[test]
    fn remove_invalidates_token() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, [0u8; 32], false, false);
        reg.remove(&token);
        assert_eq!(reg.admin_id(&token), None);
    }

    #[test]
    fn expired_session_is_evicted() {
        let reg = AdminSessionRegistry::new(Duration::from_millis(1));
        let token = reg.create(1, [0u8; 32], false, false);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(reg.admin_id(&token), None);
    }

    #[test]
    fn unknown_token_returns_none() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        assert_eq!(reg.admin_id("nonexistent"), None);
    }

    #[test]
    fn password_change_promotes_current_session_and_revokes_others() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let current = reg.create(1, [1u8; 32], true, false);
        let sibling = reg.create(1, [1u8; 32], false, false);
        assert_eq!(reg.password_change_required(&current), Some(true));

        assert!(reg.complete_password_change(&current, 1, [2u8; 32]));
        assert_eq!(reg.password_change_required(&current), Some(false));
        assert_eq!(reg.wrap_key(&current), Some([2u8; 32]));
        assert_eq!(reg.admin_id(&sibling), None);
    }

    #[test]
    fn mfa_pending_blocks_until_completed() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, [0u8; 32], false, true);
        assert_eq!(reg.mfa_pending(&token), Some(true));

        assert!(reg.complete_mfa(&token, 1));
        assert_eq!(reg.mfa_pending(&token), Some(false));
    }

    #[test]
    fn complete_mfa_rejects_wrong_admin_id() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, [0u8; 32], false, true);
        assert!(!reg.complete_mfa(&token, 2));
        assert_eq!(reg.mfa_pending(&token), Some(true));
    }

    #[test]
    fn sessions_without_mfa_enabled_start_unblocked() {
        let reg = AdminSessionRegistry::new(Duration::from_secs(60));
        let token = reg.create(1, [0u8; 32], false, false);
        assert_eq!(reg.mfa_pending(&token), Some(false));
    }
}
