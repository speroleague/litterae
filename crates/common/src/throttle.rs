//! Per-identity login throttle (spec §8.4 hardening: brute-force
//! protection on admin/account auth). Exponential lockout keyed by the
//! identity being authenticated against (username, or `local@domain`) --
//! not by IP, since a single-operator server's real threat here is
//! many-guesses-against-one-account, not distributed source addresses.
//! Checking the lockout before running Argon2id also means a locked-out
//! caller doesn't get to spend the server's CPU on the KDF each attempt.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    failures: u32,
    locked_until: Instant,
}

pub struct LoginThrottle {
    state: Mutex<HashMap<String, Entry>>,
    base_delay: Duration,
    max_delay: Duration,
}

impl LoginThrottle {
    pub fn new(base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            base_delay,
            max_delay,
        }
    }

    /// `Err(remaining)` if `key` is currently locked out; `Ok(())` if the
    /// caller should proceed to verify credentials.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let state = self.state.lock().expect("login throttle mutex poisoned");
        match state.get(key) {
            Some(entry) => {
                let now = Instant::now();
                if now < entry.locked_until {
                    Err(entry.locked_until - now)
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
        }
    }

    /// Records a failed attempt, doubling the lockout window (capped at
    /// `max_delay`) each time.
    pub fn record_failure(&self, key: &str) {
        let mut state = self.state.lock().expect("login throttle mutex poisoned");
        let entry = state.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            locked_until: Instant::now(),
        });
        entry.failures = entry.failures.saturating_add(1);
        let exponent = entry.failures.saturating_sub(1).min(10);
        let delay = self.base_delay.saturating_mul(1u32 << exponent).min(self.max_delay);
        entry.locked_until = Instant::now() + delay;
    }

    /// Clears the failure count on a successful login.
    pub fn record_success(&self, key: &str) {
        self.state.lock().expect("login throttle mutex poisoned").remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_key_is_never_locked() {
        let throttle = LoginThrottle::new(Duration::from_millis(10), Duration::from_secs(1));
        assert!(throttle.check("admin").is_ok());
    }

    #[test]
    fn a_failure_locks_out_briefly_then_clears() {
        let throttle = LoginThrottle::new(Duration::from_millis(10), Duration::from_secs(1));
        throttle.record_failure("admin");
        assert!(throttle.check("admin").is_err());
        std::thread::sleep(Duration::from_millis(20));
        assert!(throttle.check("admin").is_ok());
    }

    #[test]
    fn repeated_failures_grow_the_lockout_up_to_the_cap() {
        let throttle = LoginThrottle::new(Duration::from_millis(1), Duration::from_millis(50));
        for _ in 0..20 {
            throttle.record_failure("admin");
        }
        let remaining = throttle.check("admin").unwrap_err();
        assert!(remaining <= Duration::from_millis(50));
    }

    #[test]
    fn success_clears_the_failure_history() {
        let throttle = LoginThrottle::new(Duration::from_secs(5), Duration::from_secs(60));
        throttle.record_failure("admin");
        assert!(throttle.check("admin").is_err());
        throttle.record_success("admin");
        assert!(throttle.check("admin").is_ok());
    }

    #[test]
    fn different_keys_are_independent() {
        let throttle = LoginThrottle::new(Duration::from_secs(5), Duration::from_secs(60));
        throttle.record_failure("alice");
        assert!(throttle.check("alice").is_err());
        assert!(throttle.check("bob").is_ok());
    }
}
