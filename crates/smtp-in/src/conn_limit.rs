//! Caps concurrent connections per source IP, independent of the global
//! connection semaphore in `server::run`. Without this, a single IP can
//! hold every slot in the global cap and deny the listener to everyone
//! else -- the global semaphore alone only protects against exhausting
//! total capacity, not against one source monopolizing it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub struct PerIpLimiter {
    max_per_ip: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl PerIpLimiter {
    pub fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `None` if `ip` is already at the per-IP cap. The returned
    /// guard must be held for the lifetime of the connection; dropping it
    /// frees the slot.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PerIpGuard> {
        let mut counts = self
            .counts
            .lock()
            .expect("per-ip connection counter mutex poisoned");
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(PerIpGuard {
            limiter: self.clone(),
            ip,
        })
    }
}

pub struct PerIpGuard {
    limiter: Arc<PerIpLimiter>,
    ip: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .expect("per-ip connection counter mutex poisoned");
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_the_same_ip_past_the_cap_but_not_a_different_one() {
        let limiter = Arc::new(PerIpLimiter::new(2));
        let ip_a: IpAddr = "127.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "127.0.0.2".parse().unwrap();

        let g1 = limiter.try_acquire(ip_a).expect("1st connection from A");
        let g2 = limiter.try_acquire(ip_a).expect("2nd connection from A");
        assert!(
            limiter.try_acquire(ip_a).is_none(),
            "3rd connection from A must be rejected"
        );
        assert!(
            limiter.try_acquire(ip_b).is_some(),
            "a different IP must be unaffected by A's usage"
        );

        drop(g1);
        assert!(
            limiter.try_acquire(ip_a).is_some(),
            "dropping a guard must free the slot"
        );
        drop(g2);
    }

    #[test]
    fn dropped_ip_entry_is_removed_not_left_at_zero() {
        let limiter = Arc::new(PerIpLimiter::new(1));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let guard = limiter.try_acquire(ip).unwrap();
        drop(guard);
        assert!(limiter.counts.lock().unwrap().is_empty());
    }
}
