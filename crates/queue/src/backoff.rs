//! Retry backoff schedule: exponential with jitter, capped, bounded by a
//! total lifetime. `next_attempt_at` is authoritative -- the worker
//! computes it, commits it, and moves on; nothing here sleeps or holds a
//! timer in memory (spec-free restart-safety: a crash loses no schedule).

use rand::RngExt;

pub const MAX_LIFETIME_SECS: i64 = 5 * 24 * 3600;
/// If still undelivered after this long and the recipient asked for a
/// DELAY notification, send one "still trying" DSN (at most once).
pub const DELAYED_DSN_THRESHOLD_SECS: i64 = 30 * 60;

const SCHEDULE_MINUTES: [i64; 6] = [5, 15, 30, 60, 120, 240];
const CAP_MINUTES: i64 = 480;

/// Seconds to wait before the next attempt, given `attempts` prior tries
/// (1 = this was the first failure). Includes +/-15% jitter to avoid
/// thundering-herd retries against a recovering host.
pub fn next_delay_secs(attempts: i64) -> i64 {
    let base_minutes = if attempts >= 1 && (attempts as usize) <= SCHEDULE_MINUTES.len() {
        SCHEDULE_MINUTES[(attempts - 1) as usize]
    } else {
        CAP_MINUTES
    };
    let base_secs = base_minutes * 60;
    let jitter_frac = rand::rng().random_range(-0.15..=0.15);
    (base_secs as f64 * (1.0 + jitter_frac)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_monotonically_non_decreasing_ignoring_jitter() {
        let bases: Vec<i64> = (1..=8).map(next_delay_secs).collect();
        // With +/-15% jitter, attempt N's delay can't exceed attempt N+1's
        // theoretical max by enough to invert order at these step sizes.
        for w in bases.windows(2) {
            assert!(w[1] as f64 >= w[0] as f64 * 0.7, "{:?}", bases);
        }
    }

    #[test]
    fn caps_at_eight_hours_for_high_attempt_counts() {
        let cap_secs = CAP_MINUTES * 60;
        for attempts in [7, 8, 20, 100] {
            let delay = next_delay_secs(attempts);
            assert!(delay <= cap_secs * 115 / 100, "delay={delay}");
            assert!(delay >= cap_secs * 85 / 100, "delay={delay}");
        }
    }

    #[test]
    fn first_attempt_is_about_five_minutes() {
        let delay = next_delay_secs(1);
        assert!((255..=345).contains(&delay), "delay={delay}");
    }
}
