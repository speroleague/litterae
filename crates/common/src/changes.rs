//! Cross-crate account change notifications, backing JMAP push (RFC 8620
//! §7.3). One process-wide broadcast channel: the delivery path (smtp-in,
//! the outbound worker's local DSN delivery) and JMAP's own mutation
//! handlers (Email/set, EmailSubmission/set) call `notify()` after a
//! successful write; the JMAP SSE handler subscribes and filters by
//! account id. No receiver connected (no open SSE stream) is the common
//! case, not an error -- `notify` never blocks on that.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountChanged {
    pub account_id: i64,
    /// Opaque, monotonically increasing per account -- not a real JMAP
    /// per-type state string (Mailbox/Email state tracking doesn't exist
    /// yet), just enough for a push client to know "something changed,
    /// re-fetch."
    pub state: u64,
}

pub struct ChangeNotifier {
    tx: broadcast::Sender<AccountChanged>,
    counters: Mutex<HashMap<i64, u64>>,
}

impl ChangeNotifier {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn notify(&self, account_id: i64) {
        let state = {
            let mut counters = self
                .counters
                .lock()
                .expect("change notifier mutex poisoned");
            let entry = counters.entry(account_id).or_insert(0);
            *entry += 1;
            *entry
        };
        let _ = self.tx.send(AccountChanged { account_id, state });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AccountChanged> {
        self.tx.subscribe()
    }
}

impl Default for ChangeNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriber_receives_matching_account_notification() {
        let notifier = ChangeNotifier::new();
        let mut rx = notifier.subscribe();
        notifier.notify(42);
        let changed = rx.try_recv().unwrap();
        assert_eq!(changed.account_id, 42);
        assert_eq!(changed.state, 1);
    }

    #[test]
    fn state_counter_increments_per_account_independently() {
        let notifier = ChangeNotifier::new();
        let mut rx = notifier.subscribe();
        notifier.notify(1);
        notifier.notify(2);
        notifier.notify(1);
        assert_eq!(
            rx.try_recv().unwrap(),
            AccountChanged {
                account_id: 1,
                state: 1
            }
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            AccountChanged {
                account_id: 2,
                state: 1
            }
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            AccountChanged {
                account_id: 1,
                state: 2
            }
        );
    }

    #[test]
    fn notify_with_no_subscribers_does_not_panic() {
        let notifier = ChangeNotifier::new();
        notifier.notify(1);
    }
}
