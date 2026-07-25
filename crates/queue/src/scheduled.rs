//! CRUD for `scheduled_events` (spec §8.6 / A.9): reminders, snoozes, and
//! follow-up nudges. Storage-only -- the actual "hide until fired"/"check
//! for a reply" semantics live in `worker::Worker::fire_due_scheduled_events`
//! and the `jmap` crate's `Email/set` patch handling, same separation as
//! the rest of this crate (this module just persists rows).

use common::Result;

use crate::schema::{storage_err, QueueStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledKind {
    Remind,
    SnoozeResurface,
    FollowupNudge,
}

impl ScheduledKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScheduledKind::Remind => "remind",
            ScheduledKind::SnoozeResurface => "snooze_resurface",
            ScheduledKind::FollowupNudge => "followup_nudge",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "remind" => Some(ScheduledKind::Remind),
            "snooze_resurface" => Some(ScheduledKind::SnoozeResurface),
            "followup_nudge" => Some(ScheduledKind::FollowupNudge),
            _ => None,
        }
    }
}

pub struct NewScheduledEvent<'a> {
    pub account_id: i64,
    pub kind: ScheduledKind,
    pub fire_at: i64,
    pub thread_id: Option<&'a str>,
    /// The affected message, `"m{id}"` -- see the schema comment in
    /// `schema.rs` for why this is a bare string, not JSON.
    pub payload: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredScheduledEvent {
    pub id: i64,
    pub account_id: i64,
    pub kind: String,
    pub fire_at: i64,
    pub thread_id: Option<String>,
    pub payload: Option<String>,
    pub state: String,
}

const EVENT_COLUMNS: &str = "id, account_id, kind, fire_at, thread_id, payload, state";

impl QueueStore {
    pub fn insert_scheduled_event(&self, ev: &NewScheduledEvent) -> Result<i64> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        conn.execute(
            "INSERT INTO scheduled_events (account_id, kind, fire_at, thread_id, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                ev.account_id,
                ev.kind.as_str(),
                ev.fire_at,
                ev.thread_id,
                ev.payload,
            ],
        )
        .map_err(storage_err)?;
        Ok(conn.last_insert_rowid())
    }

    /// Rows the worker's wakeup loop should act on right now.
    pub fn due_scheduled_events(&self, now: i64) -> Result<Vec<StoredScheduledEvent>> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM scheduled_events
                 WHERE state = 'pending' AND fire_at <= ?1"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((now,), row_to_event)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    /// Pending events for an account, optionally narrowed to one `kind` --
    /// used both to compute `Email/get`'s `snoozedUntil` and to find an
    /// existing pending event to cancel when a client replaces/clears one.
    /// Personal-scale account data, so a full account scan filtered in the
    /// caller is simpler than indexing by payload.
    pub fn pending_events_for_account(
        &self,
        account_id: i64,
        kind: ScheduledKind,
    ) -> Result<Vec<StoredScheduledEvent>> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM scheduled_events
                 WHERE account_id = ?1 AND kind = ?2 AND state = 'pending'"
            ))
            .map_err(storage_err)?;
        let rows = stmt
            .query_map((account_id, kind.as_str()), row_to_event)
            .map_err(storage_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
    }

    pub fn mark_event_fired(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        conn.execute(
            "UPDATE scheduled_events SET state = 'fired' WHERE id = ?1",
            (id,),
        )
        .map_err(storage_err)?;
        Ok(())
    }

    pub fn mark_event_cancelled(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        conn.execute(
            "UPDATE scheduled_events SET state = 'cancelled' WHERE id = ?1",
            (id,),
        )
        .map_err(storage_err)?;
        Ok(())
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<StoredScheduledEvent> {
    Ok(StoredScheduledEvent {
        id: row.get(0)?,
        account_id: row.get(1)?,
        kind: row.get(2)?,
        fire_at: row.get(3)?,
        thread_id: row.get(4)?,
        payload: row.get(5)?,
        state: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(account_id: i64, fire_at: i64) -> NewScheduledEvent<'static> {
        NewScheduledEvent {
            account_id,
            kind: ScheduledKind::SnoozeResurface,
            fire_at,
            thread_id: Some("t1"),
            payload: Some("m1"),
        }
    }

    #[test]
    fn insert_and_due_round_trip() {
        let store = QueueStore::open_in_memory().unwrap();
        let id = store.insert_scheduled_event(&sample(1, 100)).unwrap();

        assert!(store.due_scheduled_events(50).unwrap().is_empty());
        let due = store.due_scheduled_events(100).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].kind, "snooze_resurface");
        assert_eq!(due[0].payload.as_deref(), Some("m1"));
        assert_eq!(due[0].state, "pending");
    }

    #[test]
    fn fired_events_are_no_longer_due() {
        let store = QueueStore::open_in_memory().unwrap();
        let id = store.insert_scheduled_event(&sample(1, 100)).unwrap();
        store.mark_event_fired(id).unwrap();
        assert!(store.due_scheduled_events(1000).unwrap().is_empty());
    }

    #[test]
    fn cancelled_events_are_no_longer_due_or_pending() {
        let store = QueueStore::open_in_memory().unwrap();
        let id = store.insert_scheduled_event(&sample(1, 100)).unwrap();
        store.mark_event_cancelled(id).unwrap();
        assert!(store.due_scheduled_events(1000).unwrap().is_empty());
        assert!(store
            .pending_events_for_account(1, ScheduledKind::SnoozeResurface)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pending_events_for_account_filters_by_kind_and_account() {
        let store = QueueStore::open_in_memory().unwrap();
        store.insert_scheduled_event(&sample(1, 100)).unwrap();
        store
            .insert_scheduled_event(&NewScheduledEvent {
                kind: ScheduledKind::FollowupNudge,
                ..sample(1, 100)
            })
            .unwrap();
        store.insert_scheduled_event(&sample(2, 100)).unwrap();

        let found = store
            .pending_events_for_account(1, ScheduledKind::SnoozeResurface)
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].account_id, 1);
    }
}
