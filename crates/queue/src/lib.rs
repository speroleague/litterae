//! Durable outbound queue: DKIM signing, MX delivery, retry/backoff, DSN
//! generation. One worker loop drains due recipients; every state
//! transition is a committed SQLite write.

pub mod backoff;
pub mod classify;
pub mod dkim;
pub mod dsn;
pub mod enqueue;
pub mod query;
pub mod schema;
pub mod types;
pub mod worker;

pub use classify::Outcome;
pub use dkim::DomainKey;
pub use enqueue::enqueue;
pub use query::QueueMetrics;
pub use schema::QueueStore;
pub use types::{NewOutbound, OutboundMessage, OutboundRecipient, RcptState};
pub use worker::Worker;
