//! Hash-chained, encrypted, append-only audit log (spec §6).

pub mod store;
pub mod types;

pub use store::AuditStore;
pub use types::AuditEntry;
