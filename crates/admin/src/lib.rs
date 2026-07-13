//! Operator-facing admin API: bootstrap admin identity, hosted-domain and
//! catch-all management, mailbox account CRUD, and outbound queue status.
//! Deliberately its own crate and its own auth model, separate from
//! mailbox JMAP access -- an admin session should never be able to reach
//! mailbox content.

pub mod handlers;
pub mod router;
pub mod session;
pub mod store;
pub mod types;

pub use router::{build_router, AppState};
pub use store::AdminStore;
pub use types::{Admin, Domain};
