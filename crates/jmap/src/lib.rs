//! Read-only JMAP core + mail (RFC 8620/8621 subset): session resource,
//! method-call dispatch for Mailbox/get, Email/query, Email/get, and SSE
//! push. Reading requires the account to be unlocked, so this crate also
//! owns the password-unlock bootstrap and the in-memory session registry
//! that holds the recovered account key for the session's lifetime.

pub mod api;
pub mod compose;
pub mod email;
pub mod handlers;
pub mod router;
pub mod search;
pub mod session_store;
pub mod types;

pub use router::{build_router, AppState};
pub use session_store::SessionRegistry;
