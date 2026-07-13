//! Submission (587 STARTTLS / 465 implicit TLS): SASL PLAIN auth, sender
//! identity enforcement, handoff to `queue`.

pub mod server;
pub mod session;
pub mod tls;

pub use server::run;
