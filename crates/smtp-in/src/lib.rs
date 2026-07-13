//! Inbound MTA (spec §1, §8.1): connect -> EHLO -> opportunistic STARTTLS ->
//! MAIL FROM -> RCPT TO -> DATA, SPF/DKIM/DMARC verification, then handoff
//! to `delivery`.

pub mod server;
pub mod session;
pub mod tls;

pub use server::run;
