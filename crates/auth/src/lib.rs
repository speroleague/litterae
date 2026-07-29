//! Account/tenant model (spec §3.2, §8.2): the account is the crypto
//! boundary. Provisioning mints the AMK hierarchy for a new mailbox; unlock
//! turns a password back into the AMK and account private key.

pub mod account;
pub mod app_password;
pub mod store;

pub use account::Account;
pub use app_password::{AppPasswordScope, AppPasswordSummary};
pub use store::{AuthStore, UnlockedAccount};
