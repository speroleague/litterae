//! Scoped application passwords (spec §8.4): a second, independently
//! revocable unlock path for one account, alongside the primary password.
//! Each one wraps the *same* AMK under its own Argon2id-derived key (spec
//! §3.2's whole reason for the AMK indirection -- "multiple unlock paths...
//! each independently wrap the same AMK") rather than gating some separate,
//! lesser credential, so an app password unlocks exactly as much mailbox
//! content as the primary password would. What differs is `scope`: it
//! controls which *listener* accepts the credential, not what it can
//! decrypt once accepted.

use serde::Serialize;

/// Which listener(s) a credential is good for. `Full` covers both; `Submission`
/// is meant for an MUA/relay that only ever sends -- handing it to that
/// device means a leak there can't be used to read the mailbox over JMAP,
/// even though the credential could technically unwrap the same AMK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppPasswordScope {
    Full,
    Submission,
}

impl AppPasswordScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            AppPasswordScope::Full => "full",
            AppPasswordScope::Submission => "submission",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "full" => Some(AppPasswordScope::Full),
            "submission" => Some(AppPasswordScope::Submission),
            _ => None,
        }
    }
}

/// Metadata only -- never the secret itself, which exists in cleartext for
/// exactly one response (the create call) and is never stored.
#[derive(Debug, Clone, Serialize)]
pub struct AppPasswordSummary {
    pub id: i64,
    pub label: String,
    pub scope: AppPasswordScope,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}
