//! Row types for the admin store.

#[derive(Debug, Clone)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub must_change_password: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub id: i64,
    pub name: String,
    pub catch_all_local_part: Option<String>,
    /// Random per-domain token; the operator publishes it in a DNS TXT
    /// record to prove control of the domain (advisory only -- nothing in
    /// litterae is gated on this, see `verified_at`).
    pub verification_token: String,
    /// Set once a `POST /admin/domains/{id}/verify` call finds the
    /// expected TXT record published. `None` means unverified; this is
    /// informational for the operator, not enforced anywhere.
    pub verified_at: Option<i64>,
    pub created_at: i64,
}
