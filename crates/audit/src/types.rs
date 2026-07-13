#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: i64,
    pub action: String,
    pub detail: String,
}
