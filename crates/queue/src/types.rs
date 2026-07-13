//! Row types for the outbound queue.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcptState {
    Ready,
    Claimed,
    Deferred,
    Delivered,
    Failed,
    Expired,
}

impl RcptState {
    pub fn as_str(&self) -> &'static str {
        match self {
            RcptState::Ready => "ready",
            RcptState::Claimed => "claimed",
            RcptState::Deferred => "deferred",
            RcptState::Delivered => "delivered",
            RcptState::Failed => "failed",
            RcptState::Expired => "expired",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "claimed" => RcptState::Claimed,
            "deferred" => RcptState::Deferred,
            "delivered" => RcptState::Delivered,
            "failed" => RcptState::Failed,
            "expired" => RcptState::Expired,
            _ => RcptState::Ready,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            RcptState::Delivered | RcptState::Failed | RcptState::Expired
        )
    }
}

/// A recipient's notification preference (RFC 3461 NOTIFY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnNotify {
    Never,
    Failure,
    Success,
    Delay,
}

impl DsnNotify {
    pub fn as_str(&self) -> &'static str {
        match self {
            DsnNotify::Never => "NEVER",
            DsnNotify::Failure => "FAILURE",
            DsnNotify::Success => "SUCCESS",
            DsnNotify::Delay => "DELAY",
        }
    }
}

pub struct NewOutbound<'a> {
    pub account_id: i64,
    pub envelope_from: &'a str,
    pub raw_message: &'a [u8],
    pub recipients: &'a [&'a str],
    pub is_dsn: bool,
    pub dsn_envid: Option<&'a str>,
    pub dsn_ret: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub id: i64,
    pub account_id: i64,
    pub message_blob: String,
    pub envelope_from: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub dsn_envid: Option<String>,
    pub dsn_ret: Option<String>,
    pub is_dsn: bool,
}

#[derive(Debug, Clone)]
pub struct OutboundRecipient {
    pub id: i64,
    pub outbound_id: i64,
    pub rcpt_to: String,
    pub domain: String,
    pub dsn_notify: String,
    pub state: RcptState,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub last_code: Option<i64>,
    pub last_status: Option<String>,
    pub last_detail: Option<String>,
    pub delayed_dsn_sent: bool,
}
