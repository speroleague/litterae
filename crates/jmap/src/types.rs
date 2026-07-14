//! JSON shapes for the JMAP subset this crate implements: the session
//! resource, method-call/method-response envelopes (RFC 8620 §3.3-3.4), and
//! the Mailbox/Email objects (RFC 8621) needed for a read-only mail list and
//! reading view.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CAPABILITY_CORE: &str = "urn:ietf:params:jmap:core";
pub const CAPABILITY_MAIL: &str = "urn:ietf:params:jmap:mail";

#[derive(Serialize)]
pub struct JmapSession {
    pub capabilities: serde_json::Value,
    pub accounts: HashMap<String, JmapAccount>,
    #[serde(rename = "primaryAccounts")]
    pub primary_accounts: HashMap<String, String>,
    pub username: String,
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "downloadUrl")]
    pub download_url: String,
    #[serde(rename = "uploadUrl")]
    pub upload_url: String,
    #[serde(rename = "eventSourceUrl")]
    pub event_source_url: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct JmapAccount {
    pub name: String,
    #[serde(rename = "isPersonal")]
    pub is_personal: bool,
    #[serde(rename = "isReadOnly")]
    pub is_read_only: bool,
    #[serde(rename = "accountCapabilities")]
    pub account_capabilities: serde_json::Value,
}

/// One `[name, arguments, callId]` entry from `methodCalls`.
#[derive(Deserialize)]
pub struct MethodCall(pub String, pub serde_json::Value, pub String);

/// One `[name, result, callId]` entry in `methodResponses`. `name` is
/// `"error"` for method-level errors (RFC 8620 §3.5.1).
#[derive(Serialize)]
pub struct MethodResponse(pub String, pub serde_json::Value, pub String);

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    pub using: Vec<String>,
    #[serde(rename = "methodCalls")]
    pub method_calls: Vec<MethodCall>,
}

#[derive(Serialize)]
pub struct Response {
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<MethodResponse>,
}

#[derive(Deserialize)]
pub struct MailboxGetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
}

#[derive(Serialize)]
pub struct MailboxGetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub state: String,
    pub list: Vec<MailboxObject>,
    #[serde(rename = "notFound")]
    pub not_found: Vec<String>,
}

#[derive(Serialize)]
pub struct MailboxObject {
    pub id: String,
    pub name: String,
    pub role: Option<String>,
    #[serde(rename = "totalEmails")]
    pub total_emails: i64,
}

#[derive(Deserialize, Default)]
pub struct EmailFilter {
    #[serde(rename = "inMailbox")]
    pub in_mailbox: Option<String>,
    #[serde(rename = "hasKeyword")]
    pub has_keyword: Option<String>,
    #[serde(rename = "notHasKeyword")]
    pub not_has_keyword: Option<String>,
    pub text: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailQueryArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(default)]
    pub filter: Option<EmailFilter>,
    #[serde(default)]
    pub position: i64,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct EmailQueryResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "queryState")]
    pub query_state: String,
    #[serde(rename = "canCalculateChanges")]
    pub can_calculate_changes: bool,
    pub position: i64,
    pub ids: Vec<String>,
    pub total: usize,
}

#[derive(Deserialize)]
pub struct EmailGetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub ids: Vec<String>,
}

#[derive(Serialize)]
pub struct EmailGetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub state: String,
    pub list: Vec<EmailObject>,
    #[serde(rename = "notFound")]
    pub not_found: Vec<String>,
}

#[derive(Serialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Serialize)]
pub struct EmailObject {
    pub id: String,
    #[serde(rename = "threadId")]
    pub thread_id: String,
    #[serde(rename = "mailboxIds")]
    pub mailbox_ids: HashMap<String, bool>,
    pub keywords: HashMap<String, bool>,
    pub from: Vec<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub subject: Option<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    pub preview: String,
    #[serde(rename = "bodyText")]
    pub body_text: Option<String>,
    pub size: i64,
    /// This message's own `Message-ID` header -- lets a client match a
    /// sibling thread message against another message's `inReplyTo`.
    #[serde(rename = "messageId")]
    pub message_id: Option<String>,
    /// The `Message-ID` this message was a reply to (RFC 5322
    /// `In-Reply-To`), not one of our own "m123" ids -- a client resolves
    /// it by matching against thread siblings' own `messageId`.
    #[serde(rename = "inReplyToMessageId")]
    pub in_reply_to_message_id: Option<String>,
    /// rspamd's raw score, `null` if antispam scanning wasn't
    /// configured/reachable for this message (always `null` for a
    /// draft/sent message -- those are never scanned).
    #[serde(rename = "spamScore")]
    pub spam_score: Option<f64>,
    /// `true` = clamd scanned and found nothing, `false` = clamd found
    /// something, `null` = not scanned.
    #[serde(rename = "avClean")]
    pub av_clean: Option<bool>,
    /// Sanitized HTML body (see `html_sanitize`), `null` if this message
    /// has no HTML part -- clients fall back to `bodyText`.
    #[serde(rename = "bodyHtml")]
    pub body_html: Option<String>,
    /// Remote images stripped from `bodyHtml` pending explicit reveal,
    /// `null` iff `bodyHtml` is `null`.
    #[serde(rename = "blockedImageCount")]
    pub blocked_image_count: Option<u32>,
}

#[derive(Deserialize)]
pub struct EmailSetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(default)]
    pub create: HashMap<String, EmailCreateRequest>,
    #[serde(default)]
    pub update: HashMap<String, HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub destroy: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct EmailSetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "newState")]
    pub new_state: String,
    pub created: HashMap<String, serde_json::Value>,
    pub updated: HashMap<String, serde_json::Value>,
    pub destroyed: Vec<String>,
    #[serde(rename = "notCreated")]
    pub not_created: HashMap<String, serde_json::Value>,
    #[serde(rename = "notUpdated")]
    pub not_updated: HashMap<String, serde_json::Value>,
    #[serde(rename = "notDestroyed")]
    pub not_destroyed: HashMap<String, serde_json::Value>,
}

/// Client-supplied compose body (a deliberately small subset of RFC 8621's
/// full Email create shape -- plain text only, one From, no attachments).
/// `inReplyTo` is our own "m123" id of the message being replied to, not a
/// raw Message-ID header value -- lets the server pull References/thread
/// linkage from a row it already has instead of trusting client-echoed
/// header text.
#[derive(Deserialize, Default)]
pub struct EmailCreateRequest {
    #[serde(default)]
    pub to: Vec<EmailAddressIn>,
    #[serde(default)]
    pub cc: Vec<EmailAddressIn>,
    #[serde(default)]
    pub bcc: Vec<EmailAddressIn>,
    pub subject: Option<String>,
    #[serde(rename = "bodyText")]
    pub body_text: Option<String>,
    #[serde(rename = "inReplyTo")]
    pub in_reply_to: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct EmailAddressIn {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Deserialize)]
pub struct EmailSubmissionSetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(default)]
    pub create: HashMap<String, EmailSubmissionCreateRequest>,
}

/// The envelope is explicit and server-trusted for `mailFrom` (always the
/// session's own address, spec's "send only as identities you own"), but
/// client-supplied for `rcptTo` -- the frontend already has the to/cc/bcc
/// list from composing the draft and passes it straight through rather
/// than making the server re-parse addresses back out of stored MIME.
#[derive(Deserialize)]
pub struct EmailSubmissionCreateRequest {
    #[serde(rename = "emailId")]
    pub email_id: String,
    pub envelope: EnvelopeIn,
}

#[derive(Deserialize)]
pub struct EnvelopeIn {
    #[serde(rename = "rcptTo")]
    pub rcpt_to: Vec<EnvelopeAddr>,
}

#[derive(Deserialize)]
pub struct EnvelopeAddr {
    pub email: String,
}

#[derive(Serialize, Default)]
pub struct EmailSubmissionSetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "newState")]
    pub new_state: String,
    pub created: HashMap<String, serde_json::Value>,
    #[serde(rename = "notCreated")]
    pub not_created: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub struct ThreadGetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub ids: Vec<String>,
}

#[derive(Serialize)]
pub struct ThreadGetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub state: String,
    pub list: Vec<ThreadObject>,
    #[serde(rename = "notFound")]
    pub not_found: Vec<String>,
}

#[derive(Serialize)]
pub struct ThreadObject {
    pub id: String,
    #[serde(rename = "emailIds")]
    pub email_ids: Vec<String>,
}

/// RFC 8621 §6: one identity per account, id fixed to the account's own
/// row id (`i{account_id}`) since litterae has no concept of multiple
/// send-as identities per mailbox yet -- there's always exactly one, and
/// it can't be created or destroyed, only updated (`textSignature`).
#[derive(Serialize, Clone)]
pub struct IdentityObject {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(rename = "textSignature")]
    pub text_signature: String,
    #[serde(rename = "mayDelete")]
    pub may_delete: bool,
}

#[derive(Deserialize)]
pub struct IdentityGetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(default)]
    pub ids: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct IdentityGetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub state: String,
    pub list: Vec<IdentityObject>,
    #[serde(rename = "notFound")]
    pub not_found: Vec<String>,
}

#[derive(Deserialize)]
pub struct IdentitySetArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(default)]
    pub update: HashMap<String, IdentityUpdatePatch>,
}

/// Only `textSignature` is settable -- `name`/`email` mirror the account
/// address and aren't independently editable.
#[derive(Deserialize)]
pub struct IdentityUpdatePatch {
    #[serde(rename = "textSignature")]
    pub text_signature: Option<String>,
}

#[derive(Serialize, Default)]
pub struct IdentitySetResult {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "newState")]
    pub new_state: String,
    pub updated: HashMap<String, serde_json::Value>,
    #[serde(rename = "notUpdated")]
    pub not_updated: HashMap<String, serde_json::Value>,
}

pub fn error_response(err_type: &str, description: &str, call_id: &str) -> MethodResponse {
    MethodResponse(
        "error".to_string(),
        serde_json::json!({ "type": err_type, "description": description }),
        call_id.to_string(),
    )
}
