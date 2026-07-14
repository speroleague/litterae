//! Method-call dispatch (RFC 8620 §3.3): each entry in `methodCalls` is
//! `[name, arguments, callId]`; each response is `[name, result, callId]`,
//! or `["error", {...}, callId]` on a method-level failure. No JMAP server
//! framework exists, so this dispatch table is hand-rolled.

use sha2::{Digest, Sha256};

use queue::QueueStore;
use store::{
    normalize_subject, BlobStore, MetadataStore, NewMessage, ThreadMatch, KEYWORD_DRAFT,
    ROLE_DRAFTS, ROLE_SENT, ROLE_TRASH,
};

use crate::compose;
use crate::email;
use crate::types::{
    error_response, EmailCreateRequest, EmailGetArgs, EmailGetResult, EmailObject, EmailQueryArgs,
    EmailQueryResult, EmailSetArgs, EmailSetResult, EmailSubmissionSetArgs,
    EmailSubmissionSetResult, IdentityGetArgs, IdentityGetResult, IdentityObject, IdentitySetArgs,
    IdentitySetResult, MailboxGetArgs, MailboxGetResult, MailboxObject, MethodCall, MethodResponse,
    ThreadGetArgs, ThreadGetResult, ThreadObject,
};

pub struct AccountContext<'a> {
    pub account_id_str: String,
    pub blobs: &'a BlobStore,
    pub metadata: &'a MetadataStore,
    pub queue: &'a QueueStore,
    pub auth_store: &'a auth::AuthStore,
    pub account_priv: &'a [u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
    pub account_pub: &'a [u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
    pub key_id: u16,
    /// This account's own address ("local@domain") -- the only valid
    /// From/mailFrom for anything this account composes (spec: accounts
    /// may only send as identities they own; enforced by never letting a
    /// client override it, not by validating a client-supplied value).
    pub address: &'a str,
    /// For sealing/opening account-settings blobs (currently just the
    /// Identity signature) that aren't mail content and so aren't
    /// HPKE-sealed to `account_pub` -- symmetric under the account's own
    /// AMK instead, same as `wrapped_account_priv`.
    pub amk: &'a crypto::AccountMasterKey,
    /// Runs a full-text query against this session's search index
    /// (building it on first use), returning matching message row ids.
    pub search: &'a dyn Fn(&str) -> common::Result<Vec<i64>>,
    /// Publishes "this account changed" for the SSE push endpoint. Called
    /// after any successful mutation in this dispatch table.
    pub notifier: &'a common::changes::ChangeNotifier,
}

pub fn dispatch(call: MethodCall, ctx: &AccountContext) -> MethodResponse {
    let MethodCall(name, args, call_id) = call;
    match name.as_str() {
        "Mailbox/get" => mailbox_get(args, &call_id, ctx),
        "Email/query" => email_query(args, &call_id, ctx),
        "Email/get" => email_get(args, &call_id, ctx),
        "Email/set" => email_set(args, &call_id, ctx),
        "EmailSubmission/set" => email_submission_set(args, &call_id, ctx),
        "Thread/get" => thread_get(args, &call_id, ctx),
        "Identity/get" => identity_get(args, &call_id, ctx),
        "Identity/set" => identity_set(args, &call_id, ctx),
        other => error_response(
            "unknownMethod",
            &format!("no such method: {other}"),
            &call_id,
        ),
    }
}

fn parse_account_id(ctx: &AccountContext) -> i64 {
    ctx.account_id_str.parse().unwrap_or(0)
}

/// Client-facing mailbox ids are `b{row_id}`; returns the row id.
fn mailbox_row_id(id: &str) -> Option<i64> {
    id.strip_prefix('b').and_then(|n| n.parse::<i64>().ok())
}

fn email_row_id(id: &str) -> Option<i64> {
    id.strip_prefix('m').and_then(|n| n.parse::<i64>().ok())
}

fn thread_row_id(id: &str) -> Option<i64> {
    id.strip_prefix('t').and_then(|n| n.parse::<i64>().ok())
}

fn mailbox_get(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: MailboxGetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }

    let account_id = parse_account_id(ctx);
    let mailboxes = match ctx.metadata.mailboxes_for_account(account_id) {
        Ok(m) => m,
        Err(e) => return error_response("serverFail", &e.to_string(), call_id),
    };
    let list = mailboxes
        .into_iter()
        .map(|mb| {
            let total = ctx
                .metadata
                .messages_in_mailbox(account_id, mb.id)
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            MailboxObject {
                id: format!("b{}", mb.id),
                name: mb.name,
                role: Some(mb.role),
                total_emails: total,
            }
        })
        .collect();

    let result = MailboxGetResult {
        account_id: ctx.account_id_str.clone(),
        state: "1".to_string(),
        list,
        not_found: Vec::new(),
    };
    MethodResponse(
        "Mailbox/get".to_string(),
        serde_json::to_value(result).expect("MailboxGetResult always serializes"),
        call_id.to_string(),
    )
}

fn email_query(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: EmailQueryArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }

    let account_id = parse_account_id(ctx);
    let filter = args.filter.unwrap_or_default();

    let matching_ids: Vec<i64> = if let Some(text) = filter.text.filter(|t| !t.trim().is_empty()) {
        match (ctx.search)(&text) {
            Ok(ids) => ids,
            Err(e) => return error_response("serverFail", &e.to_string(), call_id),
        }
    } else if let Some(keyword) = filter.has_keyword {
        match ctx.metadata.messages_with_keyword(account_id, &keyword) {
            Ok(m) => m.into_iter().map(|m| m.id).collect(),
            Err(e) => return error_response("serverFail", &e.to_string(), call_id),
        }
    } else if let Some(keyword) = filter.not_has_keyword {
        match ctx.metadata.messages_without_keyword(account_id, &keyword) {
            Ok(m) => m.into_iter().map(|m| m.id).collect(),
            Err(e) => return error_response("serverFail", &e.to_string(), call_id),
        }
    } else {
        let mailbox_id = match filter.in_mailbox.as_deref().and_then(mailbox_row_id) {
            Some(id) => id,
            None => match ctx.metadata.ensure_mailbox(account_id, store::ROLE_INBOX) {
                Ok(mb) => mb.id,
                Err(e) => return error_response("serverFail", &e.to_string(), call_id),
            },
        };
        match ctx.metadata.messages_in_mailbox(account_id, mailbox_id) {
            Ok(m) => m.into_iter().map(|m| m.id).collect(),
            Err(e) => return error_response("serverFail", &e.to_string(), call_id),
        }
    };

    let total = matching_ids.len();
    let position = args.position.max(0) as usize;
    let limit = args.limit.unwrap_or(50);
    let ids = matching_ids
        .into_iter()
        .skip(position)
        .take(limit)
        .map(|id| format!("m{id}"))
        .collect();

    let result = EmailQueryResult {
        account_id: ctx.account_id_str.clone(),
        query_state: "1".to_string(),
        can_calculate_changes: false,
        position: position as i64,
        ids,
        total,
    };
    MethodResponse(
        "Email/query".to_string(),
        serde_json::to_value(result).expect("EmailQueryResult always serializes"),
        call_id.to_string(),
    )
}

fn email_get(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: EmailGetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }

    let mut list: Vec<EmailObject> = Vec::new();
    let mut not_found = Vec::new();

    for id in &args.ids {
        let Some(row_id) = email_row_id(id) else {
            not_found.push(id.clone());
            continue;
        };
        let stored = match ctx.metadata.get_message(row_id) {
            Ok(Some(m)) if m.account_id.to_string() == ctx.account_id_str => m,
            _ => {
                not_found.push(id.clone());
                continue;
            }
        };
        match email::open_and_parse(ctx.blobs, &stored, ctx.account_priv) {
            Ok(obj) => list.push(obj),
            Err(_) => not_found.push(id.clone()),
        }
    }

    let result = EmailGetResult {
        account_id: ctx.account_id_str.clone(),
        state: "1".to_string(),
        list,
        not_found,
    };
    MethodResponse(
        "Email/get".to_string(),
        serde_json::to_value(result).expect("EmailGetResult always serializes"),
        call_id.to_string(),
    )
}

fn email_set(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: EmailSetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);

    let mut result = EmailSetResult {
        account_id: ctx.account_id_str.clone(),
        new_state: "1".to_string(),
        ..Default::default()
    };

    for (key, create_req) in &args.create {
        match create_draft(ctx, account_id, create_req) {
            Ok((row_id, thread_id)) => {
                result.created.insert(
                    key.clone(),
                    serde_json::json!({ "id": format!("m{row_id}"), "threadId": format!("t{thread_id}") }),
                );
            }
            Err(e) => {
                result.not_created.insert(
                    key.clone(),
                    serde_json::json!({"type": "serverFail", "description": e}),
                );
            }
        }
    }

    for (id, patch) in &args.update {
        let Some(row_id) = email_row_id(id) else {
            result
                .not_updated
                .insert(id.clone(), serde_json::json!({"type": "invalidPatch"}));
            continue;
        };
        let Ok(Some(existing)) = ctx.metadata.get_message(row_id) else {
            result
                .not_updated
                .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            continue;
        };
        if existing.account_id != account_id {
            result
                .not_updated
                .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            continue;
        }

        let mut new_mailbox_id: Option<i64> = None;
        let mut new_keywords: Option<Vec<String>> = None;
        let mut current_keywords: Vec<String> = existing
            .keywords
            .split(',')
            .filter(|k| !k.is_empty())
            .map(|s| s.to_string())
            .collect();

        for (path, value) in patch {
            if path == "mailboxIds" {
                if let Some(obj) = value.as_object() {
                    new_mailbox_id = obj
                        .iter()
                        .find(|(_, v)| v.as_bool() == Some(true))
                        .and_then(|(k, _)| mailbox_row_id(k));
                }
            } else if let Some(mailbox_id_str) = path.strip_prefix("mailboxIds/") {
                if value.as_bool() == Some(true) {
                    new_mailbox_id = mailbox_row_id(mailbox_id_str);
                }
            } else if path == "keywords" {
                if let Some(obj) = value.as_object() {
                    new_keywords = Some(
                        obj.iter()
                            .filter(|(_, v)| v.as_bool() == Some(true))
                            .map(|(k, _)| k.clone())
                            .collect(),
                    );
                }
            } else if let Some(keyword) = path.strip_prefix("keywords/") {
                if value.as_bool() == Some(true) {
                    if !current_keywords.iter().any(|k| k == keyword) {
                        current_keywords.push(keyword.to_string());
                    }
                } else {
                    current_keywords.retain(|k| k != keyword);
                }
                new_keywords = Some(current_keywords.clone());
            }
        }

        let keywords_str = new_keywords.map(|k| k.join(","));
        if let Err(e) = ctx
            .metadata
            .update_message(row_id, new_mailbox_id, keywords_str.as_deref())
        {
            result.not_updated.insert(
                id.clone(),
                serde_json::json!({"type": "serverFail", "description": e.to_string()}),
            );
            continue;
        }
        result.updated.insert(id.clone(), serde_json::json!(null));
    }

    for id in &args.destroy {
        let Some(row_id) = email_row_id(id) else {
            result
                .not_destroyed
                .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            continue;
        };
        let Ok(Some(existing)) = ctx.metadata.get_message(row_id) else {
            result
                .not_destroyed
                .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            continue;
        };
        if existing.account_id != account_id {
            result
                .not_destroyed
                .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            continue;
        }

        let trash = match ctx.metadata.ensure_mailbox(account_id, ROLE_TRASH) {
            Ok(mb) => mb,
            Err(e) => {
                result.not_destroyed.insert(
                    id.clone(),
                    serde_json::json!({"type": "serverFail", "description": e.to_string()}),
                );
                continue;
            }
        };

        let outcome = if existing.mailbox_id == trash.id {
            ctx.metadata
                .delete_message(row_id)
                .and_then(|()| ctx.blobs.remove(&existing.blob_hash))
        } else {
            ctx.metadata.update_message(row_id, Some(trash.id), None)
        };
        match outcome {
            Ok(()) => result.destroyed.push(id.clone()),
            Err(e) => {
                result.not_destroyed.insert(
                    id.clone(),
                    serde_json::json!({"type": "serverFail", "description": e.to_string()}),
                );
            }
        }
    }

    if !result.created.is_empty() || !result.updated.is_empty() || !result.destroyed.is_empty() {
        ctx.notifier.notify(account_id);
    }

    MethodResponse(
        "Email/set".to_string(),
        serde_json::to_value(result).expect("EmailSetResult always serializes"),
        call_id.to_string(),
    )
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds a raw RFC822 message from a compose request, seals it to the
/// account's own key, and lands it in Drafts. Reuses the exact
/// insert_message/find_or_create_thread plumbing `delivery::deliver` uses
/// for inbound mail (see that crate's doc comment) -- a draft/sent message
/// is stored identically to a received one, just with placeholder envelope
/// fields (`mail_from`/`remote_ip`/auth verdicts) since there was no real
/// SMTP transaction.
fn create_draft(
    ctx: &AccountContext,
    account_id: i64,
    req: &EmailCreateRequest,
) -> Result<(i64, i64), String> {
    if req
        .subject
        .as_deref()
        .is_some_and(|value| !common::input::valid_header_value(value))
    {
        return Err("subject contains prohibited control characters".to_string());
    }
    for address in req.to.iter().chain(req.cc.iter()).chain(req.bcc.iter()) {
        if !common::input::valid_email_address(&address.email) {
            return Err(format!("invalid email address: {}", address.email));
        }
        if address
            .name
            .as_deref()
            .is_some_and(|value| !common::input::valid_header_value(value))
        {
            return Err("display name contains prohibited control characters".to_string());
        }
    }
    let now = now_unix();

    // A reply reuses the parent's thread directly and carries its
    // Message-ID forward into In-Reply-To/References, rather than going
    // through find_or_create_thread's reference-matching (we already have
    // the exact parent row, no need to search for it).
    let mut thread_id = None;
    let mut in_reply_to_header = None;
    let mut references_header = None;
    if let Some(parent_key) = &req.in_reply_to {
        if let Some(parent_row) = email_row_id(parent_key) {
            if let Ok(Some(parent)) = ctx.metadata.get_message(parent_row) {
                if parent.account_id == account_id {
                    thread_id = Some(parent.thread_id);
                    if let Some(parent_msgid) = &parent.message_id_header {
                        in_reply_to_header = Some(parent_msgid.clone());
                        let mut refs = parent.references_header.clone().unwrap_or_default();
                        if !refs.is_empty() {
                            refs.push(' ');
                        }
                        refs.push_str(parent_msgid);
                        references_header = Some(refs);
                    }
                }
            }
        }
    }

    let subject_hash = req.subject.as_deref().map(|s| {
        let normalized = normalize_subject(s);
        let mut hash = Sha256::new();
        hash.update(ctx.account_pub);
        hash.update(normalized.as_bytes());
        hex::encode(hash.finalize())
    });

    let thread_id = match thread_id {
        Some(id) => id,
        None => ctx
            .metadata
            .find_or_create_thread(&ThreadMatch {
                account_id,
                reference_ids: &[],
                subject_hash: subject_hash.as_deref(),
            })
            .map_err(|e| e.to_string())?,
    };

    let raw = compose::build(
        ctx.address,
        &req.to,
        &req.cc,
        req.subject.as_deref(),
        req.body_text.as_deref(),
        in_reply_to_header.as_deref(),
        references_header.as_deref(),
        now,
    )?;

    let (blob_hash, dek_wrap) =
        delivery::seal_for_account(ctx.blobs, ctx.account_pub, ctx.key_id, &raw.bytes)
            .map_err(|e| e.to_string())?;
    let drafts = ctx
        .metadata
        .ensure_mailbox(account_id, ROLE_DRAFTS)
        .map_err(|e| e.to_string())?;

    let all_recipients: Vec<&str> = req
        .to
        .iter()
        .chain(req.cc.iter())
        .chain(req.bcc.iter())
        .map(|a| a.email.as_str())
        .collect();
    let rcpt_to = all_recipients.join(", ");

    let row_id = ctx
        .metadata
        .insert_message(&NewMessage {
            account_id,
            mailbox_id: drafts.id,
            thread_id,
            blob_hash: &blob_hash,
            dek_wrap: &dek_wrap,
            mail_from: ctx.address,
            rcpt_to: &rcpt_to,
            remote_ip: "",
            size_bytes: raw.bytes.len() as i64,
            spf_result: "n/a",
            dkim_result: "n/a",
            dmarc_result: "n/a",
            received_at: now,
            keywords: KEYWORD_DRAFT,
            message_id_header: Some(&raw.message_id_header),
            in_reply_to: in_reply_to_header.as_deref(),
            references_header: references_header.as_deref(),
            subject_hash: subject_hash.as_deref(),
            spam_score: None,
            av_clean: None,
        })
        .map_err(|e| e.to_string())?;

    Ok((row_id, thread_id))
}

/// `EmailSubmission/set` (RFC 8621 §7, simplified subset): sends an
/// already-created Email (normally a Drafts-mailbox message from
/// `Email/set create`), then moves it into Sent and clears `$draft`. The
/// server always enforces `mailFrom` = the session's own address --
/// there's no client-supplied envelope-from to validate, only recipients.
fn email_submission_set(
    args: serde_json::Value,
    call_id: &str,
    ctx: &AccountContext,
) -> MethodResponse {
    let args: EmailSubmissionSetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);

    let mut result = EmailSubmissionSetResult {
        account_id: ctx.account_id_str.clone(),
        new_state: "1".to_string(),
        ..Default::default()
    };

    for (key, create_req) in &args.create {
        match submit_email(ctx, account_id, create_req) {
            Ok(email_id) => {
                result.created.insert(
                    key.clone(),
                    serde_json::json!({ "id": format!("s{email_id}"), "emailId": format!("m{email_id}") }),
                );
                ctx.notifier.notify(account_id);
            }
            Err(e) => {
                result.not_created.insert(
                    key.clone(),
                    serde_json::json!({"type": "serverFail", "description": e}),
                );
            }
        }
    }

    MethodResponse(
        "EmailSubmission/set".to_string(),
        serde_json::to_value(result).expect("EmailSubmissionSetResult always serializes"),
        call_id.to_string(),
    )
}

fn submit_email(
    ctx: &AccountContext,
    account_id: i64,
    req: &crate::types::EmailSubmissionCreateRequest,
) -> Result<i64, String> {
    let Some(row_id) = email_row_id(&req.email_id) else {
        return Err("invalid emailId".to_string());
    };
    let existing = ctx
        .metadata
        .get_message(row_id)
        .map_err(|e| e.to_string())?
        .filter(|m| m.account_id == account_id)
        .ok_or_else(|| "no such email".to_string())?;

    if req.envelope.rcpt_to.is_empty() {
        return Err("envelope has no recipients".to_string());
    }
    if req.envelope.rcpt_to.len() > 100 {
        return Err("envelope has too many recipients".to_string());
    }
    if let Some(invalid) = req
        .envelope
        .rcpt_to
        .iter()
        .find(|address| !common::input::valid_email_address(&address.email))
    {
        return Err(format!("invalid envelope recipient: {}", invalid.email));
    }

    let raw = delivery::open_message(ctx.blobs, &existing, ctx.account_priv)
        .map_err(|e| e.to_string())?;
    let domain = ctx
        .address
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(ctx.address);
    let domain_key = ctx
        .queue
        .ensure_dkim_key(domain)
        .map_err(|e| e.to_string())?;
    let recipients: Vec<&str> = req
        .envelope
        .rcpt_to
        .iter()
        .map(|a| a.email.as_str())
        .collect();

    queue::enqueue(
        ctx.queue,
        ctx.blobs,
        &domain_key,
        &queue::NewOutbound {
            account_id,
            envelope_from: ctx.address,
            raw_message: &raw,
            recipients: &recipients,
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        },
    )
    .map_err(|e| e.to_string())?;

    let sent = ctx
        .metadata
        .ensure_mailbox(account_id, ROLE_SENT)
        .map_err(|e| e.to_string())?;
    let new_keywords: Vec<&str> = existing
        .keywords
        .split(',')
        .filter(|k| !k.is_empty() && *k != KEYWORD_DRAFT)
        .collect();
    ctx.metadata
        .update_message(row_id, Some(sent.id), Some(&new_keywords.join(",")))
        .map_err(|e| e.to_string())?;

    Ok(row_id)
}

fn thread_get(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: ThreadGetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);

    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in &args.ids {
        let Some(row_id) = thread_row_id(id) else {
            not_found.push(id.clone());
            continue;
        };
        match ctx.metadata.messages_in_thread(account_id, row_id) {
            Ok(msgs) if !msgs.is_empty() => list.push(ThreadObject {
                id: id.clone(),
                email_ids: msgs.into_iter().map(|m| format!("m{}", m.id)).collect(),
            }),
            _ => not_found.push(id.clone()),
        }
    }

    let result = ThreadGetResult {
        account_id: ctx.account_id_str.clone(),
        state: "1".to_string(),
        list,
        not_found,
    };
    MethodResponse(
        "Thread/get".to_string(),
        serde_json::to_value(result).expect("ThreadGetResult always serializes"),
        call_id.to_string(),
    )
}

/// Litterae's one identity per account always has id `i{accountId}`.
fn identity_id(account_id: i64) -> String {
    format!("i{account_id}")
}

fn load_identity(ctx: &AccountContext, account_id: i64) -> IdentityObject {
    let text_signature = ctx
        .auth_store
        .get_signature_sealed(account_id)
        .ok()
        .flatten()
        .and_then(|sealed| crypto::aead_open(ctx.amk.as_bytes(), &sealed).ok())
        .and_then(|opened| String::from_utf8(opened.to_vec()).ok())
        .unwrap_or_default();

    IdentityObject {
        id: identity_id(account_id),
        name: String::new(),
        email: ctx.address.to_string(),
        text_signature,
        may_delete: false,
    }
}

fn identity_get(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: IdentityGetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);
    let identity = load_identity(ctx, account_id);

    let (list, not_found) = match args.ids {
        None => (vec![identity], Vec::new()),
        Some(ids) => {
            let mut list = Vec::new();
            let mut not_found = Vec::new();
            for id in ids {
                if id == identity.id {
                    list.push(identity.clone());
                } else {
                    not_found.push(id);
                }
            }
            (list, not_found)
        }
    };

    let result = IdentityGetResult {
        account_id: ctx.account_id_str.clone(),
        state: "1".to_string(),
        list,
        not_found,
    };
    MethodResponse(
        "Identity/get".to_string(),
        serde_json::to_value(result).expect("IdentityGetResult always serializes"),
        call_id.to_string(),
    )
}

fn identity_set(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: IdentitySetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);
    let this_id = identity_id(account_id);

    let mut result = IdentitySetResult {
        account_id: ctx.account_id_str.clone(),
        new_state: "1".to_string(),
        ..Default::default()
    };

    for (id, patch) in &args.update {
        if *id != this_id {
            result
                .not_updated
                .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            continue;
        }
        let Some(text) = &patch.text_signature else {
            result.updated.insert(id.clone(), serde_json::json!(null));
            continue;
        };
        let sealed = if text.is_empty() {
            None
        } else {
            Some(crypto::aead_seal(ctx.amk.as_bytes(), 1, text.as_bytes()))
        };
        match ctx.auth_store.set_signature_sealed(account_id, sealed) {
            Ok(()) => {
                result.updated.insert(id.clone(), serde_json::json!(null));
                ctx.notifier.notify(account_id);
            }
            Err(e) => {
                result.not_updated.insert(
                    id.clone(),
                    serde_json::json!({"type": "serverFail", "description": e.to_string()}),
                );
            }
        }
    }

    MethodResponse(
        "Identity/set".to_string(),
        serde_json::to_value(result).expect("IdentitySetResult always serializes"),
        call_id.to_string(),
    )
}
