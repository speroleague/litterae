//! Method-call dispatch (RFC 8620 §3.3): each entry in `methodCalls` is
//! `[name, arguments, callId]`; each response is `[name, result, callId]`,
//! or `["error", {...}, callId]` on a method-level failure. No JMAP server
//! framework exists, so this dispatch table is hand-rolled.

use std::collections::{HashMap, HashSet};

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use queue::{NewScheduledEvent, QueueStore, ScheduledKind};
use store::{
    normalize_subject, BlobStore, MetadataStore, NewMessage, ThreadMatch, KEYWORD_DRAFT,
    ROLE_DRAFTS, ROLE_SENT, ROLE_TRASH,
};

use crate::compose;
use crate::compose_html;
use crate::contacts::{self, ContactPlain};
use crate::email;
use crate::types::{
    error_response, ContactGetArgs, ContactGetResult, ContactObject, ContactSetArgs,
    ContactSetResult, EmailCreateRequest, EmailGetArgs, EmailGetResult,
    EmailObject, EmailQueryArgs, EmailQueryResult, EmailSetArgs, EmailSetResult,
    EmailSubmissionSetArgs, EmailSubmissionSetResult, IdentityGetArgs, IdentityGetResult,
    IdentityObject, IdentitySetArgs, IdentitySetResult, MailboxGetArgs, MailboxGetResult,
    MailboxObject, MethodCall, MethodResponse, ThreadGetArgs, ThreadGetResult, ThreadObject,
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
    /// Caps an assembled outbound message's total size (body + decoded
    /// attachments), checked in `create_draft` right after `compose::build`
    /// -- the only place that number is known.
    pub max_upload_size: usize,
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
        "Contact/get" => contact_get(args, &call_id, ctx),
        "Contact/set" => contact_set(args, &call_id, ctx),
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

fn contact_row_id(id: &str) -> Option<i64> {
    id.strip_prefix('c').and_then(|n| n.parse::<i64>().ok())
}

/// `StoredMessage.keywords` is a comma-joined token list -- this checks
/// for one exact token, same convention `messages_with_keyword`'s SQL
/// `LIKE` uses, just done in Rust for an already-fetched row.
fn has_keyword(keywords: &str, keyword: &str) -> bool {
    keywords.split(',').any(|k| k == keyword)
}

/// Cancels any pending scheduled event of `kind` whose payload is this
/// message -- used both to enforce "replacing a snooze/nudge cancels the
/// old one" and to implement `snoozeUntil`/`nudgeAt: null` (manual
/// cancel). A full per-account scan filtered here in Rust, same
/// personal-scale tradeoff as `queue::QueueStore::pending_events_for_account`
/// documents.
fn cancel_pending_events(ctx: &AccountContext, account_id: i64, kind: ScheduledKind, message_id: &str) {
    if let Ok(events) = ctx.queue.pending_events_for_account(account_id, kind) {
        for ev in events {
            if ev.payload.as_deref() == Some(message_id) {
                let _ = ctx.queue.mark_event_cancelled(ev.id);
            }
        }
    }
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
            // A snoozed message is hidden everywhere except the Snoozed
            // view itself (which queries `hasKeyword: $snoozed` directly,
            // never landing here), so it's excluded from this branch too
            // -- e.g. "unread" shouldn't resurface something the user
            // explicitly hid until later.
            Ok(m) => m
                .into_iter()
                .filter(|m| !has_keyword(&m.keywords, queue::KEYWORD_SNOOZED))
                .map(|m| m.id)
                .collect(),
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
            // Snoozed = hidden from every normal mailbox listing until it
            // resurfaces (spec §8.6).
            Ok(m) => m
                .into_iter()
                .filter(|m| !has_keyword(&m.keywords, queue::KEYWORD_SNOOZED))
                .map(|m| m.id)
                .collect(),
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
    let account_id = parse_account_id(ctx);
    let properties: Option<HashSet<String>> =
        args.properties.map(|p| p.into_iter().collect());

    let mut not_found = Vec::new();
    let mut requested: Vec<(String, i64)> = Vec::with_capacity(args.ids.len());
    for id in &args.ids {
        match email_row_id(id) {
            Some(row_id) => requested.push((id.clone(), row_id)),
            None => not_found.push(id.clone()),
        }
    }

    // One batched lookup for the whole page instead of one query per id.
    let row_ids: Vec<i64> = requested.iter().map(|(_, row_id)| *row_id).collect();
    let stored_by_id: HashMap<i64, store::StoredMessage> = match ctx.metadata.get_messages(&row_ids) {
        Ok(rows) => rows.into_iter().map(|m| (m.id, m)).collect(),
        Err(e) => return error_response("serverFail", &e.to_string(), call_id),
    };

    // Decrypting, MIME-parsing, and (when requested) HTML-sanitizing each
    // message is independent CPU work, so a page of ids does it in
    // parallel rather than one at a time. Capturing plain field
    // references (not `ctx` itself, which holds a `dyn Fn`) keeps every
    // captured value `Sync`.
    let blobs = ctx.blobs;
    let account_priv = ctx.account_priv;
    let account_id_str = &ctx.account_id_str;
    let results: Vec<Result<EmailObject, String>> = requested
        .par_iter()
        .map(|(id, row_id)| {
            let stored = stored_by_id
                .get(row_id)
                .filter(|m| &m.account_id.to_string() == account_id_str)
                .ok_or_else(|| id.clone())?;
            email::open_and_parse(blobs, stored, account_priv, properties.as_ref())
                .map_err(|_| id.clone())
        })
        .collect();

    let mut list: Vec<EmailObject> = Vec::with_capacity(results.len());
    for result in results {
        match result {
            Ok(obj) => list.push(obj),
            Err(id) => not_found.push(id),
        }
    }

    // `email::open_and_parse` can't see `ctx.queue`, so `snoozedUntil`/
    // `nudgeAt` are filled in here from the account's pending scheduled
    // events -- cheap (two small per-account scans, not per-message)
    // compared to decrypt/parse above.
    if let Ok(pending) = ctx
        .queue
        .pending_events_for_account(account_id, ScheduledKind::SnoozeResurface)
    {
        let fire_at_by_message: HashMap<&str, i64> = pending
            .iter()
            .filter_map(|ev| ev.payload.as_deref().map(|p| (p, ev.fire_at)))
            .collect();
        for obj in &mut list {
            obj.snoozed_until = fire_at_by_message.get(obj.id.as_str()).copied();
        }
    }
    if let Ok(pending) = ctx
        .queue
        .pending_events_for_account(account_id, ScheduledKind::FollowupNudge)
    {
        let fire_at_by_message: HashMap<&str, i64> = pending
            .iter()
            .filter_map(|ev| ev.payload.as_deref().map(|p| (p, ev.fire_at)))
            .collect();
        for obj in &mut list {
            obj.nudge_at = fire_at_by_message.get(obj.id.as_str()).copied();
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
            } else if path == "snoozeUntil" {
                // The `$snoozed` keyword itself is set/cleared by the
                // client via the existing `keywords/$snoozed` patch path
                // in the same update call -- this only owns the wakeup
                // timer, replacing any prior pending one for this message.
                cancel_pending_events(ctx, account_id, ScheduledKind::SnoozeResurface, id);
                if let Some(fire_at) = value.as_i64() {
                    let _ = ctx.queue.insert_scheduled_event(&NewScheduledEvent {
                        account_id,
                        kind: ScheduledKind::SnoozeResurface,
                        fire_at,
                        thread_id: Some(&existing.thread_id.to_string()),
                        payload: Some(id.as_str()),
                    });
                }
            } else if path == "nudgeAt" {
                cancel_pending_events(ctx, account_id, ScheduledKind::FollowupNudge, id);
                if let Some(fire_at) = value.as_i64() {
                    let _ = ctx.queue.insert_scheduled_event(&NewScheduledEvent {
                        account_id,
                        kind: ScheduledKind::FollowupNudge,
                        fire_at,
                        thread_id: Some(&existing.thread_id.to_string()),
                        payload: Some(id.as_str()),
                    });
                }
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

pub(crate) fn now_unix() -> i64 {
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
struct ResolvedUpload {
    filename: String,
    content_type: String,
    bytes: Vec<u8>,
}

/// Resolves and decrypts one `u{id}` upload blobId. Ownership-checked
/// the same way every other cross-table lookup in this file is:
/// "doesn't exist" and "belongs to a different account" both just fail,
/// no distinction visible to the caller. Shared core for both regular
/// (chip-list) attachments and inline (`cid:`-referenced) images --
/// they differ only in what they do with the result, not in how it's
/// fetched.
fn resolve_upload(ctx: &AccountContext, account_id: i64, blob_id: &str) -> Result<ResolvedUpload, String> {
    let upload_id = blob_id
        .strip_prefix('u')
        .and_then(|rest| rest.parse::<i64>().ok())
        .ok_or_else(|| format!("invalid blobId: {blob_id}"))?;
    let stored = ctx
        .metadata
        .get_upload(upload_id)
        .map_err(|e| e.to_string())?
        .filter(|u| u.account_id == account_id)
        .ok_or_else(|| format!("no such upload: {blob_id}"))?;
    let bytes = delivery::open_blob(ctx.blobs, &stored.blob_hash, &stored.dek_wrap, ctx.account_priv)
        .map_err(|e| e.to_string())?;
    Ok(ResolvedUpload {
        filename: stored.filename,
        content_type: stored.content_type,
        bytes,
    })
}

fn resolve_attachments(
    ctx: &AccountContext,
    account_id: i64,
    blob_ids: &[String],
) -> Result<Vec<compose::Attachment>, String> {
    blob_ids
        .iter()
        .map(|blob_id| {
            let upload = resolve_upload(ctx, account_id, blob_id)?;
            Ok(compose::Attachment {
                filename: upload.filename,
                content_type: upload.content_type,
                bytes: upload.bytes,
            })
        })
        .collect()
}

/// `cids` are `u{id}` upload references pulled out of the sanitized
/// compose HTML's own `img[src="cid:..."]` attributes (see
/// `compose_html::extract_inline_cids`) -- the upload's own blobId is
/// reused directly as the MIME Content-ID, no separate id scheme.
fn resolve_inline_images(
    ctx: &AccountContext,
    account_id: i64,
    cids: &[String],
) -> Result<Vec<compose::InlineImage>, String> {
    cids.iter()
        .map(|cid| {
            let upload = resolve_upload(ctx, account_id, cid)?;
            Ok(compose::InlineImage {
                content_id: cid.clone(),
                content_type: upload.content_type,
                bytes: upload.bytes,
            })
        })
        .collect()
}

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

    let attachments = resolve_attachments(ctx, account_id, &req.attachment_blob_ids)?;

    // `body_html` is untrusted client input regardless of who's
    // logged in -- anyone can call `/jmap/api` directly with
    // hand-crafted markup -- so it's sanitized before anything else
    // touches it. Once there's a sanitized HTML body, the plain-text
    // part is always derived from it (never the client-sent
    // `bodyText`), so the two can't drift out of sync with what was
    // actually sent.
    let sanitized_html = req.body_html.as_deref().map(compose_html::sanitize_outbound);
    let inline_cids = sanitized_html
        .as_deref()
        .map(compose_html::extract_inline_cids)
        .unwrap_or_default();
    let inline_images = resolve_inline_images(ctx, account_id, &inline_cids)?;
    let derived_text = sanitized_html.as_deref().map(compose_html::html_to_text);

    let raw = compose::build(
        ctx.address,
        &req.to,
        &req.cc,
        req.subject.as_deref(),
        derived_text.as_deref().or(req.body_text.as_deref()),
        sanitized_html.as_deref(),
        in_reply_to_header.as_deref(),
        references_header.as_deref(),
        now,
        &attachments,
        &inline_images,
    )?;
    if raw.bytes.len() > ctx.max_upload_size {
        return Err("message exceeds the maximum allowed size".to_string());
    }

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

/// Opens and maps a stored row to the client-facing shape; `None` on a
/// decrypt failure (wrong/rotated AMK, corrupt row) -- callers treat that
/// the same as "not found" rather than surfacing a crypto error to the
/// client.
fn contact_object(id: i64, sealed: &[u8], ctx: &AccountContext) -> Option<ContactObject> {
    let plain = contacts::open_contact(ctx.amk, sealed).ok()?;
    Some(ContactObject {
        id: format!("c{id}"),
        name: plain.name,
        email: plain.email,
    })
}

fn contact_get(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: ContactGetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);

    let (list, not_found) = match args.ids {
        None => {
            let list = ctx
                .metadata
                .contacts_for_account(account_id)
                .unwrap_or_default()
                .iter()
                .filter_map(|c| contact_object(c.id, &c.sealed, ctx))
                .collect();
            (list, Vec::new())
        }
        Some(ids) => {
            let mut list = Vec::new();
            let mut not_found = Vec::new();
            for id in ids {
                let found = contact_row_id(&id)
                    .and_then(|row_id| ctx.metadata.get_contact(row_id).ok().flatten())
                    .filter(|c| c.account_id == account_id)
                    .and_then(|c| contact_object(c.id, &c.sealed, ctx));
                match found {
                    Some(obj) => list.push(obj),
                    None => not_found.push(id),
                }
            }
            (list, not_found)
        }
    };

    let result = ContactGetResult {
        account_id: ctx.account_id_str.clone(),
        state: "1".to_string(),
        list,
        not_found,
    };
    MethodResponse(
        "Contact/get".to_string(),
        serde_json::to_value(result).expect("ContactGetResult always serializes"),
        call_id.to_string(),
    )
}

/// Validates a create/update's `name`/`email`, following the same checks
/// `create_draft` applies to compose addresses.
fn validate_contact_fields(name: Option<&str>, email: &str) -> Result<(), String> {
    if !common::input::valid_email_address(email) {
        return Err(format!("invalid email address: {email}"));
    }
    if name.is_some_and(|value| !common::input::valid_header_value(value)) {
        return Err("display name contains prohibited control characters".to_string());
    }
    Ok(())
}

fn contact_set(args: serde_json::Value, call_id: &str, ctx: &AccountContext) -> MethodResponse {
    let args: ContactSetArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return error_response("invalidArguments", &e.to_string(), call_id),
    };
    if args.account_id != ctx.account_id_str {
        return error_response("accountNotFound", "unknown accountId", call_id);
    }
    let account_id = parse_account_id(ctx);

    let mut result = ContactSetResult {
        account_id: ctx.account_id_str.clone(),
        new_state: "1".to_string(),
        ..Default::default()
    };

    // Decrypted once up front and kept in sync as creates/updates land, so
    // duplicate-email rejection also catches duplicates within the same
    // request batch, not just against what was already stored.
    let mut existing: Vec<(i64, ContactPlain)> = ctx
        .metadata
        .contacts_for_account(account_id)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| contacts::open_contact(ctx.amk, &c.sealed).ok().map(|p| (c.id, p)))
        .collect();

    let is_duplicate = |email: &str, existing: &[(i64, ContactPlain)], excluding: Option<i64>| {
        existing
            .iter()
            .any(|(row_id, c)| Some(*row_id) != excluding && c.email.eq_ignore_ascii_case(email))
    };

    for (key, req) in &args.create {
        let outcome = (|| -> Result<(i64, ContactPlain), String> {
            validate_contact_fields(req.name.as_deref(), &req.email)?;
            if is_duplicate(&req.email, &existing, None) {
                return Err("a contact with this email already exists".to_string());
            }
            let plain = ContactPlain {
                name: req.name.clone(),
                email: req.email.clone(),
            };
            let sealed = contacts::seal_contact(ctx.amk, &plain);
            let row_id = ctx
                .metadata
                .insert_contact(account_id, &sealed, now_unix())
                .map_err(|e| e.to_string())?;
            Ok((row_id, plain))
        })();

        match outcome {
            Ok((row_id, plain)) => {
                result.created.insert(
                    key.clone(),
                    serde_json::json!({ "id": format!("c{row_id}"), "name": plain.name, "email": plain.email }),
                );
                existing.push((row_id, plain));
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
        let outcome = (|| -> Result<(), String> {
            let row_id = contact_row_id(id).ok_or_else(|| "notFound".to_string())?;
            let stored = ctx
                .metadata
                .get_contact(row_id)
                .map_err(|e| e.to_string())?
                .filter(|c| c.account_id == account_id)
                .ok_or_else(|| "notFound".to_string())?;
            let current = contacts::open_contact(ctx.amk, &stored.sealed).map_err(|e| e.to_string())?;

            let mut name = current.name;
            let mut email = current.email;
            if let Some(value) = patch.get("name") {
                name = value.as_str().map(|s| s.to_string());
            }
            if let Some(value) = patch.get("email") {
                if let Some(s) = value.as_str() {
                    email = s.to_string();
                }
            }
            validate_contact_fields(name.as_deref(), &email)?;
            if is_duplicate(&email, &existing, Some(row_id)) {
                return Err("a contact with this email already exists".to_string());
            }

            let plain = ContactPlain { name, email };
            let sealed = contacts::seal_contact(ctx.amk, &plain);
            ctx.metadata
                .update_contact(row_id, &sealed, now_unix())
                .map_err(|e| e.to_string())?;
            existing.retain(|(id, _)| *id != row_id);
            existing.push((row_id, plain));
            Ok(())
        })();

        match outcome {
            Ok(()) => {
                result.updated.insert(id.clone(), serde_json::json!(null));
            }
            Err(e) if e == "notFound" => {
                result
                    .not_updated
                    .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            }
            Err(e) => {
                result.not_updated.insert(
                    id.clone(),
                    serde_json::json!({"type": "serverFail", "description": e}),
                );
            }
        }
    }

    for id in &args.destroy {
        let outcome = (|| -> Result<(), String> {
            let row_id = contact_row_id(id).ok_or_else(|| "notFound".to_string())?;
            let stored = ctx
                .metadata
                .get_contact(row_id)
                .map_err(|e| e.to_string())?
                .filter(|c| c.account_id == account_id)
                .ok_or_else(|| "notFound".to_string())?;
            ctx.metadata
                .delete_contact(stored.id)
                .map_err(|e| e.to_string())
        })();

        match outcome {
            Ok(()) => result.destroyed.push(id.clone()),
            Err(e) if e == "notFound" => {
                result
                    .not_destroyed
                    .insert(id.clone(), serde_json::json!({"type": "notFound"}));
            }
            Err(e) => {
                result.not_destroyed.insert(
                    id.clone(),
                    serde_json::json!({"type": "serverFail", "description": e}),
                );
            }
        }
    }

    if !result.created.is_empty() || !result.updated.is_empty() || !result.destroyed.is_empty() {
        ctx.notifier.notify(account_id);
    }

    MethodResponse(
        "Contact/set".to_string(),
        serde_json::to_value(result).expect("ContactSetResult always serializes"),
        call_id.to_string(),
    )
}
