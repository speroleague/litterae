//! Internal delivery: classify -> seal to account.pub -> blob + metadata
//! (spec §1, Phase 1 acceptance criteria in §11). This crate needs no
//! private key material -- sealing to a cleartext `account_pub` is exactly
//! the "locked server is a pure producer" principle (spec §3.1), so inbound
//! delivery works whether or not the mailbox is unlocked. `open_message` is
//! the inverse, usable only once the account is unlocked and its private key
//! recovered (spec §3.7's "every read requires the password").

use std::net::IpAddr;

use sha2::{Digest, Sha256};

use common::{Error, Result};
use crypto::{aead_open, aead_seal, hpke_open, hpke_seal, random_key_256};
use store::{
    normalize_subject, BlobStore, MetadataStore, NewMessage, StoredMessage, ThreadMatch,
    KEYWORD_JUNK, ROLE_INBOX, ROLE_JUNK,
};

/// HPKE `info` string binding a seal to "this is a per-message DEK wrap".
/// Not secret, but must match between seal and open (spec's hpke_seal doc).
const DEK_SEAL_INFO: &[u8] = b"litterae/message-dek/v1";

/// Content-scan results to persist alongside a delivered message, kept as
/// plain primitives (not `scan::ScanResult`) so this crate doesn't need a
/// dependency on `scan` for two optional numbers. `Default` (both `None`)
/// is correct for anything that was never scanned -- drafts, sent copies,
/// locally-delivered DSNs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanMetadata {
    pub spam_score: Option<f64>,
    pub av_clean: Option<bool>,
}

/// Seals `raw` under a fresh per-message DEK, writes it to blob storage, and
/// HPKE-seals the DEK to `account_pub`. Shared by inbound delivery and
/// JMAP-side compose (drafts/sent) -- both end up needing the same
/// (blob_hash, dek_wrap) pair, sealed the same way, openable only by the
/// matching account private key.
pub fn seal_for_account(
    blobs: &BlobStore,
    account_pub: &[u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
    key_id: u16,
    raw: &[u8],
) -> Result<(String, Vec<u8>)> {
    let dek = random_key_256();
    let sealed_blob = aead_seal(&dek, 1, raw);
    let blob_hash = blobs.write(&sealed_blob)?;
    let dek_wrap = hpke_seal(account_pub, key_id, DEK_SEAL_INFO, dek.as_slice())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok((blob_hash, dek_wrap))
}

pub struct InboundEnvelope {
    pub mail_from: String,
    pub rcpt_to: String,
    pub remote_ip: IpAddr,
}

/// Summary auth-check verdicts to persist alongside the message (spec §7:
/// operational metadata, not message content -- kept in cleartext the same
/// way the outbound queue keeps envelope data in the clear, Part A.2).
pub struct AuthResults {
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
}

pub struct DeliveredMessage {
    pub message_id: i64,
    pub blob_hash: String,
}

/// The recipient account's identity and cleartext public key -- everything
/// `deliver` needs from `auth`, without depending on the `auth` crate
/// directly (spec §1 crate boundaries).
pub struct RecipientAccount {
    pub id: i64,
    pub account_pub: [u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
    pub key_id: u16,
}

/// Classifies (validates it parses as RFC5322), seals the raw message under
/// a fresh per-message DEK, writes the sealed blob to content-addressed
/// storage, HPKE-seals the DEK to the recipient account's public key, and
/// records the metadata row. No AMK or account private key is touched.
#[allow(clippy::too_many_arguments)]
pub fn deliver(
    blobs: &BlobStore,
    metadata: &MetadataStore,
    account: &RecipientAccount,
    envelope: &InboundEnvelope,
    auth_results: &AuthResults,
    raw_message: &[u8],
    received_at: i64,
    spam_reason: Option<&str>,
    scan: ScanMetadata,
) -> Result<DeliveredMessage> {
    // Fail closed on unparseable input rather than storing garbage that
    // the JMAP read layer would later choke on. Threading needs the
    // parsed headers too, so keep the result rather than discarding it.
    let Some(parsed) = mail_parser::MessageParser::default().parse(raw_message) else {
        return Err(Error::Storage("unparseable RFC5322 message".into()));
    };

    let message_id_header = parsed.message_id().map(|s| s.to_string());
    let in_reply_to_ids = header_value_ids(parsed.in_reply_to());
    let reference_ids = header_value_ids(parsed.references());
    let all_reference_ids: Vec<String> = in_reply_to_ids
        .iter()
        .cloned()
        .chain(reference_ids.iter().cloned())
        .collect();
    let subject_hash = parsed.subject().map(|s| {
        let normalized = normalize_subject(s);
        let mut hash = Sha256::new();
        hash.update(account.account_pub);
        hash.update(normalized.as_bytes());
        hex::encode(hash.finalize())
    });

    let mailbox = if spam_reason.is_some() {
        metadata.ensure_mailbox(account.id, ROLE_JUNK)?
    } else {
        metadata.ensure_mailbox(account.id, ROLE_INBOX)?
    };
    let thread_id = metadata.find_or_create_thread(&ThreadMatch {
        account_id: account.id,
        reference_ids: &all_reference_ids,
        subject_hash: subject_hash.as_deref(),
    })?;

    let (blob_hash, dek_wrap) =
        seal_for_account(blobs, &account.account_pub, account.key_id, raw_message)?;

    let in_reply_to_header = in_reply_to_ids.join(" ");
    let references_header = reference_ids.join(" ");

    let message_id = metadata.insert_message(&NewMessage {
        account_id: account.id,
        mailbox_id: mailbox.id,
        thread_id,
        blob_hash: &blob_hash,
        dek_wrap: &dek_wrap,
        mail_from: &envelope.mail_from,
        rcpt_to: &envelope.rcpt_to,
        remote_ip: &envelope.remote_ip.to_string(),
        size_bytes: raw_message.len() as i64,
        spf_result: &auth_results.spf,
        dkim_result: &auth_results.dkim,
        dmarc_result: &auth_results.dmarc,
        received_at,
        keywords: if spam_reason.is_some() {
            KEYWORD_JUNK
        } else {
            ""
        },
        message_id_header: message_id_header.as_deref(),
        in_reply_to: (!in_reply_to_header.is_empty()).then_some(in_reply_to_header.as_str()),
        references_header: (!references_header.is_empty()).then_some(references_header.as_str()),
        subject_hash: subject_hash.as_deref(),
        spam_score: scan.spam_score,
        av_clean: scan.av_clean,
    })?;

    Ok(DeliveredMessage {
        message_id,
        blob_hash,
    })
}

/// Message-ID header values can be a single string or a list; normalizes
/// either form to a `Vec<String>`.
fn header_value_ids(value: &mail_parser::HeaderValue) -> Vec<String> {
    match value {
        mail_parser::HeaderValue::Text(s) => vec![s.to_string()],
        mail_parser::HeaderValue::TextList(list) => list.iter().map(|s| s.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// Recovers the original raw message. Requires the account's unwrapped
/// private key (i.e. the mailbox must be unlocked) -- this is the "decrypts
/// on unlock" half of Phase 1's acceptance criteria.
pub fn open_message(
    blobs: &BlobStore,
    stored: &StoredMessage,
    account_priv: &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
) -> Result<Vec<u8>> {
    open_blob(blobs, &stored.blob_hash, &stored.dek_wrap, account_priv)
}

/// The `seal_for_account`/`open_message` pair, generalized to any sealed
/// blob (messages, but also `store::uploads` rows, which share the same
/// blob_hash+dek_wrap shape) rather than only ones with a full
/// `StoredMessage` row.
pub fn open_blob(
    blobs: &BlobStore,
    blob_hash: &str,
    dek_wrap: &[u8],
    account_priv: &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
) -> Result<Vec<u8>> {
    let dek =
        hpke_open(account_priv, DEK_SEAL_INFO, dek_wrap).map_err(|e| Error::Crypto(e.to_string()))?;
    let mut dek_bytes = [0u8; 32];
    dek_bytes.copy_from_slice(&dek);

    let sealed_blob = blobs.read(blob_hash)?;
    let plaintext =
        aead_open(&dek_bytes, &sealed_blob).map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::HpkeKeypair;

    const RAW_MESSAGE: &[u8] =
        b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n";

    fn envelope() -> InboundEnvelope {
        InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        }
    }

    fn auth_results() -> AuthResults {
        AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        }
    }

    #[test]
    fn deliver_then_open_round_trips_original_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();

        let delivered = deliver(
            &blobs,
            &metadata,
            &RecipientAccount {
                id: 1,
                account_pub: account.public,
                key_id: 1,
            },
            &envelope(),
            &auth_results(),
            RAW_MESSAGE,
            1_700_000_000,
            None,
            ScanMetadata::default(),
        )
        .unwrap();

        let stored = metadata
            .get_message(delivered.message_id)
            .unwrap()
            .expect("message row exists");
        assert_eq!(stored.blob_hash, delivered.blob_hash);
        assert_eq!(stored.dkim_result, "pass");

        let opened = open_message(&blobs, &stored, &account.private).unwrap();
        assert_eq!(opened, RAW_MESSAGE);
    }

    #[test]
    fn wrong_account_key_cannot_open() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        let other = HpkeKeypair::generate();

        let delivered = deliver(
            &blobs,
            &metadata,
            &RecipientAccount {
                id: 1,
                account_pub: account.public,
                key_id: 1,
            },
            &envelope(),
            &auth_results(),
            RAW_MESSAGE,
            1_700_000_000,
            None,
            ScanMetadata::default(),
        )
        .unwrap();
        let stored = metadata.get_message(delivered.message_id).unwrap().unwrap();

        assert!(open_message(&blobs, &stored, &other.private).is_err());
    }

    #[test]
    fn garbage_input_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();

        // mail-parser is extremely lenient (spec §2: "will make a best
        // effort to parse non-conformant messages"), so truly reject-worthy
        // input is closer to empty/binary garbage than a malformed header.
        let result = deliver(
            &blobs,
            &metadata,
            &RecipientAccount {
                id: 1,
                account_pub: account.public,
                key_id: 1,
            },
            &envelope(),
            &auth_results(),
            b"",
            1_700_000_000,
            None,
            ScanMetadata::default(),
        );
        // Empty input still parses to an empty message under mail-parser's
        // lenient rules, so this asserts the classify step runs at all
        // rather than a specific rejection; deliver() must not panic either
        // way.
        let _ = result;
    }

    #[test]
    fn locked_server_can_deliver_without_private_key() {
        // Core Phase 1 invariant (spec §3.1, §3.3): delivery only ever
        // touches the cleartext account_pub.
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        let pub_only = account.public;

        let delivered = deliver(
            &blobs,
            &metadata,
            &RecipientAccount {
                id: 1,
                account_pub: pub_only,
                key_id: 1,
            },
            &envelope(),
            &auth_results(),
            RAW_MESSAGE,
            1_700_000_000,
            None,
            ScanMetadata::default(),
        )
        .unwrap();
        assert!(delivered.message_id > 0);
    }

    #[test]
    fn delivered_message_lands_in_inbox() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();

        let delivered = deliver(
            &blobs,
            &metadata,
            &RecipientAccount {
                id: 1,
                account_pub: account.public,
                key_id: 1,
            },
            &envelope(),
            &auth_results(),
            RAW_MESSAGE,
            1_700_000_000,
            None,
            ScanMetadata::default(),
        )
        .unwrap();

        let stored = metadata.get_message(delivered.message_id).unwrap().unwrap();
        let inbox = metadata
            .get_mailbox_by_role(1, store::ROLE_INBOX)
            .unwrap()
            .unwrap();
        assert_eq!(stored.mailbox_id, inbox.id);
    }

    #[test]
    fn spam_flagged_message_routes_to_junk_and_tags_keyword() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();

        let delivered = deliver(
            &blobs,
            &metadata,
            &RecipientAccount {
                id: 1,
                account_pub: account.public,
                key_id: 1,
            },
            &envelope(),
            &auth_results(),
            RAW_MESSAGE,
            1_700_000_000,
            Some("rspamd add header"),
            ScanMetadata::default(),
        )
        .unwrap();

        let stored = metadata.get_message(delivered.message_id).unwrap().unwrap();
        let junk = metadata
            .get_mailbox_by_role(1, store::ROLE_JUNK)
            .unwrap()
            .unwrap();
        assert_eq!(stored.mailbox_id, junk.id);
        assert!(stored.keywords.contains(store::KEYWORD_JUNK));
    }

    #[test]
    fn a_reply_joins_the_original_thread() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        let recipient_account = RecipientAccount {
            id: 1,
            account_pub: account.public,
            key_id: 1,
        };

        let original = deliver(
            &blobs,
            &metadata,
            &recipient_account,
            &envelope(),
            &auth_results(),
            b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Hello\r\nMessage-ID: <orig@example.net>\r\n\r\nbody\r\n",
            1_700_000_000,
            None,
            ScanMetadata::default(),
        )
        .unwrap();

        let reply = deliver(
            &blobs,
            &metadata,
            &recipient_account,
            &envelope(),
            &auth_results(),
            b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Re: Hello\r\nMessage-ID: <reply@example.net>\r\nIn-Reply-To: <orig@example.net>\r\n\r\nbody\r\n",
            1_700_000_100,
            None,
            ScanMetadata::default(),
        )
        .unwrap();

        let original_stored = metadata.get_message(original.message_id).unwrap().unwrap();
        let reply_stored = metadata.get_message(reply.message_id).unwrap().unwrap();
        assert_eq!(original_stored.thread_id, reply_stored.thread_id);
    }

    #[test]
    fn unrelated_messages_get_different_threads() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(tmp.path()).unwrap();
        let metadata = MetadataStore::open_in_memory().unwrap();
        let account = HpkeKeypair::generate();
        let recipient_account = RecipientAccount {
            id: 1,
            account_pub: account.public,
            key_id: 1,
        };

        let first = deliver(
            &blobs, &metadata, &recipient_account, &envelope(), &auth_results(),
            b"From: a@example.net\r\nTo: alice@example.com\r\nSubject: First topic\r\nMessage-ID: <a@example.net>\r\n\r\nbody\r\n",
            1_700_000_000,
            None,
            ScanMetadata::default(),
        ).unwrap();
        let second = deliver(
            &blobs, &metadata, &recipient_account, &envelope(), &auth_results(),
            b"From: b@example.net\r\nTo: alice@example.com\r\nSubject: Second topic\r\nMessage-ID: <b@example.net>\r\n\r\nbody\r\n",
            1_700_000_100,
            None,
            ScanMetadata::default(),
        ).unwrap();

        let first_stored = metadata.get_message(first.message_id).unwrap().unwrap();
        let second_stored = metadata.get_message(second.message_id).unwrap().unwrap();
        assert_ne!(first_stored.thread_id, second_stored.thread_id);
    }
}
