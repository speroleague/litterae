//! Content-addressed blob store + SQLite metadata (spec §7). Blobs are
//! written crash-safely (write-to-tmp then atomic rename, Maildir-style);
//! metadata lives in SQLite under WAL mode.

pub mod blob;
pub mod mailboxes;
pub mod messages;
pub mod metadata;
pub mod threads;
pub mod uploads;

pub use blob::BlobStore;
pub use mailboxes::{
    Mailbox, ROLE_ARCHIVE, ROLE_DRAFTS, ROLE_INBOX, ROLE_JUNK, ROLE_SENT, ROLE_TRASH,
};
pub use messages::{NewMessage, StoredMessage, KEYWORD_DRAFT, KEYWORD_JUNK};
pub use metadata::MetadataStore;
pub use threads::{normalize_subject, ThreadMatch};
pub use uploads::{NewUpload, StoredUpload};
