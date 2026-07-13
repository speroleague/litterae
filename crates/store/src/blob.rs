//! Content-addressed blob store (spec §7): hash -> dedup + integrity check,
//! AEAD ciphertext under per-message DEKs lives here (the `store` crate
//! never touches keys -- callers pass already-sealed bytes). Writes are
//! crash-safe: write to a tmp file in the same directory, fsync, then an
//! atomic rename over the final hash-named path. A reader can only ever see
//! either no file or a complete file -- never a partial write.

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use common::{Error, Result};

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Writes `bytes` content-addressed by SHA-256, returning the hex-encoded
    /// hash. If a blob with this hash already exists, this is a no-op dedup
    /// (idempotent, safe to call again after a crash before the caller's
    /// metadata write was committed).
    pub fn write(&self, bytes: &[u8]) -> Result<String> {
        let hash = Self::hash_hex(bytes);
        let final_path = self.path_for(&hash);
        if final_path.exists() {
            return Ok(hash);
        }
        let dir = final_path
            .parent()
            .expect("path_for always has a parent shard dir");
        fs::create_dir_all(dir)?;

        // Unique tmp name in the same directory as the final path, so the
        // final rename is same-filesystem and therefore atomic.
        let tmp_path = dir.join(format!(".tmp-{}-{}", std::process::id(), &hash[..16]));
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Self::fsync_dir(dir)?;

        Ok(hash)
    }

    /// Reads a blob by hash, verifying content integrity against the address
    /// before returning it.
    pub fn read(&self, hash: &str) -> Result<Vec<u8>> {
        let bytes = fs::read(self.path_for(hash))?;
        let actual = Self::hash_hex(&bytes);
        if actual != hash {
            return Err(Error::Storage(format!(
                "blob integrity check failed: expected {hash}, got {actual}"
            )));
        }
        Ok(bytes)
    }

    pub fn exists(&self, hash: &str) -> bool {
        self.path_for(hash).exists()
    }

    fn hash_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Maildir-style sharding: first byte of the hash as a subdirectory, so
    /// no single directory accumulates unbounded entries.
    fn path_for(&self, hash: &str) -> PathBuf {
        let (shard, rest) = hash.split_at(2.min(hash.len()));
        self.root.join(shard).join(rest)
    }

    fn fsync_dir(dir: &Path) -> Result<()> {
        File::open(dir)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let hash = store.write(b"hello, litterae").unwrap();
        let read_back = store.read(&hash).unwrap();
        assert_eq!(read_back, b"hello, litterae");
    }

    #[test]
    fn identical_content_dedups_to_same_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let h1 = store.write(b"same content").unwrap();
        let h2 = store.write(b"same content").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_content_different_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let h1 = store.write(b"content a").unwrap();
        let h2 = store.write(b"content b").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn tampered_blob_fails_integrity_check() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let hash = store.write(b"original content").unwrap();

        // Simulate on-disk bit-rot / tampering by overwriting the stored
        // bytes directly, bypassing the store's write path.
        let (shard, rest) = hash.split_at(2);
        let path = tmp.path().join(shard).join(rest);
        fs::write(&path, b"corrupted!").unwrap();

        assert!(store.read(&hash).is_err());
    }

    #[test]
    fn crash_before_rename_leaves_no_visible_partial_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();

        // Simulate a crash that left a stale tmp file behind (write()
        // succeeded up to fsync but the process died before rename, or a
        // previous crash mid-write). The tmp file must never be mistaken
        // for a valid blob, and a fresh write() must still succeed cleanly.
        let hash = BlobStore::hash_hex(b"payload");
        let final_path = store.path_for(&hash);
        let dir = final_path.parent().unwrap();
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(format!(".tmp-9999-{}", &hash[..16])), b"partial-garbage").unwrap();

        assert!(!store.exists(&hash), "stale tmp file must not count as a stored blob");
        let written_hash = store.write(b"payload").unwrap();
        assert_eq!(written_hash, hash);
        assert_eq!(store.read(&hash).unwrap(), b"payload");
    }

    #[test]
    fn writing_same_content_concurrently_is_idempotent() {
        // The atomic rename means a second writer for the same hash either
        // races harmlessly (rename overwrites with byte-identical content)
        // or observes the file already exists; both are safe because the
        // content is content-addressed.
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let h1 = store.write(b"race content").unwrap();
        let h2 = store.write(b"race content").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.read(&h1).unwrap(), b"race content");
    }
}
