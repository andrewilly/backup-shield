// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! S3 (or S3-compatible) storage backend — stub implementation.
//!
//! The struct and configuration are fully defined, but all storage operations
//! return [`StorageError::NotImplemented`] because the `reqwest` HTTP client
//! dependency has not yet been added. When full S3 support is needed, add
//! `reqwest` and `aws-sign-v4` as dependencies and replace the stubs.

use crate::{Result, StorageBackend, StorageError};

// ── S3Storage ───────────────────────────────────────────────────────────────

/// Storage backend for Amazon S3 and S3-compatible object stores.
///
/// This is currently a **stub** – all [`StorageBackend`] methods return
/// [`StorageError::NotImplemented`]. The struct fields exist so that
/// configuration parsing and the factory function work end-to-end.
pub struct S3Storage {
    /// S3 endpoint URL (e.g. `https://s3.amazonaws.com`).
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// AWS region.
    pub region: String,
    /// Access key ID.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Key prefix inside the bucket.
    pub prefix: String,
}

impl S3Storage {
    /// Build an `S3Storage` from explicit configuration values.
    pub fn from_config(
        endpoint: &str,
        bucket: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        prefix: &str,
    ) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            bucket: bucket.to_string(),
            region: region.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            prefix: prefix.to_string(),
        }
    }

    /// Return the S3 object key for a chunk with the given hash.
    pub fn chunk_key(&self, hash: &str) -> String {
        let (prefix_dir, rest) = crate::split_hash(hash);
        format!("{}/chunks/{}/{}", self.prefix, prefix_dir, rest)
    }

    /// Return the S3 object key for a snapshot.
    pub fn snapshot_key(&self, name: &str) -> String {
        format!("{}/snapshots/{}", self.prefix, name)
    }

    /// Return the S3 object key for a parity shard.
    pub fn parity_key(&self, name: &str) -> String {
        format!("{}/parity/{}", self.prefix, name)
    }

    /// Return the S3 object key for an index.
    pub fn index_key(&self, name: &str) -> String {
        format!("{}/indexes/{}", self.prefix, name)
    }
}

fn not_implemented() -> Result<()> {
    Err(StorageError::NotImplemented(
        "S3 backend requires reqwest dependency".into(),
    ))
}

fn not_implemented_val<T>() -> Result<T> {
    Err(StorageError::NotImplemented(
        "S3 backend requires reqwest dependency".into(),
    ))
}

impl StorageBackend for S3Storage {
    fn name(&self) -> &str {
        "s3"
    }

    fn write_chunk(&self, _hash: &str, _data: &[u8]) -> Result<()> {
        not_implemented()
    }

    fn read_chunk(&self, _hash: &str) -> Result<Vec<u8>> {
        not_implemented_val()
    }

    fn chunk_exists(&self, _hash: &str) -> Result<bool> {
        not_implemented_val()
    }

    fn delete_chunk(&self, _hash: &str) -> Result<()> {
        not_implemented()
    }

    fn list_chunks(&self) -> Result<Vec<String>> {
        not_implemented_val()
    }

    fn write_snapshot(&self, _name: &str, _data: &[u8]) -> Result<()> {
        not_implemented()
    }

    fn read_snapshot(&self, _name: &str) -> Result<Vec<u8>> {
        not_implemented_val()
    }

    fn list_snapshots(&self) -> Result<Vec<String>> {
        not_implemented_val()
    }

    fn delete_snapshot(&self, _name: &str) -> Result<()> {
        not_implemented()
    }

    fn write_parity(&self, _name: &str, _data: &[u8]) -> Result<()> {
        not_implemented()
    }

    fn read_parity(&self, _name: &str) -> Result<Vec<u8>> {
        not_implemented_val()
    }

    fn list_parity(&self) -> Result<Vec<String>> {
        not_implemented_val()
    }

    fn write_index(&self, _name: &str, _data: &[u8]) -> Result<()> {
        not_implemented()
    }

    fn read_index(&self, _name: &str) -> Result<Vec<u8>> {
        not_implemented_val()
    }

    fn total_size(&self) -> Result<u64> {
        not_implemented_val()
    }

    fn free_space(&self) -> Result<u64> {
        not_implemented_val()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_builds_storage() {
        let storage = S3Storage::from_config(
            "https://s3.example.com",
            "my-bucket",
            "us-east-1",
            "AKID",
            "SECRET",
            "backups",
        );
        assert_eq!(storage.name(), "s3");
        assert_eq!(storage.bucket, "my-bucket");
    }

    #[test]
    fn operations_return_not_implemented() {
        let storage =
            S3Storage::from_config("https://s3.example.com", "bucket", "us-east-1", "", "", "");
        assert!(storage.write_chunk("hash", b"data").is_err());
        assert!(storage.read_chunk("hash").is_err());
        assert!(storage.list_chunks().is_err());
        assert!(storage.total_size().is_err());
    }

    #[test]
    fn chunk_key_format() {
        let storage = S3Storage::from_config("", "b", "", "", "", "repo");
        let key = storage.chunk_key("ab1234");
        assert_eq!(key, "repo/chunks/ab/1234");
    }

    #[test]
    fn snapshot_key_format() {
        let storage = S3Storage::from_config("", "b", "", "", "", "repo");
        assert_eq!(storage.snapshot_key("snap1"), "repo/snapshots/snap1");
    }
}
