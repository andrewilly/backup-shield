// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! WebDAV storage backend — stub implementation.
//!
//! The struct and configuration are fully defined, but all storage operations
//! return [`StorageError::NotImplemented`] because the `reqwest` HTTP client
//! dependency has not yet been added.

use crate::{Result, StorageBackend, StorageError};

// ── WebDAVStorage ───────────────────────────────────────────────────────────

/// Storage backend for WebDAV servers.
///
/// This is currently a **stub** – all [`StorageBackend`] methods return
/// [`StorageError::NotImplemented`].
pub struct WebDAVStorage {
    /// Base URL of the WebDAV server (e.g. `https://cloud.example.com`).
    pub url: String,
    /// Username for HTTP Basic authentication.
    pub username: String,
    /// Password for HTTP Basic authentication.
    pub password: String,
    /// Path prefix on the server.
    pub prefix: String,
}

impl WebDAVStorage {
    /// Build a `WebDAVStorage` from explicit configuration values.
    pub fn from_config(url: &str, username: &str, password: &str, prefix: &str) -> Self {
        Self {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            prefix: prefix.to_string(),
        }
    }
}

fn not_implemented() -> Result<()> {
    Err(StorageError::NotImplemented(
        "WebDAV backend requires reqwest dependency".into(),
    ))
}

fn not_implemented_val<T>() -> Result<T> {
    Err(StorageError::NotImplemented(
        "WebDAV backend requires reqwest dependency".into(),
    ))
}

impl StorageBackend for WebDAVStorage {
    fn name(&self) -> &str {
        "webdav"
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
        let storage = WebDAVStorage::from_config(
            "https://cloud.example.com",
            "admin",
            "s3cret",
            "backups/repo",
        );
        assert_eq!(storage.name(), "webdav");
        assert_eq!(storage.url, "https://cloud.example.com");
        assert_eq!(storage.prefix, "backups/repo");
    }

    #[test]
    fn operations_return_not_implemented() {
        let storage = WebDAVStorage::from_config("https://cloud.example.com", "u", "p", "");
        assert!(storage.write_chunk("h", b"d").is_err());
        assert!(storage.read_chunk("h").is_err());
        assert!(storage.total_size().is_err());
    }
}
