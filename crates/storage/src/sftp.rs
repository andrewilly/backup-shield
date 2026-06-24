// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! SFTP storage backend — stub implementation.
//!
//! The struct and configuration are fully defined, but all storage operations
//! return [`StorageError::NotImplemented`] because the `ssh2` / `openssh`
//! dependency has not yet been added.

use crate::{Result, StorageBackend, StorageError};

// ── SftpStorage ─────────────────────────────────────────────────────────────

/// Storage backend for remote servers accessed over SFTP.
///
/// This is currently a **stub** – all [`StorageBackend`] methods return
/// [`StorageError::NotImplemented`].
pub struct SftpStorage {
    /// Remote host.
    pub host: String,
    /// SSH port.
    pub port: u16,
    /// Username for authentication.
    pub username: String,
    /// Path to the SSH private key on the local filesystem.
    pub key_path: String,
    /// Remote directory path.
    pub remote_path: String,
}

impl SftpStorage {
    /// Build an `SftpStorage` from explicit configuration values.
    pub fn from_config(
        host: &str,
        port: u16,
        username: &str,
        key_path: &str,
        remote_path: &str,
    ) -> Self {
        Self {
            host: host.to_string(),
            port,
            username: username.to_string(),
            key_path: key_path.to_string(),
            remote_path: remote_path.to_string(),
        }
    }
}

fn not_implemented() -> Result<()> {
    Err(StorageError::NotImplemented(
        "SFTP backend requires ssh2 dependency".into(),
    ))
}

fn not_implemented_val<T>() -> Result<T> {
    Err(StorageError::NotImplemented(
        "SFTP backend requires ssh2 dependency".into(),
    ))
}

impl StorageBackend for SftpStorage {
    fn name(&self) -> &str {
        "sftp"
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
        let storage = SftpStorage::from_config(
            "host.example.com",
            22,
            "alice",
            "/home/alice/.ssh/id_ed25519",
            "/data/repo",
        );
        assert_eq!(storage.name(), "sftp");
        assert_eq!(storage.host, "host.example.com");
        assert_eq!(storage.port, 22);
    }

    #[test]
    fn operations_return_not_implemented() {
        let storage = SftpStorage::from_config("host", 22, "user", "", "");
        assert!(storage.write_chunk("h", b"d").is_err());
        assert!(storage.read_chunk("h").is_err());
        assert!(storage.total_size().is_err());
    }
}
