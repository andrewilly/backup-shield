//! # BackupShield Storage
//!
//! Pluggable storage backend abstraction for BackupShield.
//!
//! This crate defines the [`StorageBackend`] trait that all storage backends
//! must implement, along with concrete implementations for:
//!
//! - **Local filesystem** ([`LocalStorage`]) – fully functional
//! - **S3** ([`S3Storage`]) – stub (returns `NotImplemented`)
//! - **SFTP** ([`SftpStorage`]) – stub (returns `NotImplemented`)
//! - **WebDAV** ([`WebDAVStorage`]) – stub (returns `NotImplemented`)
//!
//! Backends are created via [`create_backend`] which takes a [`BackendConfig`]
//! and returns a `Box<dyn StorageBackend>`.

pub mod backend;
pub mod local;
pub mod s3;
pub mod sftp;
pub mod webdav;

// Re-export the primary types for convenience.
pub use backend::{create_backend, BackendConfig, StorageBackend};
pub use local::LocalStorage;
pub use s3::S3Storage;
pub use sftp::SftpStorage;
pub use webdav::WebDAVStorage;

use std::path::PathBuf;

/// Errors that can occur during storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The requested chunk was not found.
    #[error("chunk not found: {0}")]
    ChunkNotFound(String),

    /// The requested snapshot was not found.
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),

    /// The requested parity shard was not found.
    #[error("parity not found: {0}")]
    ParityNotFound(String),

    /// The requested index was not found.
    #[error("index not found: {0}")]
    IndexNotFound(String),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The operation is not implemented for this backend.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// Invalid configuration was supplied.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The backend is not connected.
    #[error("not connected")]
    NotConnected,

    /// A general storage error.
    #[error("{0}")]
    Other(String),
}

/// Convenience type alias used throughout the crate.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Directory layout constants used by [`LocalStorage`].
pub(crate) mod dirs {
    pub const CHUNKS: &str = "chunks";
    pub const SNAPSHOTS: &str = "snapshots";
    pub const PARITY: &str = "parity";
    pub const INDEXES: &str = "indexes";
}

/// Helper: given a full hex hash string, return (two-char prefix dir, rest-of-hash filename).
///
/// For a hash like `"ab12cd34..."`, returns `("ab", "12cd34...")`.
/// If the hash is shorter than 2 characters, returns `("00", "<hash>")`.
pub(crate) fn split_hash(hash: &str) -> (String, String) {
    if hash.len() < 2 {
        ("00".to_string(), hash.to_string())
    } else {
        (hash[..2].to_string(), hash[2..].to_string())
    }
}

/// Helper: build the chunk path within a base directory.
pub(crate) fn chunk_path(base: &std::path::Path, hash: &str) -> PathBuf {
    let (prefix, rest) = split_hash(hash);
    base.join(dirs::CHUNKS).join(prefix).join(rest)
}
