// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Storage backend trait and configuration types.

use crate::{LocalStorage, Result, S3Storage, SftpStorage, StorageError, WebDAVStorage};
use std::path::Path;

// ── StorageBackend trait ────────────────────────────────────────────────────

/// Synchronous trait that every storage backend must implement.
///
/// The trait is object-safe so backends can be used behind `dyn StorageBackend`.
/// All methods are synchronous; remote backends may internally spawn threads or
/// use their own runtimes, but callers are not required to be in an async context.
pub trait StorageBackend: Send + Sync {
    /// Return a human-readable name for this backend (e.g. `"local"`, `"s3"`).
    fn name(&self) -> &str;

    /// Write a content-addressed chunk. The `hash` is the hex-encoded SHA-256
    /// of `data`. If the chunk already exists the implementation may choose to
    /// skip the write (idempotent).
    fn write_chunk(&self, hash: &str, data: &[u8]) -> Result<()>;

    /// Read a chunk by its hex hash.
    fn read_chunk(&self, hash: &str) -> Result<Vec<u8>>;

    /// Check whether a chunk exists.
    fn chunk_exists(&self, hash: &str) -> Result<bool>;

    /// Delete a chunk by its hex hash.
    fn delete_chunk(&self, hash: &str) -> Result<()>;

    /// List all chunk hashes stored in the backend.
    fn list_chunks(&self) -> Result<Vec<String>>;

    /// Write a named snapshot blob.
    fn write_snapshot(&self, name: &str, data: &[u8]) -> Result<()>;

    /// Read a named snapshot blob.
    fn read_snapshot(&self, name: &str) -> Result<Vec<u8>>;

    /// List all snapshot names.
    fn list_snapshots(&self) -> Result<Vec<String>>;

    /// Delete a named snapshot.
    fn delete_snapshot(&self, name: &str) -> Result<()>;

    /// Write a named parity shard.
    fn write_parity(&self, name: &str, data: &[u8]) -> Result<()>;

    /// Read a named parity shard.
    fn read_parity(&self, name: &str) -> Result<Vec<u8>>;

    /// List all parity shard names.
    fn list_parity(&self) -> Result<Vec<String>>;

    /// Write a named index blob.
    fn write_index(&self, name: &str, data: &[u8]) -> Result<()>;

    /// Read a named index blob.
    fn read_index(&self, name: &str) -> Result<Vec<u8>>;

    /// Compute the total size (in bytes) of all data stored in the backend.
    fn total_size(&self) -> Result<u64>;

    /// Estimate free space (in bytes) available on the backend.
    fn free_space(&self) -> Result<u64>;
}

// ── BackendConfig ───────────────────────────────────────────────────────────

/// Configuration enum that describes how to connect to a storage backend.
#[derive(Debug, Clone)]
pub enum BackendConfig {
    /// Local filesystem backend.
    Local {
        /// Absolute or relative path to the repository directory.
        path: String,
    },
    /// Amazon S3 (or S3-compatible) backend.
    S3 {
        /// S3 endpoint URL (e.g. `https://s3.amazonaws.com`).
        endpoint: String,
        /// Bucket name.
        bucket: String,
        /// AWS region.
        region: String,
        /// Access key ID.
        access_key: String,
        /// Secret access key.
        secret_key: String,
        /// Key prefix inside the bucket (e.g. `backups/repo1/`).
        prefix: String,
    },
    /// SFTP backend.
    Sftp {
        /// Remote host.
        host: String,
        /// SSH port (typically 22).
        port: u16,
        /// Username for authentication.
        username: String,
        /// Path to the SSH private key on the local filesystem.
        key_path: String,
        /// Remote directory path.
        remote_path: String,
    },
    /// WebDAV backend.
    WebDAV {
        /// WebDAV server URL.
        url: String,
        /// Username for HTTP Basic auth.
        username: String,
        /// Password for HTTP Basic auth.
        password: String,
        /// Path prefix on the server.
        prefix: String,
    },
}

impl BackendConfig {
    /// Parse a URL-like string into a [`BackendConfig`].
    ///
    /// Supported formats:
    ///
    /// - `/path/to/repo` or `file:///path/to/repo` → `Local`
    /// - `s3://bucket/prefix` → `S3` (with default endpoint & region)
    /// - `sftp://user@host:port/path` → `Sftp`
    /// - `webdav://user:pass@host/path` → `WebDAV`
    pub fn from_url(url: &str) -> Result<Self> {
        let url = url.trim();

        // Handle bare paths (no scheme) → Local
        if !url.contains("://") {
            if url.is_empty() {
                return Err(StorageError::InvalidConfig(
                    "empty path for local backend".into(),
                ));
            }
            return Ok(BackendConfig::Local {
                path: url.to_string(),
            });
        }

        // Split scheme from the rest.
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| StorageError::InvalidConfig(format!("invalid URL: {url}")))?;

        match scheme {
            "file" => {
                if rest.is_empty() {
                    return Err(StorageError::InvalidConfig(
                        "empty path for file:// URL".into(),
                    ));
                }
                Ok(BackendConfig::Local {
                    path: rest.to_string(),
                })
            }
            "s3" => {
                // s3://bucket/prefix
                let (bucket, prefix) = if let Some(slash) = rest.find('/') {
                    (&rest[..slash], rest[slash + 1..].to_string())
                } else {
                    (rest, String::new())
                };
                if bucket.is_empty() {
                    return Err(StorageError::InvalidConfig(
                        "S3 bucket name is empty".into(),
                    ));
                }
                Ok(BackendConfig::S3 {
                    endpoint: "https://s3.amazonaws.com".to_string(),
                    bucket: bucket.to_string(),
                    region: "us-east-1".to_string(),
                    access_key: String::new(), // to be supplied via env/config
                    secret_key: String::new(),
                    prefix,
                })
            }
            "sftp" => {
                // sftp://user@host:port/path
                // 1. Extract user@
                let (username, after_at) = if let Some(at_pos) = rest.find('@') {
                    (&rest[..at_pos], &rest[at_pos + 1..])
                } else {
                    return Err(StorageError::InvalidConfig(
                        "SFTP URL must include username: sftp://user@host:port/path".into(),
                    ));
                };

                // 2. Extract host:port
                let (host_port, remote_path) = if let Some(slash_pos) = after_at.find('/') {
                    (
                        &after_at[..slash_pos],
                        after_at[slash_pos + 1..].to_string(),
                    )
                } else {
                    (after_at, String::new())
                };

                let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
                    let p: u16 = host_port[colon_pos + 1..]
                        .parse()
                        .map_err(|_| StorageError::InvalidConfig("invalid SFTP port".into()))?;
                    (&host_port[..colon_pos], p)
                } else {
                    (host_port, 22)
                };

                if host.is_empty() {
                    return Err(StorageError::InvalidConfig("SFTP host is empty".into()));
                }

                Ok(BackendConfig::Sftp {
                    host: host.to_string(),
                    port,
                    username: username.to_string(),
                    key_path: String::new(), // to be supplied via env/config
                    remote_path,
                })
            }
            "webdav" => {
                // webdav://user:pass@host/path
                let (userinfo, after_at) = if let Some(at_pos) = rest.find('@') {
                    (&rest[..at_pos], &rest[at_pos + 1..])
                } else {
                    return Err(StorageError::InvalidConfig(
                        "WebDAV URL must include credentials: webdav://user:pass@host/path".into(),
                    ));
                };

                let (username, password) = if let Some(colon_pos) = userinfo.find(':') {
                    (
                        userinfo[..colon_pos].to_string(),
                        userinfo[colon_pos + 1..].to_string(),
                    )
                } else {
                    return Err(StorageError::InvalidConfig(
                        "WebDAV URL must include password: webdav://user:pass@host/path".into(),
                    ));
                };

                // The rest is host/path – prepend https:// to form a proper URL.
                let (url, prefix) = if let Some(slash_pos) = after_at.find('/') {
                    (
                        format!("https://{}", &after_at[..slash_pos]),
                        after_at[slash_pos + 1..].to_string(),
                    )
                } else {
                    (format!("https://{after_at}"), String::new())
                };

                Ok(BackendConfig::WebDAV {
                    url,
                    username,
                    password,
                    prefix,
                })
            }
            other => Err(StorageError::InvalidConfig(format!(
                "unsupported storage scheme: {other}"
            ))),
        }
    }
}

// ── Factory function ────────────────────────────────────────────────────────

/// Create a boxed storage backend from the given configuration.
pub fn create_backend(config: &BackendConfig) -> Result<Box<dyn StorageBackend>> {
    match config {
        BackendConfig::Local { path } => {
            let storage = LocalStorage::new(Path::new(path))?;
            Ok(Box::new(storage))
        }
        BackendConfig::S3 {
            endpoint,
            bucket,
            region,
            access_key,
            secret_key,
            prefix,
        } => {
            let storage =
                S3Storage::from_config(endpoint, bucket, region, access_key, secret_key, prefix);
            Ok(Box::new(storage))
        }
        BackendConfig::Sftp {
            host,
            port,
            username,
            key_path,
            remote_path,
        } => {
            let storage = SftpStorage::from_config(host, *port, username, key_path, remote_path);
            Ok(Box::new(storage))
        }
        BackendConfig::WebDAV {
            url,
            username,
            password,
            prefix,
        } => {
            let storage = WebDAVStorage::from_config(url, username, password, prefix);
            Ok(Box::new(storage))
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local_bare_path() {
        let config = BackendConfig::from_url("/tmp/repo").unwrap();
        match config {
            BackendConfig::Local { path } => assert_eq!(path, "/tmp/repo"),
            _ => panic!("expected Local variant"),
        }
    }

    #[test]
    fn parse_file_url() {
        let config = BackendConfig::from_url("file:///tmp/repo").unwrap();
        match config {
            BackendConfig::Local { path } => assert_eq!(path, "/tmp/repo"),
            _ => panic!("expected Local variant"),
        }
    }

    #[test]
    fn parse_s3_url() {
        let config = BackendConfig::from_url("s3://my-bucket/backups/repo1").unwrap();
        match config {
            BackendConfig::S3 { bucket, prefix, .. } => {
                assert_eq!(bucket, "my-bucket");
                assert_eq!(prefix, "backups/repo1");
            }
            _ => panic!("expected S3 variant"),
        }
    }

    #[test]
    fn parse_s3_url_no_prefix() {
        let config = BackendConfig::from_url("s3://my-bucket").unwrap();
        match config {
            BackendConfig::S3 { bucket, prefix, .. } => {
                assert_eq!(bucket, "my-bucket");
                assert!(prefix.is_empty());
            }
            _ => panic!("expected S3 variant"),
        }
    }

    #[test]
    fn parse_sftp_url() {
        let config =
            BackendConfig::from_url("sftp://alice@backup.example.com:2222/data/repo").unwrap();
        match config {
            BackendConfig::Sftp {
                host,
                port,
                username,
                remote_path,
                ..
            } => {
                assert_eq!(host, "backup.example.com");
                assert_eq!(port, 2222);
                assert_eq!(username, "alice");
                assert_eq!(remote_path, "data/repo");
            }
            _ => panic!("expected Sftp variant"),
        }
    }

    #[test]
    fn parse_sftp_url_default_port() {
        let config = BackendConfig::from_url("sftp://bob@server/data").unwrap();
        match config {
            BackendConfig::Sftp { port, .. } => assert_eq!(port, 22),
            _ => panic!("expected Sftp variant"),
        }
    }

    #[test]
    fn parse_webdav_url() {
        let config =
            BackendConfig::from_url("webdav://admin:s3cret@cloud.example.com/dav/repo").unwrap();
        match config {
            BackendConfig::WebDAV {
                url,
                username,
                password,
                prefix,
            } => {
                assert_eq!(url, "https://cloud.example.com");
                assert_eq!(username, "admin");
                assert_eq!(password, "s3cret");
                assert_eq!(prefix, "dav/repo");
            }
            _ => panic!("expected WebDAV variant"),
        }
    }

    #[test]
    fn parse_unsupported_scheme() {
        let result = BackendConfig::from_url("ftp://host/path");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_path_fails() {
        let result = BackendConfig::from_url("");
        assert!(result.is_err());
    }
}
