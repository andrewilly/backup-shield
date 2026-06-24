// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Repository configuration stored at the root of the backup repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryConfig {
    /// Unique repository identifier (random hex string).
    pub repo_id: String,
    /// Whether encryption is enabled for this repository.
    pub encryption_enabled: bool,
    /// Zstd compression level (1-22).
    pub compression_level: u32,
    /// Minimum chunk size in bytes.
    pub chunk_min_size: usize,
    /// Maximum chunk size in bytes.
    pub chunk_max_size: usize,
    /// Target chunk size in bytes (drives the rolling-hash mask).
    pub chunk_target_size: usize,
    /// Number of data shards for erasure coding.
    pub ecc_data_shards: usize,
    /// Number of parity shards for erasure coding.
    pub ecc_parity_shards: usize,
    /// Target pack file size in bytes (default 20 MB).
    /// Chunks are accumulated in memory and flushed to a pack file when
    /// this size is exceeded. Smaller values create more pack files but
    /// use less memory; larger values create fewer but larger packs.
    pub pack_target_size: usize,
    /// Maximum repository size in bytes (0 = unlimited).
    /// When exceeded, oldest snapshots are automatically pruned.
    #[serde(default)]
    pub max_size: u64,
    /// Minimum snapshots to keep regardless of max_size.
    #[serde(default = "default_min_snapshots")]
    pub min_snapshots: u32,
    /// Timestamp when the repository was created.
    pub created_at: DateTime<Utc>,
}

fn default_min_snapshots() -> u32 {
    3
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self {
            repo_id: Self::generate_repo_id(),
            encryption_enabled: false,
            compression_level: 3,
            chunk_min_size: 64 * 1024,       // 64 KB
            chunk_max_size: 8 * 1024 * 1024, // 8 MB
            chunk_target_size: 512 * 1024,   // 512 KB
            ecc_data_shards: 64,
            ecc_parity_shards: 8,
            pack_target_size: 20 * 1024 * 1024, // 20 MB
            max_size: 0,                        // 0 = unlimited
            min_snapshots: 3,
            created_at: Utc::now(),
        }
    }
}

impl RepositoryConfig {
    /// Generate a cryptographically secure random repository ID.
    fn generate_repo_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Validate configuration values, returning an error if anything is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.compression_level < 1 || self.compression_level > 22 {
            anyhow::bail!(
                "compression_level must be between 1 and 22, got {}",
                self.compression_level
            );
        }
        if self.chunk_min_size == 0 {
            anyhow::bail!("chunk_min_size must be > 0");
        }
        if self.chunk_max_size <= self.chunk_min_size {
            anyhow::bail!(
                "chunk_max_size ({}) must be greater than chunk_min_size ({})",
                self.chunk_max_size,
                self.chunk_min_size
            );
        }
        if self.chunk_target_size < self.chunk_min_size
            || self.chunk_target_size > self.chunk_max_size
        {
            anyhow::bail!(
                "chunk_target_size ({}) must be between chunk_min_size ({}) and chunk_max_size ({})",
                self.chunk_target_size,
                self.chunk_min_size,
                self.chunk_max_size
            );
        }
        if self.ecc_data_shards == 0 {
            anyhow::bail!("ecc_data_shards must be > 0");
        }
        if self.ecc_parity_shards == 0 {
            anyhow::bail!("ecc_parity_shards must be > 0");
        }
        Ok(())
    }

    /// Save configuration to the repository's config.toml file.
    pub fn save(&self, repo_path: &Path) -> Result<()> {
        Self::save_to_path(self, &repo_path.join("config.toml"))
    }

    /// Load configuration from the repository's config.toml file.
    pub fn load(repo_path: &Path) -> Result<Self> {
        Self::load_from_path(&repo_path.join("config.toml"))
    }

    /// Save configuration to an explicit path.
    /// Uses atomic write (tmp file + rename + fsync) to prevent corruption on crash.
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let toml_str =
            toml::to_string_pretty(self).context("failed to serialize repository config")?;
        let tmp_path = path.with_extension("toml.tmp");
        {
            let mut file = fs::File::create(&tmp_path)
                .with_context(|| format!("failed to create config tmp {:?}", tmp_path))?;
            file.write_all(toml_str.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to rename config {:?} -> {:?}", tmp_path, path))
    }

    /// Load configuration from an explicit path.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {:?}", path))?;
        let config: RepositoryConfig =
            toml::from_str(&contents).context("failed to parse repository config")?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = RepositoryConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_compression_level_fails() {
        let config = RepositoryConfig {
            compression_level: 0,
            ..RepositoryConfig::default()
        };
        assert!(config.validate().is_err());
        let config = RepositoryConfig {
            compression_level: 23,
            ..RepositoryConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let config = RepositoryConfig::default();
        config
            .save_to_path(&dir.path().join("config.toml"))
            .unwrap();
        let loaded = RepositoryConfig::load_from_path(&dir.path().join("config.toml")).unwrap();
        assert_eq!(config.repo_id, loaded.repo_id);
        assert_eq!(config.compression_level, loaded.compression_level);
        assert_eq!(config.chunk_min_size, loaded.chunk_min_size);
    }
}
