// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Hierarchical integrity verification at 3 levels.
//!
//! The verification chain is:
//! 1. **Level 1 (Chunk)**: SHA-256(chunk_content) == chunk_hash
//! 2. **Level 2 (File)**: SHA-256(concatenated chunk_hashes) == file_hash in snapshot
//! 3. **Level 3 (Snapshot)**: Snapshot JSON can be parsed and is structurally valid

use anyhow::{bail, Context, Result};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use backup_shield_core::pack::PackReader;
use backup_shield_core::repository::ChunkIndex;
use backup_shield_core::snapshot::{Snapshot, SnapshotFile, SnapshotNode};

// ── VerifyLevel ─────────────────────────────────────────────────────────────

/// Verification depth / thoroughness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyLevel {
    /// Only check that chunk files exist (stat) and snapshot JSON files parse.
    Quick,
    /// Full 3-level chain verification: chunk hashes, file hashes, snapshot integrity.
    Full,
    /// Like Full, but only verify N randomly selected chunks.
    Sample(usize),
}

impl std::fmt::Display for VerifyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyLevel::Quick => write!(f, "Quick"),
            VerifyLevel::Full => write!(f, "Full"),
            VerifyLevel::Sample(n) => write!(f, "Sample({})", n),
        }
    }
}

// ── VerifyError ─────────────────────────────────────────────────────────────

/// An integrity error discovered during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerifyError {
    /// A chunk's content hash does not match the expected hash.
    ChunkCorrupt {
        hash: String,
        expected: String,
        actual: String,
    },
    /// A chunk file is missing from disk.
    ChunkMissing { hash: String },
    /// A snapshot JSON file is corrupt or cannot be parsed.
    SnapshotCorrupt { id: String, reason: String },
    /// A file's computed hash does not match the file_hash stored in the snapshot.
    FileHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// A pack file checksum is invalid.
    PackCorrupt { pack_id: u64, reason: String },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::ChunkCorrupt {
                hash,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "chunk corrupt: {} (expected {}, got {})",
                    hash, expected, actual
                )
            }
            VerifyError::ChunkMissing { hash } => {
                write!(f, "chunk missing: {}", hash)
            }
            VerifyError::SnapshotCorrupt { id, reason } => {
                write!(f, "snapshot corrupt: {} ({})", id, reason)
            }
            VerifyError::FileHashMismatch {
                path,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "file hash mismatch: {} (expected {}, got {})",
                    path, expected, actual
                )
            }
            VerifyError::PackCorrupt { pack_id, reason } => {
                write!(f, "pack corrupt: {} ({})", pack_id, reason)
            }
        }
    }
}

impl std::error::Error for VerifyError {}

// ── VerifyResult ────────────────────────────────────────────────────────────

/// Result of a verification pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// The verification level that was used.
    pub level: VerifyLevel,
    /// Number of chunks checked.
    pub chunks_checked: u64,
    /// Number of chunks that passed verification.
    pub chunks_ok: u64,
    /// Number of chunks with corrupt content (hash mismatch).
    pub chunks_corrupt: u64,
    /// Number of chunks referenced in the index but missing from disk.
    pub chunks_missing: u64,
    /// Number of snapshots checked.
    pub snapshots_checked: u64,
    /// Number of files checked (only for Full / Sample levels).
    pub files_checked: u64,
    /// Number of pack files checked.
    pub packs_checked: u64,
    /// All errors discovered during verification.
    pub errors: Vec<VerifyError>,
    /// Wall-clock duration of the verification in seconds.
    pub duration_secs: f64,
}

impl VerifyResult {
    /// Returns `true` if no errors were found.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns the total number of problematic chunks (corrupt + missing).
    pub fn total_chunk_errors(&self) -> u64 {
        self.chunks_corrupt + self.chunks_missing
    }
}

// ── Verifier ────────────────────────────────────────────────────────────────

/// Hierarchical integrity verifier for a BackupShield repository.
pub struct Verifier {
    /// Path to the repository root.
    repo_path: PathBuf,
    /// Pack reader for reading chunks from pack files.
    pack_reader: PackReader,
}

impl Verifier {
    /// Create a new verifier for the repository at `repo_path`.
    pub fn new(repo_path: &Path) -> Result<Verifier> {
        if !repo_path.exists() {
            bail!("repository path does not exist: {:?}", repo_path);
        }
        if !repo_path.join("config.toml").exists() {
            bail!(
                "not a valid repository (missing config.toml): {:?}",
                repo_path
            );
        }
        Ok(Verifier {
            repo_path: repo_path.to_path_buf(),
            pack_reader: PackReader::new(repo_path),
        })
    }

    /// Load the chunk index from disk.
    fn load_index(&self) -> Result<ChunkIndex> {
        let index_path = self.repo_path.join("indexes").join("chunk_index.json");
        if !index_path.exists() {
            return Ok(ChunkIndex::new());
        }
        let json = fs::read_to_string(&index_path)
            .with_context(|| format!("failed to read chunk index from {:?}", index_path))?;
        let index: ChunkIndex =
            serde_json::from_str(&json).with_context(|| "failed to parse chunk index")?;
        Ok(index)
    }

    /// Compute SHA-256 of a byte slice, returning hex.
    fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Read a chunk from the repository using the chunk index to locate it.
    fn read_chunk_from_index(&self, hash: &str, index: &ChunkIndex) -> Result<Vec<u8>> {
        let meta = index
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("chunk {} not in index", hash))?;

        if meta.pack_id == 0 {
            bail!("chunk {} is still in write buffer (pack_id=0)", hash);
        }

        self.pack_reader
            .read_chunk(meta.pack_id, meta.pack_offset, hash)
    }

    /// Verify a single chunk by reading it from its pack file.
    #[allow(dead_code)]
    fn verify_single_chunk(&self, hash: &str, index: &ChunkIndex) -> Result<bool> {
        let meta = match index.get(hash) {
            Some(m) => m,
            None => return Ok(false),
        };

        if meta.pack_id == 0 {
            // Still in buffer — can't verify from disk.
            return Ok(true);
        }

        match self
            .pack_reader
            .read_chunk(meta.pack_id, meta.pack_offset, hash)
        {
            Ok(data) => {
                let actual = Self::compute_hash(&data);
                Ok(actual == hash)
            }
            Err(_) => Ok(false),
        }
    }

    /// Verify a single snapshot's integrity (3-level chain).
    pub fn verify_snapshot(&self, snapshot_id: &str) -> Result<VerifyResult> {
        let start = Instant::now();
        let index = self.load_index()?;

        let snapshot_path = self
            .repo_path
            .join("snapshots")
            .join(format!("{}.json", snapshot_id));

        // Level 3: parse snapshot JSON.
        let snapshot = match Snapshot::load(&snapshot_path) {
            Ok(s) => s,
            Err(e) => {
                let mut errors = Vec::new();
                errors.push(VerifyError::SnapshotCorrupt {
                    id: snapshot_id.to_string(),
                    reason: e.to_string(),
                });
                return Ok(VerifyResult {
                    level: VerifyLevel::Full,
                    chunks_checked: 0,
                    chunks_ok: 0,
                    chunks_corrupt: 0,
                    chunks_missing: 0,
                    snapshots_checked: 1,
                    files_checked: 0,
                    packs_checked: 0,
                    errors,
                    duration_secs: start.elapsed().as_secs_f64(),
                });
            }
        };

        let mut chunks_checked: u64 = 0;
        let mut chunks_ok: u64 = 0;
        let mut chunks_corrupt: u64 = 0;
        let mut chunks_missing: u64 = 0;
        let mut files_checked: u64 = 0;
        let mut errors = Vec::new();

        let mut file_entries: Vec<(String, SnapshotFile)> = Vec::new();
        Self::collect_files(&snapshot.root, &mut file_entries, String::new());

        let mut verified_chunks = std::collections::HashSet::new();

        for (file_path, file_entry) in &file_entries {
            files_checked += 1;

            for chunk_hash in &file_entry.chunk_hashes {
                if verified_chunks.contains(chunk_hash) {
                    continue;
                }
                verified_chunks.insert(chunk_hash.clone());
                chunks_checked += 1;

                match self.read_chunk_from_index(chunk_hash, &index) {
                    Ok(data) => {
                        let actual = Self::compute_hash(&data);
                        if actual != *chunk_hash {
                            chunks_corrupt += 1;
                            errors.push(VerifyError::ChunkCorrupt {
                                hash: chunk_hash.clone(),
                                expected: chunk_hash.clone(),
                                actual,
                            });
                        } else {
                            chunks_ok += 1;
                        }
                    }
                    Err(e) => {
                        chunks_missing += 1;
                        errors.push(VerifyError::ChunkMissing {
                            hash: chunk_hash.clone(),
                        });
                        log::debug!(
                            "chunk {} missing: {}",
                            &chunk_hash[..12.min(chunk_hash.len())],
                            e
                        );
                    }
                }
            }

            // Level 2: Verify file_hash.
            let computed_file_hash = Self::compute_file_hash(&file_entry.chunk_hashes);
            if computed_file_hash != file_entry.file_hash {
                errors.push(VerifyError::FileHashMismatch {
                    path: file_path.clone(),
                    expected: file_entry.file_hash.clone(),
                    actual: computed_file_hash,
                });
            }
        }

        Ok(VerifyResult {
            level: VerifyLevel::Full,
            chunks_checked,
            chunks_ok,
            chunks_corrupt,
            chunks_missing,
            snapshots_checked: 1,
            files_checked,
            packs_checked: 0,
            errors,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    /// Run verification at the specified level.
    pub fn verify(&self, level: VerifyLevel) -> Result<VerifyResult> {
        let start = Instant::now();

        let index = self.load_index()?;

        let mut chunks_checked: u64 = 0;
        let mut chunks_ok: u64 = 0;
        let mut chunks_corrupt: u64 = 0;
        let mut chunks_missing: u64 = 0;
        let snapshots_checked: u64;
        let mut files_checked: u64 = 0;
        let mut errors: Vec<VerifyError> = Vec::new();

        // Verify pack file checksums.
        let pack_ids = self.pack_reader.list_pack_ids()?;
        let packs_checked = pack_ids.len() as u64;

        for pack_id in &pack_ids {
            if let Err(e) = self.pack_reader.verify_pack(*pack_id) {
                errors.push(VerifyError::PackCorrupt {
                    pack_id: *pack_id,
                    reason: e.to_string(),
                });
            }
        }

        // Determine which chunk hashes to verify.
        let all_hashes: Vec<String> = index.iter().map(|(h, _)| h.clone()).collect();
        let hashes_to_verify: Vec<String> = match &level {
            VerifyLevel::Quick => Vec::new(),
            VerifyLevel::Full => all_hashes.clone(),
            VerifyLevel::Sample(n) => {
                let sample_size = (*n).min(all_hashes.len());
                let mut rng = rand::thread_rng();
                let mut sampled = all_hashes.clone();
                sampled.shuffle(&mut rng);
                sampled.truncate(sample_size);
                sampled
            }
        };

        // ── Quick level: index-only check + snapshot parse ───────────────
        if level == VerifyLevel::Quick {
            for (hash, meta) in index.iter() {
                chunks_checked += 1;
                // For quick check, just verify the chunk has a valid pack_id
                // (i.e., it's been flushed to a pack file).
                if meta.pack_id == 0 {
                    // Still in write buffer — consider OK for quick check.
                    chunks_ok += 1;
                    continue;
                }
                // Check that the pack file exists.
                let pack_path =
                    backup_shield_core::pack::pack_path(&self.repo_path, meta.pack_id);
                if !pack_path.exists() {
                    chunks_missing += 1;
                    errors.push(VerifyError::ChunkMissing { hash: hash.clone() });
                } else {
                    chunks_ok += 1;
                }
            }

            let snapshots = self.load_snapshots(&mut errors);
            snapshots_checked = snapshots.len() as u64;

            return Ok(VerifyResult {
                level,
                chunks_checked,
                chunks_ok,
                chunks_corrupt,
                chunks_missing,
                snapshots_checked,
                files_checked,
                packs_checked,
                errors,
                duration_secs: start.elapsed().as_secs_f64(),
            });
        }

        // ── Full / Sample level ──────────────────────────────────────────
        for hash in &hashes_to_verify {
            chunks_checked += 1;

            match self.read_chunk_from_index(hash, &index) {
                Ok(data) => {
                    let actual = Self::compute_hash(&data);
                    if actual != *hash {
                        chunks_corrupt += 1;
                        errors.push(VerifyError::ChunkCorrupt {
                            hash: hash.clone(),
                            expected: hash.clone(),
                            actual,
                        });
                    } else {
                        chunks_ok += 1;
                    }
                }
                Err(_) => {
                    chunks_missing += 1;
                    errors.push(VerifyError::ChunkMissing { hash: hash.clone() });
                }
            }
        }

        // Level 2 & 3: Load snapshots and verify file hashes.
        let snapshots = self.load_snapshots(&mut errors);
        snapshots_checked = snapshots.len() as u64;

        let bad_hashes: std::collections::HashSet<String> = errors
            .iter()
            .filter_map(|e| match e {
                VerifyError::ChunkCorrupt { hash, .. } => Some(hash.clone()),
                VerifyError::ChunkMissing { hash } => Some(hash.clone()),
                _ => None,
            })
            .collect();

        for snapshot in &snapshots {
            let mut file_entries: Vec<(String, SnapshotFile)> = Vec::new();
            Self::collect_files(&snapshot.root, &mut file_entries, String::new());

            for (file_path, file_entry) in &file_entries {
                files_checked += 1;

                let computed_file_hash = Self::compute_file_hash(&file_entry.chunk_hashes);
                let any_bad_chunk = file_entry
                    .chunk_hashes
                    .iter()
                    .any(|h| bad_hashes.contains(h));

                if !any_bad_chunk && computed_file_hash != file_entry.file_hash {
                    errors.push(VerifyError::FileHashMismatch {
                        path: file_path.clone(),
                        expected: file_entry.file_hash.clone(),
                        actual: computed_file_hash,
                    });
                }
            }
        }

        Ok(VerifyResult {
            level,
            chunks_checked,
            chunks_ok,
            chunks_corrupt,
            chunks_missing,
            snapshots_checked,
            files_checked,
            packs_checked,
            errors,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    fn compute_file_hash(chunk_hashes: &[String]) -> String {
        let mut hasher = Sha256::new();
        for h in chunk_hashes {
            hasher.update(h.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    fn collect_files<'a>(
        node: &'a SnapshotNode,
        files: &mut Vec<(String, SnapshotFile)>,
        parent_path: String,
    ) {
        match node {
            SnapshotNode::File(f) => {
                let path = if parent_path.is_empty() {
                    f.name.clone()
                } else {
                    format!("{}/{}", parent_path, f.name)
                };
                files.push((path, f.clone()));
            }
            SnapshotNode::Directory(d) => {
                let dir_path = if parent_path.is_empty() {
                    d.name.clone()
                } else {
                    format!("{}/{}", parent_path, d.name)
                };
                for child in &d.children {
                    Self::collect_files(child, files, dir_path.clone());
                }
            }
            SnapshotNode::Symlink(_) => {}
        }
    }

    fn load_snapshots(&self, errors: &mut Vec<VerifyError>) -> Vec<Snapshot> {
        let snapshots_dir = self.repo_path.join("snapshots");
        if !snapshots_dir.exists() {
            return Vec::new();
        }

        let mut snapshots = Vec::new();
        let entries = match fs::read_dir(&snapshots_dir) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    log::warn!("failed to read entry in snapshots dir: {}", err);
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                let snapshot_id = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();

                match Snapshot::load(&path) {
                    Ok(snap) => snapshots.push(snap),
                    Err(e) => {
                        errors.push(VerifyError::SnapshotCorrupt {
                            id: snapshot_id,
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        snapshots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_shield_core::repository::Repository;

    fn temp_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-test-repo");
        (dir, path)
    }

    fn init_repo(path: &Path) -> Repository {
        Repository::init(path, None).unwrap()
    }

    #[test]
    fn verifier_new_valid_repo() {
        let (_dir, path) = temp_repo();
        let _repo = init_repo(&path);
        let verifier = Verifier::new(&path);
        assert!(verifier.is_ok());
    }

    #[test]
    fn verifier_new_invalid_path() {
        let path = PathBuf::from("/nonexistent/path");
        let verifier = Verifier::new(&path);
        assert!(verifier.is_err());
    }

    #[test]
    fn verify_quick_empty_repo() {
        let (_dir, path) = temp_repo();
        let _repo = init_repo(&path);
        let verifier = Verifier::new(&path).unwrap();
        let result = verifier.verify(VerifyLevel::Quick).unwrap();
        assert!(result.is_ok());
        assert_eq!(result.chunks_checked, 0);
    }

    #[test]
    fn verify_full_with_chunks() {
        let (_dir, path) = temp_repo();
        let mut repo = init_repo(&path);
        repo.store_chunk(b"test data 1").unwrap();
        repo.store_chunk(b"test data 2").unwrap();
        repo.flush_pending().unwrap();
        repo.save_index().unwrap();

        let verifier = Verifier::new(&path).unwrap();
        let result = verifier.verify(VerifyLevel::Full).unwrap();
        assert!(result.is_ok());
        assert_eq!(result.chunks_checked, 2);
        assert_eq!(result.chunks_ok, 2);
    }

    #[test]
    fn verify_sample_fewer_than_total() {
        let (_dir, path) = temp_repo();
        let mut repo = init_repo(&path);
        repo.store_chunk(b"chunk a").unwrap();
        repo.store_chunk(b"chunk b").unwrap();
        repo.store_chunk(b"chunk c").unwrap();
        repo.flush_pending().unwrap();
        repo.save_index().unwrap();

        let verifier = Verifier::new(&path).unwrap();
        let result = verifier.verify(VerifyLevel::Sample(2)).unwrap();
        assert!(result.is_ok());
        assert_eq!(result.chunks_checked, 2);
    }

    #[test]
    fn verify_level_display() {
        assert_eq!(VerifyLevel::Quick.to_string(), "Quick");
        assert_eq!(VerifyLevel::Full.to_string(), "Full");
        assert_eq!(VerifyLevel::Sample(5).to_string(), "Sample(5)");
    }
}
