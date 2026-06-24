// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::RepositoryConfig;
use crate::pack::{PackReader, PackWriter, DEFAULT_PACK_SIZE};

/// Name of the lock file created in the repository root.
const LOCK_FILE_NAME: &str = ".backup-shield.lock";

/// Return the path to the repository lock file.
fn lock_file_path(repo_path: &Path) -> PathBuf {
    repo_path.join(LOCK_FILE_NAME)
}

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("repository already exists at {0}")]
    AlreadyExists(String),

    #[error("repository not found at {0}")]
    NotFound(String),

    #[error("chunk not found: {0}")]
    ChunkNotFound(String),

    #[error("index corrupted: {0}")]
    IndexCorrupted(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ── Chunk metadata ───────────────────────────────────────────────────────────

/// Metadata about a single chunk stored in the repository index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    /// Hex-encoded SHA-256 hash of the chunk contents.
    pub hash: String,
    /// Original (uncompressed) size in bytes.
    pub size: usize,
    /// Compressed size in bytes (equal to `size` when no compression is applied).
    pub compressed_size: usize,
    /// Number of snapshots that reference this chunk.
    pub refs: u64,
    /// Parity group identifier (for erasure coding; 0 if not set).
    pub parity_group: u32,
    /// Pack file ID where this chunk is stored (0 = still in write buffer).
    pub pack_id: u64,
    /// Byte offset within the pack file where this chunk starts.
    pub pack_offset: u64,
}

// ── Chunk index ──────────────────────────────────────────────────────────────

/// In-memory index mapping chunk hashes to their metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChunkIndex {
    /// Map from hex SHA-256 hash → ChunkMeta.
    entries: HashMap<String, ChunkMeta>,
}

impl ChunkIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a chunk entry.  If the hash already exists, the ref
    /// count is incremented.
    pub fn upsert(&mut self, meta: ChunkMeta) {
        self.entries
            .entry(meta.hash.clone())
            .and_modify(|e| e.refs += 1)
            .or_insert(meta);
    }

    /// Get a reference to a chunk's metadata.
    pub fn get(&self, hash: &str) -> Option<&ChunkMeta> {
        self.entries.get(hash)
    }

    /// Get a mutable reference to a chunk's metadata.
    pub fn get_mut(&mut self, hash: &str) -> Option<&mut ChunkMeta> {
        self.entries.get_mut(hash)
    }

    /// Decrement the ref count for a chunk.  Returns `true` if the ref count
    /// dropped to zero (meaning the chunk should be deleted).
    pub fn decrement_ref(&mut self, hash: &str) -> bool {
        if let Some(meta) = self.entries.get_mut(hash) {
            meta.refs = meta.refs.saturating_sub(1);
            meta.refs == 0
        } else {
            false
        }
    }

    /// Remove a chunk entry from the index.
    pub fn remove(&mut self, hash: &str) -> Option<ChunkMeta> {
        self.entries.remove(hash)
    }

    /// Return true if the index contains the given hash.
    pub fn contains(&self, hash: &str) -> bool {
        self.entries.contains_key(hash)
    }

    /// Return the number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return an iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ChunkMeta)> {
        self.entries.iter()
    }
}

// ── Repository statistics ────────────────────────────────────────────────────

/// Summary statistics for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryStats {
    /// Total number of unique chunks stored.
    pub total_chunks: u64,
    /// Total uncompressed size of all chunks in bytes.
    pub total_size: u64,
    /// Total compressed size of all chunks in bytes.
    pub total_compressed_size: u64,
    /// Deduplication ratio (1.0 = no dedup, >1.0 = some dedup).
    pub dedup_ratio: f64,
    /// Number of snapshots stored in the repository.
    pub snapshot_count: u64,
    /// Number of pack files.
    pub pack_count: u64,
}

// ── Repository ───────────────────────────────────────────────────────────────

/// Content-addressable storage repository with pack file support.
///
/// The on-disk layout is:
/// ```text
/// <repo_path>/
///   config.toml
///   data/
///     pack-000001.pack     ← chunks stored in pack files (~20 MB each)
///     pack-000002.pack
///     ...
///   snapshots/
///   indexes/
///     chunk_index.json     ← maps hash → (pack_id, offset, meta)
///   parity/
///   keys/
/// ```
#[derive(Debug)]
pub struct Repository {
    /// Root path of the repository on disk.
    pub path: PathBuf,
    /// Repository configuration.
    pub config: RepositoryConfig,
    /// In-memory chunk index.
    pub index: ChunkIndex,
    /// Pack writer for accumulating new chunks.
    pack_writer: Option<PackWriter>,
    /// Pack reader for reading existing chunks.
    pack_reader: PackReader,
    /// Lock file handle (holds exclusive flock); `None` until initialised/opened.
    lock_file: Option<std::fs::File>,
}

impl Drop for Repository {
    fn drop(&mut self) {
        // The lock file handle is dropped automatically, releasing the flock.
        // Log the release for debugging purposes.
        if self.lock_file.is_some() {
            log::debug!("releasing repository lock for {:?}", self.path);
        }
    }
}

impl Repository {
    // ── Initialisation ───────────────────────────────────────────────────

    /// Initialise a new repository at the given path.
    pub fn init(path: &Path, config: Option<RepositoryConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();
        config.validate()?;

        if path.exists() && path.join("config.toml").exists() {
            bail!(RepositoryError::AlreadyExists(path.display().to_string()));
        }

        // Create directory structure.
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create repo dir {:?}", path))?;

        let subdirs = ["data", "snapshots", "indexes", "parity", "keys"];
        for subdir in &subdirs {
            fs::create_dir_all(path.join(subdir))
                .with_context(|| format!("failed to create subdir {:?}", path.join(subdir)))?;
        }

        // Write config.
        config.save(path)?;

        let pack_size = DEFAULT_PACK_SIZE.max(config.pack_target_size);

        // Create lock file and acquire exclusive flock (non-blocking).
        let lf_path = lock_file_path(path);
        let lock_file = fs::File::create(&lf_path)
            .with_context(|| format!("failed to create lock file {:?}", lf_path))?;
        fs2::FileExt::try_lock_exclusive(&lock_file).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                anyhow::anyhow!("Repository already in use by another process")
            } else {
                anyhow::anyhow!("failed to acquire repository lock: {}", e)
            }
        })?;
        log::debug!("acquired exclusive lock on {:?}", lf_path);

        // Write empty index.
        let repo = Self {
            path: path.to_path_buf(),
            config,
            index: ChunkIndex::new(),
            pack_writer: Some(PackWriter::new(path, 1, pack_size)),
            pack_reader: PackReader::new(path),
            lock_file: Some(lock_file),
        };
        repo.save_index()?;

        log::info!("initialised repository at {:?}", path);
        Ok(repo)
    }

    /// Open an existing repository, loading the config and index from disk.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() || !path.join("config.toml").exists() {
            bail!(RepositoryError::NotFound(path.display().to_string()));
        }

        let config = RepositoryConfig::load(path)?;

        // Open (or create) the lock file and acquire exclusive flock (non-blocking).
        let lf_path = lock_file_path(path);
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lf_path)
            .with_context(|| format!("failed to open lock file {:?}", lf_path))?;
        fs2::FileExt::try_lock_exclusive(&lock_file).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                anyhow::anyhow!("Repository already in use by another process")
            } else {
                anyhow::anyhow!("failed to acquire repository lock: {}", e)
            }
        })?;
        log::debug!("acquired exclusive lock on {:?}", lf_path);

        let mut repo = Self {
            path: path.to_path_buf(),
            config,
            index: ChunkIndex::new(),
            pack_writer: None,
            pack_reader: PackReader::new(path),
            lock_file: Some(lock_file),
        };
        repo.load_index()?;

        // Determine the next pack ID from existing packs.
        let next_pack_id = repo.pack_reader.max_pack_id()? + 1;
        repo.pack_writer = Some(PackWriter::new(
            path,
            next_pack_id,
            repo.config.pack_target_size as usize,
        ));

        log::info!("opened repository at {:?}", path);
        Ok(repo)
    }

    // ── Chunk operations ─────────────────────────────────────────────────

    /// Compute the SHA-256 hash of a byte slice and return it as hex.
    fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Store a chunk of data in the repository.
    ///
    /// The chunk is addressed by the SHA-256 hash of its contents.  If the
    /// chunk already exists, its reference count is incremented and no data
    /// is written to disk.
    ///
    /// Chunks are accumulated in the pack writer's buffer and flushed to a
    /// pack file when the buffer exceeds the target size.
    ///
    /// Returns the hex-encoded SHA-256 hash of the chunk.
    pub fn store_chunk(&mut self, data: &[u8]) -> Result<String> {
        let hash = Self::compute_hash(data);

        if self.index.contains(&hash) {
            // Chunk already stored – just increment the ref count.
            if let Some(meta) = self.index.get_mut(&hash) {
                meta.refs += 1;
            }
            log::trace!(
                "store_chunk: duplicate {}, refs incremented",
                &hash[..12.min(hash.len())]
            );
            return Ok(hash);
        }

        // Add to the pack writer's buffer.
        let mut my_pack_id: u64 = 0;
        let mut my_pack_offset: u64 = 0;

        if let Some(ref mut writer) = self.pack_writer {
            let should_flush = writer.add_chunk(&hash, data);

            if should_flush {
                // Flush the current buffer to a pack file.
                if let Some(flush_result) = writer.flush()? {
                    // Update the index for ALL chunks that were just flushed
                    // (they were in the buffer with pack_id=0).
                    for (flushed_hash, offset, size) in &flush_result.chunk_locations {
                        if let Some(meta) = self.index.get_mut(flushed_hash) {
                            meta.pack_id = flush_result.pack_id;
                            meta.pack_offset = *offset;
                            meta.compressed_size = *size as usize;
                        }
                    }

                    // Find the current chunk's location.
                    if let Some(loc) = flush_result
                        .chunk_locations
                        .iter()
                        .find(|(h, _, _)| h == &hash)
                    {
                        my_pack_id = flush_result.pack_id;
                        my_pack_offset = loc.1;
                    }
                }
            }
            // If not flushed, chunk stays in buffer with pack_id=0.
        } else {
            bail!("pack writer not initialised");
        }

        // Update the index.
        let meta = ChunkMeta {
            hash: hash.clone(),
            size: data.len(),
            compressed_size: data.len(), // compression handled externally
            refs: 1,
            parity_group: 0,
            pack_id: my_pack_id,
            pack_offset: my_pack_offset,
        };
        self.index.upsert(meta);

        log::trace!(
            "store_chunk: new {} ({} bytes)",
            &hash[..12.min(hash.len())],
            data.len()
        );
        Ok(hash)
    }

    /// Read a chunk from the repository by its hex-encoded SHA-256 hash.
    ///
    /// If the chunk is still in the pack writer's pending buffer, it is
    /// returned from there. Otherwise, it is read from the appropriate
    /// pack file on disk.
    pub fn read_chunk(&self, hash: &str) -> Result<Vec<u8>> {
        // First, check the pack writer's pending buffer.
        if let Some(ref writer) = self.pack_writer {
            if let Some(data) = writer.get_pending(hash) {
                return Ok(data.to_vec());
            }
        }

        // Look up the chunk in the index.
        let meta = self
            .index
            .get(hash)
            .ok_or_else(|| RepositoryError::ChunkNotFound(hash.to_string()))?;

        if meta.pack_id == 0 {
            // Chunk is marked as pending but not found in buffer.
            // Try the buffer one more time.
            if let Some(ref writer) = self.pack_writer {
                if let Some(data) = writer.get_pending(hash) {
                    return Ok(data.to_vec());
                }
            }
            bail!(RepositoryError::ChunkNotFound(format!(
                "{} (pending but not in buffer)",
                hash
            )));
        }

        // Read from the pack file.
        self.pack_reader
            .read_chunk(meta.pack_id, meta.pack_offset, hash)
            .with_context(|| {
                format!(
                    "failed to read chunk {} from pack {} at offset {}",
                    &hash[..12.min(hash.len())],
                    meta.pack_id,
                    meta.pack_offset
                )
            })
    }

    /// Check whether a chunk with the given hash exists in the repository.
    pub fn chunk_exists(&self, hash: &str) -> bool {
        self.index.contains(hash)
    }

    /// Get metadata for a chunk, if it exists.
    pub fn get_chunk_meta(&self, hash: &str) -> Option<&ChunkMeta> {
        self.index.get(hash)
    }

    /// Delete a chunk from the index (does not remove from pack files;
    /// actual disk space is reclaimed by the `compact` operation).
    ///
    /// This should only be called when the ref count has reached zero.
    pub fn remove_chunk(&mut self, hash: &str) -> Result<()> {
        self.index.remove(hash);
        log::trace!(
            "remove_chunk: removed {} from index (pack data reclaimed on compact)",
            &hash[..12.min(hash.len())]
        );
        Ok(())
    }

    /// Write a repaired chunk back to the repository.
    ///
    /// Creates a new small pack file containing just the repaired chunk,
    /// and updates the index with the new location.
    /// Write a repaired chunk back to the repository and persist the index.
    pub fn write_repaired_chunk(&mut self, hash: &str, data: &[u8]) -> Result<()> {
        // Verify the hash matches.
        let computed = Self::compute_hash(data);
        if computed != hash {
            bail!(
                "repaired chunk hash mismatch: expected {}, computed {}",
                hash,
                computed
            );
        }

        // Write to a new pack file.
        let next_pack_id = self.pack_reader.max_pack_id()? + 1;
        let mut writer = PackWriter::new(&self.path, next_pack_id, DEFAULT_PACK_SIZE);
        writer.add_chunk(hash, data);
        let flush_result = writer.flush()?;

        if let Some(result) = flush_result {
            // Update the index with the new location.
            if let Some(meta) = self.index.get_mut(hash) {
                meta.pack_id = result.pack_id;
                meta.pack_offset = result.chunk_locations[0].1;
                meta.compressed_size = data.len();
            }
        }

        // Persist the updated index.
        self.save_index()?;

        Ok(())
    }

    // ── Index persistence ─────────────────────────────────────────────────

    /// Persist the in-memory chunk index to `indexes/chunk_index.json`.
    ///
    /// Writes to a temporary file first (with fsync), then renames atomically
    /// so that a concurrent reader never sees a partially-written index.
    pub fn save_index(&self) -> Result<()> {
        let index_path = self.path.join("indexes").join("chunk_index.json");
        let tmp_path = index_path.with_extension("json.tmp");
        let json =
            serde_json::to_string_pretty(&self.index).context("failed to serialize chunk index")?;
        {
            use std::io::Write;
            let mut file = fs::File::create(&tmp_path)
                .with_context(|| format!("failed to create temp index {:?}", tmp_path))?;
            file.write_all(json.as_bytes())
                .with_context(|| format!("failed to write temp index to {:?}", tmp_path))?;
            file.sync_all()
                .with_context(|| format!("failed to sync temp index {:?}", tmp_path))?;
        }
        fs::rename(&tmp_path, &index_path)
            .with_context(|| format!("failed to rename temp index to {:?}", index_path))?;
        Ok(())
    }

    /// Flush any pending chunks in the pack writer's buffer to disk,
    /// and update the index with their actual locations.
    pub fn flush_pending(&mut self) -> Result<()> {
        if let Some(ref mut writer) = self.pack_writer {
            if let Some(flush_result) = writer.flush()? {
                for (hash, offset, size) in &flush_result.chunk_locations {
                    if let Some(meta) = self.index.get_mut(hash) {
                        meta.pack_id = flush_result.pack_id;
                        meta.pack_offset = *offset;
                        meta.compressed_size = *size as usize;
                    }
                }
            }
        }
        Ok(())
    }

    /// Load the chunk index from `indexes/chunk_index.json`, replacing the
    /// in-memory index.
    pub fn load_index(&mut self) -> Result<()> {
        let index_path = self.path.join("indexes").join("chunk_index.json");
        if !index_path.exists() {
            self.index = ChunkIndex::new();
            return Ok(());
        }
        let json = fs::read_to_string(&index_path)
            .with_context(|| format!("failed to read chunk index from {:?}", index_path))?;
        self.index = serde_json::from_str(&json)
            .with_context(|| "failed to parse chunk index – file may be corrupted")?;
        Ok(())
    }

    // ── Statistics ────────────────────────────────────────────────────────

    /// Compute repository statistics.
    pub fn stats(&self) -> RepositoryStats {
        let mut total_size: u64 = 0;
        let mut total_compressed_size: u64 = 0;
        let mut total_refs: u64 = 0;

        for (_, meta) in self.index.iter() {
            total_size += meta.size as u64;
            total_compressed_size += meta.compressed_size as u64;
            total_refs += meta.refs;
        }

        let dedup_ratio = if total_compressed_size > 0 && total_refs > 0 {
            (total_size as f64 * total_refs as f64) / total_compressed_size as f64
        } else {
            1.0
        };

        let snapshot_count = match std::fs::read_dir(self.path.join("snapshots")) {
            Ok(entries) => {
                let mut count = 0u64;
                for entry in entries {
                    match entry {
                        Ok(_) => count += 1,
                        Err(e) => log::warn!("failed to read snapshot directory entry: {}", e),
                    }
                }
                count
            }
            Err(e) => {
                log::warn!("failed to read snapshots directory: {}", e);
                0
            }
        };

        let pack_count = self
            .pack_reader
            .list_pack_ids()
            .map(|ids| ids.len() as u64)
            .unwrap_or(0);

        RepositoryStats {
            total_chunks: self.index.len() as u64,
            total_size,
            total_compressed_size,
            dedup_ratio,
            snapshot_count,
            pack_count,
        }
    }

    /// Get the pack reader for this repository (used by verifier/scrubber).
    pub fn pack_reader(&self) -> &PackReader {
        &self.pack_reader
    }

    /// Calculate total disk usage in bytes (all files in repository).
    pub fn calculate_disk_usage(&self) -> u64 {
        let mut total: u64 = 0;

        for subdir in &["data", "snapshots", "parity", "indexes"] {
            total += Self::sum_dir_sizes(&self.path.join(subdir));
        }

        total
    }

    /// Sum the sizes of all files in a directory, logging warnings on errors.
    fn sum_dir_sizes(dir: &Path) -> u64 {
        let mut total: u64 = 0;
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(e) => match e.metadata() {
                            Ok(meta) => total += meta.len(),
                            Err(err) => {
                                log::warn!("failed to read metadata for {:?}: {}", e.path(), err)
                            }
                        },
                        Err(err) => log::warn!("failed to read entry in {:?}: {}", dir, err),
                    }
                }
            }
            Err(err) => {
                log::warn!("failed to read directory {:?}: {}", dir, err);
            }
        }
        total
    }

    /// Check if repository exceeds max_size and return recommended snapshots to prune.
    pub fn check_storage_limit(&self) -> Option<Vec<String>> {
        let max_size = self.config.max_size;
        if max_size == 0 {
            return None; // No limit set
        }

        let current_size = self.calculate_disk_usage();
        if current_size <= max_size {
            return None; // Under limit
        }

        // Load snapshots and sort by timestamp (oldest first)
        let snapshots = match crate::snapshot::list_snapshots(&self.path) {
            Ok(s) => s,
            Err(_) => return None,
        };

        if snapshots.len() <= self.config.min_snapshots as usize {
            return None; // Can't prune below minimum
        }

        // Calculate how much to prune
        let _size_to_free = current_size - max_size;
        let mut to_prune = Vec::new();

        for snap in snapshots
            .iter()
            .take(snapshots.len() - self.config.min_snapshots as usize)
        {
            to_prune.push(snap.id.clone());
            // Rough estimate: each snapshot is roughly total_size / snapshot_count
            if to_prune.len() as u64 >= snapshots.len() as u64 - self.config.min_snapshots as u64 {
                break;
            }
        }

        Some(to_prune)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo_path() -> PathBuf {
        tempfile::tempdir().unwrap().path().join("test-repo")
    }

    #[test]
    fn init_creates_directory_structure() {
        let path = temp_repo_path();
        let repo = Repository::init(&path, None).unwrap();
        assert!(path.join("config.toml").exists());
        assert!(path.join("data").exists());
        assert!(path.join("snapshots").exists());
        assert!(path.join("indexes").exists());
        assert!(path.join("parity").exists());
        assert!(path.join("keys").exists());
        assert!(path.join("indexes/chunk_index.json").exists());
        drop(repo);
    }

    #[test]
    fn init_fails_if_already_exists() {
        let path = temp_repo_path();
        Repository::init(&path, None).unwrap();
        let result = Repository::init(&path, None);
        assert!(result.is_err());
    }

    #[test]
    fn open_loads_config_and_index() {
        let path = temp_repo_path();
        let repo = Repository::init(&path, None).unwrap();
        let repo_id = repo.config.repo_id.clone();
        drop(repo);

        let opened = Repository::open(&path).unwrap();
        assert_eq!(opened.config.repo_id, repo_id);
    }

    #[test]
    fn store_and_read_chunk() {
        let path = temp_repo_path();
        let mut repo = Repository::init(&path, None).unwrap();

        let data = b"hello, backup world!";
        let hash = repo.store_chunk(data).unwrap();

        // Flush to disk.
        repo.flush_pending().unwrap();

        // Chunk should exist.
        assert!(repo.chunk_exists(&hash));

        // Reading it back should yield the same data.
        let read_data = repo.read_chunk(&hash).unwrap();
        assert_eq!(read_data, data);

        // Meta should be correct.
        let meta = repo.get_chunk_meta(&hash).unwrap();
        assert_eq!(meta.size, data.len());
        assert_eq!(meta.refs, 1);
    }

    #[test]
    fn store_duplicate_chunk_increments_ref() {
        let path = temp_repo_path();
        let mut repo = Repository::init(&path, None).unwrap();

        let data = b"duplicate data";
        let h1 = repo.store_chunk(data).unwrap();
        let h2 = repo.store_chunk(data).unwrap();
        assert_eq!(h1, h2);

        let meta = repo.get_chunk_meta(&h1).unwrap();
        assert_eq!(meta.refs, 2);
    }

    #[test]
    fn stats_are_correct() {
        let path = temp_repo_path();
        let mut repo = Repository::init(&path, None).unwrap();

        repo.store_chunk(b"aaaa").unwrap();
        repo.store_chunk(b"bbbb").unwrap();
        repo.flush_pending().unwrap();

        let stats = repo.stats();
        assert_eq!(stats.total_chunks, 2);
        assert_eq!(stats.total_size, 8);
    }

    #[test]
    fn read_chunk_from_pending_buffer() {
        let path = temp_repo_path();
        let mut repo = Repository::init(&path, None).unwrap();

        let data = b"still in buffer";
        let hash = repo.store_chunk(data).unwrap();

        // Don't flush — should still be readable from the buffer.
        let read_data = repo.read_chunk(&hash).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn concurrent_open_fails_with_lock() {
        // Opening the same repo from two processes/handles should fail.
        let path = temp_repo_path();
        let _repo1 = Repository::init(&path, None).unwrap();

        let result = Repository::open(&path);
        assert!(
            result.is_err(),
            "second open should fail with 'already in use' error"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("already in use"),
            "error should mention 'already in use', got: {}",
            err
        );
    }

    #[test]
    fn lock_is_released_on_drop() {
        // After dropping the first handle, a second should succeed.
        let path = temp_repo_path();

        {
            let _repo1 = Repository::init(&path, None).unwrap();
            // Lock is held here.
        }
        // repo1 dropped → lock released.

        let _repo2 =
            Repository::open(&path).expect("should succeed after previous handle is dropped");
    }

    #[test]
    fn lock_file_is_recoverable_after_crash() {
        // Simulate a crash by creating the lock file manually and verifying
        // that a new handle can acquire the lock (flock is released when the
        // kernel sees the process died — we simulate by closing our handle).
        let path = temp_repo_path();
        Repository::init(&path, None).unwrap();

        // Drop the repo → lock released.
        // Now the lock file still exists on disk, but flock is released.
        let _repo = Repository::open(&path)
            .expect("lock should be recoverable even though .lock file exists");
    }

    #[test]
    fn multiple_flushes_create_multiple_packs() {
        let path = temp_repo_path();
        let mut repo = Repository::init(&path, None).unwrap();

        // Use a very small pack size to force multiple packs.
        // Each chunk entry is ~1 + 64 + 4 + 100 = 169 bytes plus header(14) + footer(33).
        // With target=140, even the first chunk exceeds it (14+169+33=216 > 140),
        // so every store_chunk triggers a flush.
        repo.config.pack_target_size = 140;
        let next_id = repo.pack_reader.max_pack_id().unwrap() + 1;
        repo.pack_writer = Some(PackWriter::new(&path, next_id, 140));

        for i in 0..10u8 {
            let data = vec![i; 100];
            repo.store_chunk(&data).unwrap();
        }
        repo.flush_pending().unwrap();

        let stats = repo.stats();
        assert!(
            stats.pack_count > 1,
            "should have multiple packs, got {}",
            stats.pack_count
        );
    }
}
