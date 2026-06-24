// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Pack file management for hybrid chunk storage.
//!
//! Instead of storing each chunk as a separate file (which is slow on HDDs,
//! NAS, and cloud storage), chunks are accumulated in memory and written to
//! "pack files" of approximately `pack_target_size` bytes each.
//!
//! Pack file binary format:
//! ```text
//! HEADER (14 bytes):
//!   [4 bytes]  "BKSP" magic
//!   [2 bytes]  version (u16 LE) — currently 0x0001
//!   [8 bytes]  pack_id (u64 LE) — sequential identifier
//!
//! CHUNK ENTRIES (repeated):
//!   [1 byte]     0x01 = chunk marker
//!   [64 bytes]   hex SHA-256 hash (ASCII)
//!   [4 bytes]    stored_size (u32 LE)
//!   [N bytes]    chunk data
//!
//! END MARKER:
//!   [1 byte]     0x00
//!
//! CHECKSUM (32 bytes):
//!   SHA-256 of all preceding bytes
//! ```
//!
//! The chunk index (`chunk_index.json`) stores the `pack_id` and `pack_offset`
//! for each chunk, allowing O(1) random access via seek.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ── Constants ────────────────────────────────────────────────────────────────

/// Pack file magic number.
pub const PACK_MAGIC: &[u8; 4] = b"BKSP";

/// Current pack file format version.
pub const PACK_VERSION: u16 = 1;

/// Default target size for a pack file (20 MB).
pub const DEFAULT_PACK_SIZE: usize = 20 * 1024 * 1024;

/// Chunk entry marker byte.
const CHUNK_MARKER: u8 = 0x01;

/// End-of-entries marker byte.
const END_MARKER: u8 = 0x00;

/// Hex SHA-256 hash length (always 64 characters).
const HASH_LEN: usize = 64;

/// Header size: magic(4) + version(2) + pack_id(8) = 14 bytes.
const HEADER_SIZE: usize = 14;

/// Per-chunk overhead: marker(1) + hash(64) + size_field(4) = 69 bytes.
const CHUNK_OVERHEAD: usize = 1 + HASH_LEN + 4;

/// Footer size: end_marker(1) + checksum(32) = 33 bytes.
const FOOTER_SIZE: usize = 1 + 32;

// ── Pack file naming ────────────────────────────────────────────────────────

/// Generate the filename for a pack file given its ID.
pub fn pack_filename(pack_id: u64) -> String {
    format!("pack-{:06}.pack", pack_id)
}

/// Generate the path for a pack file within a repository.
pub fn pack_path(repo_path: &Path, pack_id: u64) -> PathBuf {
    repo_path.join("data").join(pack_filename(pack_id))
}

// ── PackWriter ──────────────────────────────────────────────────────────────

/// Accumulates chunks in memory and writes them to a pack file when the
/// buffer exceeds `target_size`, or when explicitly flushed.
#[derive(Debug)]
pub struct PackWriter {
    /// Repository root path.
    repo_path: PathBuf,
    /// Target pack file size in bytes.
    target_size: usize,
    /// Next pack ID to assign.
    next_pack_id: u64,
    /// Buffered chunks: (hash_hex, data).
    buffer: Vec<(String, Vec<u8>)>,
    /// Total bytes currently in the buffer (including overhead).
    buffer_bytes: usize,
}

/// Result of flushing a pack to disk.
#[derive(Debug, Clone)]
pub struct FlushResult {
    /// The pack ID that was written.
    pub pack_id: u64,
    /// The path of the pack file on disk.
    pub pack_file: PathBuf,
    /// Number of chunks written in this pack.
    pub chunk_count: usize,
    /// Per-chunk (hash, offset_in_pack, stored_size).
    pub chunk_locations: Vec<(String, u64, u32)>,
}

impl PackWriter {
    /// Create a new `PackWriter` for the repository at `repo_path`.
    ///
    /// `next_pack_id` should be the highest existing pack ID + 1 (or 1 if
    /// no packs exist yet).
    pub fn new(repo_path: &Path, next_pack_id: u64, target_size: usize) -> Self {
        Self {
            repo_path: repo_path.to_path_buf(),
            target_size,
            next_pack_id,
            buffer: Vec::new(),
            buffer_bytes: 0,
        }
    }

    /// Add a chunk to the buffer. Returns `(should_flush, pack_id_if_flushed)`.
    /// The caller should call `flush()` if `should_flush` is true.
    pub fn add_chunk(&mut self, hash: &str, data: &[u8]) -> bool {
        let entry_size = CHUNK_OVERHEAD + data.len();
        self.buffer.push((hash.to_string(), data.to_vec()));
        self.buffer_bytes += entry_size;

        // Flush if we've exceeded the target size (accounting for header + footer).
        let total_estimated = HEADER_SIZE + self.buffer_bytes + FOOTER_SIZE;
        total_estimated >= self.target_size
    }

    /// Flush all buffered chunks to a pack file on disk.
    ///
    /// Returns `FlushResult` with the locations of each chunk within the pack,
    /// or `None` if the buffer is empty.
    pub fn flush(&mut self) -> Result<Option<FlushResult>> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let pack_id = self.next_pack_id;
        self.next_pack_id += 1;

        let pack_file = pack_path(&self.repo_path, pack_id);
        // Write to a .tmp file first, then rename atomically.
        let tmp_file = pack_file.with_extension("pack.tmp");

        // Ensure the data directory exists.
        if let Some(parent) = pack_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create data dir {:?}", parent))?;
        }

        let mut writer = BufWriter::new(
            fs::File::create(&tmp_file)
                .with_context(|| format!("failed to create temp pack file {:?}", tmp_file))?,
        );

        // Write header.
        writer.write_all(PACK_MAGIC)?;
        writer.write_all(&PACK_VERSION.to_le_bytes())?;
        writer.write_all(&pack_id.to_le_bytes())?;

        let mut chunk_locations = Vec::with_capacity(self.buffer.len());
        let mut current_offset = HEADER_SIZE as u64;

        // Write each chunk entry.
        for (hash, data) in &self.buffer {
            writer.write_all(&[CHUNK_MARKER])?;
            writer.write_all(hash.as_bytes())?;
            writer.write_all(&(data.len() as u32).to_le_bytes())?;
            writer.write_all(data)?;

            chunk_locations.push((hash.clone(), current_offset, data.len() as u32));

            // Next chunk starts after: marker(1) + hash(64) + size(4) + data_len
            current_offset += (1 + HASH_LEN + 4 + data.len()) as u64;
        }

        // Write end marker.
        writer.write_all(&[END_MARKER])?;

        // Compute and write checksum of everything so far.
        writer.flush()?;
        drop(writer);

        // Read the temp file back to compute checksum.
        let file_data = fs::read(&tmp_file)
            .with_context(|| format!("failed to read back temp pack file {:?}", tmp_file))?;
        let checksum = compute_checksum(&file_data);

        // Append checksum.
        {
            let file = fs::OpenOptions::new()
                .append(true)
                .open(&tmp_file)
                .with_context(|| format!("failed to open temp pack for append {:?}", tmp_file))?;
            let mut appender = BufWriter::new(file);
            appender.write_all(&checksum)?;
            appender.flush()?;
            // fsync: ensure data is on physical media before rename.
            // Without this, a crash after rename loses data still in page-cache.
            appender
                .into_inner()
                .map_err(|e| anyhow::anyhow!("failed to finalize pack write: {}", e))?
                .sync_all()?;
        }

        // Atomic rename: .pack.tmp → .pack
        fs::rename(&tmp_file, &pack_file)
            .with_context(|| format!("failed to rename {:?} to {:?}", tmp_file, pack_file))?;

        let chunk_count = self.buffer.len();

        // Clear the buffer.
        self.buffer.clear();
        self.buffer_bytes = 0;

        log::info!(
            "flushed pack {}: {} chunks, {} bytes",
            pack_filename(pack_id),
            chunk_count,
            file_data.len() + 32,
        );

        Ok(Some(FlushResult {
            pack_id,
            pack_file,
            chunk_count,
            chunk_locations,
        }))
    }

    /// Force-flush any remaining buffer contents. This should be called at the
    /// end of a backup session to ensure all chunks are persisted.
    pub fn finish(&mut self) -> Result<Option<FlushResult>> {
        self.flush()
    }

    /// Return the number of chunks currently in the buffer.
    pub fn pending_count(&self) -> usize {
        self.buffer.len()
    }

    /// Return the approximate number of bytes in the buffer.
    pub fn pending_bytes(&self) -> usize {
        self.buffer_bytes
    }

    /// Look up a chunk in the pending buffer (not yet flushed to disk).
    /// Returns the chunk data if found.
    pub fn get_pending(&self, hash: &str) -> Option<&[u8]> {
        for (h, data) in &self.buffer {
            if h == hash {
                return Some(data.as_slice());
            }
        }
        None
    }
}

// ── PackReader ──────────────────────────────────────────────────────────────

/// Reads chunks from pack files on disk.
#[derive(Debug)]
pub struct PackReader {
    /// Repository root path.
    repo_path: PathBuf,
}

impl PackReader {
    /// Create a new `PackReader` for the repository at `repo_path`.
    pub fn new(repo_path: &Path) -> Self {
        Self {
            repo_path: repo_path.to_path_buf(),
        }
    }

    /// Read a chunk from a specific pack file at the given offset.
    ///
    /// Returns the chunk data, or an error if the chunk cannot be found or
    /// the data is corrupt.
    pub fn read_chunk(&self, pack_id: u64, offset: u64, expected_hash: &str) -> Result<Vec<u8>> {
        let path = pack_path(&self.repo_path, pack_id);

        let mut file = BufReader::new(
            fs::File::open(&path)
                .with_context(|| format!("failed to open pack file {:?}", path))?,
        );

        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed to seek to offset {} in {:?}", offset, path))?;

        // Read and verify the chunk marker.
        let mut marker = [0u8; 1];
        file.read_exact(&mut marker)?;
        if marker[0] != CHUNK_MARKER {
            bail!(
                "invalid chunk marker at offset {} in {:?}: expected 0x01, got 0x{:02x}",
                offset,
                path,
                marker[0]
            );
        }

        // Read the hash.
        let mut hash_buf = [0u8; HASH_LEN];
        file.read_exact(&mut hash_buf)?;
        let hash_str = std::str::from_utf8(&hash_buf)
            .with_context(|| format!("invalid hash encoding in {:?}", path))?;

        if hash_str != expected_hash {
            bail!(
                "hash mismatch at offset {} in {:?}: expected {}, found {}",
                offset,
                path,
                expected_hash,
                hash_str
            );
        }

        // Read the data length.
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let data_len = u32::from_le_bytes(size_buf) as usize;

        // Read the chunk data.
        let mut data = vec![0u8; data_len];
        file.read_exact(&mut data)?;

        // Verify chunk content hash against the expected hash.
        let computed_hash = hex::encode(compute_checksum(&data));
        if computed_hash != expected_hash {
            bail!(
                "chunk data corruption in {:?}: hash mismatch at offset {}, expected {}",
                path,
                offset,
                expected_hash
            );
        }

        Ok(data)
    }

    /// Verify the checksum of a pack file.
    ///
    /// Returns `Ok(())` if the checksum is valid, or an error describing the
    /// problem.
    pub fn verify_pack(&self, pack_id: u64) -> Result<()> {
        let path = pack_path(&self.repo_path, pack_id);

        let file_data =
            fs::read(&path).with_context(|| format!("failed to read pack file {:?}", path))?;

        if file_data.len() < HEADER_SIZE + FOOTER_SIZE {
            bail!(
                "pack file {:?} is too small ({} bytes)",
                path,
                file_data.len()
            );
        }

        // Split off the last 32 bytes (checksum).
        let data_len = file_data.len() - 32;
        let stored_checksum = &file_data[data_len..];
        let computed_checksum = compute_checksum(&file_data[..data_len]);

        if stored_checksum != computed_checksum {
            bail!(
                "checksum mismatch in {:?}: expected {}, found {}",
                path,
                hex::encode(computed_checksum),
                hex::encode(stored_checksum),
            );
        }

        // Verify header magic.
        if &file_data[..4] != PACK_MAGIC {
            bail!("invalid magic in {:?}", path);
        }

        Ok(())
    }

    /// List all chunk hashes in a pack file (used for compaction/recovery).
    ///
    /// Returns a vector of (hash_hex, offset, stored_size) tuples.
    pub fn list_chunks(&self, pack_id: u64) -> Result<Vec<(String, u64, u32)>> {
        let path = pack_path(&self.repo_path, pack_id);

        let file = fs::File::open(&path)
            .with_context(|| format!("failed to open pack file {:?}", path))?;
        let mut reader = BufReader::new(file);

        // Skip header.
        reader.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        let mut chunks = Vec::new();
        let mut offset = HEADER_SIZE as u64;

        loop {
            // Read marker byte.
            let mut marker = [0u8; 1];
            reader.read_exact(&mut marker)?;

            if marker[0] == END_MARKER {
                break;
            }

            if marker[0] != CHUNK_MARKER {
                bail!(
                    "unexpected marker 0x{:02x} at offset {} in {:?}",
                    marker[0],
                    offset,
                    path
                );
            }

            let chunk_offset = offset;
            offset += 1;

            // Read hash.
            let mut hash_buf = [0u8; HASH_LEN];
            reader.read_exact(&mut hash_buf)?;
            let hash_str = std::str::from_utf8(&hash_buf)
                .with_context(|| format!("invalid hash in {:?}", path))?
                .to_string();
            offset += HASH_LEN as u64;

            // Read size.
            let mut size_buf = [0u8; 4];
            reader.read_exact(&mut size_buf)?;
            let stored_size = u32::from_le_bytes(size_buf);
            offset += 4;

            // Skip chunk data.
            reader.seek(SeekFrom::Current(stored_size as i64))?;
            offset += stored_size as u64;

            chunks.push((hash_str, chunk_offset, stored_size));
        }

        Ok(chunks)
    }

    /// List all pack files in the repository's data directory.
    ///
    /// Returns a sorted list of pack IDs.
    pub fn list_pack_ids(&self) -> Result<Vec<u64>> {
        let data_dir = self.repo_path.join("data");
        if !data_dir.exists() {
            return Ok(Vec::new());
        }

        let mut pack_ids = Vec::new();
        for entry in fs::read_dir(&data_dir)
            .with_context(|| format!("failed to read data dir {:?}", data_dir))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with("pack-") && name_str.ends_with(".pack") {
                // Parse the ID from "pack-NNNNNN.pack"
                let id_str = &name_str[5..name_str.len() - 5];
                if let Ok(id) = id_str.parse::<u64>() {
                    pack_ids.push(id);
                }
            }
        }

        pack_ids.sort();
        Ok(pack_ids)
    }

    /// Find the highest pack ID in the data directory (for determining the
    /// next pack ID to use).
    pub fn max_pack_id(&self) -> Result<u64> {
        let ids = self.list_pack_ids()?;
        Ok(ids.into_iter().max().unwrap_or(0))
    }
}

// ── Compact operation ───────────────────────────────────────────────────────

/// Result of a compaction operation.
#[derive(Debug, Clone)]
pub struct CompactResult {
    /// Number of packs before compaction.
    pub packs_before: usize,
    /// Number of packs after compaction.
    pub packs_after: usize,
    /// Number of chunks that were kept (live).
    pub chunks_kept: u64,
    /// Number of chunks that were discarded (orphaned).
    pub chunks_discarded: u64,
    /// Bytes freed by discarding orphaned chunks.
    pub bytes_freed: u64,
}

/// Compact the repository's pack files, removing orphaned chunks and
/// rewriting packs to reclaim space.
///
/// `live_hashes` is the set of chunk hashes that are still referenced by
/// snapshots (i.e., should be kept).
pub fn compact_packs(
    repo_path: &Path,
    live_hashes: &std::collections::HashSet<String>,
    pack_target_size: usize,
) -> Result<CompactResult> {
    // Acquire exclusive lock on the repository (non-blocking).
    let lf_path = repo_path.join(".backup-shield.lock");
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
    log::debug!("compact_packs: acquired exclusive lock on {:?}", lf_path);

    let reader = PackReader::new(repo_path);
    let pack_ids = reader.list_pack_ids()?;

    let packs_before = pack_ids.len();

    if pack_ids.is_empty() {
        return Ok(CompactResult {
            packs_before: 0,
            packs_after: 0,
            chunks_kept: 0,
            chunks_discarded: 0,
            bytes_freed: 0,
        });
    }

    // Determine the next pack ID for new compacted packs.
    let max_id = pack_ids.iter().max().unwrap();
    let next_pack_id = max_id + 1;

    // Collect all live chunks from all packs.
    let mut live_chunks: Vec<(String, Vec<u8>)> = Vec::new();
    let mut chunks_kept: u64 = 0;
    let mut chunks_discarded: u64 = 0;
    let mut bytes_freed: u64 = 0;

    for pack_id in &pack_ids {
        let chunk_list = reader.list_chunks(*pack_id)?;

        for (hash, _offset, stored_size) in &chunk_list {
            if live_hashes.contains(hash) {
                // Read the chunk data.
                let data = reader.read_chunk(*pack_id, *_offset, hash)?;
                live_chunks.push((hash.clone(), data));
                chunks_kept += 1;
            } else {
                chunks_discarded += 1;
                bytes_freed += *stored_size as u64;
            }
        }
    }

    // Write new compacted packs FIRST, before deleting old ones.
    // This ensures crash safety: if we crash during compaction, the old
    // packs are still intact and the repository remains valid.
    let mut writer = PackWriter::new(repo_path, next_pack_id, pack_target_size);
    let mut new_pack_ids: Vec<u64> = Vec::new();
    let mut new_locations: Vec<(String, u64, u64, u32)> = Vec::new();

    for (hash, data) in &live_chunks {
        let should_flush = writer.add_chunk(hash, data);
        if should_flush {
            if let Some(flush_result) = writer.flush()? {
                for (h, offset, size) in &flush_result.chunk_locations {
                    new_locations.push((h.clone(), flush_result.pack_id, *offset, *size));
                }
                new_pack_ids.push(flush_result.pack_id);
                let _next_pack_id = flush_result.pack_id + 1;
            }
        }
    }

    // Flush remaining.
    if let Some(flush_result) = writer.finish()? {
        for (h, offset, size) in &flush_result.chunk_locations {
            new_locations.push((h.clone(), flush_result.pack_id, *offset, *size));
        }
        new_pack_ids.push(flush_result.pack_id);
    }

    let packs_after = new_pack_ids.len();

    // Update the chunk index with new locations.
    let index_path = repo_path.join("indexes").join("chunk_index.json");
    if index_path.exists() {
        let json = fs::read_to_string(&index_path)?;
        let mut index: super::repository::ChunkIndex =
            serde_json::from_str(&json).with_context(|| "failed to parse chunk index")?;

        // Update pack_id and pack_offset for each relocated chunk.
        for (hash, new_pack_id, new_offset, _new_size) in &new_locations {
            if let Some(meta) = index.get_mut(hash) {
                meta.pack_id = *new_pack_id;
                meta.pack_offset = *new_offset;
            }
        }

        // Remove orphaned entries from the index.
        let orphaned: Vec<String> = index
            .iter()
            .filter(|(h, _)| !live_hashes.contains(*h))
            .map(|(h, _)| h.clone())
            .collect();
        for hash in &orphaned {
            index.remove(hash);
        }

        // Save the updated index atomically with fsync.
        let tmp_index = index_path.with_extension("json.tmp");
        let updated_json = serde_json::to_string_pretty(&index)?;
        {
            let mut file = fs::File::create(&tmp_index)?;
            file.write_all(updated_json.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_index, &index_path)?;
    }

    // Delete old pack files AFTER new packs and index are safely written.
    // If we crash before this point, the old packs are still intact and
    // the repository remains valid (the index still references them).
    for pack_id in &pack_ids {
        let path = pack_path(repo_path, *pack_id);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete old pack {:?}", path))?;
        }
    }

    log::info!(
        "compaction complete: {} packs → {} packs, {} chunks kept, {} discarded, {} bytes freed",
        packs_before,
        packs_after,
        chunks_kept,
        chunks_discarded,
        bytes_freed
    );

    Ok(CompactResult {
        packs_before,
        packs_after,
        chunks_kept,
        chunks_discarded,
        bytes_freed,
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Compute the SHA-256 checksum of a byte slice.
fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pack-test-repo");
        fs::create_dir_all(&path).unwrap();
        fs::create_dir_all(path.join("data")).unwrap();
        (dir, path)
    }

    #[test]
    fn write_and_read_single_chunk() {
        let (_dir, repo_path) = temp_repo();

        // Use the actual SHA-256 hash of "hello pack".
        let data = b"hello pack";
        let actual_hash = hex::encode(compute_checksum(data));

        let mut writer = PackWriter::new(&repo_path, 1, DEFAULT_PACK_SIZE);
        writer.add_chunk(&actual_hash, data);
        let flush_result = writer.flush().unwrap().unwrap();

        assert_eq!(flush_result.pack_id, 1);
        assert_eq!(flush_result.chunk_count, 1);
        assert_eq!(flush_result.chunk_locations.len(), 1);
        assert_eq!(flush_result.chunk_locations[0].0, actual_hash);

        // Read.
        let reader = PackReader::new(&repo_path);
        let (h, offset, _size) = &flush_result.chunk_locations[0];
        let read_data = reader.read_chunk(flush_result.pack_id, *offset, h).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn write_multiple_chunks_and_read_back() {
        let (_dir, repo_path) = temp_repo();

        let data_a = b"chunk A";
        let data_b = b"chunk B data that is longer";
        let data_c = b"C";
        let hash_a = hex::encode(compute_checksum(data_a));
        let hash_b = hex::encode(compute_checksum(data_b));
        let hash_c = hex::encode(compute_checksum(data_c));

        let mut writer = PackWriter::new(&repo_path, 1, DEFAULT_PACK_SIZE);
        writer.add_chunk(&hash_a, data_a);
        writer.add_chunk(&hash_b, data_b);
        writer.add_chunk(&hash_c, data_c);

        let result = writer.flush().unwrap().unwrap();
        assert_eq!(result.chunk_count, 3);

        let reader = PackReader::new(&repo_path);
        for (hash, offset, _size) in &result.chunk_locations {
            let _data = reader.read_chunk(result.pack_id, *offset, hash).unwrap();
        }
    }

    #[test]
    fn auto_flush_when_target_exceeded() {
        let (_dir, repo_path) = temp_repo();

        // Set target so small that each chunk triggers a flush.
        // Each chunk entry is ~129 bytes + header(14) + footer(33) = ~176 bytes total.
        // With target=140, even the first chunk exceeds it (14+129+33=176 > 140),
        // so add_chunk returns true after adding the chunk.
        let mut writer = PackWriter::new(&repo_path, 1, 140);

        let mut flush_count = 0;
        for i in 0..5 {
            let hash = format!("{:064}", i);
            let data = vec![i as u8; 60];
            if writer.add_chunk(&hash, &data) {
                let _ = writer.flush().unwrap();
                flush_count += 1;
            }
        }
        // Flush remaining.
        if writer.finish().unwrap().is_some() {
            flush_count += 1;
        }

        assert!(
            flush_count > 1,
            "should have flushed multiple packs, got {}",
            flush_count
        );
    }

    #[test]
    fn verify_pack_checksum() {
        let (_dir, repo_path) = temp_repo();

        let mut writer = PackWriter::new(&repo_path, 1, DEFAULT_PACK_SIZE);
        writer.add_chunk(&"x".repeat(64), b"verify me");
        writer.flush().unwrap();

        let reader = PackReader::new(&repo_path);
        assert!(reader.verify_pack(1).is_ok());

        // Corrupt the file.
        let path = pack_path(&repo_path, 1);
        let mut data = fs::read(&path).unwrap();
        data[20] ^= 0xFF; // flip a bit
        fs::write(&path, &data).unwrap();

        assert!(reader.verify_pack(1).is_err());
    }

    #[test]
    fn list_chunks_in_pack() {
        let (_dir, repo_path) = temp_repo();

        let mut writer = PackWriter::new(&repo_path, 1, DEFAULT_PACK_SIZE);
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        writer.add_chunk(&hash_a, b"data A");
        writer.add_chunk(&hash_b, b"data B");
        writer.flush().unwrap();

        let reader = PackReader::new(&repo_path);
        let chunks = reader.list_chunks(1).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, hash_a);
        assert_eq!(chunks[1].0, hash_b);
    }

    #[test]
    fn list_pack_ids() {
        let (_dir, repo_path) = temp_repo();

        // Create a few pack files with sequential IDs.
        let mut writer = PackWriter::new(&repo_path, 1, 50);
        for i in 1..=3 {
            let hash = format!("{:064}", i);
            writer.add_chunk(&hash, b"x");
            // Force flush each one.
            writer.flush().unwrap();
            // Create a new writer for the next pack.
            writer = PackWriter::new(&repo_path, i + 1, 50);
        }

        let reader = PackReader::new(&repo_path);
        let ids = reader.list_pack_ids().unwrap();
        assert!(!ids.is_empty());
        // IDs should be sorted.
        for window in ids.windows(2) {
            assert!(
                window[0] < window[1],
                "pack IDs not sorted: {} >= {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn pending_lookup() {
        let (_dir, repo_path) = temp_repo();
        let mut writer = PackWriter::new(&repo_path, 1, DEFAULT_PACK_SIZE);

        let hash = "a".repeat(64);
        writer.add_chunk(&hash, b"pending data");

        assert_eq!(writer.get_pending(&hash), Some(&b"pending data"[..]));
        assert_eq!(writer.get_pending("nonexistent"), None);
    }

    #[test]
    fn empty_flush_returns_none() {
        let (_dir, repo_path) = temp_repo();
        let mut writer = PackWriter::new(&repo_path, 1, DEFAULT_PACK_SIZE);
        assert!(writer.flush().unwrap().is_none());
    }
}
