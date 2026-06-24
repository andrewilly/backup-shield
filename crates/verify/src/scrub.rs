// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Periodic scrubbing (ZFS-style) for BackupShield repositories.
//!
//! The scrubber iterates through ALL chunks in the repository, verifies each
//! one, and optionally repairs corrupt/missing chunks using Reed-Solomon
//! parity data managed by the `backup-shield-ecc` crate.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use backup_shield_core::pack::PackReader;
use backup_shield_core::repository::{ChunkIndex, Repository};
use backup_shield_ecc::repair::{ParityIndex, ParityManager};

use crate::checker::VerifyError;

// ── ScrubProgress ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubProgress {
    pub chunks_total: u64,
    pub chunks_scanned: u64,
    pub chunks_ok: u64,
    pub chunks_errors: u64,
    pub start_time: DateTime<Utc>,
    pub is_complete: bool,
}

impl ScrubProgress {
    pub fn percent(&self) -> f64 {
        if self.chunks_total == 0 {
            100.0
        } else {
            (self.chunks_scanned as f64 / self.chunks_total as f64) * 100.0
        }
    }
}

// ── ScrubResult ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubResult {
    pub progress: ScrubProgress,
    pub errors_found: Vec<VerifyError>,
    pub repaired_count: u64,
    pub duration_secs: f64,
}

impl ScrubResult {
    pub fn is_ok(&self) -> bool {
        self.errors_found.is_empty()
    }
}

// ── Scrubber ────────────────────────────────────────────────────────────────

pub struct Scrubber {
    repo_path: PathBuf,
    progress: Mutex<ScrubProgress>,
}

impl Scrubber {
    pub fn new(repo_path: &Path) -> Result<Scrubber> {
        Ok(Scrubber {
            repo_path: repo_path.to_path_buf(),
            progress: Mutex::new(ScrubProgress {
                chunks_total: 0,
                chunks_scanned: 0,
                chunks_ok: 0,
                chunks_errors: 0,
                start_time: Utc::now(),
                is_complete: false,
            }),
        })
    }

    pub fn get_progress(&self) -> ScrubProgress {
        self.progress.lock().unwrap().clone()
    }

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

    fn load_parity_index(&self) -> Result<ParityIndex> {
        let parity_path = self.repo_path.join("parity").join("parity_index.json");
        if !parity_path.exists() {
            return Ok(ParityIndex::new());
        }
        ParityIndex::load(&parity_path).map_err(|e| anyhow::anyhow!("{}", e))
    }

    fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Read a chunk from the repository using the pack file system.
    fn read_chunk(
        &self,
        hash: &str,
        index: &ChunkIndex,
        pack_reader: &PackReader,
    ) -> Result<Vec<u8>> {
        let meta = index
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("chunk {} not in index", hash))?;

        if meta.pack_id == 0 {
            return Err(anyhow::anyhow!("chunk {} is still in write buffer", hash));
        }

        pack_reader.read_chunk(meta.pack_id, meta.pack_offset, hash)
    }

    /// Run a scrub: iterate through ALL chunks and verify each one.
    pub fn scrub(&self) -> Result<ScrubResult> {
        let start = Instant::now();
        let index = self.load_index()?;
        let pack_reader = PackReader::new(&self.repo_path);

        let all_hashes: Vec<String> = index.iter().map(|(h, _)| h.clone()).collect();
        let chunks_total = all_hashes.len() as u64;

        {
            let mut progress = self.progress.lock().unwrap();
            progress.chunks_total = chunks_total;
            progress.chunks_scanned = 0;
            progress.chunks_ok = 0;
            progress.chunks_errors = 0;
            progress.start_time = Utc::now();
            progress.is_complete = false;
        }

        let mut errors_found: Vec<VerifyError> = Vec::new();

        // Verify pack file checksums before checking individual chunks.
        if let Ok(pack_ids) = pack_reader.list_pack_ids() {
            for pack_id in &pack_ids {
                if let Err(e) = pack_reader.verify_pack(*pack_id) {
                    errors_found.push(VerifyError::PackCorrupt {
                        pack_id: *pack_id,
                        reason: e.to_string(),
                    });
                }
            }
        }

        for hash in &all_hashes {
            match self.read_chunk(hash, &index, &pack_reader) {
                Ok(data) => {
                    let actual = Self::compute_hash(&data);
                    if actual != *hash {
                        errors_found.push(VerifyError::ChunkCorrupt {
                            hash: hash.clone(),
                            expected: hash.clone(),
                            actual,
                        });
                        self.increment_progress(false);
                    } else {
                        self.increment_progress(true);
                    }
                }
                Err(_) => {
                    errors_found.push(VerifyError::ChunkMissing { hash: hash.clone() });
                    self.increment_progress(false);
                }
            }
        }

        let duration_secs = start.elapsed().as_secs_f64();

        let final_progress = {
            let mut progress = self.progress.lock().unwrap();
            progress.is_complete = true;
            progress.clone()
        };

        Ok(ScrubResult {
            progress: final_progress,
            errors_found,
            repaired_count: 0,
            duration_secs,
        })
    }

    /// Run a scrub and attempt to repair any corrupt/missing chunks using
    /// Reed-Solomon parity data.
    pub fn scrub_and_repair(&self) -> Result<ScrubResult> {
        let start = Instant::now();
        let index = self.load_index()?;
        let parity_index = self.load_parity_index()?;
        let pack_reader = PackReader::new(&self.repo_path);

        let all_hashes: Vec<String> = index.iter().map(|(h, _)| h.clone()).collect();
        let chunks_total = all_hashes.len() as u64;

        let config = backup_shield_core::config::RepositoryConfig::load(&self.repo_path)?;
        let parity_manager =
            ParityManager::new(config.ecc_data_shards, config.ecc_parity_shards)
                .map_err(|e| anyhow::anyhow!("failed to create ParityManager: {}", e))?;

        {
            let mut progress = self.progress.lock().unwrap();
            progress.chunks_total = chunks_total;
            progress.chunks_scanned = 0;
            progress.chunks_ok = 0;
            progress.chunks_errors = 0;
            progress.start_time = Utc::now();
            progress.is_complete = false;
        }

        let mut errors_found: Vec<VerifyError> = Vec::new();
        let mut repaired_count: u64 = 0;

        // Phase 1: Identify all corrupt/missing chunks.
        let mut bad_hashes: Vec<String> = Vec::new();
        for hash in &all_hashes {
            match self.read_chunk(hash, &index, &pack_reader) {
                Ok(data) => {
                    let actual = Self::compute_hash(&data);
                    if actual != *hash {
                        bad_hashes.push(hash.clone());
                        errors_found.push(VerifyError::ChunkCorrupt {
                            hash: hash.clone(),
                            expected: hash.clone(),
                            actual,
                        });
                        self.increment_progress(false);
                    } else {
                        self.increment_progress(true);
                    }
                }
                Err(_) => {
                    bad_hashes.push(hash.clone());
                    errors_found.push(VerifyError::ChunkMissing { hash: hash.clone() });
                    self.increment_progress(false);
                }
            }
        }

        // Phase 2: Attempt repair for each bad chunk.
        if !bad_hashes.is_empty() {
            log::info!(
                "scrub_and_repair: found {} bad chunks, attempting repair",
                bad_hashes.len()
            );

            let mut groups_to_repair: std::collections::HashMap<u32, Vec<String>> =
                std::collections::HashMap::new();

            for bad_hash in &bad_hashes {
                if let Some(group) = parity_index.find_group_by_hash(bad_hash) {
                    groups_to_repair
                        .entry(group.group_id)
                        .or_default()
                        .push(bad_hash.clone());
                } else {
                    log::warn!(
                        "scrub_and_repair: chunk {} not in any parity group, cannot repair",
                        &bad_hash[..12.min(bad_hash.len())]
                    );
                }
            }

            // Open the repository for writing repaired chunks.
            let mut repo = Repository::open(&self.repo_path)?;

            for (group_id, group_bad_hashes) in &groups_to_repair {
                let group = match parity_index.find_group(*group_id) {
                    Some(g) => g,
                    None => {
                        log::warn!("scrub_and_repair: parity group {} not found", group_id);
                        continue;
                    }
                };

                let total_chunks = group.data_chunk_hashes.len() + group.parity_chunk_hashes.len();
                let all_group_hashes: Vec<&String> = group
                    .data_chunk_hashes
                    .iter()
                    .chain(group.parity_chunk_hashes.iter())
                    .collect();

                let bad_set: HashSet<String> = group_bad_hashes.iter().cloned().collect();
                let mut available_chunks: Vec<(usize, Vec<u8>)> = Vec::new();

                for (idx, hash) in all_group_hashes.iter().enumerate() {
                    if bad_set.contains(*hash) {
                        continue;
                    }

                    match self.read_chunk(hash, &index, &pack_reader) {
                        Ok(data) => {
                            available_chunks.push((idx, data));
                        }
                        Err(_) => {
                            log::warn!(
                                "scrub_and_repair: chunk {} in group {} unexpectedly unreadable",
                                &hash[..12.min(hash.len())],
                                group_id
                            );
                        }
                    }
                }

                if available_chunks.len() < group.data_chunk_hashes.len() {
                    log::warn!(
                        "scrub_and_repair: not enough shards for group {} (have {}, need {})",
                        group_id,
                        available_chunks.len(),
                        group.data_chunk_hashes.len()
                    );
                    continue;
                }

                match parity_manager.repair_chunks(&available_chunks, total_chunks, group.chunk_size) {
                    Ok(reconstructed) => {
                        for (idx, hash) in all_group_hashes.iter().enumerate() {
                            if bad_set.contains(*hash) && idx < reconstructed.len() {
                                let original_size = index.get(hash).map(|m| m.size);
                                let data = if let Some(size) = original_size {
                                    let r = &reconstructed[idx];
                                    if size <= r.len() {
                                        r[..size].to_vec()
                                    } else {
                                        r.clone()
                                    }
                                } else {
                                    reconstructed[idx].clone()
                                };

                                let actual_hash = Self::compute_hash(&data);
                                if actual_hash == **hash {
                                    match repo.write_repaired_chunk(hash, &data) {
                                        Ok(()) => {
                                            repaired_count += 1;
                                            log::info!(
                                                "scrub_and_repair: repaired chunk {}",
                                                &hash[..12.min(hash.len())]
                                            );
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "scrub_and_repair: failed to write repaired chunk {}: {}",
                                                &hash[..12.min(hash.len())],
                                                e
                                            );
                                        }
                                    }
                                } else {
                                    log::error!(
                                        "scrub_and_repair: reconstructed chunk hash mismatch for {}",
                                        &hash[..12.min(hash.len())]
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "scrub_and_repair: failed to reconstruct group {}: {}",
                            group_id,
                            e
                        );
                    }
                }
            }

            // Save the updated index.
            repo.save_index()?;
        }

        let duration_secs = start.elapsed().as_secs_f64();

        let final_progress = {
            let mut progress = self.progress.lock().unwrap();
            progress.is_complete = true;
            progress.clone()
        };

        Ok(ScrubResult {
            progress: final_progress,
            errors_found,
            repaired_count,
            duration_secs,
        })
    }

    fn increment_progress(&self, is_ok: bool) {
        let mut progress = self.progress.lock().unwrap();
        progress.chunks_scanned += 1;
        if is_ok {
            progress.chunks_ok += 1;
        } else {
            progress.chunks_errors += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_shield_core::repository::Repository;

    fn temp_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scrub-test-repo");
        (dir, path)
    }

    fn init_repo(path: &Path) -> Repository {
        Repository::init(path, None).unwrap()
    }

    #[test]
    fn scrubber_new_valid_repo() {
        let (_dir, path) = temp_repo();
        let _repo = init_repo(&path);
        let scrubber = Scrubber::new(&path);
        assert!(scrubber.is_ok());
    }

    #[test]
    fn scrub_empty_repo() {
        let (_dir, path) = temp_repo();
        let _repo = init_repo(&path);
        let scrubber = Scrubber::new(&path).unwrap();
        let result = scrubber.scrub().unwrap();
        assert!(result.is_ok());
        assert_eq!(result.progress.chunks_total, 0);
    }

    #[test]
    fn scrub_with_valid_chunks() {
        let (_dir, path) = temp_repo();
        let mut repo = init_repo(&path);
        repo.store_chunk(b"data 1").unwrap();
        repo.store_chunk(b"data 2").unwrap();
        repo.flush_pending().unwrap();
        repo.save_index().unwrap();

        let scrubber = Scrubber::new(&path).unwrap();
        let result = scrubber.scrub().unwrap();
        assert!(result.is_ok());
        assert_eq!(result.progress.chunks_total, 2);
        assert_eq!(result.progress.chunks_ok, 2);
        assert_eq!(result.progress.chunks_errors, 0);
    }

    #[test]
    fn scrub_progress_tracking() {
        let (_dir, path) = temp_repo();
        let mut repo = init_repo(&path);
        repo.store_chunk(b"a").unwrap();
        repo.store_chunk(b"b").unwrap();
        repo.store_chunk(b"c").unwrap();
        repo.flush_pending().unwrap();
        repo.save_index().unwrap();

        let scrubber = Scrubber::new(&path).unwrap();
        let result = scrubber.scrub().unwrap();
        assert!(result.progress.is_complete);
        assert_eq!(result.progress.percent(), 100.0);
    }
}
