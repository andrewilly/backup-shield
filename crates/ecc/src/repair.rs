//! # High-level Repair Operations for BackupShield
//!
//! This module provides the `ParityGroup`, `ParityIndex`, and `ParityManager`
//! types for managing erasure-coded parity groups in a backup repository.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reed_solomon::ReedSolomon;
use crate::EccError;

// ---------------------------------------------------------------------------
// ParityGroup
// ---------------------------------------------------------------------------

/// A parity group associates data chunks with their parity chunks.
///
/// All chunks in a group have the same padded size so that the Reed-Solomon
/// matrix math works correctly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityGroup {
    /// Unique identifier for this parity group.
    pub group_id: u32,
    /// SHA-256 hashes of the data chunks (in order).
    pub data_chunk_hashes: Vec<String>,
    /// SHA-256 hashes of the parity chunks (in order).
    pub parity_chunk_hashes: Vec<String>,
    /// The (padded) chunk size that all chunks in this group share.
    pub chunk_size: usize,
}

impl ParityGroup {
    /// Create a new, empty parity group.
    pub fn new(group_id: u32, chunk_size: usize) -> Self {
        Self {
            group_id,
            data_chunk_hashes: Vec::new(),
            parity_chunk_hashes: Vec::new(),
            chunk_size,
        }
    }

    /// Total number of chunks (data + parity).
    pub fn total_chunks(&self) -> usize {
        self.data_chunk_hashes.len() + self.parity_chunk_hashes.len()
    }
}

// ---------------------------------------------------------------------------
// ParityIndex
// ---------------------------------------------------------------------------

/// An index of all parity groups, persisted as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParityIndex {
    /// The parity groups in the repository.
    pub groups: Vec<ParityGroup>,
}

impl ParityIndex {
    /// Create a new, empty parity index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Save the parity index to a JSON file at the given path.
    /// Uses atomic write (tmp file + rename) to prevent corruption on crash.
    pub fn save(&self, path: &Path) -> Result<(), EccError> {
        let parent = path.parent().ok_or_else(|| {
            EccError::IoError(format!("Cannot determine parent directory of {:?}", path))
        })?;
        fs::create_dir_all(parent)
            .map_err(|e| EccError::IoError(format!("Failed to create directory: {}", e)))?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| EccError::SerializationError(e.to_string()))?;
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &json)
            .map_err(|e| EccError::IoError(format!("Failed to write parity index: {}", e)))?;
        fs::rename(&tmp_path, path)
            .map_err(|e| EccError::IoError(format!("Failed to rename parity index: {}", e)))?;
        Ok(())
    }

    /// Load a parity index from a JSON file at the given path.
    pub fn load(path: &Path) -> Result<ParityIndex, EccError> {
        let content = fs::read_to_string(path)
            .map_err(|e| EccError::IoError(format!("Failed to read parity index: {}", e)))?;
        let index: ParityIndex = serde_json::from_str(&content)
            .map_err(|e| EccError::SerializationError(e.to_string()))?;
        Ok(index)
    }

    /// Find a parity group by its group_id.
    pub fn find_group(&self, group_id: u32) -> Option<&ParityGroup> {
        self.groups.iter().find(|g| g.group_id == group_id)
    }

    /// Find a parity group by the hash of one of its chunks.
    pub fn find_group_by_hash(&self, hash: &str) -> Option<&ParityGroup> {
        self.groups.iter().find(|g| {
            g.data_chunk_hashes.iter().any(|h| h == hash)
                || g.parity_chunk_hashes.iter().any(|h| h == hash)
        })
    }
}

// ---------------------------------------------------------------------------
// ParityManager
// ---------------------------------------------------------------------------

/// High-level manager for computing parity and repairing chunks.
pub struct ParityManager {
    /// Underlying Reed-Solomon codec.
    rs: ReedSolomon,
    /// Number of data shards per group.
    data_shards: usize,
    /// Number of parity shards per group.
    parity_shards: usize,
}

impl ParityManager {
    /// Create a new ParityManager.
    ///
    /// # Errors
    ///
    /// Returns an error if the shard counts are invalid for Reed-Solomon.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, EccError> {
        let rs =
            ReedSolomon::new(data_shards, parity_shards).map_err(EccError::ReedSolomonError)?;
        Ok(Self {
            rs,
            data_shards,
            parity_shards,
        })
    }

    /// Compute parity chunks for the given data chunks.
    ///
    /// All data chunks are padded to the length of the longest chunk before
    /// computing parity. Returns the parity chunks (still padded).
    ///
    /// # Errors
    ///
    /// Returns an error if the number of data chunks doesn't match
    /// `data_shards`.
    pub fn compute_parity(&self, data_chunks: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, EccError> {
        if data_chunks.len() != self.data_shards {
            return Err(EccError::InvalidInput(format!(
                "Expected {} data chunks, got {}",
                self.data_shards,
                data_chunks.len()
            )));
        }

        // Find max chunk length
        let max_len = data_chunks.iter().map(|c| c.len()).max().unwrap_or(0);

        // Pad all chunks to max_len
        let padded: Vec<Vec<u8>> = data_chunks
            .iter()
            .map(|c| {
                let mut padded_chunk = c.clone();
                padded_chunk.resize(max_len, 0);
                padded_chunk
            })
            .collect();

        // If all chunks are empty, we can still compute (empty) parity
        let parity = self
            .rs
            .encode(&padded)
            .map_err(EccError::ReedSolomonError)?;

        Ok(parity)
    }

    /// Repair (reconstruct) all chunks from the available ones.
    ///
    /// `available_chunks` is a list of `(original_index, data)` pairs for
    /// chunks that are still valid. `total_chunks` is the total number of
    /// chunks (data + parity).
    ///
    /// Returns all reconstructed chunks as a `Vec<Vec<u8>>`, where index `i`
    /// corresponds to chunk `i` in the original layout (data shards first,
    /// then parity shards).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `total_chunks` != `data_shards + parity_shards`
    /// - Fewer than `data_shards` chunks are available
    /// - Available chunks have inconsistent lengths
    pub fn repair_chunks(
        &self,
        available_chunks: &[(usize, Vec<u8>)],
        total_chunks: usize,
        shard_len: usize,
    ) -> Result<Vec<Vec<u8>>, EccError> {
        let expected_total = self.data_shards + self.parity_shards;
        if total_chunks != expected_total {
            return Err(EccError::InvalidInput(format!(
                "total_chunks = {}, expected {}",
                total_chunks, expected_total
            )));
        }

        // Build the shards and shard_present arrays
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_chunks];
        let mut shard_present = vec![false; total_chunks];

        for &(idx, ref data) in available_chunks {
            if idx >= total_chunks {
                return Err(EccError::InvalidInput(format!(
                    "Chunk index {} out of range (total_chunks = {})",
                    idx, total_chunks
                )));
            }
            // Pad available data to shard_len
            let mut padded = data.clone();
            padded.resize(shard_len, 0);
            shards[idx] = Some(padded);
            shard_present[idx] = true;
        }

        // Reconstruct missing shards
        self.rs
            .reconstruct(&mut shards, &shard_present)
            .map_err(EccError::ReedSolomonError)?;

        // Collect results
        let result: Vec<Vec<u8>> = shards
            .into_iter()
            .map(|opt| opt.unwrap_or_default())
            .collect();

        Ok(result)
    }

    /// Create a `ParityGroup` from data chunks and their computed parity.
    ///
    /// Computes SHA-256 hashes of all chunks and returns a `ParityGroup`
    /// recording the hashes, the group ID, and the (padded) chunk size.
    pub fn create_parity_group(
        &self,
        group_id: u32,
        data_chunks: &[Vec<u8>],
        parity_chunks: &[Vec<u8>],
        chunk_size: usize,
    ) -> ParityGroup {
        let mut data_chunk_hashes = Vec::with_capacity(data_chunks.len());
        for chunk in data_chunks {
            data_chunk_hashes.push(hash_chunk(chunk));
        }

        let mut parity_chunk_hashes = Vec::with_capacity(parity_chunks.len());
        for chunk in parity_chunks {
            parity_chunk_hashes.push(hash_chunk(chunk));
        }

        ParityGroup {
            group_id,
            data_chunk_hashes,
            parity_chunk_hashes,
            chunk_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of a chunk, returning it as a hex string.
pub fn hash_chunk(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parity_manager_new() {
        assert!(ParityManager::new(4, 2).is_ok());
        assert!(ParityManager::new(0, 2).is_err());
        assert!(ParityManager::new(4, 0).is_err());
        assert!(ParityManager::new(200, 60).is_err());
    }

    #[test]
    fn test_compute_parity_basic() {
        let pm = ParityManager::new(3, 2).unwrap();
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = pm.compute_parity(&data).unwrap();
        assert_eq!(parity.len(), 2);
        assert_eq!(parity[0].len(), 3);
        assert_eq!(parity[1].len(), 3);
    }

    #[test]
    fn test_compute_parity_with_padding() {
        let pm = ParityManager::new(3, 2).unwrap();
        let data = vec![vec![1, 2], vec![4, 5, 6], vec![7]];
        let parity = pm.compute_parity(&data).unwrap();
        assert_eq!(parity.len(), 2);
        // All parity chunks should be padded to the max length (3)
        assert_eq!(parity[0].len(), 3);
        assert_eq!(parity[1].len(), 3);
    }

    #[test]
    fn test_compute_parity_wrong_count() {
        let pm = ParityManager::new(3, 2).unwrap();
        let data = vec![vec![1, 2], vec![3, 4]]; // only 2 chunks
        assert!(pm.compute_parity(&data).is_err());
    }

    #[test]
    fn test_repair_chunks_basic() {
        let pm = ParityManager::new(3, 2).unwrap();
        let data = vec![vec![10, 20, 30], vec![40, 50, 60], vec![70, 80, 90]];
        let parity = pm.compute_parity(&data).unwrap();
        let total = 5;

        // All chunks available
        let available: Vec<(usize, Vec<u8>)> = vec![
            (0, data[0].clone()),
            (1, data[1].clone()),
            (2, data[2].clone()),
            (3, parity[0].clone()),
            (4, parity[1].clone()),
        ];
        let shard_len = data.iter().map(|c| c.len()).max().unwrap_or(0);
        let repaired = pm.repair_chunks(&available, total, shard_len).unwrap();
        assert_eq!(repaired[0], data[0]);
        assert_eq!(repaired[1], data[1]);
        assert_eq!(repaired[2], data[2]);
    }

    #[test]
    fn test_repair_chunks_with_loss() {
        let pm = ParityManager::new(3, 2).unwrap();
        let data = vec![vec![10, 20, 30], vec![40, 50, 60], vec![70, 80, 90]];
        let parity = pm.compute_parity(&data).unwrap();
        let total = 5;

        // Lose data shard 1 and parity shard 0
        let available: Vec<(usize, Vec<u8>)> = vec![
            (0, data[0].clone()),
            (2, data[2].clone()),
            (4, parity[1].clone()),
        ];
        let shard_len = data.iter().map(|c| c.len()).max().unwrap_or(0);
        let repaired = pm.repair_chunks(&available, total, shard_len).unwrap();

        assert_eq!(repaired[0], data[0]);
        assert_eq!(repaired[1], data[1]);
        assert_eq!(repaired[2], data[2]);
    }

    #[test]
    fn test_repair_chunks_max_loss() {
        let pm = ParityManager::new(4, 3).unwrap();
        let data: Vec<Vec<u8>> = vec![
            (0..50).map(|i| (i % 256) as u8).collect(),
            (50..100).map(|i| (i % 256) as u8).collect(),
            (100..150).map(|i| (i % 256) as u8).collect(),
            (150..200).map(|i| (i % 256) as u8).collect(),
        ];
        let parity = pm.compute_parity(&data).unwrap();
        let total = 7;

        // Lose 3 chunks (equal to parity_shards)
        let available: Vec<(usize, Vec<u8>)> = vec![
            (1, data[1].clone()),
            (2, data[2].clone()),
            (3, data[3].clone()),
            (5, parity[1].clone()),
        ];
        let shard_len = data.iter().map(|c| c.len()).max().unwrap_or(0);
        let repaired = pm.repair_chunks(&available, total, shard_len).unwrap();

        assert_eq!(repaired[0], data[0]);
        assert_eq!(repaired[4], parity[0]);
        assert_eq!(repaired[6], parity[2]);
    }

    #[test]
    fn test_repair_chunks_too_many_lost() {
        let pm = ParityManager::new(3, 2).unwrap();
        let total = 5;

        // Only 2 available chunks, need at least 3
        let available: Vec<(usize, Vec<u8>)> = vec![(0, vec![1, 2, 3]), (4, vec![7, 8, 9])];
        assert!(pm.repair_chunks(&available, total, 3).is_err());
    }

    #[test]
    fn test_parity_index_save_load() {
        let index = ParityIndex {
            groups: vec![ParityGroup {
                group_id: 1,
                data_chunk_hashes: vec!["abc123".to_string(), "def456".to_string()],
                parity_chunk_hashes: vec!["ghi789".to_string()],
                chunk_size: 4096,
            }],
        };

        let dir = std::env::temp_dir().join("backup_shield_ecc_test_parity_index");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("parity_index.json");

        index.save(&path).unwrap();
        let loaded = ParityIndex::load(&path).unwrap();

        assert_eq!(loaded.groups.len(), 1);
        assert_eq!(loaded.groups[0].group_id, 1);
        assert_eq!(loaded.groups[0].data_chunk_hashes.len(), 2);
        assert_eq!(loaded.groups[0].parity_chunk_hashes.len(), 1);
        assert_eq!(loaded.groups[0].chunk_size, 4096);
    }

    #[test]
    fn test_parity_index_find_group() {
        let index = ParityIndex {
            groups: vec![
                ParityGroup {
                    group_id: 1,
                    data_chunk_hashes: vec!["abc".to_string()],
                    parity_chunk_hashes: vec!["def".to_string()],
                    chunk_size: 1024,
                },
                ParityGroup {
                    group_id: 2,
                    data_chunk_hashes: vec!["ghi".to_string()],
                    parity_chunk_hashes: vec!["jkl".to_string()],
                    chunk_size: 2048,
                },
            ],
        };

        assert!(index.find_group(1).is_some());
        assert!(index.find_group(2).is_some());
        assert!(index.find_group(3).is_none());

        let group = index.find_group(1).unwrap();
        assert_eq!(group.chunk_size, 1024);
    }

    #[test]
    fn test_parity_index_find_by_hash() {
        let index = ParityIndex {
            groups: vec![ParityGroup {
                group_id: 1,
                data_chunk_hashes: vec!["abc".to_string()],
                parity_chunk_hashes: vec!["def".to_string()],
                chunk_size: 1024,
            }],
        };

        assert!(index.find_group_by_hash("abc").is_some());
        assert!(index.find_group_by_hash("def").is_some());
        assert!(index.find_group_by_hash("xyz").is_none());
    }

    #[test]
    fn test_create_parity_group() {
        let pm = ParityManager::new(3, 2).unwrap();
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = pm.compute_parity(&data).unwrap();

        let group = pm.create_parity_group(42, &data, &parity, 3);

        assert_eq!(group.group_id, 42);
        assert_eq!(group.data_chunk_hashes.len(), 3);
        assert_eq!(group.parity_chunk_hashes.len(), 2);
        assert_eq!(group.chunk_size, 3);

        // Verify that hashes match actual chunk hashes
        for (i, hash) in group.data_chunk_hashes.iter().enumerate() {
            assert_eq!(hash, &hash_chunk(&data[i]));
        }
        for (i, hash) in group.parity_chunk_hashes.iter().enumerate() {
            assert_eq!(hash, &hash_chunk(&parity[i]));
        }
    }

    #[test]
    fn test_hash_chunk_deterministic() {
        let data = vec![1, 2, 3, 4, 5];
        let h1 = hash_chunk(&data);
        let h2 = hash_chunk(&data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_hash_chunk_different_data() {
        let h1 = hash_chunk(&[1, 2, 3]);
        let h2 = hash_chunk(&[3, 2, 1]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_end_to_end_workflow() {
        // Simulate a full workflow: compute parity -> lose chunks -> repair
        let pm = ParityManager::new(4, 2).unwrap();

        // Original data
        let data: Vec<Vec<u8>> = vec![
            b"Hello, world! This is chunk 1".to_vec(),
            b"And this is chunk number two".to_vec(),
            b"Third chunk has some data too".to_vec(),
            b"Fourth and final data chunk!".to_vec(),
        ];

        // Compute parity
        let parity = pm.compute_parity(&data).unwrap();
        assert_eq!(parity.len(), 2);

        // Create parity group
        let chunk_size = data.iter().map(|c| c.len()).max().unwrap();
        let _group = pm.create_parity_group(0, &data, &parity, chunk_size);

        // Simulate loss of data chunks 0 and 3
        let available: Vec<(usize, Vec<u8>)> = vec![
            (1, data[1].clone()),
            (2, data[2].clone()),
            (4, parity[0].clone()),
            (5, parity[1].clone()),
        ];

        let total = 6;
        // shard_len must match what compute_parity used: max of data_chunk sizes
        let shard_len = data.iter().map(|c| c.len()).max().unwrap_or(0);
        let repaired = pm.repair_chunks(&available, total, shard_len).unwrap();

        // Data shards should be recovered (padded)
        // Note: repaired chunks are padded to the max length
        assert_eq!(&repaired[0][..data[0].len()], &data[0][..]);
        assert_eq!(&repaired[1][..data[1].len()], &data[1][..]);
        assert_eq!(&repaired[2][..data[2].len()], &data[2][..]);
        assert_eq!(&repaired[3][..data[3].len()], &data[3][..]);
    }

    #[test]
    fn test_parity_group_total_chunks() {
        let group = ParityGroup {
            group_id: 1,
            data_chunk_hashes: vec!["a".to_string(), "b".to_string()],
            parity_chunk_hashes: vec!["c".to_string()],
            chunk_size: 1024,
        };
        assert_eq!(group.total_chunks(), 3);
    }

    #[test]
    fn test_parity_index_empty() {
        let index = ParityIndex::new();
        assert!(index.groups.is_empty());
        assert!(index.find_group(0).is_none());
    }
}
