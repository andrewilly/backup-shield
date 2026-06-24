// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{Context, Result};
use std::path::Path;

/// Buzhash rolling hash with a 32-byte window.
///
/// The lookup table contains 256 deterministic pseudo-random u32 values that are
/// produced from a fixed seed so that the same input data always produces the
/// same chunk boundaries across runs and machines.
pub struct Buzhash {
    /// Rolling hash state.
    hash: u32,
    /// 32-byte circular buffer holding the last 32 bytes that contributed to the hash.
    window: [u8; 32],
    /// Current position within the circular window (0..32).
    window_pos: usize,
    /// Lookup table: maps each byte value to a pseudo-random u32.
    table: [u32; 256],
}

impl Buzhash {
    /// Create a new Buzhash with the deterministic lookup table.
    pub fn new() -> Self {
        let mut bh = Self {
            hash: 0,
            window: [0u8; 32],
            window_pos: 0,
            table: [0u32; 256],
        };
        bh.init_table();
        bh
    }

    /// Initialise the 256-entry lookup table using a simple PRNG seeded with a
    /// fixed value.  We use a 64-bit xorshift so that the table is completely
    /// deterministic – no `rand` crate required.
    fn init_table(&mut self) {
        // Fixed seed so chunking is reproducible.
        let mut state: u64 = 0x0123_4567_89AB_CDEF;
        for entry in self.table.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *entry = state as u32;
        }
    }

    /// Reset the hash state so the instance can be reused.
    pub fn reset(&mut self) {
        self.hash = 0;
        self.window = [0u8; 32];
        self.window_pos = 0;
    }

    /// Slide one byte into the rolling hash.
    ///
    /// The oldest byte in the 32-byte window is removed (by XOR-ing out its
    /// rotated contribution) and the new byte is XOR-ed in.
    pub fn update(&mut self, byte: u8) {
        let oldest = self.window[self.window_pos];
        // Remove the oldest byte's contribution (it was shifted 31 positions
        // when first inserted, so we rotate left by 31 to undo it).
        self.hash ^= Self::rotate_left(self.table[oldest as usize], 31);
        // Shift the whole window one position and add the new byte.
        self.hash = Self::rotate_left(self.hash, 1);
        self.hash ^= self.table[byte as usize];
        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) % 32;
    }

    /// Return the current 32-bit hash value.
    pub fn hash_value(&self) -> u32 {
        self.hash
    }

    /// Left-rotate a u32 by `n` bits.
    fn rotate_left(v: u32, n: u32) -> u32 {
        v.rotate_left(n)
    }
}

impl Default for Buzhash {
    fn default() -> Self {
        Self::new()
    }
}

/// Content-defined chunker that splits data into variable-size chunks using
/// the Buzhash rolling hash for boundary detection.
pub struct Chunker {
    /// Minimum chunk size in bytes (no boundary checks below this).
    pub min_size: usize,
    /// Maximum chunk size in bytes (force a boundary at this size).
    pub max_size: usize,
    /// Target average chunk size in bytes.
    pub target_size: usize,
    /// Mask derived from `target_size`; a boundary is triggered when
    /// `hash % mask == mask - 1`.
    mask: u32,
}

impl Chunker {
    /// Create a new chunker with the given size parameters.
    ///
    /// The mask is computed as the largest power of two ≤ target_size.
    ///
    /// # Errors
    ///
    /// Returns `Err` if parameters are invalid (min=0, max ≤ min, target out of range).
    pub fn new(min_size: usize, max_size: usize, target_size: usize) -> Result<Self> {
        if min_size == 0 {
            anyhow::bail!("min_size must be > 0");
        }
        if max_size <= min_size {
            anyhow::bail!(
                "max_size ({}) must be greater than min_size ({})",
                max_size,
                min_size
            );
        }
        if target_size < min_size || target_size > max_size {
            anyhow::bail!(
                "target_size ({}) must be between min_size ({}) and max_size ({})",
                target_size,
                min_size,
                max_size,
            );
        }
        // Derive mask: largest power of two ≤ target_size.
        let mask = target_size.next_power_of_two() >> 1;
        let mask = if mask == 0 { 1 } else { mask };
        Ok(Self {
            min_size,
            max_size,
            target_size,
            mask: mask as u32,
        })
    }

    /// Split a byte slice into variable-size chunks.
    ///
    /// The algorithm uses the Buzhash rolling hash to find natural boundaries
    /// in the data:
    /// - Before `min_size` bytes: never cut.
    /// - Between `min_size` and `max_size`: cut when `hash % mask == mask - 1`.
    /// - At `max_size`: force a cut.
    pub fn chunk_data(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return Vec::new();
        }

        let mut buzhash = Buzhash::new();
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut chunk_start: usize = 0;

        for (i, &byte) in data.iter().enumerate() {
            let pos_in_chunk = i - chunk_start;

            buzhash.update(byte);

            // Don't check for boundaries until we've reached min_size.
            if pos_in_chunk + 1 < self.min_size {
                continue;
            }

            // Force a boundary at max_size.
            if pos_in_chunk + 1 >= self.max_size {
                chunks.push(data[chunk_start..=i].to_vec());
                chunk_start = i + 1;
                buzhash.reset();
                continue;
            }

            // Check rolling-hash boundary.
            if pos_in_chunk + 1 >= self.min_size {
                let h = buzhash.hash_value();
                if h % self.mask == self.mask - 1 {
                    chunks.push(data[chunk_start..=i].to_vec());
                    chunk_start = i + 1;
                    buzhash.reset();
                }
            }
        }

        // Remaining bytes form the last chunk (if any).
        if chunk_start < data.len() {
            chunks.push(data[chunk_start..].to_vec());
        }

        chunks
    }

    /// Read a file from disk and chunk it.
    pub fn chunk_file(&self, path: &Path) -> Result<Vec<Vec<u8>>> {
        let data = std::fs::read(path)
            .with_context(|| format!("failed to read file for chunking: {:?}", path))?;
        Ok(self.chunk_data(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buzhash_deterministic() {
        let mut h1 = Buzhash::new();
        let mut h2 = Buzhash::new();
        for b in 0u8..=255 {
            h1.update(b);
            h2.update(b);
        }
        assert_eq!(h1.hash_value(), h2.hash_value());
    }

    #[test]
    fn chunker_empty_input() {
        let chunker = Chunker::new(1024, 8192, 4096).unwrap();
        let chunks = chunker.chunk_data(&[]);
        assert!(chunks.is_empty());
    }

    #[test]
    fn chunker_small_input_less_than_min() {
        let chunker = Chunker::new(1024, 8192, 4096).unwrap();
        let data = vec![0u8; 512];
        let chunks = chunker.chunk_data(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 512);
    }

    #[test]
    fn chunker_forces_boundary_at_max() {
        let min = 64;
        let max = 256;
        let target = 128;
        let chunker = Chunker::new(min, max, target).unwrap();
        // All zeros means the hash will be the same everywhere – boundaries
        // will only be forced at max_size.
        let data = vec![0xABu8; 600];
        let chunks = chunker.chunk_data(&data);
        for chunk in &chunks {
            assert!(chunk.len() <= max);
        }
        // The total bytes must be preserved.
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 600);
    }

    #[test]
    fn chunker_preserves_data() {
        let chunker = Chunker::new(64, 4096, 512).unwrap();
        let data: Vec<u8> = (0..10000).map(|i| (i % 251) as u8).collect();
        let chunks = chunker.chunk_data(&data);
        let reconstructed: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn chunker_reproducible() {
        let chunker = Chunker::new(64, 4096, 512).unwrap();
        let data: Vec<u8> = (0..5000).map(|i| (i % 197) as u8).collect();
        let c1 = chunker.chunk_data(&data);
        let c2 = chunker.chunk_data(&data);
        assert_eq!(c1, c2);
    }
}
