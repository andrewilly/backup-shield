// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Zstd compression and decompression for backup chunks.
//!
//! This module provides both raw and chunked compression/decompression:
//! - Raw: straightforward zstd compress/decompress
//! - Chunked: prepends a 4-byte little-endian header storing the original uncompressed
//!   size, which is useful for streaming decompression where the output size must be
//!   known in advance.

use std::io::Write;

use thiserror::Error;

/// Custom error type for compression operations.
#[derive(Error, Debug)]
pub enum CompressionError {
    /// Error during compression.
    #[error("Compression error: {0}")]
    CompressError(String),

    /// Error during decompression.
    #[error("Decompression error: {0}")]
    DecompressError(String),

    /// Invalid compression level.
    #[error("Invalid compression level: {0}")]
    InvalidLevel(i32),
}

/// Result type alias for compression operations.
pub type Result<T> = std::result::Result<T, CompressionError>;

/// A validated zstd compression level.
///
/// Zstd supports levels from 1 (fastest) to 22 (best compression).
/// This newtype ensures that only valid levels are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompressionLevel(i32);

impl CompressionLevel {
    /// Minimum compression level (fastest).
    pub const MIN: i32 = 1;

    /// Default compression level (good balance of speed and ratio).
    pub const DEFAULT: i32 = 3;

    /// Maximum compression level (best compression).
    pub const MAX: i32 = 22;

    /// Creates a new `CompressionLevel`, validating that the level is within
    /// the supported range (1–22).
    ///
    /// # Errors
    ///
    /// Returns [`CompressionError::InvalidLevel`] if the level is outside the
    /// range `[1, 22]`.
    pub fn new(level: i32) -> Result<Self> {
        if (Self::MIN..=Self::MAX).contains(&level) {
            Ok(CompressionLevel(level))
        } else {
            Err(CompressionError::InvalidLevel(level))
        }
    }

    /// Returns the raw compression level value.
    pub fn level(&self) -> i32 {
        self.0
    }
}

impl Default for CompressionLevel {
    fn default() -> Self {
        CompressionLevel(Self::DEFAULT)
    }
}

impl From<CompressionLevel> for i32 {
    fn from(level: CompressionLevel) -> i32 {
        level.0
    }
}

/// Compresses data using zstd at the given compression level.
///
/// This is a straightforward one-shot compression. For chunked compression
/// with a size header, use [`compress_chunk`] instead.
///
/// # Errors
///
/// Returns [`CompressionError::CompressError`] if the zstd encoder fails.
pub fn compress(data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
    zstd::encode_all(data, level.level())
        .map_err(|e| CompressionError::CompressError(e.to_string()))
}

/// Decompresses zstd-compressed data.
///
/// # Errors
///
/// Returns [`CompressionError::DecompressError`] if the zstd decoder fails,
/// for example when the input is not valid zstd data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data).map_err(|e| CompressionError::DecompressError(e.to_string()))
}

/// Compresses data with a 4-byte little-endian header storing the original
/// uncompressed size.
///
/// The output format is: `[4-byte LE original_size][zstd-compressed payload]`.
/// This is useful for streaming decompression where the output buffer size
/// must be known in advance.
///
/// # Errors
///
/// Returns [`CompressionError::CompressError`] if the zstd encoder fails.
pub fn compress_chunk(data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
    let original_size = data.len() as u32;

    let compressed = zstd::encode_all(data, level.level())
        .map_err(|e| CompressionError::CompressError(e.to_string()))?;

    let mut output = Vec::with_capacity(4 + compressed.len());
    output
        .write_all(&original_size.to_le_bytes())
        .map_err(|e| CompressionError::CompressError(e.to_string()))?;
    output
        .write_all(&compressed)
        .map_err(|e| CompressionError::CompressError(e.to_string()))?;

    Ok(output)
}

/// Decompresses a chunk that was compressed with [`compress_chunk`].
///
/// Reads the 4-byte little-endian header for the original uncompressed size,
/// then decompresses the remaining zstd payload.
///
/// # Errors
///
/// Returns [`CompressionError::DecompressError`] if:
/// - The input is fewer than 4 bytes (missing header)
/// - The zstd decoder fails
pub fn decompress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        return Err(CompressionError::DecompressError(
            "Chunk too short: missing 4-byte size header".to_string(),
        ));
    }

    let (header, payload) = data.split_at(4);
    let original_size = u32::from_le_bytes(header.try_into().map_err(
        |e: std::array::TryFromSliceError| CompressionError::DecompressError(e.to_string()),
    )?) as usize;

    // Safety limit: prevent decompression bomb
    const MAX_DECOMPRESS_SIZE: usize = 256 * 1024 * 1024; // 256 MB
    if original_size > MAX_DECOMPRESS_SIZE {
        return Err(CompressionError::DecompressError(format!(
            "Decompressed size {} exceeds maximum of {}",
            original_size, MAX_DECOMPRESS_SIZE
        )));
    }

    // Use bulk decompress with capacity limit for memory safety.
    let output = zstd::bulk::decompress(payload, original_size).map_err(|e| {
        CompressionError::DecompressError(format!("zstd decompression failed: {}", e))
    })?;
    Ok(output)
}

/// Estimates the compression ratio for a given data sample and level.
///
/// Compresses the provided data with the specified level and returns the ratio
/// `compressed_size / original_size`. A value less than 1.0 indicates the data
/// compresses well; a value greater than or equal to 1.0 indicates the data
/// does not benefit from compression.
///
/// For very small inputs the overhead of zstd framing may cause the ratio to
/// exceed 1.0 even for data that would otherwise compress well at larger sizes.
pub fn estimate_compression_ratio(data: &[u8], level: CompressionLevel) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let compressed = match compress(data, level) {
        Ok(c) => c,
        Err(_) => return 1.0,
    };

    compressed.len() as f64 / data.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_level_valid() {
        assert!(CompressionLevel::new(1).is_ok());
        assert!(CompressionLevel::new(3).is_ok());
        assert!(CompressionLevel::new(22).is_ok());
    }

    #[test]
    fn test_compression_level_invalid() {
        assert!(CompressionLevel::new(0).is_err());
        assert!(CompressionLevel::new(23).is_err());
        assert!(CompressionLevel::new(-1).is_err());
        assert!(CompressionLevel::new(100).is_err());
    }

    #[test]
    fn test_compression_level_default() {
        let level = CompressionLevel::default();
        assert_eq!(level.level(), 3);
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, BackupShield! ".repeat(50);
        let level = CompressionLevel::default();
        let compressed = compress(&data, level).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compress_reduces_size() {
        let data = b"AAAAAAAAAA".repeat(1000);
        let level = CompressionLevel::default();
        let compressed = compress(&data, level).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_compress_chunk_decompress_chunk_roundtrip() {
        let data = b"Chunked compression test data ".repeat(50);
        let level = CompressionLevel::default();
        let compressed = compress_chunk(&data, level).unwrap();

        // Verify the 4-byte header is present
        assert!(compressed.len() > 4);

        let decompressed = decompress_chunk(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_decompress_chunk_too_short() {
        let data = [0u8; 3];
        let result = decompress_chunk(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_estimate_compression_ratio() {
        let data = b"BBBBBBBBBB".repeat(1000);
        let level = CompressionLevel::default();
        let ratio = estimate_compression_ratio(&data, level);
        // Highly repetitive data should compress well
        assert!(ratio < 0.1);
    }

    #[test]
    fn test_estimate_compression_ratio_empty() {
        let level = CompressionLevel::default();
        let ratio = estimate_compression_ratio(&[], level);
        assert_eq!(ratio, 0.0);
    }

    #[test]
    fn test_all_levels_roundtrip() {
        let data = b"Testing all compression levels! ".repeat(20);
        for level_val in 1..=22 {
            let level = CompressionLevel::new(level_val).unwrap();
            let compressed = compress(&data, level).unwrap();
            let decompressed = decompress(&compressed).unwrap();
            assert_eq!(data.as_slice(), decompressed.as_slice());
        }
    }
}
