//! # BackupShield Compression Module
//!
//! This crate provides compression and decompression operations for BackupShield, including:
//! - Zstd-based compression and decompression for backup chunks
//! - Chunked compression with a 4-byte little-endian header for streaming support
//! - Compression level validation and estimation utilities
//!
//! # Example
//!
//! ```no_run
//! use backup_shield_compression::{compress, decompress, CompressionLevel};
//!
//! // Create a compression level
//! let level = CompressionLevel::default();
//!
//! // Compress some data
//! let data = b"Hello, world!".repeat(100);
//! let compressed = compress(&data, level).unwrap();
//!
//! // Decompress it back
//! let decompressed = decompress(&compressed).unwrap();
//! assert_eq!(data.as_slice(), decompressed.as_slice());
//! ```

pub mod compressor;

// Re-export key types for convenience
pub use compressor::{
    compress, compress_chunk, decompress, decompress_chunk, estimate_compression_ratio,
    CompressionError, CompressionLevel,
};
