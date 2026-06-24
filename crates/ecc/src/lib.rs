#![allow(clippy::needless_range_loop)]

//! # BackupShield ECC (Error Correction Codes) Module
//!
//! This crate provides erasure coding functionality for BackupShield, including:
//! - Reed-Solomon error correction over GF(256) using Vandermonde matrices
//! - High-level parity computation and chunk repair operations
//! - Parity group indexing with JSON persistence
//!
//! # Example
//!
//! ```
//! use backup_shield_ecc::{ParityManager, ReedSolomon};
//!
//! // Create a Reed-Solomon codec with 4 data shards and 2 parity shards
//! let rs = ReedSolomon::new(4, 2).unwrap();
//!
//! // Encode data
//! let data: Vec<Vec<u8>> = vec![
//!     vec![1, 2, 3, 4],
//!     vec![5, 6, 7, 8],
//!     vec![9, 10, 11, 12],
//!     vec![13, 14, 15, 16],
//! ];
//! let parity = rs.encode(&data).unwrap();
//!
//! // Use ParityManager for higher-level operations
//! let pm = ParityManager::new(4, 2).unwrap();
//! let parity = pm.compute_parity(&data).unwrap();
//! ```

pub mod reed_solomon;
pub mod repair;

// Re-export key types for convenience
pub use reed_solomon::{Gf256, Matrix, ReedSolomon};
pub use repair::{hash_chunk, ParityGroup, ParityIndex, ParityManager};

use thiserror::Error;

/// Custom error type for ECC operations.
#[derive(Error, Debug)]
pub enum EccError {
    /// Error from the Reed-Solomon codec.
    #[error("Reed-Solomon error: {0}")]
    ReedSolomonError(String),

    /// Invalid input parameters.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Serialization or deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(String),

    /// Division by zero in GF(256).
    #[error("division by zero in GF(256)")]
    DivisionByZero,

    /// Inverse of zero in GF(256).
    #[error("inverse of zero in GF(256) is undefined")]
    InverseOfZero,
}

/// Result type alias for ECC operations.
pub type Result<T> = std::result::Result<T, EccError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reexport_types() {
        // Verify that re-exported types are accessible
        let _rs = ReedSolomon::new(2, 1).unwrap();
        let _pm = ParityManager::new(2, 1).unwrap();
        let _gf = Gf256::new();
        let _group = ParityGroup::new(0, 1024);
        let _index = ParityIndex::new();
    }

    #[test]
    fn test_ecc_error_display() {
        let err = EccError::ReedSolomonError("test error".to_string());
        assert_eq!(format!("{}", err), "Reed-Solomon error: test error");

        let err = EccError::InvalidInput("bad input".to_string());
        assert_eq!(format!("{}", err), "Invalid input: bad input");

        let err = EccError::SerializationError("serde fail".to_string());
        assert_eq!(format!("{}", err), "Serialization error: serde fail");

        let err = EccError::IoError("file not found".to_string());
        assert_eq!(format!("{}", err), "I/O error: file not found");
    }

    #[test]
    fn test_result_type() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }
}
