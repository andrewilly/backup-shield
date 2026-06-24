//! # BackupShield Crypto Module
//!
//! This crate provides cryptographic operations for BackupShield, including:
//! - AES-256-GCM encryption and decryption for backup chunks
//! - Argon2id-based key derivation from passwords
//! - Key material persistence and verification
//!
//! # Example
//!
//! ```no_run
//! use backup_shield_crypto::{encrypt_chunk, decrypt_chunk, derive_key, key_from_password};
//!
//! // Derive a key from a password
//! let key_material = derive_key("my_secure_password", None).unwrap();
//!
//! // Encrypt a chunk
//! let key: [u8; 32] = key_material.key.clone().try_into().unwrap();
//! let plaintext = b"Hello, world!";
//! let encrypted = encrypt_chunk(plaintext, &key).unwrap();
//!
//! // Decrypt the chunk
//! let decrypted = decrypt_chunk(&encrypted, &key).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```

pub mod encryption;
pub mod keygen;

// Re-export key types for convenience
pub use encryption::{decrypt_chunk, decrypt_data, encrypt_chunk, encrypt_data, EncryptedData};
pub use keygen::{
    derive_key, generate_salt, key_from_password, load_key_material, save_key_material, KeyMaterial,
};

use thiserror::Error;

/// Custom error type for cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Error during encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Error during decryption.
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Error during key derivation.
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    /// Key verification failed (wrong password).
    #[error("Key verification failed: {0}")]
    KeyVerificationFailed(String),

    /// Error during serialization or deserialization.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(String),
}

/// Result type alias for crypto operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
