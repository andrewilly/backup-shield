// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};

use crate::CryptoError;
use crate::Result;

/// AES-GCM nonce size in bytes (96 bits).
const NONCE_SIZE: usize = 12;

/// Size of the nonce length prefix in bytes (u32 little-endian).
const NONCE_LEN_PREFIX_SIZE: usize = 4;

/// Encrypted data container holding the nonce and ciphertext.
///
/// The authentication tag is handled internally by the `aes-gcm` crate
/// and is appended to the ciphertext.
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// The 12-byte nonce used for encryption.
    pub nonce: Vec<u8>,
    /// The encrypted ciphertext (includes the authentication tag appended by aes-gcm).
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Serialize the encrypted data into a byte vector.
    ///
    /// Format: `[4-byte nonce length (LE)] [nonce bytes] [ciphertext bytes]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let nonce_len = self.nonce.len() as u32;
        let mut bytes =
            Vec::with_capacity(NONCE_LEN_PREFIX_SIZE + self.nonce.len() + self.ciphertext.len());
        bytes.extend_from_slice(&nonce_len.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize encrypted data from a byte slice.
    ///
    /// Expected format: `[4-byte nonce length (LE)] [nonce bytes] [ciphertext bytes]`
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < NONCE_LEN_PREFIX_SIZE {
            return Err(CryptoError::SerializationError(
                "Data too short to contain nonce length prefix".to_string(),
            ));
        }

        let nonce_len =
            u32::from_le_bytes(data[..NONCE_LEN_PREFIX_SIZE].try_into().map_err(|_| {
                CryptoError::SerializationError("Failed to read nonce length".to_string())
            })?) as usize;

        let remaining = data.len() - NONCE_LEN_PREFIX_SIZE;
        if remaining < nonce_len {
            return Err(CryptoError::SerializationError(
                "Data too short to contain nonce".to_string(),
            ));
        }

        let nonce_start = NONCE_LEN_PREFIX_SIZE;
        let nonce_end = nonce_start + nonce_len;
        let nonce = data[nonce_start..nonce_end].to_vec();

        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::SerializationError(format!(
                "Invalid nonce size: expected {}, got {}",
                NONCE_SIZE,
                nonce.len()
            )));
        }

        let ciphertext = data[nonce_end..].to_vec();

        if ciphertext.is_empty() {
            return Err(CryptoError::SerializationError(
                "No ciphertext data found".to_string(),
            ));
        }

        Ok(EncryptedData { nonce, ciphertext })
    }
}

/// Encrypt data using AES-256-GCM.
///
/// Generates a random 12-byte nonce, encrypts the data with AES-256-GCM,
/// and returns an `EncryptedData` struct containing the nonce and ciphertext.
/// The authentication tag is appended to the ciphertext by the aes-gcm crate.
///
/// # Arguments
/// * `data` - The plaintext data to encrypt
/// * `key` - The 32-byte AES-256 key
///
/// # Errors
/// Returns `CryptoError::EncryptionError` if encryption fails.
pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<EncryptedData> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| {
        CryptoError::EncryptionError(format!("AES-256-GCM encryption failed: {}", e))
    })?;

    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt data using AES-256-GCM.
///
/// Takes an `EncryptedData` struct and the 32-byte key, and returns
/// the decrypted plaintext.
///
/// # Arguments
/// * `encrypted` - The encrypted data container
/// * `key` - The 32-byte AES-256 key
///
/// # Errors
/// Returns `CryptoError::DecryptionError` if decryption fails (e.g., wrong key, tampered data).
pub fn decrypt_data(encrypted: &EncryptedData, key: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted.nonce.len() != NONCE_SIZE {
        return Err(CryptoError::DecryptionError(format!(
            "Invalid nonce size: expected {}, got {}",
            NONCE_SIZE,
            encrypted.nonce.len()
        )));
    }

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| {
            CryptoError::DecryptionError(format!("AES-256-GCM decryption failed: {}", e))
        })?;

    Ok(plaintext)
}

/// Encrypt a chunk of data and serialize it into a single byte vector.
///
/// This is a convenience function that combines `encrypt_data` and `EncryptedData::to_bytes`.
/// The output format is: `[4-byte nonce length (LE)] [nonce bytes] [ciphertext bytes]`
///
/// # Arguments
/// * `data` - The plaintext chunk to encrypt
/// * `key` - The 32-byte AES-256 key
///
/// # Errors
/// Returns `CryptoError::EncryptionError` if encryption fails.
pub fn encrypt_chunk(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted = encrypt_data(data, key)?;
    Ok(encrypted.to_bytes())
}

/// Deserialize and decrypt a chunk of data.
///
/// This is a convenience function that combines `EncryptedData::from_bytes` and `decrypt_data`.
///
/// # Arguments
/// * `data` - The serialized encrypted chunk
/// * `key` - The 32-byte AES-256 key
///
/// # Errors
/// Returns `CryptoError::SerializationError` if deserialization fails,
/// or `CryptoError::DecryptionError` if decryption fails.
pub fn decrypt_chunk(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted = EncryptedData::from_bytes(data)?;
    decrypt_data(&encrypted, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = random_key();
        let plaintext = b"Hello, BackupShield! This is a test message.";

        let encrypted = encrypt_data(plaintext, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_chunk_roundtrip() {
        let key = random_key();
        let plaintext = b"Chunk data for testing serialization.";

        let serialized = encrypt_chunk(plaintext, &key).unwrap();
        let decrypted = decrypt_chunk(&serialized, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = random_key();
        let plaintext = b"Serialization test data.";

        let encrypted = encrypt_data(plaintext, &key).unwrap();
        let bytes = encrypted.to_bytes();
        let deserialized = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.nonce, deserialized.nonce);
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let plaintext = b"Wrong key test.";

        let encrypted = encrypt_data(plaintext, &key1).unwrap();
        let result = decrypt_data(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_is_12_bytes() {
        let key = random_key();
        let encrypted = encrypt_data(b"test", &key).unwrap();
        assert_eq!(encrypted.nonce.len(), 12);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = random_key();
        let plaintext = b"";

        let encrypted = encrypt_data(plaintext, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_from_bytes_too_short() {
        let result = EncryptedData::from_bytes(&[0u8; 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = random_key();
        let plaintext = b"Tamper test data.";

        let mut encrypted = encrypt_data(plaintext, &key).unwrap();
        // Tamper with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        let result = decrypt_data(&encrypted, &key);
        assert!(result.is_err());
    }
}
