// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CryptoError;
use crate::Result;

/// Salt size in bytes.
const SALT_SIZE: usize = 32;

/// Derived key size in bytes (AES-256).
const KEY_SIZE: usize = 32;

/// Argon2id parameters.
const M_COST: u32 = 65536; // 64 MB memory
const T_COST: u32 = 3; // 3 iterations
const P_COST: u32 = 4; // 4 parallelism

/// Key material containing the salt and derived key.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// The 32-byte salt used for key derivation.
    pub salt: Vec<u8>,
    /// The 32-byte derived key.
    pub key: Vec<u8>,
}

/// JSON-serializable key file structure for persisting key material.
#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    /// The salt in hexadecimal encoding.
    salt: String,
    /// SHA-256 hash of the derived key in hexadecimal encoding, used for verification.
    verify_hash: String,
}

/// Generate a random 32-byte salt.
///
/// Uses the operating system's cryptographically secure random number generator.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte key from a password using Argon2id.
///
/// If no salt is provided, a random 32-byte salt is generated.
/// Uses Argon2id with the following parameters:
/// - Memory cost: 65536 KiB (64 MB)
/// - Time cost: 3 iterations
/// - Parallelism: 4 threads
///
/// # Arguments
/// * `password` - The password to derive the key from
/// * `salt` - Optional salt; if `None`, a random salt is generated
///
/// # Errors
/// Returns `CryptoError::KeyDerivationError` if key derivation fails.
pub fn derive_key(password: &str, salt: Option<&[u8]>) -> Result<KeyMaterial> {
    let salt_bytes = match salt {
        Some(s) => {
            if s.len() != SALT_SIZE {
                return Err(CryptoError::KeyDerivationError(format!(
                    "Invalid salt size: expected {}, got {}",
                    SALT_SIZE,
                    s.len()
                )));
            }
            s.to_vec()
        }
        None => generate_salt(),
    };

    let params = Params::new(M_COST, T_COST, P_COST, Some(KEY_SIZE)).map_err(|e| {
        CryptoError::KeyDerivationError(format!("Failed to create Argon2 params: {}", e))
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key)
        .map_err(|e| {
            CryptoError::KeyDerivationError(format!("Argon2id key derivation failed: {}", e))
        })?;

    Ok(KeyMaterial {
        salt: salt_bytes,
        key,
    })
}

/// Convenience function to derive a 32-byte key from a password and salt.
///
/// # Arguments
/// * `password` - The password to derive the key from
/// * `salt` - The salt to use for key derivation (must be 32 bytes)
///
/// # Errors
/// Returns `CryptoError::KeyDerivationError` if key derivation fails or salt is invalid.
pub fn key_from_password(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let key_material = derive_key(password, Some(salt))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_material.key);
    Ok(key)
}

/// Compute the SHA-256 hash of a key for verification purposes.
fn compute_key_hash(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Save key material to a JSON file.
///
/// The file contains the salt (hex-encoded) and a SHA-256 hash of the derived key
/// for verification when loading.
///
/// # Arguments
/// * `key_material` - The key material to save
/// * `path` - The file path to save the key material to
///
/// # Errors
/// Returns `CryptoError::IoError` if file operations fail,
/// or `CryptoError::SerializationError` if JSON serialization fails.
pub fn save_key_material(key_material: &KeyMaterial, path: &Path) -> Result<()> {
    let key_file = KeyFile {
        salt: hex::encode(&key_material.salt),
        verify_hash: compute_key_hash(&key_material.key),
    };

    let json = serde_json::to_string_pretty(&key_file).map_err(|e| {
        CryptoError::SerializationError(format!("Failed to serialize key file: {}", e))
    })?;

    // Atomic write: tmp file + rename to prevent corruption on crash.
    let tmp_path = path.with_extension("key.tmp");
    std::fs::write(&tmp_path, &json)
        .map_err(|e| CryptoError::IoError(format!("Failed to write key file: {}", e)))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| CryptoError::IoError(format!("Failed to rename key file: {}", e)))?;

    log::info!("Key material saved to {}", path.display());
    Ok(())
}

/// Load key material from a JSON file and verify the password.
///
/// Reads the salt from the file, re-derives the key from the password and salt,
/// and verifies that the derived key matches the stored verification hash.
///
/// # Arguments
/// * `path` - The file path to load the key material from
/// * `password` - The password to verify against the stored key
///
/// # Errors
/// Returns `CryptoError::IoError` if file operations fail,
/// `CryptoError::SerializationError` if JSON deserialization fails,
/// or `CryptoError::KeyVerificationFailed` if the password does not match.
pub fn load_key_material(path: &Path, password: &str) -> Result<KeyMaterial> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| CryptoError::IoError(format!("Failed to read key file: {}", e)))?;

    let key_file: KeyFile = serde_json::from_str(&json).map_err(|e| {
        CryptoError::SerializationError(format!("Failed to deserialize key file: {}", e))
    })?;

    let salt = hex::decode(&key_file.salt).map_err(|e| {
        CryptoError::SerializationError(format!("Failed to decode salt hex: {}", e))
    })?;

    if salt.len() != SALT_SIZE {
        return Err(CryptoError::SerializationError(format!(
            "Invalid salt size in key file: expected {}, got {}",
            SALT_SIZE,
            salt.len()
        )));
    }

    // Re-derive the key from the password and salt
    let key_material = derive_key(password, Some(&salt))?;

    // Verify the derived key matches the stored hash
    let computed_hash = compute_key_hash(&key_material.key);
    if !constant_time_eq(&computed_hash, &key_file.verify_hash) {
        return Err(CryptoError::KeyVerificationFailed(
            "Password does not match the stored key".to_string(),
        ));
    }

    log::info!("Key material loaded and verified from {}", path.display());
    Ok(key_material)
}

/// Constant-time string comparison to prevent timing attacks.
///
/// This function always compares all characters regardless of where
/// the first difference occurs.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (a_byte, b_byte) in a.bytes().zip(b.bytes()) {
        result |= a_byte ^ b_byte;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), SALT_SIZE);
        assert_eq!(salt2.len(), SALT_SIZE);
        assert_ne!(salt1, salt2, "Two generated salts should be different");
    }

    #[test]
    fn test_derive_key_with_provided_salt() {
        let salt = generate_salt();
        let key_material = derive_key("test_password", Some(&salt)).unwrap();

        assert_eq!(key_material.salt, salt);
        assert_eq!(key_material.key.len(), KEY_SIZE);
    }

    #[test]
    fn test_derive_key_without_salt() {
        let key_material = derive_key("test_password", None).unwrap();

        assert_eq!(key_material.salt.len(), SALT_SIZE);
        assert_eq!(key_material.key.len(), KEY_SIZE);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = generate_salt();
        let key1 = derive_key("test_password", Some(&salt)).unwrap();
        let key2 = derive_key("test_password", Some(&salt)).unwrap();

        assert_eq!(key1.key, key2.key);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = generate_salt();
        let key1 = derive_key("password1", Some(&salt)).unwrap();
        let key2 = derive_key("password2", Some(&salt)).unwrap();

        assert_ne!(key1.key, key2.key);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let key1 = derive_key("test_password", Some(&salt1)).unwrap();
        let key2 = derive_key("test_password", Some(&salt2)).unwrap();

        assert_ne!(key1.key, key2.key);
    }

    #[test]
    fn test_key_from_password() {
        let salt = generate_salt();
        let key = key_from_password("test_password", &salt).unwrap();

        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_key_from_password_matches_derive_key() {
        let salt = generate_salt();
        let key_material = derive_key("test_password", Some(&salt)).unwrap();
        let key = key_from_password("test_password", &salt).unwrap();

        assert_eq!(key_material.key.as_slice(), key.as_slice());
    }

    #[test]
    fn test_invalid_salt_size() {
        let short_salt = vec![0u8; 16];
        let result = derive_key("test_password", Some(&short_salt));

        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_key_material() {
        let dir = std::env::temp_dir().join("backup-shield-crypto-test");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_key.json");

        // Clean up any previous test file
        let _ = fs::remove_file(&path);

        let key_material = derive_key("test_password", None).unwrap();
        save_key_material(&key_material, &path).unwrap();

        let loaded = load_key_material(&path, "test_password").unwrap();
        assert_eq!(key_material.salt, loaded.salt);
        assert_eq!(key_material.key, loaded.key);

        // Clean up
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_load_key_material_wrong_password() {
        let dir = std::env::temp_dir().join("backup-shield-crypto-test-wrong");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_key_wrong.json");

        let _ = fs::remove_file(&path);

        let key_material = derive_key("correct_password", None).unwrap();
        save_key_material(&key_material, &path).unwrap();

        let result = load_key_material(&path, "wrong_password");
        assert!(result.is_err());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
