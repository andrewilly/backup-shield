// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Local filesystem storage backend.

use crate::{chunk_path, dirs, Result, StorageBackend, StorageError};
use std::fs;
use std::path::{Path, PathBuf};

// ── LocalStorage ────────────────────────────────────────────────────────────

/// Storage backend that reads and writes directly to the local filesystem.
///
/// The on-disk layout mirrors the repository layout defined in the core crate:
///
/// ```text
/// <root>/
///   chunks/
///     00/ … ff/          # 256 sub-directories keyed by first 2 hex chars
///   snapshots/
///   parity/
///   indexes/
/// ```
pub struct LocalStorage {
    /// Root directory of the local repository.
    root: PathBuf,
}

impl LocalStorage {
    /// Create a new `LocalStorage` pointing at `root`.
    ///
    /// The directory must already exist. Use [`LocalStorage::init`] to create
    /// the directory structure from scratch.
    pub fn new(root: &Path) -> Result<Self> {
        let root = canonicalize(root)?;
        if !root.is_dir() {
            return Err(StorageError::InvalidConfig(format!(
                "path does not exist or is not a directory: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Initialise a new local repository at `root`, creating the directory
    /// structure and all 256 chunk sub-directories. Returns a `LocalStorage`
    /// handle on success.
    pub fn init(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).map_err(|e| {
            StorageError::InvalidConfig(format!(
                "failed to create repository directory {}: {e}",
                root.display()
            ))
        })?;

        for subdir in &[dirs::CHUNKS, dirs::SNAPSHOTS, dirs::PARITY, dirs::INDEXES] {
            fs::create_dir_all(root.join(subdir)).map_err(|e| {
                StorageError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to create {subdir} directory: {e}"),
                ))
            })?;
        }

        // Create 256 chunk sub-directories (00..ff).
        for i in 0u16..256 {
            let dir_name = format!("{i:02x}");
            let path = root.join(dirs::CHUNKS).join(&dir_name);
            fs::create_dir_all(&path).map_err(|e| {
                StorageError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to create chunk sub-dir {}: {e}", dir_name),
                ))
            })?;
        }

        log::info!("initialised local storage at {}", root.display());
        Self::new(root)
    }

    /// Return the root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Sanitize a user-supplied name to prevent path traversal attacks.
    /// Removes path separators (`/`, `\`), parent-dir references (`..`),
    /// and any other non-alphanumeric characters except `-`, `_`, and `.`.
    /// Returns "unnamed" if the result is empty, `"."`, or `".."`.
    fn sanitize_name(name: &str) -> String {
        let cleaned: String = name
            .chars()
            .filter(|&c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            .collect();
        match cleaned.as_str() {
            "" | "." | ".." => "unnamed".to_string(),
            other => other.to_string(),
        }
    }

    fn snapshot_path(&self, name: &str) -> PathBuf {
        self.root
            .join(dirs::SNAPSHOTS)
            .join(Self::sanitize_name(name))
    }

    fn parity_path(&self, name: &str) -> PathBuf {
        self.root.join(dirs::PARITY).join(Self::sanitize_name(name))
    }

    fn index_path(&self, name: &str) -> PathBuf {
        self.root
            .join(dirs::INDEXES)
            .join(Self::sanitize_name(name))
    }

    /// List all file names (as Strings) in a directory, ignoring sub-dirs.
    fn list_files_in_dir(dir: &Path) -> Result<Vec<String>> {
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).map_err(StorageError::Io)? {
            let entry = entry.map_err(StorageError::Io)?;
            if entry.file_type().map_err(StorageError::Io)?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// Recursively compute the total size of all files under `dir`.
    fn dir_size(dir: &Path) -> Result<u64> {
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        walk_dir(dir, &mut |path| {
            if let Ok(meta) = fs::metadata(path) {
                if meta.is_file() {
                    total += meta.len();
                }
            }
        })?;
        Ok(total)
    }
}

/// Cross-platform canonicalize that doesn't fail if the path doesn't exist
/// (falls back to the original path).
fn canonicalize(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).or_else(|_| {
        // On some systems canonicalize requires the path to exist.
        // If it fails, just use the path as-is.
        Ok(path.to_path_buf())
    })
}

/// Recursively walk a directory, calling `f` for every entry.
fn walk_dir(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(StorageError::Io)?;
    for entry in entries {
        let entry = entry.map_err(StorageError::Io)?;
        let path = entry.path();
        let ft = entry.file_type().map_err(StorageError::Io)?;
        if ft.is_dir() {
            walk_dir(&path, f)?;
        } else {
            f(&path);
        }
    }
    Ok(())
}

// ── StorageBackend implementation ───────────────────────────────────────────

impl StorageBackend for LocalStorage {
    fn name(&self) -> &str {
        "local"
    }

    fn write_chunk(&self, hash: &str, data: &[u8]) -> Result<()> {
        let path = chunk_path(&self.root, hash);
        if path.exists() {
            // Chunk already stored – skip write (idempotent).
            return Ok(());
        }
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }
        fs::write(&path, data).map_err(StorageError::Io)?;
        log::trace!(
            "write_chunk: wrote {} bytes for hash {}",
            data.len(),
            &hash[..12.min(hash.len())]
        );
        Ok(())
    }

    fn read_chunk(&self, hash: &str) -> Result<Vec<u8>> {
        let path = chunk_path(&self.root, hash);
        if !path.exists() {
            return Err(StorageError::ChunkNotFound(hash.to_string()));
        }
        fs::read(&path).map_err(StorageError::Io)
    }

    fn chunk_exists(&self, hash: &str) -> Result<bool> {
        let path = chunk_path(&self.root, hash);
        Ok(path.exists())
    }

    fn delete_chunk(&self, hash: &str) -> Result<()> {
        let path = chunk_path(&self.root, hash);
        if path.exists() {
            fs::remove_file(&path).map_err(StorageError::Io)?;
        }
        Ok(())
    }

    fn list_chunks(&self) -> Result<Vec<String>> {
        let chunks_dir = self.root.join(dirs::CHUNKS);
        if !chunks_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut hashes = Vec::new();
        let prefix_dirs = fs::read_dir(&chunks_dir).map_err(StorageError::Io)?;

        for prefix_entry in prefix_dirs {
            let prefix_entry = prefix_entry.map_err(StorageError::Io)?;
            if !prefix_entry.file_type().map_err(StorageError::Io)?.is_dir() {
                continue;
            }
            let prefix_name = prefix_entry.file_name().to_str().unwrap_or("").to_string();
            if prefix_name.len() != 2 {
                continue;
            }

            let sub_dir = prefix_entry.path();
            let entries = fs::read_dir(&sub_dir).map_err(StorageError::Io)?;
            for entry in entries {
                let entry = entry.map_err(StorageError::Io)?;
                if !entry.file_type().map_err(StorageError::Io)?.is_file() {
                    continue;
                }
                if let Some(rest) = entry.file_name().to_str() {
                    hashes.push(format!("{prefix_name}{rest}"));
                }
            }
        }

        hashes.sort();
        Ok(hashes)
    }

    fn write_snapshot(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.snapshot_path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }
        fs::write(&path, data).map_err(StorageError::Io)?;
        Ok(())
    }

    fn read_snapshot(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.snapshot_path(name);
        if !path.exists() {
            return Err(StorageError::SnapshotNotFound(name.to_string()));
        }
        fs::read(&path).map_err(StorageError::Io)
    }

    fn list_snapshots(&self) -> Result<Vec<String>> {
        Self::list_files_in_dir(&self.root.join(dirs::SNAPSHOTS))
    }

    fn delete_snapshot(&self, name: &str) -> Result<()> {
        let path = self.snapshot_path(name);
        if path.exists() {
            fs::remove_file(&path).map_err(StorageError::Io)?;
        }
        Ok(())
    }

    fn write_parity(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.parity_path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }
        fs::write(&path, data).map_err(StorageError::Io)?;
        Ok(())
    }

    fn read_parity(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.parity_path(name);
        if !path.exists() {
            return Err(StorageError::ParityNotFound(name.to_string()));
        }
        fs::read(&path).map_err(StorageError::Io)
    }

    fn list_parity(&self) -> Result<Vec<String>> {
        Self::list_files_in_dir(&self.root.join(dirs::PARITY))
    }

    fn write_index(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.index_path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }
        fs::write(&path, data).map_err(StorageError::Io)?;
        Ok(())
    }

    fn read_index(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.index_path(name);
        if !path.exists() {
            return Err(StorageError::IndexNotFound(name.to_string()));
        }
        fs::read(&path).map_err(StorageError::Io)
    }

    fn total_size(&self) -> Result<u64> {
        Self::dir_size(&self.root)
    }

    fn free_space(&self) -> Result<u64> {
        // Use fs2::available_space to query the actual free space on the
        // filesystem where the repository resides.
        let available = fs2::available_space(&self.root).map_err(|e| {
            log::warn!("failed to query free space for {:?}: {}", self.root, e);
            StorageError::Io(e)
        })?;
        Ok(available)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        tempfile::tempdir().unwrap().path().join("test-repo")
    }

    #[test]
    fn init_creates_directory_structure() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();
        assert!(path.join("chunks").is_dir());
        assert!(path.join("chunks/00").is_dir());
        assert!(path.join("chunks/ff").is_dir());
        assert!(path.join("snapshots").is_dir());
        assert!(path.join("parity").is_dir());
        assert!(path.join("indexes").is_dir());
        drop(storage);
    }

    #[test]
    fn new_rejects_nonexistent_path() {
        let path = temp_dir().join("nope");
        let result = LocalStorage::new(&path);
        assert!(result.is_err());
    }

    #[test]
    fn write_and_read_chunk() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        let data = b"hello, storage!";
        let hash = "ab12cd34ef5678901112131415161718192021222324252627282930313233";
        storage.write_chunk(hash, data).unwrap();

        assert!(storage.chunk_exists(hash).unwrap());
        let read = storage.read_chunk(hash).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn write_chunk_is_idempotent() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        let hash = "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
        storage.write_chunk(hash, b"first").unwrap();
        storage.write_chunk(hash, b"second").unwrap();

        // Should still contain the first write (idempotent skips).
        let data = storage.read_chunk(hash).unwrap();
        assert_eq!(data, b"first");
    }

    #[test]
    fn read_nonexistent_chunk_fails() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();
        let result = storage.read_chunk("fffffffffffffff...");
        assert!(matches!(result, Err(StorageError::ChunkNotFound(_))));
    }

    #[test]
    fn delete_chunk() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        let hash = "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
        storage.write_chunk(hash, b"data").unwrap();
        assert!(storage.chunk_exists(hash).unwrap());

        storage.delete_chunk(hash).unwrap();
        assert!(!storage.chunk_exists(hash).unwrap());
    }

    #[test]
    fn list_chunks() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        let h1 = "aa1111111111111111111111111111111111111111111111111111111111111111";
        let h2 = "ab2222222222222222222222222222222222222222222222222222222222222222";
        let h3 = "aa3333333333333333333333333333333333333333333333333333333333333333";

        storage.write_chunk(h1, b"1").unwrap();
        storage.write_chunk(h2, b"2").unwrap();
        storage.write_chunk(h3, b"3").unwrap();

        let chunks = storage.list_chunks().unwrap();
        assert_eq!(chunks.len(), 3);
        // Sorted.
        assert_eq!(chunks[0], h1);
        assert_eq!(chunks[1], h3);
        assert_eq!(chunks[2], h2);
    }

    #[test]
    fn snapshot_roundtrip() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        storage.write_snapshot("snap1", b"snap-data").unwrap();
        let data = storage.read_snapshot("snap1").unwrap();
        assert_eq!(data, b"snap-data");

        let snapshots = storage.list_snapshots().unwrap();
        assert_eq!(snapshots, vec!["snap1"]);

        storage.delete_snapshot("snap1").unwrap();
        assert!(storage.list_snapshots().unwrap().is_empty());
    }

    #[test]
    fn parity_roundtrip() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        storage.write_parity("p1", b"parity-data").unwrap();
        let data = storage.read_parity("p1").unwrap();
        assert_eq!(data, b"parity-data");

        let list = storage.list_parity().unwrap();
        assert_eq!(list, vec!["p1"]);
    }

    #[test]
    fn index_roundtrip() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        storage.write_index("idx1", b"index-data").unwrap();
        let data = storage.read_index("idx1").unwrap();
        assert_eq!(data, b"index-data");
    }

    #[test]
    fn total_size_accounts_for_data() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();

        // Write some data.
        let hash = "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
        storage.write_chunk(hash, b"some data here").unwrap();

        let size = storage.total_size().unwrap();
        assert!(size > 0);
    }

    #[test]
    fn backend_name() {
        let path = temp_dir();
        let storage = LocalStorage::init(&path).unwrap();
        assert_eq!(storage.name(), "local");
    }
}
