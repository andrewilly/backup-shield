// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

// ── File index entry ─────────────────────────────────────────────────────────

/// An entry in the file index, linking a file path and modification time to a
/// snapshot and its chunk hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndexEntry {
    /// The file path (relative to the backup root).
    pub path: String,
    /// The snapshot that contains this version of the file.
    pub snapshot_id: String,
    /// SHA-256 hashes of the chunks that make up this file.
    pub chunk_hashes: Vec<String>,
    /// Last modification time of the file.
    pub modified: DateTime<Utc>,
}

// ── File index ───────────────────────────────────────────────────────────────

/// A fast-lookup index that maps `(file_path, file_modified_time)` to snapshot
/// information and chunk hashes.  This allows quickly finding which chunks
/// belong to a file across multiple snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileIndex {
    /// Map from (path, modified_timestamp) → FileIndexEntry.
    entries: HashMap<String, FileIndexEntry>,
}

impl FileIndex {
    /// Create a new, empty file index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the composite key used for lookups.
    fn make_key(path: &str, modified: &DateTime<Utc>) -> String {
        format!("{}|{}", path, modified.to_rfc3339())
    }

    /// Add an entry to the index.  If an entry with the same (path, modified)
    /// key already exists, it is replaced.
    pub fn add_entry(&mut self, entry: FileIndexEntry) {
        let key = Self::make_key(&entry.path, &entry.modified);
        self.entries.insert(key, entry);
    }

    /// Look up entries by file path and modification time.
    ///
    /// Returns `Some(&FileIndexEntry)` if an exact match is found.
    pub fn lookup(&self, path: &str, modified: &DateTime<Utc>) -> Option<&FileIndexEntry> {
        let key = Self::make_key(path, modified);
        self.entries.get(&key)
    }

    /// Look up all entries whose file path matches the given path, regardless
    /// of modification time.  Useful for finding all historical versions of a
    /// file.
    pub fn lookup_by_path(&self, path: &str) -> Vec<&FileIndexEntry> {
        self.entries.values().filter(|e| e.path == path).collect()
    }

    /// Look up entries by snapshot ID.  Returns all file entries that belong
    /// to the specified snapshot.
    pub fn lookup_by_snapshot(&self, snapshot_id: &str) -> Vec<&FileIndexEntry> {
        self.entries
            .values()
            .filter(|e| e.snapshot_id == snapshot_id)
            .collect()
    }

    /// Remove all entries associated with a given snapshot ID.
    ///
    /// Returns the number of entries removed.
    pub fn remove_by_snapshot(&mut self, snapshot_id: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.snapshot_id != snapshot_id);
        before - self.entries.len()
    }

    /// Return the number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Save the file index to disk as JSON with atomic write (tmp + rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .with_context(|| format!("index path has no parent: {:?}", path))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create index directory {:?}", parent))?;
        let json = serde_json::to_string_pretty(self).context("failed to serialize file index")?;
        let tmp_path = path.with_extension("json.tmp");
        {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to rename tmp index to {:?}", path))?;
        Ok(())
    }

    /// Load a file index from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)
            .with_context(|| format!("failed to read file index from {:?}", path))?;
        let index: FileIndex = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse file index from {:?}", path))?;
        Ok(index)
    }

    /// Return an iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &FileIndexEntry> {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_lookup() {
        let mut idx = FileIndex::new();
        let now = Utc::now();
        let entry = FileIndexEntry {
            path: "docs/readme.md".to_string(),
            snapshot_id: "abc123".to_string(),
            chunk_hashes: vec!["hash1".to_string(), "hash2".to_string()],
            modified: now,
        };
        idx.add_entry(entry);

        let found = idx.lookup("docs/readme.md", &now).unwrap();
        assert_eq!(found.snapshot_id, "abc123");
        assert_eq!(found.chunk_hashes.len(), 2);
    }

    #[test]
    fn lookup_by_path_finds_multiple_versions() {
        let mut idx = FileIndex::new();
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::hours(1);

        idx.add_entry(FileIndexEntry {
            path: "foo.txt".into(),
            snapshot_id: "snap1".into(),
            chunk_hashes: vec!["h1".into()],
            modified: t1,
        });
        idx.add_entry(FileIndexEntry {
            path: "foo.txt".into(),
            snapshot_id: "snap2".into(),
            chunk_hashes: vec!["h2".into()],
            modified: t2,
        });

        let results = idx.lookup_by_path("foo.txt");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn remove_by_snapshot() {
        let mut idx = FileIndex::new();
        let now = Utc::now();
        idx.add_entry(FileIndexEntry {
            path: "a.txt".into(),
            snapshot_id: "snap1".into(),
            chunk_hashes: vec![],
            modified: now,
        });
        idx.add_entry(FileIndexEntry {
            path: "b.txt".into(),
            snapshot_id: "snap2".into(),
            chunk_hashes: vec![],
            modified: now,
        });

        let removed = idx.remove_by_snapshot("snap1");
        assert_eq!(removed, 1);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file_index.json");

        let mut idx = FileIndex::new();
        let now = Utc::now();
        idx.add_entry(FileIndexEntry {
            path: "test.rs".into(),
            snapshot_id: "snap42".into(),
            chunk_hashes: vec!["c1".into(), "c2".into()],
            modified: now,
        });

        idx.save(&path).unwrap();
        let loaded = FileIndex::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        let found = loaded.lookup("test.rs", &now).unwrap();
        assert_eq!(found.snapshot_id, "snap42");
    }
}
