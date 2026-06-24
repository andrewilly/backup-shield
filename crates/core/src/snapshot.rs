// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::chunker::Chunker;
use crate::repository::Repository;

// ── Snapshot node types ──────────────────────────────────────────────────────

/// A file version entry (for version history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersion {
    /// Snapshot ID where this version was created.
    pub snapshot_id: String,
    /// When this version was created.
    pub timestamp: DateTime<Utc>,
    /// File size in this version.
    pub size: u64,
    /// Chunk hashes for this version.
    pub chunk_hashes: Vec<String>,
    /// File hash for this version.
    pub file_hash: String,
}

/// A file entry within a snapshot tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    /// File name (last component of the path).
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Last modification time.
    pub modified: DateTime<Utc>,
    /// Unix file mode / permissions.
    pub mode: u32,
    /// Hex SHA-256 hashes of the chunks that make up this file.
    pub chunk_hashes: Vec<String>,
    /// SHA-256 hash of the concatenation of all chunk hashes (commitment).
    pub file_hash: String,
    /// Previous versions of this file (if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<FileVersion>,
    /// Windows-specific: NTFS file attributes (FILE_ATTRIBUTE_* flags).
    #[cfg(target_os = "windows")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_attributes: Option<u32>,
    /// Windows-specific: NTFS security descriptor (raw DACL bytes).
    #[cfg(target_os = "windows")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_acl: Option<Vec<u8>>,
    /// Windows-specific: alternate data streams (name, content) pairs.
    #[cfg(target_os = "windows")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_ads: Option<Vec<(String, Vec<u8>)>>,
}

/// A directory entry within a snapshot tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDir {
    /// Directory name.
    pub name: String,
    /// Last modification time.
    pub modified: DateTime<Utc>,
    /// Unix directory mode / permissions.
    pub mode: u32,
    /// Child nodes contained in this directory.
    pub children: Vec<SnapshotNode>,
}

/// A symbolic link entry within a snapshot tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSymlink {
    /// Symlink name.
    pub name: String,
    /// Target path the symlink points to.
    pub target: String,
}

/// A node in the snapshot tree – either a file, directory, or symlink.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnapshotNode {
    File(SnapshotFile),
    Directory(SnapshotDir),
    Symlink(SnapshotSymlink),
}

impl SnapshotNode {
    /// Return the name of this node.
    pub fn name(&self) -> &str {
        match self {
            SnapshotNode::File(f) => &f.name,
            SnapshotNode::Directory(d) => &d.name,
            SnapshotNode::Symlink(s) => &s.name,
        }
    }

    /// If this node is a Directory, return a mutable reference to its children.
    pub fn children_mut(&mut self) -> Option<&mut Vec<SnapshotNode>> {
        match self {
            SnapshotNode::Directory(d) => Some(&mut d.children),
            _ => None,
        }
    }
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

/// A snapshot represents a point-in-time capture of a directory tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Unique snapshot identifier (random hex string).
    pub id: String,
    /// When this snapshot was taken.
    pub timestamp: DateTime<Utc>,
    /// Hostname of the machine where the snapshot was taken.
    pub hostname: String,
    /// User-defined tags for organising snapshots.
    pub tags: Vec<String>,
    /// Root of the snapshot tree.
    pub root: SnapshotNode,
    /// Total uncompressed size of all files in bytes.
    pub total_size: u64,
    /// Total number of chunks across all files.
    pub total_chunks: u64,
    /// ID of the parent snapshot (for incremental backup with hard links).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_snapshot_id: Option<String>,
}

impl Snapshot {
    /// Generate a unique snapshot ID using cryptographically secure random bytes.
    fn generate_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Compute the `file_hash` field: SHA-256 of the concatenation of chunk hashes.
    fn compute_file_hash(chunk_hashes: &[String]) -> String {
        let mut hasher = Sha256::new();
        for h in chunk_hashes {
            hasher.update(h.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Build a snapshot from a filesystem path.
    ///
    /// Walks the directory tree, chunks each file using the provided chunker,
    /// stores the chunks in the repository, and constructs the snapshot tree.
    pub fn build_from_path(
        path: &Path,
        chunker: &Chunker,
        repo: &mut Repository,
    ) -> Result<Snapshot> {
        let root_node = Self::build_node(path, chunker, repo)?;

        // Compute aggregate stats.
        let (total_size, total_chunks) = Self::compute_stats(&root_node);

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(Snapshot {
            id: Self::generate_id(),
            timestamp: Utc::now(),
            hostname,
            tags: Vec::new(),
            root: root_node,
            total_size,
            total_chunks,
            parent_snapshot_id: None,
        })
    }

    /// Recursively build a `SnapshotNode` from a filesystem path.
    fn build_node(path: &Path, chunker: &Chunker, repo: &mut Repository) -> Result<SnapshotNode> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to read metadata for {:?}", path))?;

        // Handle symbolic links (including broken ones).
        if metadata.file_type().is_symlink() {
            let target = match fs::read_link(path) {
                Ok(t) => t.to_string_lossy().to_string(),
                Err(e) => {
                    log::warn!("failed to read symlink {:?}: {} — treating as broken", path, e);
                    String::new()
                }
            };
            return Ok(SnapshotNode::Symlink(SnapshotSymlink {
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                target,
            }));
        }

        if metadata.is_dir() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let modified: DateTime<Utc> = metadata
                .modified()
                .ok()
                .map(DateTime::from)
                .unwrap_or_else(Utc::now);
            let mode = Self::unix_mode(&metadata);

            let mut children = Vec::new();
            let entries = fs::read_dir(path)
                .with_context(|| format!("failed to read directory {:?}", path))?;

            // Sort entries for deterministic output; log warnings on I/O errors.
            let mut sorted_entries = Vec::new();
            for entry in entries {
                match entry {
                    Ok(e) => sorted_entries.push(e),
                    Err(err) => log::warn!("failed to read entry in {:?}: {}", path, err),
                }
            }
            sorted_entries.sort_by_key(|e| e.file_name());

            for entry in sorted_entries {
                let child_path = entry.path();
                match Self::build_node(&child_path, chunker, repo) {
                    Ok(node) => children.push(node),
                    Err(e) => {
                        log::warn!("skipping {:?}: {}", child_path, e);
                    }
                }
            }

            return Ok(SnapshotNode::Directory(SnapshotDir {
                name,
                modified,
                mode,
                children,
            }));
        }

        // Regular file.
        if metadata.is_file() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let size = metadata.len();
            let modified: DateTime<Utc> = metadata
                .modified()
                .ok()
                .map(DateTime::from)
                .unwrap_or_else(Utc::now);
            let mode = Self::unix_mode(&metadata);

            // Chunk the file and store chunks.
            let chunks = chunker.chunk_file(path)?;
            let mut chunk_hashes = Vec::with_capacity(chunks.len());
            for chunk_data in &chunks {
                let hash = repo.store_chunk(chunk_data)?;
                chunk_hashes.push(hash);
            }

            let file_hash = Self::compute_file_hash(&chunk_hashes);

            #[cfg(target_os = "windows")]
            let windows_attributes = match crate::windows_attrs::read_file_attributes(path) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("failed to read Windows attributes for {:?}: {}", path, e);
                    None
                }
            };
            #[cfg(target_os = "windows")]
            let windows_acl = match crate::windows_attrs::read_security_descriptor(path) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("failed to read Windows ACL for {:?}: {}", path, e);
                    None
                }
            };
            #[cfg(target_os = "windows")]
            let windows_ads = match crate::windows_attrs::read_alternate_data_streams(path) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("failed to read Windows ADS for {:?}: {}", path, e);
                    None
                }
            };

            return Ok(SnapshotNode::File(SnapshotFile {
                name,
                size,
                modified,
                mode,
                chunk_hashes,
                file_hash,
                versions: Vec::new(),
                #[cfg(target_os = "windows")]
                windows_attributes,
                #[cfg(target_os = "windows")]
                windows_acl,
                #[cfg(target_os = "windows")]
                windows_ads,
            }));
        }

        bail!("unsupported file type: {:?}", path)
    }

    /// Extract unix mode bits from metadata (0 on Windows).
    #[allow(unused_variables)]
    fn unix_mode(metadata: &fs::Metadata) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        }
        #[cfg(not(unix))]
        {
            0o644
        }
    }

    /// Recursively compute total size and chunk count from a snapshot tree.
    fn compute_stats(node: &SnapshotNode) -> (u64, u64) {
        match node {
            SnapshotNode::File(f) => (f.size, f.chunk_hashes.len() as u64),
            SnapshotNode::Directory(d) => {
                let mut total_size = 0u64;
                let mut total_chunks = 0u64;
                for child in &d.children {
                    let (s, c) = Self::compute_stats(child);
                    total_size += s;
                    total_chunks += c;
                }
                (total_size, total_chunks)
            }
            SnapshotNode::Symlink(_) => (0, 0),
        }
    }

    /// Save this snapshot to the repository's `snapshots/` directory.
    /// Uses atomic write (tmp file + rename + fsync) to prevent corruption on crash.
    pub fn save(&self, repo_path: &Path) -> Result<()> {
        let snapshots_dir = repo_path.join("snapshots");
        fs::create_dir_all(&snapshots_dir)
            .with_context(|| format!("failed to create snapshots dir {:?}", snapshots_dir))?;
        let path = snapshots_dir.join(format!("{}.json", self.id));
        let tmp_path = snapshots_dir.join(format!("{}.json.tmp", self.id));
        let json = serde_json::to_string_pretty(self).context("failed to serialize snapshot")?;
        {
            let mut file = fs::File::create(&tmp_path)
                .with_context(|| format!("failed to write snapshot to {:?}", tmp_path))?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, &path)
            .with_context(|| format!("failed to rename snapshot {:?} -> {:?}", tmp_path, path))?;
        Ok(())
    }

    /// Load a snapshot from a JSON file.
    pub fn load(path: &Path) -> Result<Snapshot> {
        let json = fs::read_to_string(path)
            .with_context(|| format!("failed to read snapshot from {:?}", path))?;
        let snapshot: Snapshot = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse snapshot from {:?}", path))?;
        Ok(snapshot)
    }

    /// Collect all chunk hashes referenced by this snapshot.
    pub fn all_chunk_hashes(&self) -> Vec<String> {
        let mut hashes = Vec::new();
        Self::collect_chunk_hashes(&self.root, &mut hashes);
        hashes
    }

    fn collect_chunk_hashes(node: &SnapshotNode, hashes: &mut Vec<String>) {
        match node {
            SnapshotNode::File(f) => hashes.extend(f.chunk_hashes.iter().cloned()),
            SnapshotNode::Directory(d) => {
                for child in &d.children {
                    Self::collect_chunk_hashes(child, hashes);
                }
            }
            SnapshotNode::Symlink(_) => {}
        }
    }

    /// Find a file in this snapshot by relative path.
    /// Returns (size, modified_time, chunk_hashes) if found.
    pub fn find_file(&self, rel_path: &Path) -> Option<(u64, DateTime<Utc>, Vec<String>)> {
        Self::find_file_node(&self.root, rel_path).map(|(s, m, c, _)| (s, m, c))
    }

    /// Find a file in this snapshot with version history.
    /// Returns (size, modified_time, chunk_hashes, versions) if found.
    pub fn find_file_with_versions(
        &self,
        rel_path: &Path,
    ) -> Option<(u64, DateTime<Utc>, Vec<String>, Vec<FileVersion>)> {
        Self::find_file_node(&self.root, rel_path)
    }

    fn find_file_node(
        node: &SnapshotNode,
        rel_path: &Path,
    ) -> Option<(u64, DateTime<Utc>, Vec<String>, Vec<FileVersion>)> {
        let components: Vec<&str> = rel_path.iter().filter_map(|p| p.to_str()).collect();
        if components.is_empty() {
            return None;
        }

        let first = components[0];
        let remaining_str = components[1..].join(std::path::MAIN_SEPARATOR_STR);
        let remaining = Path::new(&remaining_str);

        match node {
            SnapshotNode::File(f) if components.len() == 1 && f.name == first => Some((
                f.size,
                f.modified,
                f.chunk_hashes.clone(),
                f.versions.clone(),
            )),
            SnapshotNode::Directory(d) => {
                if d.name == first && !remaining.as_os_str().is_empty() {
                    for child in &d.children {
                        if let Some(result) = Self::find_file_node(child, remaining) {
                            return Some(result);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ── Snapshot listing and querying ────────────────────────────────────────────

/// List all snapshots in a repository, sorted by timestamp (oldest first).
pub fn list_snapshots(repo_path: &Path) -> Result<Vec<Snapshot>> {
    let snapshots_dir = repo_path.join("snapshots");
    if !snapshots_dir.exists() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    let entries = fs::read_dir(&snapshots_dir)
        .with_context(|| format!("failed to read snapshots dir {:?}", snapshots_dir))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                log::warn!("failed to read entry in snapshots dir: {}", err);
                continue;
            }
        };
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "json") {
            match Snapshot::load(&path) {
                Ok(snap) => snapshots.push(snap),
                Err(e) => {
                    log::warn!("failed to load snapshot {:?}: {}", path, e);
                }
            }
        }
    }

    snapshots.sort_by_key(|s| s.timestamp);
    Ok(snapshots)
}

/// Find a snapshot by query string.
///
/// Supported query forms:
/// - `"latest"` – returns the most recent snapshot.
/// - A partial hex ID prefix – returns the first snapshot whose ID starts with the prefix.
/// - A tag name – returns the first snapshot tagged with the given tag.
pub fn find_snapshot(repo_path: &Path, query: &str) -> Result<Snapshot> {
    let snapshots = list_snapshots(repo_path)?;

    if query == "latest" {
        return snapshots.into_iter().last().context("no snapshots found");
    }

    // Try partial ID match.
    if let Some(found) = snapshots.iter().find(|s| s.id.starts_with(query)) {
        return Ok(found.clone());
    }

    // Try tag match.
    if let Some(found) = snapshots.iter().find(|s| s.tags.iter().any(|t| t == query)) {
        return Ok(found.clone());
    }

    bail!("no snapshot matching query '{}'", query)
}

/// Prune old snapshots according to a retention policy.
///
/// The policy keeps:
/// - `keep_daily` most recent snapshots per day,
/// - `keep_weekly` most recent snapshots per week,
/// - `keep_monthly` most recent snapshots per month.
///
/// Returns the IDs of snapshots that were removed.  When a snapshot is
/// removed, the ref count for each of its chunks is decremented; chunks whose
/// ref count reaches zero are deleted from disk.
pub fn prune_snapshots(
    repo_path: &Path,
    keep_daily: u32,
    keep_weekly: u32,
    keep_monthly: u32,
) -> Result<Vec<String>> {
    let mut snapshots = list_snapshots(repo_path)?;
    if snapshots.is_empty() {
        return Ok(Vec::new());
    }

    // Sort newest first.
    snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let mut to_keep = std::collections::HashSet::new();
    let mut daily_counts: BTreeMap<(i32, u32, u32), u32> = BTreeMap::new(); // (year, month, day)
    let mut weekly_counts: BTreeMap<(i32, u32), u32> = BTreeMap::new(); // (year, week)
    let mut monthly_counts: BTreeMap<(i32, u32), u32> = BTreeMap::new(); // (year, month)

    for snap in &snapshots {
        let date = snap.timestamp.date_naive();
        let year = date.year();
        let month = date.month();
        let day = date.day();
        let week = iso_week_number(date);

        let mut should_keep = false;

        // Daily policy.
        let daily_key = (year, month, day);
        let daily_count = daily_counts.entry(daily_key).or_insert(0);
        if *daily_count < keep_daily {
            *daily_count += 1;
            should_keep = true;
        }

        // Weekly policy.
        let weekly_key = (year, week);
        let weekly_count = weekly_counts.entry(weekly_key).or_insert(0);
        if *weekly_count < keep_weekly {
            *weekly_count += 1;
            should_keep = true;
        }

        // Monthly policy.
        let monthly_key = (year, month);
        let monthly_count = monthly_counts.entry(monthly_key).or_insert(0);
        if *monthly_count < keep_monthly {
            *monthly_count += 1;
            should_keep = true;
        }

        if should_keep {
            to_keep.insert(snap.id.clone());
        }
    }

    // Determine which snapshots to remove.
    let mut removed_ids = Vec::new();
    let mut repo = Repository::open(repo_path)?;

    for snap in &snapshots {
        if to_keep.contains(&snap.id) {
            continue;
        }

        log::info!("pruning snapshot {}", &snap.id[..12]);

        // Decrement ref counts for all chunks in this snapshot.
        let chunk_hashes = snap.all_chunk_hashes();
        for hash in &chunk_hashes {
            let should_delete = repo.index.decrement_ref(hash);
            if should_delete {
                repo.remove_chunk(hash)?;
            }
        }

        // Delete the snapshot file.
        let snapshot_path = repo_path
            .join("snapshots")
            .join(format!("{}.json", snap.id));
        if snapshot_path.exists() {
            fs::remove_file(&snapshot_path)
                .with_context(|| format!("failed to delete snapshot file {:?}", snapshot_path))?;
        }

        removed_ids.push(snap.id.clone());
    }

    // Persist the updated index.
    repo.save_index()?;

    Ok(removed_ids)
}

/// Delete specific snapshots by ID and update chunk ref counts.
/// Returns list of deleted snapshot IDs.
pub fn delete_snapshots(repo_path: &Path, snapshot_ids: &[String]) -> Result<Vec<String>> {
    if snapshot_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut repo = Repository::open(repo_path)?;
    let snapshots = list_snapshots(repo_path)?;

    let mut removed_ids = Vec::new();

    for id in snapshot_ids {
        // Find snapshot
        let snap = match snapshots.iter().find(|s| &s.id == id) {
            Some(s) => s,
            None => {
                log::warn!("snapshot {} not found, skipping", &id[..12.min(id.len())]);
                continue;
            }
        };

        // Decrement ref counts for all chunks
        let chunk_hashes = snap.all_chunk_hashes();
        for hash in &chunk_hashes {
            let should_delete = repo.index.decrement_ref(hash);
            if should_delete {
                repo.remove_chunk(hash)?;
            }
        }

        // Delete snapshot file
        let snapshot_path = repo_path.join("snapshots").join(format!("{}.json", id));
        if snapshot_path.exists() {
            fs::remove_file(&snapshot_path)?;
        }

        removed_ids.push(id.clone());
        log::info!("Deleted snapshot: {}", &id[..12.min(id.len())]);
    }

    repo.save_index()?;
    Ok(removed_ids)
}

/// Compute the ISO week number for a `NaiveDate`.
fn iso_week_number(date: chrono::NaiveDate) -> u32 {
    date.iso_week().week()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp_repo() -> (std::path::PathBuf, Repository) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repo");
        let repo = Repository::init(&path, None).unwrap();
        (path, repo)
    }

    #[test]
    fn snapshot_build_from_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"hello snapshot world").unwrap();

        let (_repo_path, mut repo) = temp_repo();
        let chunker = Chunker::new(
            repo.config.chunk_min_size,
            repo.config.chunk_max_size,
            repo.config.chunk_target_size,
        )
        .unwrap();

        let snapshot = Snapshot::build_from_path(&file_path, &chunker, &mut repo).unwrap();

        // The snapshot should have identified the file.
        match &snapshot.root {
            SnapshotNode::File(f) => {
                assert_eq!(f.name, "test.txt");
                assert!(f.size > 0);
                assert!(!f.chunk_hashes.is_empty());
            }
            other => panic!("expected File node, got {:?}", other),
        }
    }

    #[test]
    fn snapshot_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hello.txt");
        fs::write(&file_path, b"snapshot persistence test").unwrap();

        let (repo_path, mut repo) = temp_repo();
        let chunker = Chunker::new(
            repo.config.chunk_min_size,
            repo.config.chunk_max_size,
            repo.config.chunk_target_size,
        )
        .unwrap();

        let mut snapshot = Snapshot::build_from_path(&file_path, &chunker, &mut repo).unwrap();
        snapshot.tags.push("test".to_string());
        snapshot.save(&repo_path).unwrap();

        let loaded = Snapshot::load(
            &repo_path
                .join("snapshots")
                .join(format!("{}.json", snapshot.id)),
        )
        .unwrap();
        assert_eq!(loaded.id, snapshot.id);
        assert!(loaded.tags.contains(&"test".to_string()));
    }

    #[test]
    fn list_and_find_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("data.bin");
        fs::write(&file_path, b"find test data").unwrap();

        let (repo_path, mut repo) = temp_repo();
        let chunker = Chunker::new(
            repo.config.chunk_min_size,
            repo.config.chunk_max_size,
            repo.config.chunk_target_size,
        )
        .unwrap();

        let mut s1 = Snapshot::build_from_path(&file_path, &chunker, &mut repo).unwrap();
        s1.tags.push("important".to_string());
        s1.save(&repo_path).unwrap();

        let s2 = Snapshot::build_from_path(&file_path, &chunker, &mut repo).unwrap();
        s2.save(&repo_path).unwrap();

        let list = list_snapshots(&repo_path).unwrap();
        assert_eq!(list.len(), 2);

        let latest = find_snapshot(&repo_path, "latest").unwrap();
        assert_eq!(latest.id, s2.id);

        let by_tag = find_snapshot(&repo_path, "important").unwrap();
        assert_eq!(by_tag.id, s1.id);
    }
}
