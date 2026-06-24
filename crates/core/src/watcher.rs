// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.
//
//! Platform-native file system watcher (FSEvents on macOS, inotify on Linux).
//!
//! Uses the `notify` crate to monitor directories for changes and accumulate
//! modified / created / deleted paths for incremental backup.

use anyhow::{Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A platform-native recursive file system watcher.
///
/// Monitors one or more directories and accumulates paths that have been
/// created, modified, or removed.
pub struct FileWatcher {
    changed: Arc<Mutex<HashSet<PathBuf>>>,
    running: Arc<AtomicBool>,
    /// The underlying notify watcher must be kept alive for events to flow.
    _watcher: Option<RecommendedWatcher>,
    /// Handle to the event-processing thread.
    _thread_handle: Option<thread::JoinHandle<()>>,
}

impl FileWatcher {
    /// Create a new watcher and start monitoring the given directories recursively.
    ///
    /// Spawns a background thread that receives file system events and updates
    /// the internal set of changed paths.
    pub fn new(dirs: &[PathBuf]) -> Result<Self> {
        let changed: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
        let running = Arc::new(AtomicBool::new(true));

        let (tx, rx) = channel::<Result<Event, notify::Error>>();
        let mut watcher: RecommendedWatcher = RecommendedWatcher::new(tx, Config::default())
            .map_err(|e| anyhow::anyhow!("failed to create file watcher: {}", e))?;

        for dir in dirs {
            // Canonicalize to resolve symlinks (e.g. /var -> /private/var on macOS)
            // so that paths reported by FSEvents match what the user expects.
            let canonical = dir
                .canonicalize()
                .with_context(|| format!("failed to canonicalize directory: {:?}", dir))?;
            watcher
                .watch(&canonical, RecursiveMode::Recursive)
                .with_context(|| format!("failed to watch directory: {:?}", canonical))?;
            log::info!("watching directory: {:?}", canonical);
        }

        let changed_clone = Arc::clone(&changed);
        let running_clone = Arc::clone(&running);
        let handle = thread::spawn(move || {
            Self::event_loop(rx, changed_clone, running_clone);
        });

        Ok(FileWatcher {
            changed,
            running,
            _watcher: Some(watcher),
            _thread_handle: Some(handle),
        })
    }

    /// Internal event processing loop.
    fn event_loop(
        rx: Receiver<Result<Event, notify::Error>>,
        changed: Arc<Mutex<HashSet<PathBuf>>>,
        running: Arc<AtomicBool>,
    ) {
        while running.load(Ordering::SeqCst) {
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(event)) => {
                    Self::process_event(&event, &changed);
                }
                Ok(Err(e)) => {
                    log::warn!("file watcher error: {}", e);
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Normal — no events in this interval
                }
                Err(RecvTimeoutError::Disconnected) => {
                    log::info!("file watcher channel disconnected");
                    break;
                }
            }
        }
    }

    /// Record paths from a notify event into the changed set.
    fn process_event(event: &Event, changed: &Arc<Mutex<HashSet<PathBuf>>>) {
        let relevant = matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        );
        if !relevant {
            return;
        }
        if let Ok(mut set) = changed.lock() {
            for path in &event.paths {
                set.insert(path.clone());
                log::debug!("file changed: {:?}", path);
            }
        }
    }

    /// Return all files that changed since the last call to [`clear`].
    pub fn get_changed(&self) -> Vec<PathBuf> {
        self.changed
            .lock()
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Return the number of unique changed paths.
    pub fn changed_count(&self) -> usize {
        self.changed.lock().map(|set| set.len()).unwrap_or(0)
    }

    /// Clear the set of changed paths.
    pub fn clear(&self) {
        if let Ok(mut set) = self.changed.lock() {
            set.clear();
        }
    }

    /// Stop the watcher and background thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Drop the watcher explicitly to close the event channel.
        self._watcher.take();
    }
}

impl Drop for FileWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Save the set of changed paths to a JSON state file for later incremental use.
pub fn save_watcher_state(state_path: &Path, changed: &[PathBuf]) -> Result<()> {
    let paths: Vec<String> = changed
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let json = serde_json::to_string(&paths).context("failed to serialize watcher state")?;
    std::fs::write(state_path, json)
        .with_context(|| format!("failed to write watcher state to {:?}", state_path))?;
    Ok(())
}

/// Load the set of changed paths from a JSON state file.
pub fn load_watcher_state(state_path: &Path) -> Result<Vec<PathBuf>> {
    if !state_path.exists() {
        return Ok(Vec::new());
    }
    let json = std::fs::read_to_string(state_path)
        .with_context(|| format!("failed to read watcher state from {:?}", state_path))?;
    let paths: Vec<String> =
        serde_json::from_str(&json).context("failed to parse watcher state")?;
    Ok(paths.into_iter().map(PathBuf::from).collect())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Snapshot merge utilities for incremental backup
// ═══════════════════════════════════════════════════════════════════════════════

/// Replace or insert a file node into a snapshot tree by relative path.
///
/// Navigates the snapshot tree to the parent directory of `rel_path`, removes
/// any existing child with that name, and inserts the new `SnapshotNode`.
/// Creates intermediate directories if they don't exist.
///
/// `rel_path` must be a relative path from the snapshot root.
pub fn merge_file_into_snapshot(
    root: &mut crate::snapshot::SnapshotNode,
    rel_path: &Path,
    new_node: crate::snapshot::SnapshotNode,
) -> Result<()> {
    let components: Vec<&str> = rel_path.iter().filter_map(|c| c.to_str()).collect();

    anyhow::ensure!(!components.is_empty(), "empty relative path");

    let file_name = components
        .last()
        .ok_or_else(|| anyhow::anyhow!("empty path"))?;
    let dir_components = &components[..components.len().saturating_sub(1)];

    // Navigate to (or create) the parent directory.
    let parent = ensure_directory_path(root, dir_components)?;

    // Remove existing child with the same name.
    parent.retain(|child| child.name() != *file_name);

    // Insert the new node.
    parent.push(new_node);

    Ok(())
}

/// Navigate the snapshot tree to a directory path, creating intermediate
/// directories as needed. Returns a mutable reference to the children vector
/// of the target directory.
fn ensure_directory_path<'a>(
    node: &'a mut crate::snapshot::SnapshotNode,
    components: &[&str],
) -> Result<&'a mut Vec<crate::snapshot::SnapshotNode>> {
    if components.is_empty() {
        // Return the root's children if root is a directory
        match node {
            crate::snapshot::SnapshotNode::Directory(ref mut d) => Ok(&mut d.children),
            _ => anyhow::bail!("root is not a directory"),
        }
    } else {
        let (first, rest) = (components[0], &components[1..]);

        // Try to find an existing child directory with this name.
        // We need to collect indices first to avoid borrow issues.
        let child_exists = match node {
            crate::snapshot::SnapshotNode::Directory(ref d) => d.children.iter().any(|c| {
                c.name() == first && matches!(c, crate::snapshot::SnapshotNode::Directory(_))
            }),
            _ => return Err(anyhow::anyhow!("cannot navigate into non-directory node")),
        };

        if !child_exists {
            // Create the missing directory.
            match node {
                crate::snapshot::SnapshotNode::Directory(ref mut d) => {
                    d.children.push(crate::snapshot::SnapshotNode::Directory(
                        crate::snapshot::SnapshotDir {
                            name: first.to_string(),
                            modified: chrono::Utc::now(),
                            mode: 0o755,
                            children: Vec::new(),
                        },
                    ));
                }
                _ => unreachable!(),
            }
        }

        // Now find the child directory and recurse.
        match node {
            crate::snapshot::SnapshotNode::Directory(ref mut d) => {
                for child in &mut d.children {
                    if child.name() == first {
                        return ensure_directory_path(child, rest);
                    }
                }
                anyhow::bail!("failed to find or create directory: {}", first);
            }
            _ => unreachable!(),
        }
    }
}

/// Remove a file from the snapshot tree by relative path.
/// Returns `true` if the file was found and removed.
pub fn remove_file_from_snapshot(
    root: &mut crate::snapshot::SnapshotNode,
    rel_path: &Path,
) -> Result<bool> {
    let components: Vec<&str> = rel_path.iter().filter_map(|c| c.to_str()).collect();

    anyhow::ensure!(!components.is_empty(), "empty relative path");

    let file_name = components
        .last()
        .ok_or_else(|| anyhow::anyhow!("empty path"))?;
    let dir_components = &components[..components.len().saturating_sub(1)];

    remove_file_recursive(root, dir_components, file_name)
}

/// Recursive helper for remove_file_from_snapshot.
fn remove_file_recursive(
    node: &mut crate::snapshot::SnapshotNode,
    components: &[&str],
    file_name: &str,
) -> Result<bool> {
    if components.is_empty() {
        match node {
            crate::snapshot::SnapshotNode::Directory(ref mut d) => {
                let before = d.children.len();
                d.children.retain(|c| c.name() != file_name);
                return Ok(d.children.len() < before);
            }
            _ => return Ok(false),
        }
    }

    let (first, rest) = (components[0], &components[1..]);
    match node {
        crate::snapshot::SnapshotNode::Directory(ref mut d) => {
            for child in &mut d.children {
                if child.name() == first {
                    return remove_file_recursive(child, rest, file_name);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Walk a list of changed paths relative to `base_dir` and derive the set of
/// files that are still present (exist on disk) vs. deleted.
pub fn classify_changes(_base_dir: &Path, changed: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut present = Vec::new();
    let mut deleted = Vec::new();

    for path in changed {
        if path.exists() {
            present.push(path.clone());
        } else {
            deleted.push(path.clone());
        }
    }

    (present, deleted)
}

/// Make a path relative to a base directory.
/// Returns `None` if the path is not under `base_dir`.
pub fn make_relative(base_dir: &Path, path: &Path) -> Option<PathBuf> {
    path.strip_prefix(base_dir).ok().map(|p| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{SnapshotDir, SnapshotFile, SnapshotNode};
    use chrono::Utc;
    use std::fs;
    use std::thread;
    use tempfile::TempDir;

    fn make_file_node(name: &str) -> SnapshotNode {
        SnapshotNode::File(SnapshotFile {
            name: name.to_string(),
            size: 100,
            modified: Utc::now(),
            mode: 0o644,
            chunk_hashes: vec!["abc123".to_string()],
            file_hash: "def456".to_string(),
            versions: vec![],
            #[cfg(target_os = "windows")]
            windows_attributes: None,
            #[cfg(target_os = "windows")]
            windows_acl: None,
            #[cfg(target_os = "windows")]
            windows_ads: None,
        })
    }

    fn make_dir_node(name: &str) -> SnapshotNode {
        SnapshotNode::Directory(SnapshotDir {
            name: name.to_string(),
            modified: Utc::now(),
            mode: 0o755,
            children: vec![],
        })
    }

    #[test]
    fn test_merge_new_file_into_root() -> Result<()> {
        let mut root = make_dir_node("source");
        let file = make_file_node("hello.txt");

        merge_file_into_snapshot(&mut root, Path::new("hello.txt"), file)?;

        match &root {
            SnapshotNode::Directory(d) => {
                assert_eq!(d.children.len(), 1);
                assert_eq!(d.children[0].name(), "hello.txt");
            }
            _ => panic!("expected directory"),
        }
        Ok(())
    }

    #[test]
    fn test_merge_file_into_subdirectory() -> Result<()> {
        let mut root = make_dir_node("source");
        // Add a subdirectory
        let sub = make_dir_node("subdir");
        match &mut root {
            SnapshotNode::Directory(ref mut d) => d.children.push(sub),
            _ => unreachable!(),
        }

        let file = make_file_node("nested.txt");
        merge_file_into_snapshot(&mut root, Path::new("subdir/nested.txt"), file)?;

        match &mut root {
            SnapshotNode::Directory(d) => {
                assert_eq!(d.children.len(), 1);
                match &d.children[0] {
                    SnapshotNode::Directory(sub) => {
                        assert_eq!(sub.children.len(), 1);
                        assert_eq!(sub.children[0].name(), "nested.txt");
                    }
                    _ => panic!("expected directory"),
                }
            }
            _ => panic!("expected directory"),
        }
        Ok(())
    }

    #[test]
    fn test_merge_replaces_existing_file() -> Result<()> {
        let mut root = make_dir_node("source");
        let file1 = make_file_node("data.txt");
        let file2 = make_file_node("data.txt");

        // Insert twice — second should replace first
        merge_file_into_snapshot(&mut root, Path::new("data.txt"), file1)?;
        merge_file_into_snapshot(&mut root, Path::new("data.txt"), file2)?;

        match &root {
            SnapshotNode::Directory(d) => {
                assert_eq!(d.children.len(), 1, "should only have one child");
            }
            _ => panic!("expected directory"),
        }
        Ok(())
    }

    #[test]
    fn test_remove_file_from_root() -> Result<()> {
        let mut root = make_dir_node("source");
        let file = make_file_node("remove_me.txt");
        merge_file_into_snapshot(&mut root, Path::new("remove_me.txt"), file)?;

        let removed = remove_file_from_snapshot(&mut root, Path::new("remove_me.txt"))?;
        assert!(removed);

        match &root {
            SnapshotNode::Directory(d) => {
                assert!(d.children.is_empty());
            }
            _ => panic!("expected directory"),
        }
        Ok(())
    }

    #[test]
    fn test_watcher_detects_new_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        let watcher = FileWatcher::new(std::slice::from_ref(&dir))?;

        // Create a new file
        let new_file = dir.join("test.txt");
        fs::write(&new_file, "hello")?;

        // Give FSEvents time to fire
        thread::sleep(Duration::from_millis(800));

        let changed = watcher.get_changed();
        assert!(
            changed.contains(&new_file),
            "new file should be detected: got {:?}",
            changed
        );

        Ok(())
    }

    #[test]
    fn test_watcher_clear() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        let watcher = FileWatcher::new(std::slice::from_ref(&dir))?;

        let new_file = dir.join("test.txt");
        fs::write(&new_file, "hello")?;
        thread::sleep(Duration::from_millis(500));

        assert!(!watcher.get_changed().is_empty());
        watcher.clear();
        assert!(watcher.get_changed().is_empty());

        Ok(())
    }

    #[test]
    fn test_watcher_detects_modify() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        let watcher = FileWatcher::new(std::slice::from_ref(&dir))?;

        let file = dir.join("modify.txt");
        fs::write(&file, "original")?;
        thread::sleep(Duration::from_millis(300));
        watcher.clear();

        fs::write(&file, "modified")?;
        thread::sleep(Duration::from_millis(500));

        let changed = watcher.get_changed();
        assert!(
            changed.contains(&file),
            "modified file should be detected: got {:?}",
            changed
        );

        Ok(())
    }

    #[test]
    fn test_watcher_detects_rename() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        let watcher = FileWatcher::new(std::slice::from_ref(&dir))?;

        let old_file = dir.join("old.txt");
        let new_file = dir.join("new.txt");
        fs::write(&old_file, "rename me")?;
        thread::sleep(Duration::from_millis(300));
        watcher.clear();

        fs::rename(&old_file, &new_file)?;
        thread::sleep(Duration::from_millis(500));

        let changed = watcher.get_changed();
        // On APFS/FSEvents, rename fires as create(new) + remove(old)
        assert!(
            changed.contains(&new_file) || changed.contains(&old_file),
            "rename should be detected: got {:?}",
            changed
        );

        Ok(())
    }

    #[test]
    fn test_watcher_detects_delete() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        let watcher = FileWatcher::new(std::slice::from_ref(&dir))?;

        let file = dir.join("delete_me.txt");
        fs::write(&file, "bye")?;
        thread::sleep(Duration::from_millis(300));
        watcher.clear();

        fs::remove_file(&file)?;
        thread::sleep(Duration::from_millis(500));

        let changed = watcher.get_changed();
        assert!(
            changed.contains(&file),
            "deleted file should be detected: got {:?}",
            changed
        );

        Ok(())
    }

    #[test]
    fn test_save_load_watcher_state() -> Result<()> {
        let tmp = TempDir::new()?;
        let state_path = tmp.path().join("watcher_state.json");

        let changed = vec![
            PathBuf::from("/source/file1.txt"),
            PathBuf::from("/source/subdir/file2.txt"),
        ];

        save_watcher_state(&state_path, &changed)?;
        assert!(state_path.exists());

        let loaded = load_watcher_state(&state_path)?;
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], PathBuf::from("/source/file1.txt"));

        Ok(())
    }

    #[test]
    fn test_classify_changes() -> Result<()> {
        let tmp = TempDir::new()?;
        let existing = tmp.path().join("exists.txt");
        let deleted = tmp.path().join("deleted.txt");
        fs::write(&existing, "hello")?;
        // Don't create `deleted`

        let changed = vec![existing.clone(), deleted.clone()];
        let (present, removed) = classify_changes(tmp.path(), &changed);

        assert_eq!(present, vec![existing]);
        assert_eq!(removed, vec![deleted]);

        Ok(())
    }

    #[test]
    fn test_make_relative() {
        assert_eq!(
            make_relative(Path::new("/source"), Path::new("/source/file.txt")),
            Some(PathBuf::from("file.txt"))
        );
        assert_eq!(
            make_relative(Path::new("/source"), Path::new("/source/sub/file.txt")),
            Some(PathBuf::from("sub/file.txt"))
        );
        assert_eq!(
            make_relative(Path::new("/source"), Path::new("/other/file.txt")),
            None
        );
    }
}
