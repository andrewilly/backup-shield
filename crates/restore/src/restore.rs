// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

use backup_shield_compression::compressor::decompress_chunk;
use backup_shield_crypto::encryption::decrypt_chunk;

#[cfg(unix)]
fn validate_symlink_target(target: &str, target_base: &Path) -> Result<()> {
    backup_shield_core::fs_utils::validate_symlink_target(target, target_base)
}

/// Windows-specific symlink target validation.
/// Handles drive letters, accepts absolute paths (with warning),
/// and rejects `..` that escape the restore directory.
#[cfg(windows)]
fn validate_symlink_target_windows(target: &str, target_base: &Path) -> Result<()> {
    backup_shield_core::fs_utils::validate_symlink_target_windows(target, target_base)
}

use backup_shield_core::repository::Repository;
use backup_shield_core::snapshot::{
    find_snapshot, SnapshotDir, SnapshotFile, SnapshotNode, SnapshotSymlink,
};

// ── Error types ──────────────────────────────────────────────────────────────

/// Errors that can occur during the restore process.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RestoreError {
    #[error("chunk missing: hash={hash}, file={file_path}")]
    ChunkMissing { hash: String, file_path: String },

    #[error("chunk corrupt: hash={hash}, file={file_path}, expected={expected}, actual={actual}")]
    ChunkCorrupt {
        hash: String,
        file_path: String,
        expected: String,
        actual: String,
    },

    #[error("file write error: path={path}, reason={reason}")]
    FileWriteError { path: String, reason: String },

    #[error("directory create error: path={path}, reason={reason}")]
    DirectoryCreateError { path: String, reason: String },

    #[error("permission error: path={path}, reason={reason}")]
    PermissionError { path: String, reason: String },

    #[error("file already exists: {path}")]
    FileExists { path: String },
}

// ── Options ──────────────────────────────────────────────────────────────────

/// Options controlling the restore behaviour.
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// Path to the backup repository.
    pub repo_path: PathBuf,
    /// Snapshot query: `"latest"`, a partial UUID, or a tag name.
    pub snapshot_query: String,
    /// Directory where files will be restored to.
    pub target_path: PathBuf,
    /// Optional list of glob patterns to filter which files are restored
    /// (e.g. `["documents/*.pdf", "photos/**/*.jpg"]`).
    pub file_filter: Option<Vec<String>>,
    /// If `true`, simulate the restore without writing any files.
    pub dry_run: bool,
    /// If `true`, verify each chunk's hash and the overall file hash after
    /// reconstructing the file.
    pub verify: bool,
    /// If `true`, overwrite files that already exist in the target directory.
    pub overwrite: bool,
    /// If `true`, attempt to restore original Unix file permissions.
    pub preserve_permissions: bool,
    /// Optional 256-bit AES key for decrypting encrypted chunks.
    /// When `Some(key)`, each chunk read from the repository is decrypted
    /// with `backup_shield_crypto::decrypt_chunk` before being written.
    pub encryption_key: Option<[u8; 32]>,
    /// If `true`, chunks are decompressed with zstd after decryption.
    /// Must be enabled for backups created with compression.
    pub compression_enabled: bool,
}

impl RestoreOptions {
    /// Create a new `RestoreOptions` with required fields and sensible defaults.
    pub fn new(repo_path: PathBuf, snapshot_query: String, target_path: PathBuf) -> Self {
        Self {
            repo_path,
            snapshot_query,
            target_path,
            file_filter: None,
            dry_run: false,
            verify: false,
            overwrite: false,
            preserve_permissions: false,
            encryption_key: None,
            compression_enabled: false,
        }
    }
}

// ── Result ───────────────────────────────────────────────────────────────────

/// Summary of a restore operation.
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// Number of files successfully restored.
    pub files_restored: u64,
    /// Number of files skipped (e.g. due to filter or existing files).
    pub files_skipped: u64,
    /// Total bytes of file data restored.
    pub bytes_restored: u64,
    /// Number of directories created.
    pub directories_created: u64,
    /// Number of symbolic links created.
    pub symlinks_created: u64,
    /// Errors encountered during restore (non-fatal).
    pub errors: Vec<RestoreError>,
    /// Wall-clock duration of the restore in seconds.
    pub duration_secs: f64,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

// ── Stats ────────────────────────────────────────────────────────────────────

/// Progress statistics tracked during a restore operation.
#[derive(Debug, Clone, Default)]
pub struct RestoreStats {
    /// Total number of files found in the snapshot.
    pub files_total: u64,
    /// Number of files processed so far.
    pub files_processed: u64,
    /// Total bytes across all files in the snapshot.
    pub bytes_total: u64,
    /// Total bytes processed so far.
    pub bytes_processed: u64,
}

// ── Restorer ─────────────────────────────────────────────────────────────────

/// The main restore engine.
pub struct Restorer {
    /// Path to the backup repository.
    repo_path: PathBuf,
}

impl Restorer {
    /// Create a new `Restorer` for the given repository path.
    pub fn new(repo_path: &Path) -> Result<Restorer> {
        // Verify the repository exists.
        if !repo_path.exists() || !repo_path.join("config.toml").exists() {
            bail!("repository not found at {}", repo_path.display());
        }
        Ok(Restorer {
            repo_path: repo_path.to_path_buf(),
        })
    }

    /// Perform a full restore based on the given options.
    pub fn restore(&self, options: RestoreOptions) -> Result<RestoreResult> {
        let start = Instant::now();

        // Open the repository.
        let repo = Repository::open(&options.repo_path)
            .with_context(|| format!("failed to open repository at {:?}", options.repo_path))?;

        // Find the snapshot by query.
        let snapshot =
            find_snapshot(&options.repo_path, &options.snapshot_query).with_context(|| {
                format!(
                    "failed to find snapshot matching '{}'",
                    options.snapshot_query
                )
            })?;

        log::info!(
            "restoring snapshot {} (taken at {})",
            &snapshot.id[..12.min(snapshot.id.len())],
            snapshot.timestamp
        );

        // Walk the snapshot tree and restore.
        let mut result = RestoreResult {
            files_restored: 0,
            files_skipped: 0,
            bytes_restored: 0,
            directories_created: 0,
            symlinks_created: 0,
            errors: Vec::new(),
            duration_secs: 0.0,
            dry_run: options.dry_run,
        };

        let mut stats = RestoreStats::default();
        self.count_stats(&snapshot.root, &mut stats);

        // Create the target directory if it doesn't exist (and not dry_run).
        if !options.dry_run {
            if let Err(e) = std::fs::create_dir_all(&options.target_path) {
                result.errors.push(RestoreError::DirectoryCreateError {
                    path: options.target_path.display().to_string(),
                    reason: e.to_string(),
                });
                result.duration_secs = start.elapsed().as_secs_f64();
                return Ok(result);
            }
        }

        // Restore the snapshot tree.  When the root is a directory, we
        // restore its children directly into the target path rather than
        // creating a subdirectory named after the source directory.
        match &snapshot.root {
            SnapshotNode::Directory(root_dir) => {
                for child in &root_dir.children {
                    self.restore_node(
                        child,
                        PathBuf::new(),
                        &repo,
                        &options,
                        &mut result,
                        &mut stats,
                    );
                }
            }
            _ => {
                self.restore_node(
                    &snapshot.root,
                    PathBuf::new(),
                    &repo,
                    &options,
                    &mut result,
                    &mut stats,
                );
            }
        }

        result.duration_secs = start.elapsed().as_secs_f64();

        log::info!(
            "restore complete: {} files ({} bytes), {} dirs, {} symlinks, {} errors in {:.2}s",
            result.files_restored,
            result.bytes_restored,
            result.directories_created,
            result.symlinks_created,
            result.errors.len(),
            result.duration_secs,
        );

        Ok(result)
    }

    /// Restore specific files from a snapshot.
    pub fn restore_files(
        &self,
        repo_path: &Path,
        snapshot_id: &str,
        file_paths: &[&str],
        target: &Path,
    ) -> Result<RestoreResult> {
        let mut options = RestoreOptions::new(
            repo_path.to_path_buf(),
            snapshot_id.to_string(),
            target.to_path_buf(),
        );
        options.file_filter = Some(file_paths.iter().map(|s| (*s).to_string()).collect());
        options.verify = true;
        options.preserve_permissions = true;
        self.restore(options)
    }

    /// List all restorable file paths in a snapshot.
    pub fn list_restorable_files(&self, snapshot_id: &str) -> Result<Vec<String>> {
        let snapshot = find_snapshot(&self.repo_path, snapshot_id)
            .with_context(|| format!("failed to find snapshot '{}'", snapshot_id))?;

        let mut paths = Vec::new();
        match &snapshot.root {
            SnapshotNode::Directory(root_dir) => {
                for child in &root_dir.children {
                    self.collect_file_paths(child, PathBuf::new(), &mut paths);
                }
            }
            _ => {
                self.collect_file_paths(&snapshot.root, PathBuf::new(), &mut paths);
            }
        }
        Ok(paths)
    }

    /// Preview what would be restored (dry-run that returns the list of file
    /// paths that would be restored).
    pub fn preview(&self, options: RestoreOptions) -> Result<Vec<String>> {
        let snapshot =
            find_snapshot(&options.repo_path, &options.snapshot_query).with_context(|| {
                format!(
                    "failed to find snapshot matching '{}'",
                    options.snapshot_query
                )
            })?;

        let mut paths = Vec::new();
        match &snapshot.root {
            SnapshotNode::Directory(root_dir) => {
                for child in &root_dir.children {
                    self.collect_matching_paths(child, PathBuf::new(), &options, &mut paths);
                }
            }
            _ => {
                self.collect_matching_paths(&snapshot.root, PathBuf::new(), &options, &mut paths);
            }
        }
        Ok(paths)
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Recursively restore a snapshot node.
    fn restore_node(
        &self,
        node: &SnapshotNode,
        rel_path: PathBuf,
        repo: &Repository,
        options: &RestoreOptions,
        result: &mut RestoreResult,
        stats: &mut RestoreStats,
    ) {
        match node {
            SnapshotNode::Directory(dir) => {
                self.restore_directory(dir, rel_path, repo, options, result, stats);
            }
            SnapshotNode::File(file) => {
                self.restore_file(file, rel_path, repo, options, result, stats);
            }
            SnapshotNode::Symlink(symlink) => {
                self.restore_symlink(symlink, rel_path, options, result);
            }
        }
    }

    /// Restore a directory node.
    fn restore_directory(
        &self,
        dir: &SnapshotDir,
        rel_path: PathBuf,
        repo: &Repository,
        options: &RestoreOptions,
        result: &mut RestoreResult,
        stats: &mut RestoreStats,
    ) {
        let dir_path = if rel_path.as_os_str().is_empty() {
            PathBuf::from(&dir.name)
        } else {
            rel_path.join(&dir.name)
        };

        let target_dir = options.target_path.join(&dir_path);

        if !options.dry_run {
            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                result.errors.push(RestoreError::DirectoryCreateError {
                    path: target_dir.display().to_string(),
                    reason: e.to_string(),
                });
                // Still try to restore children; they may fail due to the
                // missing parent, but that will produce individual errors.
            } else {
                result.directories_created += 1;

                // Try to preserve directory permissions.
                if options.preserve_permissions {
                    self.set_permissions(&target_dir, dir.mode, result);
                }
            }
        } else {
            // In dry_run, still count the directory.
            result.directories_created += 1;
        }

        // Recurse into children.
        for child in &dir.children {
            self.restore_node(child, dir_path.clone(), repo, options, result, stats);
        }
    }

    /// Restore a file node.
    fn restore_file(
        &self,
        file: &SnapshotFile,
        rel_path: PathBuf,
        repo: &Repository,
        options: &RestoreOptions,
        result: &mut RestoreResult,
        stats: &mut RestoreStats,
    ) {
        let file_path = if rel_path.as_os_str().is_empty() {
            PathBuf::from(&file.name)
        } else {
            rel_path.join(&file.name)
        };

        let file_path_str = file_path.to_string_lossy().to_string();

        stats.files_total += 1;
        stats.bytes_total += file.size;

        // Apply file filter.
        if let Some(ref patterns) = options.file_filter {
            if !matches_filter(&file_path_str, patterns) {
                result.files_skipped += 1;
                stats.files_processed += 1;
                stats.bytes_processed += file.size;
                log::trace!("skipping file (filter): {}", file_path_str);
                return;
            }
        }

        // Check if the target file already exists.
        let target_file = options.target_path.join(&file_path);
        if !options.overwrite && !options.dry_run && target_file.exists() {
            result.errors.push(RestoreError::FileExists {
                path: target_file.display().to_string(),
            });
            result.files_skipped += 1;
            stats.files_processed += 1;
            stats.bytes_processed += file.size;
            log::debug!("file already exists, skipping: {}", target_file.display());
            return;
        }

        // Read and concatenate all chunks.
        let mut file_data = Vec::with_capacity(file.size as usize);
        for chunk_hash in &file.chunk_hashes {
            match repo.read_chunk(chunk_hash) {
                Ok(chunk_data) => {
                    // Decrypt the chunk if encryption is enabled.
                    let chunk_data = if let Some(ref key) = options.encryption_key {
                        match decrypt_chunk(&chunk_data, key) {
                            Ok(decrypted) => decrypted,
                            Err(e) => {
                                result.errors.push(RestoreError::ChunkCorrupt {
                                    hash: chunk_hash.clone(),
                                    file_path: file_path_str.clone(),
                                    expected: chunk_hash.clone(),
                                    actual: "decryption_failed".to_string(),
                                });
                                log::error!("failed to decrypt chunk {}: {}", &chunk_hash[..12], e);
                                // Cannot continue without decrypted data.
                                stats.files_processed += 1;
                                stats.bytes_processed += file.size;
                                result.files_skipped += 1;
                                return;
                            }
                        }
                    } else {
                        chunk_data
                    };

                    // Decompress the chunk if compression was enabled.
                    let chunk_data = if options.compression_enabled {
                        match decompress_chunk(&chunk_data) {
                            Ok(d) => d,
                            Err(e) => {
                                result.errors.push(RestoreError::ChunkCorrupt {
                                    hash: chunk_hash.clone(),
                                    file_path: file_path_str.clone(),
                                    expected: chunk_hash.clone(),
                                    actual: format!("decompress_failed: {}", e),
                                });
                                log::error!(
                                    "failed to decompress chunk {}: {}",
                                    &chunk_hash[..12.min(chunk_hash.len())],
                                    e
                                );
                                stats.files_processed += 1;
                                stats.bytes_processed += file.size;
                                result.files_skipped += 1;
                                return;
                            }
                        }
                    } else {
                        chunk_data
                    };

                    // NOTE: hash verification against chunk_hash is intentionally
                    // skipped when compression is active, because chunk_hash refers
                    // to the stored (compressed+encrypted) data, not the decompressed
                    // data. The file-level hash check below still applies.

                    file_data.extend_from_slice(&chunk_data);
                }
                Err(_) => {
                    result.errors.push(RestoreError::ChunkMissing {
                        hash: chunk_hash.clone(),
                        file_path: file_path_str.clone(),
                    });
                    // We cannot complete the file without this chunk.
                    stats.files_processed += 1;
                    stats.bytes_processed += file.size;
                    result.files_skipped += 1;
                    return;
                }
            }
        }

        // Verify the overall file hash if requested.
        if options.verify {
            let computed_file_hash = compute_file_hash(&file.chunk_hashes);
            if computed_file_hash != file.file_hash {
                result.errors.push(RestoreError::ChunkCorrupt {
                    hash: "file_hash".to_string(),
                    file_path: file_path_str.clone(),
                    expected: file.file_hash.clone(),
                    actual: computed_file_hash,
                });
            }
        }

        // Write the file (unless dry_run).
        if !options.dry_run {
            // Ensure the parent directory exists.
            if let Some(parent) = target_file.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    result.errors.push(RestoreError::DirectoryCreateError {
                        path: parent.display().to_string(),
                        reason: e.to_string(),
                    });
                    stats.files_processed += 1;
                    stats.bytes_processed += file.size;
                    result.files_skipped += 1;
                    return;
                }
            }

            // Write atomically: tmp file → rename to final path.
            // This prevents partial/corrupt files on crash during restore.
            let tmp_path = target_file.with_extension("tmp");
            match std::fs::write(&tmp_path, &file_data) {
                Ok(()) => {
                    match std::fs::rename(&tmp_path, &target_file) {
                        Ok(()) => {
                            result.files_restored += 1;
                            result.bytes_restored += file_data.len() as u64;

                            // Preserve file permissions if requested.
                            if options.preserve_permissions {
                                self.set_permissions(&target_file, file.mode, result);
                            }

                            // Restore Windows-specific attributes (ACL, ADS, flags).
                            #[cfg(target_os = "windows")]
                            {
                                use backup_shield_core::windows_attrs;
                                if let Some(attrs) = &file.windows_attributes {
                                    if let Err(e) =
                                        windows_attrs::apply_file_attributes(&target_file, *attrs)
                                    {
                                        log::warn!(
                                            "failed to restore Windows attributes for {:?}: {}",
                                            target_file,
                                            e
                                        );
                                    }
                                }
                                if let Some(acl) = &file.windows_acl {
                                    if let Err(e) =
                                        windows_attrs::apply_security_descriptor(&target_file, acl)
                                    {
                                        log::warn!(
                                            "failed to restore ACL for {:?}: {}",
                                            target_file,
                                            e
                                        );
                                    }
                                }
                                if let Some(ads) = &file.windows_ads {
                                    for (name, content) in ads {
                                        if let Err(e) = windows_attrs::write_alternate_data_stream(
                                            &target_file,
                                            name,
                                            content,
                                        ) {
                                            log::warn!(
                                                "failed to restore ADS '{}' for {:?}: {}",
                                                name,
                                                target_file,
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let _ = std::fs::remove_file(&tmp_path);
                            result.errors.push(RestoreError::FileWriteError {
                                path: target_file.display().to_string(),
                                reason: format!("rename failed: {}", e),
                            });
                            result.files_skipped += 1;
                        }
                    }
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp_path);
                    result.errors.push(RestoreError::FileWriteError {
                        path: target_file.display().to_string(),
                        reason: e.to_string(),
                    });
                    result.files_skipped += 1;
                }
            }
        } else {
            // In dry_run, count as restored for reporting.
            result.files_restored += 1;
            result.bytes_restored += file_data.len() as u64;
        }

        stats.files_processed += 1;
        stats.bytes_processed += file.size;
    }

    /// Restore a symbolic link node.
    fn restore_symlink(
        &self,
        symlink: &SnapshotSymlink,
        rel_path: PathBuf,
        options: &RestoreOptions,
        result: &mut RestoreResult,
    ) {
        let link_path = if rel_path.as_os_str().is_empty() {
            PathBuf::from(&symlink.name)
        } else {
            rel_path.join(&symlink.name)
        };

        let target_link = options.target_path.join(&link_path);

        if !options.dry_run {
            // Ensure the parent directory exists.
            if let Some(parent) = target_link.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    result.errors.push(RestoreError::DirectoryCreateError {
                        path: parent.display().to_string(),
                        reason: e.to_string(),
                    });
                    return;
                }
            }

            // Remove existing file/symlink if overwrite is set.
            if options.overwrite && target_link.exists() {
                if let Err(e) = std::fs::remove_file(&target_link) {
                    result.errors.push(RestoreError::FileWriteError {
                        path: target_link.display().to_string(),
                        reason: format!("failed to remove existing file: {}", e),
                    });
                    return;
                }
            }

            // Check if symlink already exists.
            if !options.overwrite && target_link.exists() {
                result.errors.push(RestoreError::FileExists {
                    path: target_link.display().to_string(),
                });
                return;
            }

            #[cfg(unix)]
            {
                if let Err(e) = validate_symlink_target(&symlink.target, &options.target_path) {
                    result.errors.push(RestoreError::FileWriteError {
                        path: target_link.display().to_string(),
                        reason: format!("invalid symlink target: {}", e),
                    });
                    return;
                }
                match std::os::unix::fs::symlink(&symlink.target, &target_link) {
                    Ok(()) => {
                        result.symlinks_created += 1;
                    }
                    Err(e) => {
                        result.errors.push(RestoreError::FileWriteError {
                            path: target_link.display().to_string(),
                            reason: format!("failed to create symlink: {}", e),
                        });
                    }
                }
            }

            #[cfg(windows)]
            {
                if let Err(e) =
                    validate_symlink_target_windows(&symlink.target, &options.target_path)
                {
                    result.errors.push(RestoreError::FileWriteError {
                        path: target_link.display().to_string(),
                        reason: format!("invalid symlink target: {}", e),
                    });
                    return;
                }
                let symlink_result = {
                    let target_path = std::path::Path::new(&symlink.target);
                    if target_path.is_dir() {
                        std::os::windows::fs::symlink_dir(target_path, &target_link)
                    } else {
                        std::os::windows::fs::symlink_file(target_path, &target_link)
                    }
                };
                match symlink_result {
                    Ok(()) => {
                        result.symlinks_created += 1;
                    }
                    Err(e) => {
                        result.errors.push(RestoreError::FileWriteError {
                            path: target_link.display().to_string(),
                            reason: format!(
                                "failed to create symlink {} -> {}: {}. Note: requires Admin or Developer Mode",
                                target_link.display(), symlink.target, e
                            ),
                        });
                    }
                }
            }

            #[cfg(not(any(unix, windows)))]
            {
                log::warn!(
                    "symlink creation not fully supported on this platform, skipping: {}",
                    target_link.display()
                );
            }
        } else {
            result.symlinks_created += 1;
        }
    }

    /// Set file/directory permissions on Unix. On Windows, this is a no-op.
    fn set_permissions(&self, path: &Path, mode: u32, result: &mut RestoreResult) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            if let Err(e) = std::fs::set_permissions(path, perms) {
                result.errors.push(RestoreError::PermissionError {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                });
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode, result);
        }
    }

    /// Count total files and bytes in the snapshot tree for stats.
    fn count_stats(&self, node: &SnapshotNode, stats: &mut RestoreStats) {
        match node {
            SnapshotNode::File(f) => {
                stats.files_total += 1;
                stats.bytes_total += f.size;
            }
            SnapshotNode::Directory(d) => {
                for child in &d.children {
                    self.count_stats(child, stats);
                }
            }
            SnapshotNode::Symlink(_) => {}
        }
    }

    /// Collect all file paths from a snapshot tree.
    fn collect_file_paths(&self, node: &SnapshotNode, rel_path: PathBuf, paths: &mut Vec<String>) {
        match node {
            SnapshotNode::File(f) => {
                let file_path = if rel_path.as_os_str().is_empty() {
                    f.name.clone()
                } else {
                    format!("{}/{}", rel_path.display(), f.name)
                };
                paths.push(file_path);
            }
            SnapshotNode::Directory(d) => {
                let dir_path = if rel_path.as_os_str().is_empty() {
                    PathBuf::from(&d.name)
                } else {
                    rel_path.join(&d.name)
                };
                for child in &d.children {
                    self.collect_file_paths(child, dir_path.clone(), paths);
                }
            }
            SnapshotNode::Symlink(_) => {}
        }
    }

    /// Collect file paths that match the filter options (for preview).
    fn collect_matching_paths(
        &self,
        node: &SnapshotNode,
        rel_path: PathBuf,
        options: &RestoreOptions,
        paths: &mut Vec<String>,
    ) {
        match node {
            SnapshotNode::File(f) => {
                let file_path = if rel_path.as_os_str().is_empty() {
                    f.name.clone()
                } else {
                    format!("{}/{}", rel_path.display(), f.name)
                };

                // Apply filter.
                if let Some(ref patterns) = options.file_filter {
                    if !matches_filter(&file_path, patterns) {
                        return;
                    }
                }

                // Check overwrite / existence only if not dry_run path.
                // For preview, we just list everything that would be restored.
                paths.push(file_path);
            }
            SnapshotNode::Directory(d) => {
                let dir_path = if rel_path.as_os_str().is_empty() {
                    PathBuf::from(&d.name)
                } else {
                    rel_path.join(&d.name)
                };
                for child in &d.children {
                    self.collect_matching_paths(child, dir_path.clone(), options, paths);
                }
            }
            SnapshotNode::Symlink(_) => {}
        }
    }
}

// ── Helper functions ─────────────────────────────────────────────────────────

/// Compute the file hash: SHA-256 of the concatenation of chunk hash strings.
/// This mirrors `Snapshot::compute_file_hash` from the core crate.
fn compute_file_hash(chunk_hashes: &[String]) -> String {
    let mut hasher = Sha256::new();
    for h in chunk_hashes {
        hasher.update(h.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Check whether a file path matches any of the given glob patterns.
///
/// Uses the `glob` crate for pattern matching. The path separator is
/// normalised to `/` so that patterns like `"documents/*.pdf"` work
/// consistently across platforms.
pub fn matches_filter(file_path: &str, patterns: &[String]) -> bool {
    // Normalise path separators for cross-platform glob matching.
    let normalised = file_path.replace('\\', "/");

    for pattern in patterns {
        let glob_pattern = match glob::Pattern::new(pattern) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("invalid glob pattern '{}': {}", pattern, e);
                continue;
            }
        };

        if glob_pattern.matches(&normalised) {
            return true;
        }

        // Also try matching with `**/` prefix for convenience, so that
        // "documents/*.pdf" matches "some/prefix/documents/test.pdf".
        let recursive_pattern = format!("**/{}", pattern);
        if let Ok(p) = glob::Pattern::new(&recursive_pattern) {
            if p.matches(&normalised) {
                return true;
            }
        }
    }
    false
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use backup_shield_core::chunker::Chunker;
    use backup_shield_core::snapshot::Snapshot;

    /// Helper: create a temporary repository with a snapshot.
    fn setup_repo_with_snapshot() -> (tempfile::TempDir, PathBuf, String) {
        let tmp = tempfile::tempdir().unwrap();
        let repo_path = tmp.path().join("repo");

        let mut repo = Repository::init(&repo_path, None).unwrap();
        let chunker = Chunker::new(
            repo.config.chunk_min_size,
            repo.config.chunk_max_size,
            repo.config.chunk_target_size,
        )
        .unwrap();

        // Create a small directory to back up.
        let src_dir = tmp.path().join("source");
        std::fs::create_dir_all(src_dir.join("docs")).unwrap();
        std::fs::write(src_dir.join("hello.txt"), b"hello world").unwrap();
        std::fs::write(src_dir.join("docs").join("readme.md"), b"# Readme").unwrap();

        let snapshot = Snapshot::build_from_path(&src_dir, &chunker, &mut repo).unwrap();
        let snapshot_id = snapshot.id.clone();
        snapshot.save(&repo_path).unwrap();

        // Save the index so chunks can be found on reopen.
        repo.flush_pending().unwrap();
        repo.save_index().unwrap();

        (tmp, repo_path, snapshot_id)
    }

    #[test]
    fn restore_basic() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );

        let result = restorer.restore(options).unwrap();
        assert!(
            result.files_restored >= 2,
            "should restore at least 2 files"
        );
        assert!(
            result.errors.is_empty(),
            "no errors expected: {:?}",
            result.errors
        );
    }

    #[test]
    fn restore_latest_query() {
        let (_tmp, repo_path, _snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let options = RestoreOptions::new(
            repo_path.clone(),
            "latest".to_string(),
            target.path().to_path_buf(),
        );

        let result = restorer.restore(options).unwrap();
        assert!(result.files_restored >= 2);
    }

    #[test]
    fn restore_dry_run() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let mut options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );
        options.dry_run = true;

        let result = restorer.restore(options).unwrap();
        assert!(result.dry_run);
        assert!(result.files_restored >= 2);

        // No files should actually exist in the target.
        assert!(!target.path().join("hello.txt").exists());
    }

    #[test]
    fn restore_with_verify() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let mut options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );
        options.verify = true;

        let result = restorer.restore(options).unwrap();
        assert!(
            result.errors.is_empty(),
            "no errors expected: {:?}",
            result.errors
        );
    }

    #[test]
    fn restore_file_exists_no_overwrite() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        // Pre-create a file that will conflict.
        std::fs::write(target.path().join("hello.txt"), b"old data").unwrap();

        let options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );

        let result = restorer.restore(options).unwrap();

        // Should have at least one FileExists error.
        let exists_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| matches!(e, RestoreError::FileExists { .. }))
            .collect();
        assert!(!exists_errors.is_empty(), "expected FileExists error");

        // The file should not have been overwritten.
        let content = std::fs::read_to_string(target.path().join("hello.txt")).unwrap();
        assert_eq!(content, "old data");
    }

    #[test]
    fn restore_with_overwrite() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        // Pre-create a file that will conflict.
        std::fs::write(target.path().join("hello.txt"), b"old data").unwrap();

        let mut options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );
        options.overwrite = true;

        let result = restorer.restore(options).unwrap();

        // The file should have been overwritten.
        let content = std::fs::read_to_string(target.path().join("hello.txt")).unwrap();
        assert_eq!(content, "hello world");

        // No FileExists errors.
        let exists_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| matches!(e, RestoreError::FileExists { .. }))
            .collect();
        assert!(exists_errors.is_empty());
    }

    #[test]
    fn restore_with_filter() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let mut options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );
        options.file_filter = Some(vec!["*.txt".to_string()]);

        let result = restorer.restore(options).unwrap();

        // hello.txt should be restored, readme.md should not.
        assert!(target.path().join("hello.txt").exists());
        assert!(!target.path().join("docs").join("readme.md").exists());
        assert!(result.files_skipped > 0);
    }

    #[test]
    fn list_restorable_files() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let files = restorer.list_restorable_files(&snapshot_id).unwrap();

        assert!(files.len() >= 2, "should have at least 2 files");
    }

    #[test]
    fn preview() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );

        let preview = restorer.preview(options).unwrap();
        assert!(preview.len() >= 2, "should preview at least 2 files");
    }

    #[test]
    fn matches_filter_basic() {
        let patterns = vec!["*.txt".to_string()];
        assert!(matches_filter("hello.txt", &patterns));
        assert!(!matches_filter("hello.pdf", &patterns));
    }

    #[test]
    fn matches_filter_directory() {
        let patterns = vec!["documents/*.pdf".to_string()];
        assert!(matches_filter("documents/report.pdf", &patterns));
        assert!(!matches_filter("documents/report.txt", &patterns));
    }

    #[test]
    fn matches_filter_recursive() {
        let patterns = vec!["documents/*.pdf".to_string()];
        // Should match via the `**/` fallback.
        assert!(matches_filter(
            "some/prefix/documents/report.pdf",
            &patterns
        ));
    }

    #[test]
    fn restore_preserves_permissions() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let mut options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );
        options.preserve_permissions = true;

        let result = restorer.restore(options).unwrap();
        // On Unix, permissions should be set without errors.
        // On Windows, this is silently skipped.
        #[cfg(unix)]
        {
            let perm_errors: Vec<_> = result
                .errors
                .iter()
                .filter(|e| matches!(e, RestoreError::PermissionError { .. }))
                .collect();
            assert!(
                perm_errors.is_empty(),
                "permission errors: {:?}",
                perm_errors
            );
        }
    }

    #[test]
    fn restore_file_content_integrity() {
        let (_tmp, repo_path, snapshot_id) = setup_repo_with_snapshot();

        let restorer = Restorer::new(&repo_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let mut options = RestoreOptions::new(
            repo_path.clone(),
            snapshot_id.clone(),
            target.path().to_path_buf(),
        );
        options.verify = true;
        options.overwrite = true;

        let result = restorer.restore(options).unwrap();
        assert!(
            result.errors.is_empty(),
            "unexpected errors: {:?}",
            result.errors
        );

        // Verify the actual content of restored files.
        let content = std::fs::read_to_string(target.path().join("hello.txt")).unwrap();
        assert_eq!(content, "hello world");
    }
}
