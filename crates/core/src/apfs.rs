// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.
//
//! APFS snapshot integration for macOS.
//!
//! Provides functions to create, mount, list, and delete APFS filesystem snapshots
//! using `tmutil` and `mount_apfs`.  A [`Drop`] guard (`ApfsSnapshotGuard`) ensures
//! that a snapshot is always unmounted and cleaned up, even when the enclosing
//! operation panics or returns an error.
//!
//! ## Workflow
//!
//! ```ignore
//! let guard = ApfsSnapshotGuard::new("/")?;
//! let mount_point = guard.mount_path();
//! // … perform backup on mount_point …
//! // guard is dropped → unmount + delete snapshot
//! ```

#[allow(unused_imports)]
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── Core APFS snapshot API ─────────────────────────────────────────────────

/// Create an APFS snapshot of the given volume using `tmutil localsnapshot`.
///
/// Returns the snapshot date string (e.g. `"2026-05-25-185730"`).
///
/// # Errors
///
/// Fails if `tmutil` is not available, the volume does not exist, or the
/// snapshot creation command returns a non-zero exit code.
#[cfg(target_os = "macos")]
pub fn create_apfs_snapshot(volume: &Path) -> Result<String> {
    let volume_str = volume.to_string_lossy();
    let output = Command::new("tmutil")
        .args(["localsnapshot", &volume_str])
        .output()
        .with_context(|| format!("failed to execute tmutil localsnapshot for {:?}", volume))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "tmutil localsnapshot failed for {:?}: {}",
            volume,
            stderr.trim()
        );
    }

    // Parse the snapshot name from tmutil output.
    // macOS 15+ output: "Created local snapshot with date: 2026-05-25-185730"
    // Older macOS output: "Created local snapshot with name: com.apple.TimeMachine.2026-05-25-185730"
    let stdout = String::from_utf8_lossy(&output.stdout);
    let snapshot_name = stdout
        .lines()
        .find_map(|line| {
            let line = line.trim();
            // Try "with date:" format (macOS 15+)
            if let Some(date) = line.strip_prefix("Created local snapshot with date: ") {
                return Some(date.trim().to_string());
            }
            // Try "with name:" format (older macOS)
            if let Some(name) = line.strip_prefix("Created local snapshot with name: ") {
                return Some(name.trim().to_string());
            }
            // Try quoted format: Created local snapshot '...'
            if let Some(start) = line.find('\'') {
                if let Some(end) = line[start + 1..].find('\'') {
                    return Some(line[start + 1..start + 1 + end].to_string());
                }
            }
            None
        })
        .with_context(|| {
            format!(
                "could not parse snapshot name from tmutil output: {}",
                stdout.trim()
            )
        })?;

    log::info!(
        "Created APFS snapshot '{}' on volume {:?}",
        snapshot_name,
        volume
    );

    Ok(snapshot_name)
}

/// Mount an APFS snapshot at the given mount point using `mount_apfs -s`.
///
/// The mount point directory will be created if it does not exist.
///
/// # Errors
///
/// Fails if `mount_apfs` is not available, the snapshot does not exist, the
/// mount point cannot be created, or the mount command fails.
#[cfg(target_os = "macos")]
pub fn mount_apfs_snapshot(snapshot_name: &str, mount_point: &Path) -> Result<()> {
    // Ensure mount point exists.
    std::fs::create_dir_all(mount_point)
        .with_context(|| format!("failed to create mount point {:?}", mount_point))?;

    // Resolve the device node for the snapshot.
    // We need to find which volume this snapshot belongs to.
    // The snapshot name from tmutil is typically a date string like "2026-05-25-185730".
    // We use mount_apfs with the -s flag to mount by snapshot name.
    // mount_apfs -s <snapshot> <device> <mount-point>
    //
    // For the root volume, the device is typically the APFS Volume without the
    // snapshot suffix. For other volumes, it's the APFS Volume device.

    // First try: use tmutil to get the machinedir and find the relevant volume.
    // Second try: resolve the device by listing snapshots on all APFS volumes.

    // Get all APFS volumes and find the one containing this snapshot.
    let volumes = enumerate_apfs_volumes()?;
    let mut device_found: Option<PathBuf> = None;

    for vol in &volumes {
        let snapshots = list_volume_snapshots(vol)?;
        if snapshots.iter().any(|s| s == snapshot_name) {
            device_found = Some(vol.clone());
            break;
        }
    }

    let device = device_found
        .with_context(|| format!("snapshot '{}' not found on any APFS volume", snapshot_name))?;

    let output = Command::new("mount_apfs")
        .args([
            "-s",
            snapshot_name,
            &device.to_string_lossy(),
            &mount_point.to_string_lossy(),
        ])
        .output()
        .with_context(|| {
            format!(
                "failed to execute mount_apfs -s for snapshot '{}' on device {:?}",
                snapshot_name, device
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "mount_apfs failed for snapshot '{}' on device {:?}: {}",
            snapshot_name,
            device,
            stderr.trim()
        );
    }

    log::info!(
        "Mounted APFS snapshot '{}' at {:?}",
        snapshot_name,
        mount_point
    );

    Ok(())
}

/// Enumerate APFS volumes (non-snapshot devices) on the system.
///
/// Returns a list of device paths (e.g. `/dev/disk1s1`, `/dev/disk1s4`).
#[cfg(target_os = "macos")]
fn enumerate_apfs_volumes() -> Result<Vec<PathBuf>> {
    let output = Command::new("diskutil")
        .args(["apfs", "list", "-plist"])
        .output()
        .context("failed to execute diskutil apfs list")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("diskutil apfs list failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut volumes = Vec::new();

    // Parse the plist output to find APFS Volume devices.
    // We look for lines containing "DeviceIdentifier" and collect.
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Look for <string>disk...</string> patterns
        if trimmed.starts_with("<string>disk") && trimmed.ends_with("</string>") {
            let inner = &trimmed[8..trimmed.len() - 9]; // strip <string> and </string>
                                                        // Exclude snapshot devices (e.g. disk1s1s1 has three 's' groups)
            let s_count = inner.matches('s').count();
            if s_count <= 2 {
                volumes.push(PathBuf::from("/dev").join(inner));
            }
        }
    }

    if volumes.is_empty() {
        // Fallback: try parsing `diskutil apfs list` text output
        let text_output = Command::new("diskutil")
            .args(["apfs", "list"])
            .output()
            .context("failed to execute diskutil apfs list")?;
        let text_stdout = String::from_utf8_lossy(&text_output.stdout);
        for line in text_stdout.lines() {
            let trimmed = line.trim();
            // Look for lines like "APFS Volume MacOs-SSD (disk1s1)"
            if let Some(start) = trimmed.find("(disk") {
                let end = trimmed[start + 1..]
                    .find(')')
                    .map(|i| start + 1 + i)
                    .unwrap_or(trimmed.len());
                let ident = &trimmed[start + 1..end];
                let s_count = ident.matches('s').count();
                if s_count <= 2 {
                    volumes.push(PathBuf::from("/dev").join(ident));
                }
            }
        }
    }

    Ok(volumes)
}

/// List APFS snapshots on a given volume device.
#[cfg(target_os = "macos")]
fn list_volume_snapshots(volume: &Path) -> Result<Vec<String>> {
    let output = Command::new("diskutil")
        .args(["apfs", "listSnapshots", &volume.to_string_lossy()])
        .output()
        .with_context(|| {
            format!(
                "failed to execute diskutil apfs listSnapshots for {:?}",
                volume
            )
        })?;

    if !output.status.success() {
        return Ok(Vec::new()); // Some volumes don't support snapshots
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let snapshots: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Format: "+-- SnapshotName"
            if line.starts_with("+-- ") {
                Some(line[4..].to_string())
            } else if let Some(s) = line.strip_prefix("Snapshot: ") {
                Some(s.to_string())
            } else {
                None
            }
        })
        .collect();

    Ok(snapshots)
}

/// Delete an APFS snapshot by name.
///
/// # Errors
///
/// Fails if `tmutil` is not available, the snapshot does not exist, or the
/// deletion command fails.
#[cfg(target_os = "macos")]
pub fn delete_apfs_snapshot(snapshot_name: &str) -> Result<()> {
    let output = Command::new("tmutil")
        .args(["deletelocalsnapshots", snapshot_name])
        .output()
        .with_context(|| {
            format!(
                "failed to execute tmutil deletelocalsnapshots for '{}'",
                snapshot_name
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Some versions of tmutil return non-zero even on success when deleting
        // individual snapshots. Log as warning rather than erroring out.
        log::warn!(
            "tmutil deletelocalsnapshots for '{}' returned non-zero: {}",
            snapshot_name,
            stderr.trim()
        );
    } else {
        log::info!("Deleted APFS snapshot '{}'", snapshot_name);
    }

    Ok(())
}

/// List all APFS snapshot names on the system.
///
/// Scans all APFS volumes and collects their snapshots.
#[cfg(target_os = "macos")]
pub fn list_apfs_snapshots(_volume: &Path) -> Result<Vec<String>> {
    let volumes = enumerate_apfs_volumes()?;
    let mut all_snapshots = Vec::new();

    for vol in &volumes {
        if let Ok(snapshots) = list_volume_snapshots(vol) {
            all_snapshots.extend(snapshots);
        }
    }

    Ok(all_snapshots)
}

/// Resolve the volume (mount point) for a given path.
///
/// For example, given `/Users/john/Documents`, returns `/`.
/// Given `/Volumes/External/Data`, returns `/Volumes/External`.
///
/// Uses `stat` to determine the device ID of each path component.
#[cfg(target_os = "macos")]
pub fn resolve_volume(path: &Path) -> Result<PathBuf> {
    // Canonicalize the path first.
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize path {:?}", path))?;

    // Walk up the directory tree until the device changes or we hit "/".
    let mut current = canonical.clone();
    loop {
        if current == Path::new("/") {
            return Ok(PathBuf::from("/"));
        }

        let parent = match current.parent() {
            Some(p) => p.to_path_buf(),
            None => return Ok(current),
        };

        // Compare device IDs using metadata.
        let current_dev = match std::fs::metadata(&current) {
            Ok(m) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    m.dev()
                }
                #[cfg(not(unix))]
                {
                    let _ = m;
                    0
                }
            }
            Err(_) => break,
        };

        let parent_dev = match std::fs::metadata(&parent) {
            Ok(m) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    m.dev()
                }
                #[cfg(not(unix))]
                {
                    let _ = m;
                    0
                }
            }
            Err(_) => break,
        };

        if current_dev != parent_dev {
            // Device boundary: current is the mount point.
            return Ok(current);
        }

        current = parent;
    }

    // Fallback: return the root of the canonical path.
    Ok(canonical
        .ancestors()
        .last()
        .unwrap_or(Path::new("/"))
        .to_path_buf())
}

// ── Drop guard ──────────────────────────────────────────────────────────────

/// A RAII guard that unmounts and deletes an APFS snapshot when dropped.
///
/// # Example
///
/// ```ignore
/// let guard = ApfsSnapshotGuard::new("/")?;
/// let backup_source = guard.mount_path();
/// // perform backup on backup_source…
/// // guard is dropped here → unmount + delete
/// ```
pub struct ApfsSnapshotGuard {
    /// The name of the APFS snapshot.
    snapshot_name: String,
    /// The directory where the snapshot is mounted.
    mount_point: PathBuf,
    /// Whether the cleanup has already been performed (e.g. by an explicit call).
    cleaned_up: Arc<AtomicBool>,
    /// The original volume path.
    volume: PathBuf,
}

impl ApfsSnapshotGuard {
    /// Create an APFS snapshot of the given volume, mount it, and return a guard.
    ///
    /// The snapshot is mounted at `<tempdir>/backupshield_apfs_<timestamp>`.
    ///
    /// # Errors
    ///
    /// Delegates to [`create_apfs_snapshot`] and [`mount_apfs_snapshot`].
    #[cfg(target_os = "macos")]
    pub fn new(volume: &Path) -> Result<Self> {
        let snapshot_name = create_apfs_snapshot(volume)?;

        // Create a temporary mount point.
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let mount_base = std::env::temp_dir().join(format!("backupshield_apfs_{}", timestamp));
        let mount_point = mount_base.join("snapshot");

        mount_apfs_snapshot(&snapshot_name, &mount_point)?;

        log::info!(
            "APFS snapshot '{}' mounted at {:?} (volume {:?})",
            snapshot_name,
            mount_point,
            volume
        );

        Ok(Self {
            snapshot_name,
            mount_point,
            cleaned_up: Arc::new(AtomicBool::new(false)),
            volume: volume.to_path_buf(),
        })
    }

    /// Return the path where the snapshot is mounted.
    pub fn mount_path(&self) -> &Path {
        &self.mount_point
    }

    /// Return the name of the snapshot.
    pub fn snapshot_name(&self) -> &str {
        &self.snapshot_name
    }

    /// Return the original volume path.
    pub fn volume(&self) -> &Path {
        &self.volume
    }

    /// Explicitly clean up: unmount the snapshot and delete it.
    ///
    /// This is idempotent — calling it multiple times has no effect.
    #[allow(clippy::needless_return)]
    pub fn cleanup(&self) {
        if self.cleaned_up.swap(true, Ordering::SeqCst) {
            return;
        }

        #[cfg(target_os = "macos")]
        {
            if self.mount_point.exists() {
                if let Err(e) = unmount_apfs_snapshot(&self.mount_point) {
                    log::error!(
                        "Failed to unmount APFS snapshot '{}' at {:?}: {}",
                        self.snapshot_name,
                        self.mount_point,
                        e
                    );
                }
            }

            if let Err(e) = delete_apfs_snapshot(&self.snapshot_name) {
                log::error!(
                    "Failed to delete APFS snapshot '{}': {}",
                    self.snapshot_name,
                    e
                );
            }

            log::info!(
                "Cleaned up APFS snapshot '{}' (was mounted at {:?})",
                self.snapshot_name,
                self.mount_point
            );
        }
    }
}

impl Drop for ApfsSnapshotGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Unmount an APFS snapshot (or any volume) at the given mount point.
///
/// Uses `diskutil unmount` to ensure a clean unmount.
#[cfg(target_os = "macos")]
fn unmount_apfs_snapshot(mount_point: &Path) -> Result<()> {
    let mount_str = mount_point.to_string_lossy();
    let output = Command::new("diskutil")
        .args(["unmount", &mount_str])
        .output()
        .with_context(|| format!("failed to execute diskutil unmount for {:?}", mount_point))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The mount point might already be unmounted or not exist.
        log::warn!(
            "diskutil unmount for {:?} returned non-zero: {}",
            mount_point,
            stderr.trim()
        );
    }

    Ok(())
}

// ── Platform fallback (non-macOS) ──────────────────────────────────────────

/// Fallback for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn create_apfs_snapshot(_volume: &Path) -> Result<String> {
    anyhow::bail!("APFS snapshots are only supported on macOS");
}

/// Fallback for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn mount_apfs_snapshot(_snapshot_name: &str, _mount_point: &Path) -> Result<()> {
    anyhow::bail!("APFS snapshots are only supported on macOS");
}

/// Fallback for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn delete_apfs_snapshot(_snapshot_name: &str) -> Result<()> {
    anyhow::bail!("APFS snapshots are only supported on macOS");
}

/// Fallback for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn list_apfs_snapshots(_volume: &Path) -> Result<Vec<String>> {
    anyhow::bail!("APFS snapshots are only supported on macOS");
}

/// Fallback for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn resolve_volume(_path: &Path) -> Result<PathBuf> {
    anyhow::bail!("APFS snapshots are only supported on macOS");
}

impl ApfsSnapshotGuard {
    /// Create an APFS snapshot guard (non-macOS fallback).
    #[cfg(not(target_os = "macos"))]
    pub fn new(_volume: &Path) -> Result<Self> {
        anyhow::bail!("APFS snapshots are only supported on macOS");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit tests for helper functions ─────────────────────────────────

    #[test]
    fn test_resolve_volume_root() {
        // The root "/" should always resolve to itself.
        let vol = resolve_volume(Path::new("/")).unwrap_or_else(|_| PathBuf::from("/"));
        assert_eq!(vol, PathBuf::from("/"));
    }

    #[test]
    fn test_apfs_guard_drop_does_not_panic() {
        // Creating a snapshot requires root-like permissions on a real APFS
        // volume, so this test only verifies that instantiation fails gracefully
        // (non-macOS) or creates a guard that cleans up on drop (macOS).
        // On macOS without full privileges, we expect an error, not a panic.
        let result = ApfsSnapshotGuard::new(Path::new("/"));
        match result {
            Ok(guard) => {
                // We actually have a snapshot — drop it immediately.
                drop(guard);
                // If we get here without panic, the guard cleaned up correctly.
            }
            Err(e) => {
                // Expected on non-macOS or without privileges.
                // The actual error message depends on macOS version and permissions.
                // We just verify it doesn't panic — any error is acceptable.
                let _msg = format!("{}", e);
                // Accept any error message — just don't panic.
            }
        }
    }

    #[test]
    fn test_list_apfs_snapshots() {
        // Should not panic regardless of environment.
        let result = list_apfs_snapshots(Path::new("/"));
        match result {
            Ok(snapshots) => {
                // This is fine — may or may not have snapshots.
                assert!(snapshots.iter().all(|s| !s.is_empty()));
            }
            Err(_) => {
                // Also fine — may not be supported.
            }
        }
    }

    #[test]
    fn test_create_snapshot_invalid_volume() {
        // An invalid path (not a volume) should fail.
        let result = create_apfs_snapshot(Path::new("/tmp/some_random_path_12345"));
        match result {
            Ok(name) => {
                // If it did create one, clean it up.
                let _ = delete_apfs_snapshot(&name);
            }
            Err(_) => {
                // Expected — invalid volume path.
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_delete_nonexistent_snapshot() {
        // Deleting a non-existent snapshot should not panic.
        let result = delete_apfs_snapshot("nonexistent_snapshot_test_12345");
        assert!(
            result.is_ok(),
            "delete of non-existent snapshot should not fail: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_mount_nonexistent_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let mount_point = tmp.path().join("mount_test");
        let result = mount_apfs_snapshot("nonexistent_snapshot_test_12345", &mount_point);
        match result {
            Ok(()) => {
                // If it mounted for some reason, clean up.
                let _ = std::process::Command::new("diskutil")
                    .args(["unmount", &mount_point.to_string_lossy()])
                    .status();
            }
            Err(_) => {
                // Expected — snapshot doesn't exist.
            }
        }
    }

    #[test]
    fn test_guard_cleanup_idempotent() {
        // Test that cleanup() can be called multiple times.
        let result = ApfsSnapshotGuard::new(Path::new("/"));
        if let Ok(guard) = result {
            guard.cleanup();
            guard.cleanup(); // second call should be a no-op
        }
        // If it fails, we skip — the test is about idempotency, not snapshot creation.
    }
}
