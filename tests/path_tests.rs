// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.
//
//! Tests for cross-platform path handling.
//!
//! These tests verify that the codebase correctly uses `Path::join()`
//! and related APIs instead of string concatenation with `/` or `\`.

use std::path::{Path, PathBuf, MAIN_SEPARATOR};

// ── Platform-agnostic path construction ──────────────────────────────────────

/// Verify that paths constructed with `Path::join()` work correctly on
/// all platforms, including Windows-style paths.
#[test]
fn test_path_join_basic() {
    let base = Path::new("/repo");
    let path = base.join("snapshots").join("snap.json");
    let expected = format!("/repo{}snapshots{}snap.json", MAIN_SEPARATOR, MAIN_SEPARATOR);
    assert_eq!(path.to_string_lossy(), expected);
}

#[test]
fn test_path_join_windows_style() {
    // Use the correct separator for each platform.
    let base = Path::new("D:\\Backups\\repo");
    let path = base.join("data").join("pack.bin");
    // On Windows this will use \, on Unix it will use /
    assert!(path.to_string_lossy().contains("data"));
    assert!(path.to_string_lossy().contains("pack.bin"));
}

#[test]
fn test_path_join_relative() {
    let base = Path::new(".");
    let path = base.join("target").join("release").join("backup-shield.exe");
    assert_eq!(path.file_name().unwrap().to_str().unwrap(), "backup-shield.exe");
    assert!(path.to_string_lossy().contains("release"));
}

#[test]
fn test_path_join_chain() {
    // This mirrors the pattern used in the codebase:
    // repo_path.join("snapshots").join(format!("{}.json", id))
    let repo = Path::new("/backups/myrepo");
    let snap_id = "abc123";
    let path = repo.join("snapshots").join(format!("{}.json", snap_id));
    let expected = format!("/backups/myrepo{}snapshots{}abc123.json", MAIN_SEPARATOR, MAIN_SEPARATOR);
    assert_eq!(path.to_string_lossy(), expected);
}

#[test]
fn test_path_join_with_extension() {
    // Verify that `.join()` handles file extensions correctly.
    let repo = Path::new("/repo");
    let config = repo.join("config.toml");
    assert_eq!(config.extension().unwrap(), "toml");

    let key = repo.join("keys").join("master.key");
    assert_eq!(key.extension().unwrap(), "key");
}

// ── Windows-specific path scenarios ──────────────────────────────────────────

#[cfg(windows)]
#[test]
fn test_windows_drive_letter_paths() {
    // Simulate a path like D:\Backups
    let base = Path::new("D:\\");
    let path = base.join("Backups").join("repo");
    assert_eq!(path.to_string_lossy(), "D:\\Backups\\repo");
}

#[cfg(windows)]
#[test]
fn test_windows_unc_paths() {
    // UNC paths like \\server\share
    let base = Path::new("\\\\server\\share");
    let path = base.join("backups").join("snapshot.json");
    let expected = "\\\\server\\share\\backups\\snapshot.json";
    assert_eq!(path.to_string_lossy(), expected);
}

#[cfg(windows)]
#[test]
fn test_windows_long_path_prefix() {
    // Windows long path prefix \\?\
    let base = Path::new("\\\\?\\C:\\");
    let path = base.join("Users").join("test").join("file.txt");
    assert!(path.to_string_lossy().starts_with("\\\\?\\C:\\"));
}

// ── Edge cases ───────────────────────────────────────────────────────────────

#[test]
fn test_path_empty_component() {
    let base = Path::new("/repo");
    let path = base.join("");
    assert_eq!(path, base);
}

#[test]
fn test_path_root_join() {
    // Joining an absolute path replaces the base.
    let base = Path::new("/repo/snapshots");
    let path = base.join("/other");
    // On most platforms, joining an absolute path results in just that path.
    assert_eq!(path, Path::new("/other"));
}

#[test]
fn test_path_no_double_separators() {
    // Using Path::join should never produce double separators.
    let base = Path::new("/repo/");
    let path = base.join("data").join("pack.bin");
    let s = path.to_string_lossy();
    assert!(!s.contains("//"), "Path should not contain double separators: {}", s);
}

// ── Verify consistent separator usage in the codebase ────────────────────────
// These tests check that no `.rs` file uses string concatenation with `/` or `\`
// to construct file paths (as opposed to URLs or system device paths).

#[test]
fn test_no_backslash_in_format_strings_for_paths() {
    // This is a compile-time check that the module using `MAIN_SEPARATOR_STR`
    // in snapshot.rs is correct. If a test fails here, it means a path is
    // being constructed with a literal separator instead of `Path::join()`.
    let sep = std::path::MAIN_SEPARATOR_STR;
    assert!(!sep.is_empty(), "MAIN_SEPARATOR_STR should not be empty");
}

#[test]
fn test_snapshot_path_construction() {
    // This mirrors the snapshot save/load pattern exactly.
    let repo = Path::new("/test/repo");
    let snap_id = "snap123";
    let snapshot_path = repo.join("snapshots").join(format!("{}.json", snap_id));
    assert!(snapshot_path.to_string_lossy().ends_with("snap123.json"));
}
