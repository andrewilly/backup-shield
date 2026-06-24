// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! Filesystem utility functions shared across BackupShield crates.

use anyhow::{bail, Result};
use std::path::Path;

/// Validate that a symlink target is safe to restore.
///
/// Checks that:
/// - The target is a relative path (not absolute).
/// - The target does not contain `..` components.
/// - The resolved target stays within the `target_base` directory tree.
///
/// On non-Unix platforms this function is a no-op (symlinks are typically
/// not security-relevant on Windows in the same way).
#[cfg(unix)]
pub fn validate_symlink_target(target: &str, target_base: &Path) -> Result<()> {
    let p = std::path::PathBuf::from(target);
    if p.is_absolute() {
        bail!(
            "symlink target must be relative, got absolute path: {}",
            target
        );
    }
    for component in p.components() {
        if let std::path::Component::ParentDir = component {
            bail!("symlink target must not contain '..', got: {}", target);
        }
    }
    let resolved = target_base.join(&p);
    let canonical_base = target_base
        .canonicalize()
        .unwrap_or_else(|_| target_base.to_path_buf());
    if !resolved
        .canonicalize()
        .map(|p| p.starts_with(&canonical_base))
        .unwrap_or(true)
    {
        bail!("symlink target would escape restore directory: {}", target);
    }
    Ok(())
}

/// Stub for non-Unix platforms.
#[cfg(not(unix))]
pub fn validate_symlink_target(_target: &str, _target_base: &Path) -> Result<()> {
    Ok(())
}

/// Validate a symlink target on Windows.
///
/// Windows-specific validation:
/// - Rejects `..` components that would escape the restore directory.
/// - Accepts absolute paths (e.g. `C:\target`) but logs a warning, because
///   they are valid on Windows but hurt portability.
/// - Handles Windows drive-letter paths natively.
///
/// Note: on Windows the `..` escape is less of a security concern than on
/// Unix (no SUID / sticky-bit issues), but it is still checked to prevent
/// accidental restoration outside the target directory.
#[cfg(windows)]
pub fn validate_symlink_target_windows(target: &str, target_base: &Path) -> Result<()> {
    use std::path::Component;

    let p = std::path::PathBuf::from(target);

    // Reject parent-dir components that escape the restore tree.
    for component in p.components() {
        if let Component::ParentDir = component {
            let resolved = target_base.join(&p);
            let canonical_base = target_base
                .canonicalize()
                .unwrap_or_else(|_| target_base.to_path_buf());
            if resolved
                .canonicalize()
                .map(|cr| !cr.starts_with(&canonical_base))
                .unwrap_or(true)
            {
                bail!(
                    "symlink target '{}' would escape restore directory via '..'",
                    target
                );
            }
        }
    }

    // Absolute paths are valid on Windows but warn for portability.
    if p.is_absolute() {
        log::warn!(
            "symlink target is an absolute path: {}. \
             Consider using relative paths for better portability.",
            target
        );
    }

    Ok(())
}

/// Stub for non-Windows platforms.
#[cfg(not(windows))]
pub fn validate_symlink_target_windows(_target: &str, _target_base: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_absolute_target() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_symlink_target("/etc/passwd", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute path"));
    }

    #[test]
    fn rejects_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_symlink_target("../etc/passwd", dir.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not contain '..'"));
    }

    #[test]
    fn accepts_valid_relative_target() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_symlink_target("valid_file.txt", dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_subdirectory_target() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("subdir")).unwrap();
        let result = validate_symlink_target("subdir/target.txt", dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_escape_outside_base() {
        let dir = tempfile::tempdir().unwrap();
        // Create a real file outside the target base.
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("malicious.txt");
        fs::write(&outside_file, b"data").unwrap();

        // Attempt to link to a path that resolves outside the base.
        // We use a path that traverses up.
        let result = validate_symlink_target("../outside.txt", dir.path());
        assert!(result.is_err());
    }

    // ── Windows-specific tests ────────────────────────────────────────────────

    #[cfg(windows)]
    #[test]
    fn windows_rejects_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_symlink_target_windows(r"..\..\Windows\system32\config", dir.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("would escape restore directory"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_accepts_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        // Absolute paths are accepted (with a warning) on Windows.
        let result = validate_symlink_target_windows(r"C:\Program Files\Common Files", dir.path());
        assert!(result.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_accepts_relative_target() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_symlink_target_windows("relative\\target.txt", dir.path());
        assert!(result.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_accepts_relative_with_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("subdir")).unwrap();
        let result = validate_symlink_target_windows("subdir\\target.txt", dir.path());
        assert!(result.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_escape_via_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("malicious.txt");
        fs::write(&outside_file, b"data").unwrap();

        let result = validate_symlink_target_windows(r"..\..\..\malicious.txt", dir.path());
        assert!(result.is_err());
    }
}
