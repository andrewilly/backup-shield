//! # BackupShield Restore
//!
//! Restore functionality for the BackupShield incremental backup system.
//!
//! This crate provides the ability to restore files from a backup repository
//! to a target directory, with support for:
//!
//! - **Selective restore** – restore specific files using glob patterns.
//! - **Dry-run mode** – preview what would be restored without writing.
//! - **Verification** – verify chunk integrity and file hash after restore.
//! - **Permission preservation** – restore Unix file permissions when possible.
//! - **Overwrite control** – skip or overwrite existing files.

pub mod restore;

pub use restore::{
    matches_filter, RestoreError, RestoreOptions, RestoreResult, RestoreStats, Restorer,
};
