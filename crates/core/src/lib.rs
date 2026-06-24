#![allow(
    clippy::manual_strip,
    clippy::manual_map,
    clippy::unnecessary_cast,
    clippy::type_complexity,
    clippy::unnecessary_map_or,
    clippy::unnecessary_sort_by,
    clippy::double_ended_iterator_last,
    clippy::suspicious_open_options
)]

//! # BackupShield Core
//!
//! Core library for the BackupShield incremental backup system.
//!
//! This crate provides the fundamental building blocks:
//!
//! - **Configuration** ([`config`]) – repository settings and persistence.
//! - **Content-defined chunking** ([`chunker`]) – Buzhash-based variable-size chunker.
//! - **Content-addressable storage** ([`repository`]) – chunk store, index, and dedup.
//! - **Snapshot management** ([`snapshot`]) – creating, saving, querying, and pruning snapshots.
//! - **File index** ([`index`]) – fast lookup from file paths to chunk hashes.
//! - **APFS snapshots** ([`apfs`]) – create, mount, list, delete APFS filesystem snapshots (macOS only).
//! - **File system watcher** ([`watcher`]) – FSEvents-based change tracking (macOS) with cross-platform fallback.

pub mod apfs;
pub mod chunker;
pub mod config;
pub mod fs_utils;
pub mod index;
pub mod pack;
pub mod repository;
pub mod snapshot;
pub mod system;
pub mod watcher;

// VSS (Volume Shadow Copy) is only available on Windows.
#[cfg(target_os = "windows")]
pub mod vss;

// Windows-specific file attributes, ACLs, and alternate data streams.
#[cfg(target_os = "windows")]
pub mod windows_attrs;
