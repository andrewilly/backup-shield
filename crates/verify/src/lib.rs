#![allow(
    clippy::vec_init_then_push,
    clippy::nonminimal_bool,
    clippy::needless_lifetimes,
    clippy::unnecessary_map_or
)]

//! # BackupShield Verify
//!
//! Integrity verification and scrubbing for BackupShield repositories.
//!
//! This crate provides:
//!
//! - **Hierarchical verification** ([`checker`]) – three-level integrity checks:
//!   1. Chunk level: SHA-256(chunk_content) == chunk_hash
//!   2. File level: SHA-256(concatenated chunk_hashes) == file_hash
//!   3. Snapshot level: entire snapshot JSON integrity
//!
//! - **Periodic scrubbing** ([`scrub`]) – ZFS-style scrub that iterates through
//!   all chunks, verifies them, and optionally repairs corrupt/missing chunks
//!   using Reed-Solomon parity data.

pub mod checker;
pub mod scrub;

// Re-export primary types for convenience
pub use checker::{Verifier, VerifyError, VerifyLevel, VerifyResult};
pub use scrub::{ScrubProgress, ScrubResult, Scrubber};
