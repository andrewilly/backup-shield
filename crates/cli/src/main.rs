// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.
//
//! CLI – the main binary that ties all crates together.

#![allow(
    clippy::unnecessary_cast,
    clippy::manual_flatten,
    clippy::field_reassign_with_default,
    clippy::too_many_arguments,
    clippy::print_literal,
    clippy::useless_format,
    clippy::only_used_in_recursion,
    clippy::drain_collect,
    clippy::needless_return
)]
//!
//! Provides subcommands: init, backup, snapshots, files, verify, repair, restore, prune, stats.

use anyhow::{bail, Context, Result};
use backup_shield_compression::{compress_chunk, decompress_chunk, CompressionLevel};
use backup_shield_core::apfs::ApfsSnapshotGuard;
use backup_shield_core::chunker::Chunker;
use backup_shield_core::config::RepositoryConfig;
use backup_shield_core::pack::compact_packs;
use backup_shield_core::repository::Repository;
use backup_shield_core::snapshot::{
    find_snapshot, list_snapshots, prune_snapshots, FileVersion, Snapshot, SnapshotDir,
    SnapshotFile, SnapshotNode, SnapshotSymlink,
};
#[cfg(target_os = "windows")]
use backup_shield_core::vss::VssSnapshot;
use backup_shield_crypto::{
    decrypt_chunk, derive_key, encrypt_chunk, load_key_material, save_key_material,
};
use backup_shield_ecc::repair::{ParityGroup, ParityIndex, ParityManager};
use backup_shield_restore::matches_filter;
use backup_shield_verify::{Scrubber, Verifier, VerifyLevel};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ═══════════════════════════════════════════════════════════════════════════════
// CLI definition
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, clap::ValueEnum)]
enum Schedule {
    /// Run backup every hour
    Hourly,
    /// Run backup every day at 2am
    Daily,
    /// Run backup every week on Sunday at 3am
    Weekly,
}

#[derive(Parser)]
#[command(name = "backup-shield")]
#[command(about = "Cross-platform incremental backup with data integrity and auto-repair")]
#[command(version)]
#[command(
    after_help = "Concept and original idea by André Willy Rizzo\nCopyright (c) 2026 André Willy Rizzo. All rights reserved."
)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new backup repository
    Init {
        /// Repository path
        repo_path: String,
        /// Enable encryption
        #[arg(long)]
        encrypt: bool,
        /// Set password (will prompt if encryption enabled and not provided)
        #[arg(long)]
        password: Option<String>,
        /// Compression level (1-22, default 3)
        #[arg(long, default_value = "3")]
        compression_level: u32,
        /// Number of Reed-Solomon data shards (default 64)
        #[arg(long, default_value = "64")]
        ecc_data_shards: usize,
        /// Number of Reed-Solomon parity shards (default 8)
        #[arg(long, default_value = "8")]
        ecc_parity_shards: usize,
    },

    /// Create a backup snapshot
    ///
    /// You can specify multiple source paths (e.g. `C:\Docs G:\Photos`) and all
    /// files will be captured in the same snapshot under a shared virtual root.
    Backup {
        /// Source path(s) to backup — can be specified multiple times
        #[arg(required = true, num_args = 1..)]
        source_path: Vec<String>,
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Tags for this snapshot
        #[arg(short, long)]
        tag: Vec<String>,
        /// Enable encryption for this backup
        #[arg(long)]
        encrypt: bool,
        /// Password for encryption
        #[arg(long)]
        password: Option<String>,
        /// Compression level override
        #[arg(long)]
        compression_level: Option<u32>,
        /// Schedule automatic backups (daily, weekly, hourly)
        #[arg(long, value_enum)]
        schedule: Option<Schedule>,
        /// Patterns to exclude (e.g. --exclude '.*' --exclude '*.tmp')
        #[arg(long)]
        exclude: Vec<String>,
        /// Watch for file system changes and perform automatic incremental backups
        #[arg(long)]
        watch: bool,
        /// Incremental: only process files changed since last watcher session
        #[arg(long)]
        incremental: bool,
        /// [macOS] Use APFS snapshot for point-in-time consistency.
        /// Creates an APFS snapshot of the source volume, backs up from the
        /// snapshot, then deletes it automatically.
        #[arg(long)]
        apfs_snapshot: bool,
        /// [Windows] Use Volume Shadow Copy (VSS) for consistent snapshots
        /// (requires administrator privileges)
        #[arg(long)]
        vss: bool,
    },

    /// List snapshots in repository
    Snapshots {
        /// Repository path
        #[arg(short, long)]
        repo: String,
    },

    /// Verify repository integrity
    Verify {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Quick verification (only check existence)
        #[arg(long)]
        quick: bool,
        /// Full verification (read and hash all chunks)
        #[arg(long)]
        full: bool,
        /// Sample N random chunks for verification
        #[arg(long)]
        sample: Option<usize>,
        /// Verify a specific snapshot only
        #[arg(long)]
        snapshot: Option<String>,
    },

    /// Repair corrupted data using parity information
    Repair {
        /// Repository path
        #[arg(short, long)]
        repo: String,
    },

    /// Restore from a snapshot
    Restore {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Snapshot to restore (ID, "latest", or tag)
        #[arg(long, default_value = "latest")]
        snapshot: String,
        /// Target directory for restoration
        #[arg(long)]
        target: String,
        /// Restore only files matching these glob patterns
        #[arg(long)]
        files: Vec<String>,
        /// Dry run (don't actually write files)
        #[arg(long)]
        dry_run: bool,
        /// Verify each file after restoration
        #[arg(long)]
        verify: bool,
        /// Overwrite existing files
        #[arg(long)]
        overwrite: bool,
        /// Preserve file permissions
        #[arg(long)]
        preserve_permissions: bool,
        /// Password for encrypted repository
        #[arg(long)]
        password: Option<String>,
    },

    /// Remove old snapshots based on retention policy
    Prune {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Keep N daily snapshots
        #[arg(long)]
        keep_daily: Option<u32>,
        /// Keep N weekly snapshots
        #[arg(long)]
        keep_weekly: Option<u32>,
        /// Keep N monthly snapshots
        #[arg(long)]
        keep_monthly: Option<u32>,
    },

    /// Show repository statistics
    Stats {
        /// Repository path
        #[arg(short, long)]
        repo: String,
    },

    /// Compact pack files to reclaim space from orphaned chunks
    Compact {
        /// Repository path
        #[arg(short, long)]
        repo: String,
    },

    /// List files in a snapshot
    Files {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Snapshot to list (ID, "latest", or tag)
        #[arg(long, default_value = "latest")]
        snapshot: String,
        /// Filter files by glob pattern
        #[arg(long)]
        filter: Vec<String>,
        /// Show file size and modification time
        #[arg(long)]
        long: bool,
    },

    /// List version history for a file
    Versions {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// File path to show versions for
        file: String,
        /// Snapshot to start from (default: latest)
        #[arg(long, default_value = "latest")]
        snapshot: String,
    },

    /// Restore a specific version of a file
    RestoreVersion {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// File path to restore
        file: String,
        /// Version to restore (snapshot ID or "latest")
        version: String,
        /// Target directory for restoration
        #[arg(long)]
        target: String,
    },

    /// Manage repository settings (max size, etc.)
    Config {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Set maximum repository size in GB (0 = unlimited)
        #[arg(long)]
        max_size_gb: Option<f64>,
        /// Set minimum snapshots to keep
        #[arg(long)]
        min_snapshots: Option<u32>,
        /// Show current configuration
        #[arg(long)]
        show: bool,
    },

    /// Automatically prune to stay within storage limits
    AutoPrune {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Actually perform pruning (dry-run by default)
        #[arg(long)]
        execute: bool,
    },

    /// Create a recovery bundle (portable backup for system recovery)
    CreateRecovery {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Output path for recovery bundle
        #[arg(short, long)]
        output: String,
        /// Include the backup-shield binary
        #[arg(long, default_value = "true")]
        include_binary: bool,
    },

    /// System backup: capture system state + backup system directories
    BackupSystem {
        /// Repository path
        #[arg(short, long)]
        repo: String,
        /// Patterns to exclude (e.g. --exclude '*.tmp')
        #[arg(long)]
        exclude: Vec<String>,
        /// Compression level override
        #[arg(long)]
        compression_level: Option<u32>,
        /// Enable encryption
        #[arg(long)]
        encrypt: bool,
        /// Password for encryption
        #[arg(long)]
        password: Option<String>,
    },

    /// System restore: restore entire system from backup (run from macOS Recovery)
    RestoreSystem {
        /// Repository path (scan all volumes if not specified)
        #[arg(short, long)]
        repo: Option<String>,
        /// Target volume to restore to
        #[arg(short, long)]
        target: String,
        /// Snapshot to restore (default: latest)
        #[arg(long, default_value = "latest")]
        snapshot: String,
        /// Dry run — show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
        /// Skip macOS reinstallation
        #[arg(long)]
        skip_os_install: bool,
        /// Show system manifest info and exit
        #[arg(long)]
        info: bool,
    },

    /// Create a bootable recovery USB drive
    CreateRecoveryUsb {
        /// Disk identifier (e.g. disk2)
        disk: String,
        /// Repository path to include
        #[arg(short, long)]
        repo: String,
        /// Force format even if disk has data
        #[arg(long)]
        force: bool,
    },

    /// Remove a scheduled automatic backup (launchd / Task Scheduler)
    Unschedule {
        /// Schedule to remove (hourly, daily, weekly). If not specified, removes all.
        #[arg(long, value_enum)]
        schedule: Option<Schedule>,
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
// Backup statistics
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Default)]
struct BackupStats {
    files_count: u64,
    new_chunks: u64,
    duplicate_chunks: u64,
    total_raw_size: u64,
    total_stored_size: u64,
}

/// Progress tracker for backup operations
struct BackupProgress {
    total_files: u64,
    processed_files: u64,
    processed_bytes: u64,
    last_update_time: std::time::Instant,
}

impl BackupProgress {
    fn new(total_files: u64, _total_bytes: u64) -> Self {
        Self {
            total_files,
            processed_files: 0,
            processed_bytes: 0,
            last_update_time: std::time::Instant::now(),
        }
    }

    fn update(&mut self, files: u64, bytes: u64) {
        self.processed_files += files;
        self.processed_bytes += bytes;

        // Only update display every 100ms to avoid excessive output
        if self.last_update_time.elapsed().as_millis() > 100 {
            self.display();
            self.last_update_time = std::time::Instant::now();
        }
    }

    fn display(&self) {
        let percent = if self.total_files > 0 {
            (self.processed_files as f64 / self.total_files as f64 * 100.0).min(100.0)
        } else {
            100.0
        };

        // Simple progress bar
        let bar_width: usize = 30;
        let filled = ((percent / 100.0) * bar_width as f64) as usize;
        let bar: String = format!(
            "{}{}",
            "=".repeat(filled),
            "-".repeat(bar_width.saturating_sub(filled as usize))
        );

        print!(
            "\r[{}] {:5.1}% | {}/{} files | {}",
            bar,
            percent,
            self.processed_files,
            self.total_files,
            format_size(self.processed_bytes)
        );
        let _ = std::io::stdout().flush();
    }

    fn finish(&self) {
        println!();
        println!(
            "Progress: {}/{} files ({} bytes)",
            self.processed_files,
            self.total_files,
            format_size(self.processed_bytes)
        );
    }
}

/// Count files and total size in a directory
fn count_files_and_size(path: &Path) -> Result<(u64, u64)> {
    let mut count = 0u64;
    let mut size = 0u64;

    if path.is_file() {
        return Ok((1, path.metadata().map(|m| m.len()).unwrap_or(0)));
    }

    for entry in walkdir::WalkDir::new(path) {
        if let Ok(entry) = entry {
            if entry.file_type().is_file() {
                count += 1;
                size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    Ok((count, size))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise logger based on verbosity.
    let log_level = if cli.verbose { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    match cli.command {
        Commands::Init {
            repo_path,
            encrypt,
            password,
            compression_level,
            ecc_data_shards,
            ecc_parity_shards,
        } => cmd_init(
            &repo_path,
            encrypt,
            password,
            compression_level,
            ecc_data_shards,
            ecc_parity_shards,
        ),

        Commands::Backup {
            source_path,
            repo,
            tag,
            encrypt,
            password,
            compression_level,
            schedule,
            exclude,
            watch,
            incremental,
            apfs_snapshot,
            vss,
        } => cmd_backup(
            &source_path.iter().map(String::as_str).collect::<Vec<_>>(),
            &repo,
            &tag,
            encrypt,
            password,
            compression_level,
            schedule,
            &exclude,
            watch,
            incremental,
            apfs_snapshot,
            vss,
        ),

        Commands::Snapshots { repo } => cmd_snapshots(&repo),

        Commands::Verify {
            repo,
            quick,
            full,
            sample,
            snapshot,
        } => cmd_verify(&repo, quick, full, sample, snapshot),

        Commands::Repair { repo } => cmd_repair(&repo),

        Commands::Restore {
            repo,
            snapshot,
            target,
            files,
            dry_run,
            verify,
            overwrite,
            preserve_permissions,
            password,
        } => cmd_restore(
            &repo,
            &snapshot,
            &target,
            &files,
            dry_run,
            verify,
            overwrite,
            preserve_permissions,
            password,
        ),

        Commands::Prune {
            repo,
            keep_daily,
            keep_weekly,
            keep_monthly,
        } => cmd_prune(&repo, keep_daily, keep_weekly, keep_monthly),

        Commands::Stats { repo } => cmd_stats(&repo),

        Commands::Compact { repo } => cmd_compact(&repo),

        Commands::Files {
            repo,
            snapshot,
            filter,
            long,
        } => cmd_files(&repo, &snapshot, &filter, long),

        Commands::Versions {
            repo,
            file,
            snapshot,
        } => cmd_versions(&repo, &file, &snapshot),

        Commands::RestoreVersion {
            repo,
            file,
            version,
            target,
        } => cmd_restore_version(&repo, &file, &version, &target),

        Commands::Config {
            repo,
            max_size_gb,
            min_snapshots,
            show,
        } => cmd_config(&repo, max_size_gb, min_snapshots, show),

        Commands::AutoPrune { repo, execute } => cmd_auto_prune(&repo, execute),

        Commands::CreateRecovery {
            repo,
            output,
            include_binary,
        } => cmd_create_recovery(&repo, &output, include_binary),

        Commands::BackupSystem {
            repo,
            exclude,
            compression_level,
            encrypt,
            password,
        } => cmd_backup_system(&repo, &exclude, compression_level, encrypt, password),

        Commands::RestoreSystem {
            repo,
            target,
            snapshot,
            dry_run,
            skip_os_install,
            info,
        } => cmd_restore_system(
            repo.as_deref(),
            &target,
            &snapshot,
            dry_run,
            skip_os_install,
            info,
        ),

        Commands::CreateRecoveryUsb { disk, repo, force } => {
            cmd_create_recovery_usb(&disk, &repo, force)
        }

        Commands::Unschedule { schedule } => cmd_unschedule(schedule),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: init
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_init(
    repo_path: &str,
    encrypt: bool,
    password: Option<String>,
    compression_level: u32,
    ecc_data_shards: usize,
    ecc_parity_shards: usize,
) -> Result<()> {
    // Print banner.
    println!("\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
    println!(
        "\u{2551}  BackupShield v{}                                \u{2551}",
        env!("CARGO_PKG_VERSION")
    );
    println!("\u{2551}  Concept & original idea: André Willy Rizzo           \u{2551}");
    println!("\u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}");
    println!();

    let path = Path::new(repo_path);

    // Build config.
    let mut config = RepositoryConfig::default();
    config.encryption_enabled = encrypt;
    config.compression_level = compression_level;
    config.ecc_data_shards = ecc_data_shards;
    config.ecc_parity_shards = ecc_parity_shards;

    let repo = Repository::init(path, Some(config))?;

    // If encryption is enabled, derive key and save key material.
    if encrypt {
        let pwd = get_password(password)?;
        let key_material =
            derive_key(&pwd, None).map_err(|e| anyhow::anyhow!("key derivation failed: {}", e))?;
        let key_path = path.join("keys").join("master.key");
        save_key_material(&key_material, &key_path)
            .map_err(|e| anyhow::anyhow!("failed to save key material: {}", e))?;
    }

    println!("Repository initialized successfully at {}", repo_path);
    println!();
    println!("Configuration:");
    println!(
        "  Encryption:    {}",
        if encrypt { "enabled" } else { "disabled" }
    );
    println!("  Compression:   level {}", compression_level);
    println!(
        "  ECC shards:    {} data + {} parity",
        ecc_data_shards, ecc_parity_shards
    );
    println!(
        "  Chunk sizes:   {}/{} (target {})",
        format_size(repo.config.chunk_min_size as u64),
        format_size(repo.config.chunk_max_size as u64),
        format_size(repo.config.chunk_target_size as u64),
    );
    println!(
        "  Pack target:    {}",
        format_size(repo.config.pack_target_size as u64)
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: backup
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_backup(
    source_paths: &[&str],
    repo_str: &str,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    schedule: Option<Schedule>,
    exclude: &[String],
    watch: bool,
    incremental: bool,
    apfs_snapshot: bool,
    vss: bool,
) -> Result<()> {
    let repo_path = Path::new(repo_str);

    // Validate all source paths exist before starting
    for sp in source_paths {
        if !Path::new(sp).exists() {
            bail!("source path does not exist: {}", sp);
        }
    }

    if source_paths.is_empty() {
        bail!("at least one source path is required");
    }

    // For schedule, incremental, watch, APFS, VSS — use the first source
    // (these modes only support a single source for now)
    let first_source = Path::new(source_paths[0]);

    // Handle schedule setup
    if let Some(sched) = schedule {
        return setup_schedule(source_paths[0], repo_str, tags, sched, exclude);
    }

    // ── Incremental mode ──
    if incremental {
        if source_paths.len() > 1 {
            bail!("incremental mode only supports a single source path");
        }
        return run_incremental_backup(
            first_source,
            repo_path,
            tags,
            encrypt,
            password,
            compression_level,
            exclude,
        );
    }

    // ── Watch mode ──
    if watch {
        if source_paths.len() > 1 {
            bail!("watch mode only supports a single source path");
        }
        return run_watch_daemon(
            first_source,
            repo_path,
            tags,
            encrypt,
            password,
            compression_level,
            exclude,
        );
    }

    // ── APFS snapshot mode ──
    if apfs_snapshot {
        if source_paths.len() > 1 {
            bail!("APFS snapshot mode only supports a single source path");
        }
        return run_backup_with_apfs_snapshot(
            first_source,
            repo_path,
            tags,
            encrypt,
            password,
            compression_level,
            exclude,
        );
    }

    // ── VSS snapshot mode ──
    if vss {
        if source_paths.len() > 1 {
            bail!("VSS snapshot mode only supports a single source path");
        }
        return run_backup_with_vss_snapshot(
            first_source,
            repo_path,
            tags,
            encrypt,
            password,
            compression_level,
            exclude,
        );
    }

    // ── Normal (full) backup — supports multiple sources ──
    let source_refs: Vec<&Path> = source_paths.iter().map(Path::new).collect();
    run_full_backup(
        &source_refs,
        repo_path,
        tags,
        encrypt,
        password,
        compression_level,
        exclude,
    )
}

/// Perform a standard full backup — scan all files, chunk, store, and snapshot.
///
/// When `sources` contains a single path, the snapshot root is the source directory
/// itself (backwards-compatible behaviour). When it contains multiple paths, a virtual
/// root directory named `"MultiSource-{timestamp}"` is created and each source's tree
/// becomes a child of it, preventing path collisions across volumes/directories.
fn run_full_backup(
    sources: &[&Path],
    repo_path: &Path,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    exclude: &[String],
) -> Result<()> {
    let mut repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository at {}", repo_path.display()))?;

    // Check storage limit and auto-prune if needed
    if let Some(to_prune) = repo.check_storage_limit() {
        if !to_prune.is_empty() {
            println!(
                "Storage limit exceeded. Auto-pruning {} old snapshot(s)...",
                to_prune.len()
            );
            for id in &to_prune {
                println!("  Pruning: {}", &id[..12.min(id.len())]);
            }
            drop(repo);
            backup_shield_core::snapshot::delete_snapshots(repo_path, &to_prune)?;
            repo = Repository::open(repo_path)?;
            println!("Auto-prune complete.");
        }
    }

    // Resolve compression level.
    let comp_level_val = compression_level.unwrap_or(repo.config.compression_level);
    let comp_level = CompressionLevel::new(comp_level_val as i32)
        .map_err(|e| anyhow::anyhow!("invalid compression level: {}", e))?;

    // Resolve encryption key.
    let use_encryption = encrypt || repo.config.encryption_enabled;
    let encryption_key: Option<[u8; 32]> = if use_encryption {
        let pwd = get_password(password)?;
        resolve_encryption_key(repo_path, &pwd)?
    } else {
        None
    };

    if encrypt && !repo.config.encryption_enabled {
        repo.config.encryption_enabled = true;
        repo.config.save(repo_path)?;
    }

    let chunker = Chunker::new(
        repo.config.chunk_min_size,
        repo.config.chunk_max_size,
        repo.config.chunk_target_size,
    )
    .context("invalid chunker parameters")?;

    let parity_manager =
        ParityManager::new(repo.config.ecc_data_shards, repo.config.ecc_parity_shards)
            .map_err(|e| anyhow::anyhow!("failed to create parity manager: {}", e))?;

    let mut stats = BackupStats::default();
    let mut parity_buffer: Vec<Vec<u8>> = Vec::new();
    let mut parity_hash_buffer: Vec<String> = Vec::new();
    let mut parity_groups: Vec<ParityGroup> = Vec::new();
    let mut group_id_counter: u32 = 0;
    let data_shards = repo.config.ecc_data_shards;

    // Count total files across all sources
    println!("Scanning source directories...");
    let mut total_files = 0u64;
    let mut total_bytes = 0u64;
    for src in sources {
        match count_files_and_size(src) {
            Ok((f, b)) => {
                total_files += f;
                total_bytes += b;
            }
            Err(e) => log::warn!("failed to scan {:?}: {}", src, e),
        }
    }
    println!(
        "Found {} files ({}), starting backup...",
        total_files,
        format_size(total_bytes)
    );
    println!();

    let previous_snapshot = list_snapshots(repo_path)
        .ok()
        .and_then(|snaps| snaps.into_iter().last());

    if let Some(ref prev) = previous_snapshot {
        println!(
            "Using parent snapshot: {} (for unchanged file optimization)",
            &prev.id[..12.min(prev.id.len())]
        );
    }
    println!();

    let mut progress = BackupProgress::new(total_files, total_bytes);

    // ── Build the snapshot tree ──────────────────────────────────────────
    let root_node = if sources.len() == 1 {
        // Single source: backwards-compatible behaviour — root is the source dir
        build_snapshot_tree(
            sources[0],
            &chunker,
            &mut repo,
            comp_level,
            encryption_key.as_ref(),
            use_encryption,
            &mut parity_buffer,
            &mut parity_hash_buffer,
            &mut parity_groups,
            &parity_manager,
            &mut group_id_counter,
            data_shards,
            &mut stats,
            &mut progress,
            previous_snapshot.as_ref(),
            exclude,
        )?
    } else {
        // Multiple sources: create a virtual root and add each source as a child
        build_multi_source_tree(
            sources,
            &chunker,
            &mut repo,
            comp_level,
            encryption_key.as_ref(),
            use_encryption,
            &mut parity_buffer,
            &mut parity_hash_buffer,
            &mut parity_groups,
            &parity_manager,
            &mut group_id_counter,
            data_shards,
            &mut stats,
            &mut progress,
            previous_snapshot.as_ref(),
            exclude,
        )?
    };

    finish_backup(
        sources[0], // _source is unused in finish_backup, keep for compat
        repo_path,
        &mut repo,
        root_node,
        &mut stats,
        &mut parity_buffer,
        &mut parity_hash_buffer,
        &mut parity_groups,
        &mut group_id_counter,
        data_shards,
        tags,
        previous_snapshot.as_ref(),
    )
}

/// Perform a backup using an APFS snapshot for point-in-time consistency.
///
/// This function:
/// 1. Resolves the APFS volume for the source path
/// 2. Creates an APFS snapshot of that volume
/// 3. Mounts the snapshot
/// 4. Runs a full backup from the mounted snapshot path
/// 5. The [`ApfsSnapshotGuard`] automatically unmounts and deletes the snapshot on drop
fn run_backup_with_apfs_snapshot(
    source: &Path,
    repo_path: &Path,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    exclude: &[String],
) -> Result<()> {
    println!("[APFS snapshot] Preparing point-in-time snapshot...");

    // Resolve the APFS volume for the source path.
    let volume = backup_shield_core::apfs::resolve_volume(source)
        .with_context(|| format!("failed to resolve APFS volume for {:?}", source))?;
    println!("[APFS snapshot] Volume: {:?}", volume);

    // Create the snapshot and mount it. The guard ensures cleanup on drop.
    let guard = ApfsSnapshotGuard::new(&volume)
        .context("failed to create APFS snapshot — do you have appropriate permissions?")?;

    let snapshot_name = guard.snapshot_name();
    let mount_path = guard.mount_path().to_path_buf();

    println!("[APFS snapshot] Created: {}", snapshot_name);
    println!("[APFS snapshot] Mounted at: {:?}", mount_path);
    println!();

    // Determine the snapshot source path.
    // If the source is on the same volume as the snapshot root, rebase it.
    let snapshot_source = rebase_path_to_snapshot(source, &volume, &mount_path);

    println!("[APFS snapshot] Backing up from: {:?}", snapshot_source);
    println!();

    // Run a full backup on the snapshot.
    let result = run_full_backup(
        &[&snapshot_source],
        repo_path,
        tags,
        encrypt,
        password,
        compression_level,
        exclude,
    );

    // Explicitly clean up the snapshot (though the guard's Drop will also do it).
    // This makes error cleanup explicit in the logs.
    guard.cleanup();

    println!("[APFS snapshot] Snapshot '{}' cleaned up.", snapshot_name);

    result
}

/// Rebase a source path to the corresponding path under a snapshot mount point.
///
/// For example, if `source` is `/Users/john/Documents`, the `volume` is `/`,
/// and the `snapshot_mount` is `/tmp/backupshield_apfs_.../snapshot`,
/// the result will be `/tmp/backupshield_apfs_.../snapshot/Users/john/Documents`.
fn rebase_path_to_snapshot(
    source: &Path,
    volume: &Path,
    snapshot_mount: &Path,
) -> std::path::PathBuf {
    if volume == Path::new("/") {
        // Root volume — prepend the snapshot mount.
        let relative = source.strip_prefix("/").unwrap_or(source);
        snapshot_mount.join(relative)
    } else if let Ok(relative) = source.strip_prefix(volume) {
        // Non-root volume — replace the volume prefix with the mount point.
        snapshot_mount.join(relative)
    } else {
        // Fallback: just use the original path (shouldn't happen in practice).
        log::warn!(
            "source {:?} is not under volume {:?}, using original path",
            source,
            volume
        );
        source.to_path_buf()
    }
}

/// Perform a backup using a Windows VSS (Volume Shadow Copy) snapshot for
/// point-in-time consistency.
///
/// This function:
/// 1. Resolves the Windows volume for the source path
/// 2. Creates a VSS snapshot of that volume
/// 3. Rebases the source path to the VSS mount point
/// 4. Runs a full backup from the VSS snapshot path
/// 5. The [`VssSnapshot`] Drop impl automatically deletes the snapshot
///
/// # Windows only
///
/// This is a no-op on non-Windows platforms — calling with `--vss` on
/// macOS/Linux will return an error before reaching this function.
#[cfg(target_os = "windows")]
fn run_backup_with_vss_snapshot(
    source: &Path,
    repo_path: &Path,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    exclude: &[String],
) -> Result<()> {
    println!("[VSS] Creating volume shadow copy for {:?}...", source);

    // Create the VSS snapshot. The guard's Drop ensures cleanup.
    let snap = VssSnapshot::create(source).context(
        "failed to create VSS snapshot — ensure the process is running as Administrator",
    )?;

    let mount_point = snap.mount_point().to_path_buf();
    let volume_root = snap.volume_root().to_path_buf();

    println!("[VSS] Snapshot mounted at: {:?}", mount_point);
    println!("[VSS] Volume root: {:?}", volume_root);

    // Rebase the source path to the VSS snapshot mount point.
    // If source is "D:\Data\Docs", volume_root is "D:\",
    // then relative is "Data\Docs" and the effective path is:
    //   \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Data\Docs
    let snapshot_source = if let Ok(relative) = source.strip_prefix(&volume_root) {
        mount_point.join(relative)
    } else {
        // If the source path somehow doesn't match the volume root,
        // fall back to the mount point directly (e.g. when source
        // already IS the volume root like "C:\").
        mount_point.join(source)
    };

    println!("[VSS] Backing up from: {:?}", snapshot_source);
    println!();

    // Run a full backup on the VSS snapshot.
    let result = run_full_backup(
        &[&snapshot_source],
        repo_path,
        tags,
        encrypt,
        password,
        compression_level,
        exclude,
    );

    // VssSnapshot is dropped here → snapshot is automatically deleted.

    match &result {
        Ok(()) => println!("[VSS] Backup completed. Snapshot released."),
        Err(e) => log::warn!(
            "[VSS] Backup finished with error (snapshot released): {}",
            e
        ),
    }

    result
}

/// Placeholder for non-Windows platforms — should never be called because
/// `cmd_backup` only enters this branch when `--vss` is passed, and
/// `--vss` is documented as Windows-only.
#[cfg(not(target_os = "windows"))]
fn run_backup_with_vss_snapshot(
    _source: &Path,
    _repo_path: &Path,
    _tags: &[String],
    _encrypt: bool,
    _password: Option<String>,
    _compression_level: Option<u32>,
    _exclude: &[String],
) -> Result<()> {
    anyhow::bail!(
        "The --vss flag is only supported on Windows. \
         Use --apfs-snapshot on macOS or omit the flag on Linux."
    );
}

/// Process a single changed file: chunk, compress, encrypt, store, return SnapshotNode.
fn process_changed_file(
    abs_path: &Path,
    chunker: &Chunker,
    repo: &mut Repository,
    comp_level: CompressionLevel,
    encryption_key: Option<&[u8; 32]>,
    _encryption_enabled: bool,
    parity_buffer: &mut Vec<Vec<u8>>,
    parity_hash_buffer: &mut Vec<String>,
    parity_groups: &mut Vec<ParityGroup>,
    parity_manager: &ParityManager,
    group_id_counter: &mut u32,
    data_shards: usize,
    stats: &mut BackupStats,
) -> Result<backup_shield_core::snapshot::SnapshotNode> {
    let metadata = fs::symlink_metadata(abs_path)
        .with_context(|| format!("failed to read metadata for {:?}", abs_path))?;

    // Symlink.
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(abs_path)
            .context("failed to read symlink target")?
            .to_string_lossy()
            .to_string();
        let name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        return Ok(backup_shield_core::snapshot::SnapshotNode::Symlink(
            backup_shield_core::snapshot::SnapshotSymlink { name, target },
        ));
    }

    // Directory — just return a dir node (children will be populated during merge).
    if metadata.is_dir() {
        let name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let modified: chrono::DateTime<Utc> = metadata
            .modified()
            .ok()
            .map(chrono::DateTime::from)
            .unwrap_or_else(Utc::now);
        let mode = unix_mode(&metadata);
        return Ok(backup_shield_core::snapshot::SnapshotNode::Directory(
            backup_shield_core::snapshot::SnapshotDir {
                name,
                modified,
                mode,
                children: Vec::new(),
            },
        ));
    }

    // Regular file.
    if metadata.is_file() {
        let name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let size = metadata.len();
        let modified: chrono::DateTime<Utc> = metadata
            .modified()
            .ok()
            .map(chrono::DateTime::from)
            .unwrap_or_else(Utc::now);
        let mode = unix_mode(&metadata);

        stats.files_count += 1;
        stats.total_raw_size += size;

        // Chunk the file.
        let chunks = chunker
            .chunk_file(abs_path)
            .with_context(|| format!("failed to chunk {:?}", abs_path))?;
        let mut chunk_hashes = Vec::with_capacity(chunks.len());

        for raw_chunk in &chunks {
            let stored_data = process_chunk_internal(raw_chunk, comp_level, encryption_key)?;
            stats.total_stored_size += stored_data.len() as u64;

            let existed = repo.chunk_exists(&compute_hash(&stored_data));
            let hash = repo.store_chunk(&stored_data)?;

            if existed {
                stats.duplicate_chunks += 1;
            } else {
                stats.new_chunks += 1;
            }

            chunk_hashes.push(hash.clone());

            // Accumulate for parity.
            parity_buffer.push(stored_data);
            parity_hash_buffer.push(hash.clone());

            if parity_buffer.len() == data_shards {
                flush_parity_group(
                    parity_buffer,
                    parity_hash_buffer,
                    parity_groups,
                    parity_manager,
                    group_id_counter,
                    repo,
                )?;
            }
        }

        let file_hash = compute_file_hash(&chunk_hashes);

        #[cfg(target_os = "windows")]
        let windows_attributes = backup_shield_core::windows_attrs::read_file_attributes(abs_path)
            .ok()
            .flatten();
        #[cfg(target_os = "windows")]
        let windows_acl = backup_shield_core::windows_attrs::read_security_descriptor(abs_path)
            .ok()
            .flatten();
        #[cfg(target_os = "windows")]
        let windows_ads = backup_shield_core::windows_attrs::read_alternate_data_streams(abs_path)
            .ok()
            .flatten();

        return Ok(backup_shield_core::snapshot::SnapshotNode::File(
            backup_shield_core::snapshot::SnapshotFile {
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
            },
        ));
    }

    anyhow::bail!("unsupported file type: {:?}", abs_path)
}

/// Run an incremental backup using the watcher state file to determine changed files.
fn run_incremental_backup(
    source: &Path,
    repo_path: &Path,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    exclude: &[String],
) -> Result<()> {
    let watcher_state_path = repo_path.join(".backupshield_watcher_state");
    let changed = backup_shield_core::watcher::load_watcher_state(&watcher_state_path)?;

    if changed.is_empty() {
        println!("No changes detected since last watch session. Nothing to do.");
        println!(
            "Hint: use `backup-shield backup {} --watch` to start watching for changes.",
            source.display()
        );
        return Ok(());
    }

    println!(
        "Incremental backup: {} path(s) changed since last watch session.",
        changed.len()
    );

    let prev_snapshot = list_snapshots(repo_path)
        .ok()
        .and_then(|snaps| snaps.into_iter().last())
        .ok_or_else(|| anyhow::anyhow!("no previous snapshot found; run a full backup first"))?;

    // Load repo and settings.
    let mut repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository at {}", repo_path.display()))?;

    let comp_level_val = compression_level.unwrap_or(repo.config.compression_level);
    let comp_level = CompressionLevel::new(comp_level_val as i32)
        .map_err(|e| anyhow::anyhow!("invalid compression level: {}", e))?;

    let use_encryption = encrypt || repo.config.encryption_enabled;
    let encryption_key: Option<[u8; 32]> = if use_encryption {
        let pwd = get_password(password)?;
        resolve_encryption_key(repo_path, &pwd)?
    } else {
        None
    };

    let chunker = Chunker::new(
        repo.config.chunk_min_size,
        repo.config.chunk_max_size,
        repo.config.chunk_target_size,
    )
    .context("invalid chunker parameters")?;

    let parity_manager =
        ParityManager::new(repo.config.ecc_data_shards, repo.config.ecc_parity_shards)
            .map_err(|e| anyhow::anyhow!("failed to create parity manager: {}", e))?;

    let mut stats = BackupStats::default();
    let mut parity_buffer: Vec<Vec<u8>> = Vec::new();
    let mut parity_hash_buffer: Vec<String> = Vec::new();
    let mut parity_groups: Vec<ParityGroup> = Vec::new();
    let mut group_id_counter: u32 = 0;
    let data_shards = repo.config.ecc_data_shards;

    // Classify changes into present (modified/created) and deleted.
    let (present, deleted) = backup_shield_core::watcher::classify_changes(source, &changed);
    println!(
        "  {} modified/created, {} deleted",
        present.len(),
        deleted.len()
    );

    // Clone the previous snapshot tree for mutation.
    let mut root_node = prev_snapshot.root.clone();

    // Process deleted files first (remove from tree).
    for del_path in &deleted {
        if let Some(rel) = backup_shield_core::watcher::make_relative(source, del_path) {
            log::info!("removing deleted file from snapshot: {:?}", rel);
            let _ = backup_shield_core::watcher::remove_file_from_snapshot(&mut root_node, &rel);
        }
    }

    // Process changed files.
    let mut progress = BackupProgress::new(present.len() as u64, 0);
    for file_path in &present {
        // Skip if matches exclude patterns
        if !exclude.is_empty() {
            if let Some(name) = file_path.file_name().and_then(|n| n.to_str()) {
                if matches_filter(name, exclude) {
                    log::info!("skipping excluded: {:?}", file_path);
                    continue;
                }
            }
        }

        match process_changed_file(
            file_path,
            &chunker,
            &mut repo,
            comp_level,
            encryption_key.as_ref(),
            use_encryption,
            &mut parity_buffer,
            &mut parity_hash_buffer,
            &mut parity_groups,
            &parity_manager,
            &mut group_id_counter,
            data_shards,
            &mut stats,
        ) {
            Ok(node) => {
                // Merge into snapshot tree
                if let Some(rel) = backup_shield_core::watcher::make_relative(source, file_path) {
                    if let Err(e) = backup_shield_core::watcher::merge_file_into_snapshot(
                        &mut root_node,
                        &rel,
                        node,
                    ) {
                        log::warn!("failed to merge {:?} into snapshot: {}", rel, e);
                    }
                }
                progress.update(1, 0);
            }
            Err(e) => {
                log::warn!("skipping {:?}: {}", file_path, e);
                progress.update(1, 0);
            }
        }
    }
    progress.finish();

    // Flush remaining parity.
    if parity_buffer.len() == data_shards {
        flush_parity_group(
            &mut parity_buffer,
            &mut parity_hash_buffer,
            &mut parity_groups,
            &parity_manager,
            &mut group_id_counter,
            &mut repo,
        )?;
    } else if !parity_buffer.is_empty() {
        log::info!(
            "{} chunks remaining without full parity group (need {})",
            parity_buffer.len(),
            data_shards,
        );
    }

    // Save the new snapshot.
    finish_backup(
        source,
        repo_path,
        &mut repo,
        root_node,
        &mut stats,
        &mut parity_buffer,
        &mut parity_hash_buffer,
        &mut parity_groups,
        &mut group_id_counter,
        data_shards,
        tags,
        Some(&prev_snapshot),
    )?;

    // Clear the watcher state file on success.
    if watcher_state_path.exists() {
        std::fs::remove_file(&watcher_state_path).context("failed to remove watcher state file")?;
    }

    println!();
    println!(
        "Incremental backup complete. Changed files processed: {}",
        present.len()
    );

    Ok(())
}

/// Daemon mode: watch source directory for changes and run incremental backups
/// automatically when enough changes accumulate or after a debounce interval.
fn run_watch_daemon(
    source: &Path,
    repo_path: &Path,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    exclude: &[String],
) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     BackupShield Watch Daemon                               ║");
    println!("║     Monitoring: {}  ", source.display());
    println!("║     Repository: {}  ", repo_path.display());
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Start the file watcher.
    let watcher = backup_shield_core::watcher::FileWatcher::new(&[source.to_path_buf()])
        .context("failed to start file watcher")?;

    // Run initial full backup.
    println!("[watch] Running initial full backup...");
    run_full_backup(
        &[source],
        repo_path,
        tags,
        encrypt,
        password.clone(),
        compression_level,
        exclude,
    )?;
    println!("[watch] Initial backup complete.");
    println!();

    // Daemon loop.
    let _debounce_seconds: u64 = 30; // Wait 30s after last change before triggering backup
    let min_changes: usize = 5; // Or trigger after 5 changes regardless of time
    let max_idle_seconds: u64 = 300; // Also backup if no activity for 5 min (keep things fresh)
    let mut last_backup_time = std::time::Instant::now();

    loop {
        let changed_count = watcher.changed_count();
        let idle_seconds = last_backup_time.elapsed().as_secs();

        if changed_count >= min_changes || idle_seconds >= max_idle_seconds {
            if changed_count > 0 {
                println!(
                    "[watch] {} change(s) detected. Running incremental backup...",
                    changed_count
                );
                let changed = watcher.get_changed();
                if let Err(e) = save_and_run_incremental(
                    source,
                    repo_path,
                    tags,
                    encrypt,
                    password.clone(),
                    compression_level,
                    exclude,
                    &changed,
                ) {
                    log::error!("incremental backup failed: {}", e);
                    eprintln!("[watch] Backup failed: {}", e);
                }
                watcher.clear();
                last_backup_time = std::time::Instant::now();
            } else if idle_seconds >= max_idle_seconds {
                // Idle timeout — keep connection alive, no backup needed
                log::debug!("[watch] idle heartbeat");
                last_backup_time = std::time::Instant::now();
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

/// Helper: save changed paths to state file and run incremental backup.
fn save_and_run_incremental(
    source: &Path,
    repo_path: &Path,
    tags: &[String],
    encrypt: bool,
    password: Option<String>,
    compression_level: Option<u32>,
    exclude: &[String],
    changed: &[std::path::PathBuf],
) -> Result<()> {
    let watcher_state_path = repo_path.join(".backupshield_watcher_state");
    backup_shield_core::watcher::save_watcher_state(&watcher_state_path, changed)
        .context("failed to save watcher state")?;

    run_incremental_backup(
        source,
        repo_path,
        tags,
        encrypt,
        password,
        compression_level,
        exclude,
    )
}

/// Finish a backup: create snapshot, save, flush parity/index, print summary.
fn finish_backup(
    _source: &Path,
    repo_path: &Path,
    repo: &mut Repository,
    root_node: backup_shield_core::snapshot::SnapshotNode,
    stats: &mut BackupStats,
    parity_buffer: &mut Vec<Vec<u8>>,
    parity_hash_buffer: &mut Vec<String>,
    parity_groups: &mut Vec<ParityGroup>,
    group_id_counter: &mut u32,
    data_shards: usize,
    tags: &[String],
    previous_snapshot: Option<&backup_shield_core::snapshot::Snapshot>,
) -> Result<()> {
    // Flush remaining parity buffer.
    if parity_buffer.len() == data_shards {
        flush_parity_group(
            parity_buffer,
            parity_hash_buffer,
            parity_groups,
            &ParityManager::new(data_shards, repo.config.ecc_parity_shards)
                .map_err(|e| anyhow::anyhow!("parity manager: {}", e))?,
            group_id_counter,
            repo,
        )?;
    } else if !parity_buffer.is_empty() {
        log::info!(
            "{} chunks remaining without full parity group (need {})",
            parity_buffer.len(),
            data_shards,
        );
    }

    let (total_size, total_chunks) = compute_tree_stats(&root_node);
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string());

    let snapshot = Snapshot {
        id: generate_snapshot_id(),
        timestamp: Utc::now(),
        hostname,
        tags: tags.to_vec(),
        root: root_node,
        total_size,
        total_chunks,
        parent_snapshot_id: previous_snapshot.map(|s| s.id.clone()),
    };

    let snapshot_id_short = snapshot.id[..12.min(snapshot.id.len())].to_string();

    // IMPORTANT: Order is critical for crash-safety.
    // 1. Save parity index first (references no chunks, pure metadata).
    // 2. Flush all pending chunk packs to disk.
    // 3. Update the chunk index file.
    // 4. Save snapshot LAST so it never references chunks that aren't on disk.
    if !parity_groups.is_empty() {
        let parity_index = ParityIndex {
            groups: parity_groups.clone(),
        };
        let parity_path = repo_path.join("parity").join("parity_index.json");
        parity_index
            .save(&parity_path)
            .map_err(|e| anyhow::anyhow!("failed to save parity index: {}", e))?;
    }

    repo.flush_pending()?;
    repo.save_index()?;
    snapshot.save(repo_path)?;

    println!("Backup complete!");
    println!("  Snapshot ID:    {}", snapshot_id_short);
    println!(
        "  Timestamp:      {}",
        snapshot.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if !tags.is_empty() {
        println!("  Tags:           {}", tags.join(", "));
    }
    println!("  Files:          {}", stats.files_count);
    println!("  New chunks:     {}", stats.new_chunks);
    println!("  Duplicate:      {}", stats.duplicate_chunks);
    println!("  Raw size:       {}", format_size(stats.total_raw_size));
    println!("  Stored size:    {}", format_size(stats.total_stored_size));
    if stats.total_raw_size > 0 && stats.total_stored_size > 0 {
        let ratio = stats.total_stored_size as f64 / stats.total_raw_size as f64;
        println!("  Storage ratio:  {:.2}x", ratio);
    }
    println!("  Parity groups:  {}", group_id_counter);

    Ok(())
}

/// Wrapper around compress + optionally encrypt a chunk.
fn process_chunk_internal(
    data: &[u8],
    comp_level: CompressionLevel,
    encryption_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let compressed = compress_chunk(data, comp_level)
        .map_err(|e| anyhow::anyhow!("compression failed: {}", e))?;

    if let Some(key) = encryption_key {
        encrypt_chunk(&compressed, key).map_err(|e| anyhow::anyhow!("encryption failed: {}", e))
    } else {
        Ok(compressed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: snapshots
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_snapshots(repo_str: &str) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let snapshots = list_snapshots(repo_path)
        .with_context(|| format!("failed to list snapshots in {}", repo_str))?;

    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }

    // Print header.
    println!(
        "{:<24} {:<20} {:<30} {:<12} {:<10}",
        "ID", "DATE", "TAGS", "SIZE", "FILES"
    );
    println!("{}", "-".repeat(96));

    for snap in &snapshots {
        let id_short = &snap.id[..12.min(snap.id.len())];
        let date = snap.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let tags = if snap.tags.is_empty() {
            "-".to_string()
        } else {
            snap.tags.join(", ")
        };
        let size = format_size(snap.total_size);
        let file_count = count_files(&snap.root);
        println!(
            "{:<24} {:<20} {:<30} {:<12} {:<10}",
            id_short, date, tags, size, file_count
        );
    }

    println!();
    println!("Total: {} snapshot(s)", snapshots.len());

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: verify
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_verify(
    repo_str: &str,
    quick: bool,
    full: bool,
    sample: Option<usize>,
    snapshot: Option<String>,
) -> Result<()> {
    let repo_path = Path::new(repo_str);

    // If a specific snapshot is requested, verify just that one.
    if let Some(ref snap_query) = snapshot {
        let snap = find_snapshot(repo_path, snap_query)
            .with_context(|| format!("snapshot '{}' not found", snap_query))?;
        let verifier = Verifier::new(repo_path)?;
        let result = verifier.verify_snapshot(&snap.id)?;

        print_verify_result(&result);
        if !result.is_ok() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Determine verify level.
    let level = if full {
        VerifyLevel::Full
    } else if let Some(n) = sample {
        VerifyLevel::Sample(n)
    } else {
        // Default to quick if no flag specified, full if --quick is not set
        if quick {
            VerifyLevel::Quick
        } else {
            VerifyLevel::Full
        }
    };

    let verifier = Verifier::new(repo_path)
        .with_context(|| format!("failed to create verifier for {}", repo_str))?;

    println!("Running {} verification on {}...", level, repo_str);
    let result = verifier.verify(level)?;

    print_verify_result(&result);

    if !result.is_ok() {
        std::process::exit(1);
    }

    Ok(())
}

fn print_verify_result(result: &backup_shield_verify::VerifyResult) {
    println!();
    println!(
        "Verification complete ({}) in {:.2}s",
        result.level, result.duration_secs
    );
    println!("  Chunks checked: {}", result.chunks_checked);
    println!("  Chunks OK:      {}", result.chunks_ok);
    println!("  Chunks corrupt: {}", result.chunks_corrupt);
    println!("  Chunks missing: {}", result.chunks_missing);
    println!("  Snapshots:      {}", result.snapshots_checked);
    println!("  Files checked:  {}", result.files_checked);

    if !result.errors.is_empty() {
        println!();
        println!("Errors ({}):", result.errors.len());
        for err in &result.errors {
            println!("  - {}", err);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: repair
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_repair(repo_str: &str) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let scrubber = Scrubber::new(repo_path)
        .with_context(|| format!("failed to create scrubber for {}", repo_str))?;

    println!("Running scrub and repair on {}...", repo_str);
    let result = scrubber.scrub_and_repair()?;

    println!();
    println!("Scrub complete in {:.2}s", result.duration_secs);
    println!("  Total chunks:   {}", result.progress.chunks_total);
    println!("  Chunks OK:      {}", result.progress.chunks_ok);
    println!("  Chunks errors:  {}", result.progress.chunks_errors);
    println!("  Chunks repaired: {}", result.repaired_count);

    let unrecoverable = result.errors_found.len() as u64 - result.repaired_count;
    if unrecoverable > 0 {
        println!("  Unrecoverable:  {}", unrecoverable);
    }

    if !result.errors_found.is_empty() {
        println!();
        println!("Errors found:");
        for err in &result.errors_found {
            println!("  - {}", err);
        }
    }

    if result.is_ok() {
        println!();
        println!("All chunks are healthy.");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: restore
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_restore(
    repo_str: &str,
    snapshot_query: &str,
    target_str: &str,
    file_filters: &[String],
    dry_run: bool,
    verify: bool,
    overwrite: bool,
    preserve_permissions: bool,
    password: Option<String>,
) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let target_path = Path::new(target_str);

    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository at {}", repo_str))?;

    // Resolve encryption key if needed.
    let encryption_key: Option<[u8; 32]> = if repo.config.encryption_enabled {
        let pwd = get_password(password)?;
        Some(
            resolve_encryption_key(repo_path, &pwd)?
                .context("encryption key required but not available")?,
        )
    } else {
        None
    };

    let compression_enabled = repo.config.compression_level > 0;

    // Find the snapshot.
    let snapshot = find_snapshot(repo_path, snapshot_query)
        .with_context(|| format!("snapshot '{}' not found", snapshot_query))?;

    println!(
        "Restoring snapshot {} (taken at {})...",
        &snapshot.id[..12.min(snapshot.id.len())],
        snapshot.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );

    if dry_run {
        println!("  (dry run – no files will be written)");
    }

    // Build file filter.
    let file_filter: Option<Vec<String>> = if file_filters.is_empty() {
        None
    } else {
        Some(file_filters.to_vec())
    };

    let mut result = RestoreResultInternal::default();
    let start = SystemTime::now();

    // Create target directory.
    if !dry_run {
        fs::create_dir_all(target_path)
            .with_context(|| format!("failed to create target directory {}", target_str))?;
    }

    // Walk the snapshot tree and restore.
    match &snapshot.root {
        SnapshotNode::Directory(root_dir) => {
            for child in &root_dir.children {
                restore_node(
                    child,
                    PathBuf::new(),
                    &repo,
                    target_path,
                    encryption_key.as_ref(),
                    compression_enabled,
                    &file_filter,
                    dry_run,
                    verify,
                    overwrite,
                    preserve_permissions,
                    &mut result,
                );
            }
        }
        _ => {
            restore_node(
                &snapshot.root,
                PathBuf::new(),
                &repo,
                target_path,
                encryption_key.as_ref(),
                compression_enabled,
                &file_filter,
                dry_run,
                verify,
                overwrite,
                preserve_permissions,
                &mut result,
            );
        }
    }

    let duration = start.elapsed().unwrap_or_default().as_secs_f64();

    // Print summary.
    println!();
    println!("Restore complete in {:.2}s", duration);
    println!("  Files restored:  {}", result.files_restored);
    println!("  Files skipped:   {}", result.files_skipped);
    println!("  Bytes restored:  {}", format_size(result.bytes_restored));
    println!("  Directories:     {}", result.directories_created);
    println!("  Symlinks:        {}", result.symlinks_created);
    if !result.errors.is_empty() {
        println!("  Errors:          {}", result.errors.len());
        for err in &result.errors {
            println!("    - {}", err);
        }
    }

    Ok(())
}

#[derive(Default)]
struct RestoreResultInternal {
    files_restored: u64,
    files_skipped: u64,
    bytes_restored: u64,
    directories_created: u64,
    symlinks_created: u64,
    errors: Vec<String>,
}

// validate_symlink_target is now in backup_shield_core::fs_utils.
// This re-export is kept for backward compatibility.
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

fn restore_node(
    node: &SnapshotNode,
    rel_path: PathBuf,
    repo: &Repository,
    target_base: &Path,
    encryption_key: Option<&[u8; 32]>,
    compression_enabled: bool,
    file_filter: &Option<Vec<String>>,
    dry_run: bool,
    verify: bool,
    overwrite: bool,
    preserve_permissions: bool,
    result: &mut RestoreResultInternal,
) {
    match node {
        SnapshotNode::Directory(dir) => {
            let dir_path = if rel_path.as_os_str().is_empty() {
                PathBuf::from(&dir.name)
            } else {
                rel_path.join(&dir.name)
            };
            let target_dir = target_base.join(&dir_path);

            if !dry_run {
                if let Err(e) = fs::create_dir_all(&target_dir) {
                    result.errors.push(format!(
                        "failed to create directory {}: {}",
                        target_dir.display(),
                        e
                    ));
                } else {
                    result.directories_created += 1;
                    if preserve_permissions {
                        set_permissions(&target_dir, dir.mode, result);
                    }
                }
            } else {
                result.directories_created += 1;
            }

            for child in &dir.children {
                restore_node(
                    child,
                    dir_path.clone(),
                    repo,
                    target_base,
                    encryption_key,
                    compression_enabled,
                    file_filter,
                    dry_run,
                    verify,
                    overwrite,
                    preserve_permissions,
                    result,
                );
            }
        }

        SnapshotNode::File(file) => {
            let file_path = if rel_path.as_os_str().is_empty() {
                PathBuf::from(&file.name)
            } else {
                rel_path.join(&file.name)
            };
            let file_path_str = file_path.to_string_lossy().to_string();
            let target_file = target_base.join(&file_path);

            // Apply file filter.
            if let Some(ref patterns) = file_filter {
                if !matches_filter(&file_path_str, patterns) {
                    result.files_skipped += 1;
                    return;
                }
            }

            // Check overwrite.
            if !overwrite && !dry_run && target_file.exists() {
                result
                    .errors
                    .push(format!("file already exists: {}", target_file.display()));
                result.files_skipped += 1;
                return;
            }

            // Read, decrypt, decompress, and concatenate all chunks.
            let mut file_data = Vec::with_capacity(file.size as usize);
            for chunk_hash in &file.chunk_hashes {
                match repo.read_chunk(chunk_hash) {
                    Ok(stored_data) => {
                        // Decrypt if needed.
                        let after_decrypt = match encryption_key {
                            Some(key) => match decrypt_chunk(&stored_data, key) {
                                Ok(data) => data,
                                Err(e) => {
                                    result.errors.push(format!(
                                        "decryption failed for chunk {}: {}",
                                        &chunk_hash[..12.min(chunk_hash.len())],
                                        e
                                    ));
                                    result.files_skipped += 1;
                                    return;
                                }
                            },
                            None => stored_data,
                        };

                        // Decompress if needed.
                        let raw_data = if compression_enabled {
                            match decompress_chunk(&after_decrypt) {
                                Ok(data) => data,
                                Err(_) => {
                                    // May not be compressed (small chunks).
                                    after_decrypt
                                }
                            }
                        } else {
                            after_decrypt
                        };

                        // Verify chunk hash if requested.
                        if verify {
                            let actual = compute_hash(&raw_data);
                            // Note: chunk_hash is the hash of the *stored* (processed)
                            // data, not the raw data, so we skip this check for
                            // compressed/encrypted chunks.
                            if encryption_key.is_none()
                                && !compression_enabled
                                && actual != *chunk_hash
                            {
                                result.errors.push(format!(
                                    "chunk hash mismatch: expected {}, got {}",
                                    chunk_hash, actual
                                ));
                            }
                        }

                        file_data.extend_from_slice(&raw_data);
                    }
                    Err(e) => {
                        result.errors.push(format!(
                            "chunk missing {} for file {}: {}",
                            &chunk_hash[..12.min(chunk_hash.len())],
                            file_path_str,
                            e
                        ));
                        result.files_skipped += 1;
                        return;
                    }
                }
            }

            // Verify file hash if requested.
            if verify {
                let computed_file_hash = compute_file_hash(&file.chunk_hashes);
                if computed_file_hash != file.file_hash {
                    result.errors.push(format!(
                        "file hash mismatch for {}: expected {}, got {}",
                        file_path_str, file.file_hash, computed_file_hash
                    ));
                }
            }

            // Write file.
            if !dry_run {
                if let Some(parent) = target_file.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        result.errors.push(format!(
                            "failed to create parent directory {}: {}",
                            parent.display(),
                            e
                        ));
                        result.files_skipped += 1;
                        return;
                    }
                }

                // Write atomically: tmp file → rename to final path.
                let tmp_path = target_file.with_extension("tmp");
                match fs::write(&tmp_path, &file_data) {
                    Ok(()) => {
                        match fs::rename(&tmp_path, &target_file) {
                            Ok(()) => {
                                result.files_restored += 1;
                                result.bytes_restored += file_data.len() as u64;
                                if preserve_permissions {
                                    set_permissions(&target_file, file.mode, result);
                                }
                                // Restore Windows-specific attributes.
                                #[cfg(target_os = "windows")]
                                restore_windows_attrs(
                                    &target_file,
                                    file.windows_attributes,
                                    file.windows_acl.as_deref(),
                                    file.windows_ads.as_deref(),
                                    result,
                                );
                            }
                            Err(e) => {
                                let _ = fs::remove_file(&tmp_path);
                                result.errors.push(format!(
                                    "failed to rename restored file {}: {}",
                                    target_file.display(),
                                    e
                                ));
                                result.files_skipped += 1;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_path);
                        result.errors.push(format!(
                            "failed to write file {}: {}",
                            target_file.display(),
                            e
                        ));
                        result.files_skipped += 1;
                    }
                }
            } else {
                result.files_restored += 1;
                result.bytes_restored += file_data.len() as u64;
            }
        }

        SnapshotNode::Symlink(symlink) => {
            let link_path = if rel_path.as_os_str().is_empty() {
                PathBuf::from(&symlink.name)
            } else {
                rel_path.join(&symlink.name)
            };
            let target_link = target_base.join(&link_path);

            if !dry_run {
                if let Some(parent) = target_link.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if overwrite && target_link.exists() {
                    let _ = fs::remove_file(&target_link);
                }
                if !overwrite && target_link.exists() {
                    result
                        .errors
                        .push(format!("symlink already exists: {}", target_link.display()));
                    return;
                }

                #[cfg(unix)]
                {
                    if let Err(e) = validate_symlink_target(&symlink.target, target_base) {
                        result.errors.push(format!(
                            "invalid symlink target for {}: {}",
                            target_link.display(),
                            e
                        ));
                        return;
                    }
                }

                #[cfg(windows)]
                {
                    if let Err(e) = validate_symlink_target_windows(&symlink.target, target_base) {
                        result.errors.push(format!(
                            "invalid symlink target for {}: {}",
                            target_link.display(),
                            e
                        ));
                        return;
                    }
                }

                #[cfg(unix)]
                {
                    match std::os::unix::fs::symlink(&symlink.target, &target_link) {
                        Ok(()) => result.symlinks_created += 1,
                        Err(e) => {
                            result.errors.push(format!(
                                "failed to create symlink {}: {}",
                                target_link.display(),
                                e
                            ));
                        }
                    }
                }
                #[cfg(windows)]
                {
                    let symlink_result = {
                        let target_path = std::path::Path::new(&symlink.target);
                        if target_path.is_dir() {
                            std::os::windows::fs::symlink_dir(target_path, &target_link)
                        } else {
                            std::os::windows::fs::symlink_file(target_path, &target_link)
                        }
                    };
                    match symlink_result {
                        Ok(()) => result.symlinks_created += 1,
                        Err(e) => result.errors.push(format!(
                            "failed to create symlink {} -> {}: {}. Note: requires Admin or Developer Mode",
                            target_link.display(), symlink.target, e
                        )),
                    }
                }
                #[cfg(not(any(unix, windows)))]
                {
                    log::warn!(
                        "symlink creation not supported on this platform: {}",
                        target_link.display()
                    );
                }
            } else {
                result.symlinks_created += 1;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: prune
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_prune(
    repo_str: &str,
    keep_daily: Option<u32>,
    keep_weekly: Option<u32>,
    keep_monthly: Option<u32>,
) -> Result<()> {
    let repo_path = Path::new(repo_str);

    let daily = keep_daily.unwrap_or(0);
    let weekly = keep_weekly.unwrap_or(0);
    let monthly = keep_monthly.unwrap_or(0);

    if daily == 0 && weekly == 0 && monthly == 0 {
        bail!("at least one retention policy must be specified (--keep-daily, --keep-weekly, or --keep-monthly)");
    }

    println!("Pruning snapshots in {}...", repo_str);
    println!(
        "  Retention policy: keep {} daily, {} weekly, {} monthly",
        daily, weekly, monthly
    );

    let removed = prune_snapshots(repo_path, daily, weekly, monthly)
        .with_context(|| format!("failed to prune snapshots in {}", repo_str))?;

    if removed.is_empty() {
        println!("No snapshots removed.");
    } else {
        println!();
        println!("Removed {} snapshot(s):", removed.len());
        for id in &removed {
            println!("  - {}", &id[..12.min(id.len())]);
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: stats
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_stats(repo_str: &str) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository at {}", repo_str))?;

    let stats = repo.stats();

    println!("Repository Statistics: {}", repo_str);
    println!();
    println!("  Total chunks:        {}", stats.total_chunks);
    println!("  Total size:          {}", format_size(stats.total_size));
    println!(
        "  Compressed size:     {}",
        format_size(stats.total_compressed_size)
    );
    println!("  Dedup ratio:         {:.2}x", stats.dedup_ratio);
    println!("  Snapshot count:      {}", stats.snapshot_count);
    println!("  Pack files:          {}", stats.pack_count);

    if stats.total_size > 0 && stats.total_compressed_size > 0 {
        let savings = stats.total_size - stats.total_compressed_size;
        let pct = (savings as f64 / stats.total_size as f64) * 100.0;
        println!(
            "  Space saved:         {} ({:.1}%)",
            format_size(savings),
            pct
        );
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: compact
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_compact(repo_str: &str) -> Result<()> {
    let repo_path = Path::new(repo_str);

    // Collect live chunk hashes and config BEFORE acquiring the compact lock.
    // We open a Repository here (which holds an flock), but we drop it before
    // calling compact_packs (which manages its own exclusive flock) to avoid
    // a self-deadlock within the same process.
    let pack_target_size;
    let live_hashes;
    {
        let mut repo = Repository::open(repo_path)
            .with_context(|| format!("failed to open repository at {}", repo_str))?;

        // Flush any pending chunks first.
        repo.flush_pending()?;
        repo.save_index()?;

        pack_target_size = repo.config.pack_target_size as usize;

        // Collect all live chunk hashes from all snapshots.
        let snapshots = list_snapshots(repo_path)?;
        let mut hashes: HashSet<String> = HashSet::new();
        for snap in &snapshots {
            for hash in snap.all_chunk_hashes() {
                hashes.insert(hash);
            }
        }
        live_hashes = hashes;
    } // repo dropped here → flock released

    println!("Compacting repository {}...", repo_str);
    println!("  Live chunks: {}", live_hashes.len());

    // compact_packs acquires its own exclusive flock.
    let result = compact_packs(
        repo_path,
        &live_hashes,
        pack_target_size,
    )
    .with_context(|| format!("failed to compact repository at {}", repo_str))?;

    println!();
    println!("Compaction complete in");
    println!("  Packs: {} → {}", result.packs_before, result.packs_after);
    println!("  Chunks kept: {}", result.chunks_kept);
    println!("  Chunks discarded: {}", result.chunks_discarded);
    println!("  Bytes freed: {}", format_size(result.bytes_freed));

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: files
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_files(
    repo_str: &str,
    snapshot_query: &str,
    filters: &[String],
    long_format: bool,
) -> Result<()> {
    let repo_path = Path::new(repo_str);

    let snapshot = find_snapshot(repo_path, snapshot_query)
        .with_context(|| format!("snapshot '{}' not found", snapshot_query))?;

    let snap_id_short = &snapshot.id[..12.min(snapshot.id.len())];
    println!(
        "Files in snapshot {} (taken at {}):",
        snap_id_short,
        snapshot.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();

    let mut file_list: Vec<(String, u64, String)> = Vec::new();
    collect_files(&snapshot.root, PathBuf::new(), &mut file_list);

    // Apply filter.
    let filtered: Vec<_> = if filters.is_empty() {
        file_list
    } else {
        file_list
            .into_iter()
            .filter(|(path, _, _)| matches_filter(path, filters))
            .collect()
    };

    if filtered.is_empty() {
        println!("No files found.");
        return Ok(());
    }

    if long_format {
        // Header.
        println!("{:>12}  {:<22}  {}", "SIZE", "MODIFIED", "PATH");
        println!("{}", "-".repeat(80));
        for (path, size, modified) in &filtered {
            println!("{:>12}  {:<22}  {}", format_size(*size), modified, path);
        }
    } else {
        for (path, _, _) in &filtered {
            println!("{}", path);
        }
    }

    println!();
    println!("Total: {} file(s)", filtered.len());

    Ok(())
}

fn collect_files(
    node: &SnapshotNode,
    rel_path: PathBuf,
    file_list: &mut Vec<(String, u64, String)>,
) {
    match node {
        SnapshotNode::Directory(dir) => {
            let dir_path = if rel_path.as_os_str().is_empty() {
                PathBuf::from(&dir.name)
            } else {
                rel_path.join(&dir.name)
            };
            for child in &dir.children {
                collect_files(child, dir_path.clone(), file_list);
            }
        }
        SnapshotNode::File(file) => {
            let file_path = if rel_path.as_os_str().is_empty() {
                PathBuf::from(&file.name)
            } else {
                rel_path.join(&file.name)
            };
            let path_str = file_path.to_string_lossy().to_string();
            let modified = file.modified.format("%Y-%m-%d %H:%M:%S").to_string();
            file_list.push((path_str, file.size, modified));
        }
        SnapshotNode::Symlink(symlink) => {
            let link_path = if rel_path.as_os_str().is_empty() {
                PathBuf::from(&symlink.name)
            } else {
                rel_path.join(&symlink.name)
            };
            let path_str = link_path.to_string_lossy().to_string();
            file_list.push((path_str, 0, "(symlink)".to_string()));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: versions
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_versions(repo_str: &str, file_path: &str, snapshot_query: &str) -> Result<()> {
    let repo_path = Path::new(repo_str);

    // Find the starting snapshot
    let snapshot = find_snapshot(repo_path, snapshot_query)
        .with_context(|| format!("snapshot '{}' not found", snapshot_query))?;

    let file = Path::new(file_path);
    println!("Version history for: {}", file_path);
    println!();

    // Walk the snapshot chain to collect all versions
    let mut versions: Vec<(String, String, String, u64)> = Vec::new();
    let mut current_snapshot = snapshot;
    let mut visited = HashSet::new();

    loop {
        if visited.contains(&current_snapshot.id) {
            break;
        }
        visited.insert(current_snapshot.id.clone());

        if let Some((_, modified, _, file_versions)) =
            current_snapshot.find_file_with_versions(file)
        {
            // Current version
            versions.push((
                current_snapshot.id[..12.min(current_snapshot.id.len())].to_string(),
                modified.format("%Y-%m-%d %H:%M:%S").to_string(),
                "current".to_string(),
                0, // current size tracked separately
            ));

            // Previous versions
            for v in &file_versions {
                versions.push((
                    v.snapshot_id[..12.min(v.snapshot_id.len())].to_string(),
                    v.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                    format_size(v.size),
                    v.size,
                ));
            }
        }

        // Follow parent chain
        match &current_snapshot.parent_snapshot_id {
            Some(parent_id) => {
                let parent_path = repo_path
                    .join("snapshots")
                    .join(format!("{}.json", parent_id));
                current_snapshot = Snapshot::load(&parent_path)
                    .with_context(|| format!("failed to load parent snapshot {}", parent_id))?;
            }
            None => break,
        }
    }

    if versions.is_empty() {
        println!("No version history found for this file.");
        return Ok(());
    }

    println!(
        "{:<14} {:<20} {:<12} {:>10}",
        "Snapshot", "Timestamp", "Size", "Type"
    );
    println!("{}", "-".repeat(60));

    for (id, time, size_str, _) in &versions {
        println!("{:<14} {:<20} {:<12} {:>10}", id, time, size_str, "");
    }

    println!();
    println!("Total versions: {}", versions.len());

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: restore-version
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_restore_version(repo_str: &str, file_path: &str, version: &str, target: &str) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let target_path = Path::new(target);
    let file = Path::new(file_path);

    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository at {}", repo_str))?;

    let _compression_enabled = repo.config.compression_level > 0;

    // Find the snapshot to restore from
    let snapshot = if version == "latest" {
        find_snapshot(repo_path, "latest")?
    } else {
        find_snapshot(repo_path, version)?
    };

    println!(
        "Restoring {} from snapshot {}...",
        file_path,
        &snapshot.id[..12.min(snapshot.id.len())]
    );

    // Find the file in the snapshot chain
    let mut chunk_hashes: Option<Vec<String>> = None;
    let mut current_snapshot = snapshot;
    let mut visited = HashSet::new();

    loop {
        if visited.contains(&current_snapshot.id) {
            break;
        }
        visited.insert(current_snapshot.id.clone());

        if let Some((_size, _, hashes, file_versions)) =
            current_snapshot.find_file_with_versions(file)
        {
            // Check versions for matching snapshot ID
            for v in file_versions {
                if v.snapshot_id.starts_with(version) || version == "latest" {
                    chunk_hashes = Some(v.chunk_hashes);
                    println!(
                        "Found version from snapshot: {} ({} bytes)",
                        &v.snapshot_id[..12.min(v.snapshot_id.len())],
                        v.size
                    );
                    break;
                }
            }

            // If not found in versions, check current
            if chunk_hashes.is_none() {
                chunk_hashes = Some(hashes);
            }
            break;
        }

        match &current_snapshot.parent_snapshot_id {
            Some(parent_id) => {
                let parent_path = repo_path
                    .join("snapshots")
                    .join(format!("{}.json", parent_id));
                current_snapshot = Snapshot::load(&parent_path)
                    .with_context(|| format!("failed to load parent snapshot {}", parent_id))?;
            }
            None => break,
        }
    }

    let chunk_hashes = chunk_hashes.context("file not found in any snapshot")?;

    // Read and assemble chunks
    let mut file_data = Vec::new();
    for hash in &chunk_hashes {
        let data = repo.read_chunk(hash)?;
        file_data.extend_from_slice(&data);
    }

    // Write to target atomically: tmp file → rename.
    let target_file = target_path.join(file);
    if let Some(parent) = target_file.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = target_file.with_extension("tmp");
    fs::write(&tmp_path, &file_data)
        .with_context(|| format!("failed to write temp file {:?}", tmp_path))?;
    fs::rename(&tmp_path, &target_file)
        .with_context(|| format!("failed to rename temp file {:?} to {:?}", tmp_path, target_file))?;

    println!(
        "Restored: {} ({} bytes)",
        target_file.display(),
        file_data.len()
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: config
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_config(
    repo_str: &str,
    max_size_gb: Option<f64>,
    min_snapshots: Option<u32>,
    show: bool,
) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let mut repo = Repository::open(repo_path)?;

    if show {
        println!("Repository Configuration:");
        println!(
            "  Max size: {}",
            if repo.config.max_size == 0 {
                "unlimited".to_string()
            } else {
                format_size(repo.config.max_size)
            }
        );
        println!("  Min snapshots: {}", repo.config.min_snapshots);
        println!(
            "  Current disk usage: {}",
            format_size(repo.calculate_disk_usage())
        );
        return Ok(());
    }

    if let Some(size_gb) = max_size_gb {
        if size_gb < 0.0 {
            bail!("max size must be >= 0 (0 = unlimited)");
        }
        repo.config.max_size = (size_gb * 1024.0 * 1024.0 * 1024.0) as u64;
        println!(
            "Set max size to: {} ({:.1} GB)",
            format_size(repo.config.max_size),
            size_gb
        );
    }

    if let Some(min) = min_snapshots {
        if min < 1 {
            bail!("min snapshots must be >= 1");
        }
        repo.config.min_snapshots = min;
        println!("Set min snapshots to: {}", min);
    }

    if max_size_gb.is_some() || min_snapshots.is_some() {
        repo.config.save(repo_path)?;
        println!("Configuration saved.");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: auto-prune
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_auto_prune(repo_str: &str, execute: bool) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let repo = Repository::open(repo_path)?;

    let current_size = repo.calculate_disk_usage();
    let max_size = repo.config.max_size;

    if max_size == 0 {
        println!("No storage limit configured. Use 'config --max-size-gb <GB>' to set one.");
        return Ok(());
    }

    println!("Current disk usage: {}", format_size(current_size));
    println!("Max size: {}", format_size(max_size));

    if current_size <= max_size {
        println!("Repository is within storage limits. No pruning needed.");
        return Ok(());
    }

    let over_by = current_size - max_size;
    println!("Repository exceeds limit by: {}", format_size(over_by));

    let to_prune = match repo.check_storage_limit() {
        Some(ids) if !ids.is_empty() => ids,
        _ => {
            println!(
                "Cannot prune: at minimum snapshots ({}).",
                repo.config.min_snapshots
            );
            return Ok(());
        }
    };

    println!("\nSnapshots to prune: {}", to_prune.len());
    for id in &to_prune {
        println!("  - {}", &id[..12.min(id.len())]);
    }

    if !execute {
        println!("\nThis is a dry-run. Add --execute to actually delete snapshots.");
        return Ok(());
    }

    println!("\nPruning snapshots...");
    let deleted = backup_shield_core::snapshot::delete_snapshots(repo_path, &to_prune)?;
    println!("Deleted {} snapshot(s).", deleted.len());

    // Show new size
    let repo = Repository::open(repo_path)?;
    let new_size = repo.calculate_disk_usage();
    println!("New disk usage: {}", format_size(new_size));

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: create-recovery
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// Command: backup-system
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_backup_system(
    repo_str: &str,
    exclude: &[String],
    compression_level: Option<u32>,
    encrypt: bool,
    password: Option<String>,
) -> Result<()> {
    let repo_path = Path::new(repo_str);

    if !repo_path.exists() {
        bail!("Repository does not exist: {}", repo_str);
    }

    // Capture system manifest
    println!("Capturing system information...");
    let manifest = backup_shield_core::system::SystemManifest::capture()?;
    manifest.save(repo_path)?;
    manifest.print_summary();
    println!();

    // Open repo
    let mut repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository at {}", repo_str))?;

    // Resolve compression level
    let comp_level_val = compression_level.unwrap_or(repo.config.compression_level);
    let comp_level = CompressionLevel::new(comp_level_val as i32)
        .map_err(|e| anyhow::anyhow!("invalid compression level: {}", e))?;

    // Resolve encryption
    let use_encryption = encrypt || repo.config.encryption_enabled;
    let encryption_key: Option<[u8; 32]> = if use_encryption {
        let pwd = get_password(password)?;
        resolve_encryption_key(repo_path, &pwd)?
    } else {
        None
    };

    if encrypt && !repo.config.encryption_enabled {
        repo.config.encryption_enabled = true;
        repo.config.save(repo_path)?;
    }

    // Create chunker
    let chunker = Chunker::new(
        repo.config.chunk_min_size,
        repo.config.chunk_max_size,
        repo.config.chunk_target_size,
    )
    .context("failed to create chunker with repository config")?;

    let parity_manager =
        ParityManager::new(repo.config.ecc_data_shards, repo.config.ecc_parity_shards)
            .map_err(|e| anyhow::anyhow!("failed to create parity manager: {}", e))?;

    let data_shards = repo.config.ecc_data_shards;

    // Check storage limit
    if let Some(to_prune) = repo.check_storage_limit() {
        if !to_prune.is_empty() {
            println!(
                "Storage limit exceeded. Auto-pruning {} old snapshot(s)...",
                to_prune.len()
            );
            for id in &to_prune {
                println!("  Pruning: {}", &id[..12.min(id.len())]);
            }
            drop(repo);
            backup_shield_core::snapshot::delete_snapshots(repo_path, &to_prune)?;
            repo = Repository::open(repo_path)?;
            println!("Auto-prune complete.");
        }
    }

    // Back up each system source directory
    let sources = &manifest.backup_sources;
    let mut all_children = Vec::new();
    let mut stats = BackupStats::default();
    let mut parity_buffer: Vec<Vec<u8>> = Vec::new();
    let mut parity_hash_buffer: Vec<String> = Vec::new();
    let mut parity_groups: Vec<ParityGroup> = Vec::new();
    let mut group_id_counter: u32 = 0;

    // Load previous snapshot for hard link optimization
    let previous_snapshot = list_snapshots(repo_path)
        .ok()
        .and_then(|snaps| snaps.into_iter().last());

    if let Some(ref prev) = previous_snapshot {
        println!(
            "Using parent snapshot: {} (for unchanged file optimization)",
            &prev.id[..12.min(prev.id.len())]
        );
    }

    for src in sources {
        let src_path = Path::new(src);
        if !src_path.exists() {
            println!("  Skipping {}: does not exist", src);
            continue;
        }

        println!("  Backing up {}...", src);

        let (total_files, total_bytes) = count_files_and_size(src_path)?;
        let mut progress = BackupProgress::new(total_files, total_bytes);

        let node = build_snapshot_tree(
            src_path,
            &chunker,
            &mut repo,
            comp_level,
            encryption_key.as_ref(),
            use_encryption,
            &mut parity_buffer,
            &mut parity_hash_buffer,
            &mut parity_groups,
            &parity_manager,
            &mut group_id_counter,
            data_shards,
            &mut stats,
            &mut progress,
            previous_snapshot.as_ref(),
            exclude,
        )?;

        all_children.push(node);
        progress.finish();
    }

    // Flush remaining parity
    if parity_buffer.len() == data_shards {
        flush_parity_group(
            &mut parity_buffer,
            &mut parity_hash_buffer,
            &mut parity_groups,
            &parity_manager,
            &mut group_id_counter,
            &mut repo,
        )?;
    } else if !parity_buffer.is_empty() {
        log::info!(
            "{} chunks remaining without full parity group (need {})",
            parity_buffer.len(),
            data_shards,
        );
    }

    // Build a synthetic root directory
    let root_dir = SnapshotDir {
        name: "System".to_string(),
        modified: Utc::now(),
        mode: 0o755,
        children: all_children,
    };

    let (total_size, total_chunks) = compute_tree_stats(&SnapshotNode::Directory(root_dir.clone()));
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string());

    let snapshot = Snapshot {
        id: generate_snapshot_id(),
        timestamp: Utc::now(),
        hostname,
        tags: vec!["system".to_string()],
        root: SnapshotNode::Directory(root_dir),
        total_size,
        total_chunks,
        parent_snapshot_id: previous_snapshot.map(|s| s.id.clone()),
    };

    let snapshot_id_short = snapshot.id[..12.min(snapshot.id.len())].to_string();
    snapshot.save(repo_path)?;

    // Save parity index
    if !parity_groups.is_empty() {
        let parity_index = ParityIndex {
            groups: parity_groups,
        };
        let parity_path = repo_path.join("parity").join("parity_index.json");
        parity_index
            .save(&parity_path)
            .map_err(|e| anyhow::anyhow!("failed to save parity index: {}", e))?;
    }

    repo.flush_pending()?;
    repo.save_index()?;

    println!();
    println!("System backup complete!");
    println!("  Snapshot ID:    {}", snapshot_id_short);
    println!(
        "  Timestamp:      {}",
        snapshot.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("  Files:          {}", stats.files_count);
    println!("  New chunks:     {}", stats.new_chunks);
    println!("  Duplicate:      {}", stats.duplicate_chunks);
    println!("  Raw size:       {}", format_size(stats.total_raw_size));
    println!("  Stored size:    {}", format_size(stats.total_stored_size));
    if stats.total_raw_size > 0 && stats.total_stored_size > 0 {
        let ratio = stats.total_stored_size as f64 / stats.total_raw_size as f64;
        println!("  Storage ratio:  {:.2}x", ratio);
    }
    println!("  Parity groups:  {}", group_id_counter);
    println!();
    println!("System manifest saved. Ready for system recovery.");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: restore-system
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_restore_system(
    repo_str: Option<&str>,
    target_str: &str,
    snapshot_query: &str,
    dry_run: bool,
    skip_os_install: bool,
    info: bool,
) -> Result<()> {
    let target_path = Path::new(target_str);

    // Find repository
    let repo_path = if let Some(r) = repo_str {
        Path::new(r).to_path_buf()
    } else {
        scan_for_repositories()?
    };

    if !repo_path.exists() {
        bail!("Repository not found at {:?}", repo_path);
    }

    // Load system manifest (carry an Option so it lives long enough for backup_sources)
    let manifest_opt: Option<backup_shield_core::system::SystemManifest> =
        if backup_shield_core::system::SystemManifest::exists(&repo_path) {
            let m = backup_shield_core::system::SystemManifest::load(&repo_path)?;
            if info {
                m.print_summary();
                println!();
                println!("Repository: {:?}", repo_path);
                return Ok(());
            }
            println!("System manifest loaded:");
            println!(
                "  OS: {} (build {})",
                m.os_version, m.build_number
            );
            println!("  Hardware: {}", m.hardware_model);
            println!("  Hostname: {}", m.hostname);
            println!(
                "  Backup date: {}",
                m.captured_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!("  Applications: {}", m.applications.len());
            println!("  Users: {}", m.users.len());
            Some(m)
        } else {
            println!("Warning: no system manifest found in this repository.");
            println!("This backup was not created with 'backup-system'.");
            println!("Continuing with file-only restore...");
            None
        };
    println!();

    // Determine backup sources from manifest, or fall back to defaults
    let backup_sources: Vec<String> = manifest_opt
        .as_ref()
        .map(|m| m.backup_sources.clone())
        .unwrap_or_else(backup_shield_core::system::default_system_backup_sources);

    // Verify target volume exists
    if !target_path.exists() {
        bail!("Target volume does not exist: {}", target_str);
    }

    println!("Target volume: {:?}", target_path);
    println!();

    if dry_run {
        println!("DRY RUN — No changes will be made.");
    }

    // Step 1: reinstall macOS (unless skipped)
    if !skip_os_install && !dry_run {
        println!("Step 1: macOS reinstallation");
        println!("  You will need to reinstall macOS from Recovery Mode.");
        println!("  After reinstallation, re-run: backup-shield restore-system --repo <path> --target {} --skip-os-install", target_str);
        println!();
        println!("  To reinstall macOS:");
        println!("  1. Use 'Reinstall macOS' from the Recovery menu");
        println!("  2. Select '{}' as the destination", target_str);
        println!("  3. After installation completes, open Terminal and run this command again with --skip-os-install");
        return Ok(());
    }

    // Step 2: restore data
    println!("Step 2: Restoring data from backup...");
    println!();

    // Restore each system directory
    let restorer = backup_shield_restore::Restorer::new(&repo_path)?;

    if dry_run {
        for src in &backup_sources {
            println!("  [DRY RUN] Would restore {}", src);
        }
    } else {
        for src in &backup_sources {
            // Strip leading '/' so we can join safely
            let relative = src.trim_start_matches('/');
            let target_dir = target_path.join(relative);
            println!("  Restoring {} -> {:?} ...", src, target_dir);

            let mut options = backup_shield_restore::RestoreOptions::new(
                repo_path.clone(),
                snapshot_query.to_string(),
                target_dir,
            );
            options.verify = true;
            options.overwrite = true;
            options.preserve_permissions = true;

            match restorer.restore(options) {
                Ok(result) => {
                    println!("    Files restored: {}", result.files_restored);
                    println!("    Files skipped:  {}", result.files_skipped);
                    println!("    Bytes restored: {}", format_size(result.bytes_restored));
                    if !result.errors.is_empty() {
                        println!("    Errors ({}):", result.errors.len());
                        for err in &result.errors {
                            println!("      - {:?}", err);
                        }
                    }
                }
                Err(e) => {
                    println!("    Error restoring {}: {}", src, e);
                }
            }
        }
    }

    println!();
    println!("System restore complete!");
    println!();
    println!("Next steps:");
    println!("  1. Restart your Mac");
    println!("  2. Complete macOS setup assistant");
    println!("  3. Verify your data and reinstall missing applications");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command: create-recovery-usb
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_create_recovery_usb(disk: &str, repo_str: &str, force: bool) -> Result<()> {
    let repo_path = Path::new(repo_str);

    if !repo_path.exists() {
        bail!("Repository does not exist: {}", repo_str);
    }

    if !repo_path.join("config.toml").exists() {
        bail!("Not a valid backup-shield repository: {}", repo_str);
    }

    #[cfg(target_os = "macos")]
    let disk_dev = format!("/dev/{}", disk);

    #[cfg(target_os = "macos")]
    {
        // Verify disk exists
        let disk_info = std::process::Command::new("diskutil")
            .args(["info", &disk_dev])
            .output();
        let disk_output = match disk_info {
            Ok(output) if output.status.success() => output,
            _ => bail!(
                "Disk {} not found. Use 'diskutil list' to find available disks.",
                disk
            ),
        };

        if !force {
            println!("WARNING: This will ERASE ALL DATA on /dev/{}", disk);
            println!();
            println!("The following disk will be formatted:");
            let info_output = String::from_utf8_lossy(&disk_output.stdout);
            for line in info_output.lines() {
                if line.contains("Device / Media Name")
                    || line.contains("Disk Size")
                    || line.contains("Volume Name")
                {
                    println!("  {}", line.trim());
                }
            }
            println!();
            print!("Type YES to continue: ");
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim() != "YES" {
                println!("Aborted.");
                return Ok(());
            }
        }

        println!("Formatting /dev/{} as APFS...", disk);
        let status = std::process::Command::new("diskutil")
            .args(["eraseDisk", "APFS", "BACKUPSHIELD", &disk_dev])
            .status()
            .context("failed to run diskutil")?;
        if !status.success() {
            bail!("Failed to format disk /dev/{}", disk);
        }

        // Find the new volume
        const RECOVERY_VOLUME: &str = "/Volumes/BACKUPSHIELD";
        let vol_path = Path::new(RECOVERY_VOLUME);

        println!("Copying recovery bundle to USB...");
        cmd_create_recovery(
            repo_str,
            vol_path
                .to_str()
                .with_context(|| format!("invalid volume path: {:?}", vol_path))?,
            true,
        )?;

        // Make the volume bootable
        println!("Making USB bootable...");
        let bless_status = std::process::Command::new("bless")
            .args(["--folder", RECOVERY_VOLUME, "--setBoot"])
            .status()
            .context("failed to execute bless(8) — is this macOS Recovery?")?;
        if !bless_status.success() {
            println!("Warning: bless(8) reported a non-zero exit status.");
            println!("The USB drive may not be bootable on this Mac.");
            println!("You can still access the backup by mounting the drive manually.");
        }

        println!();
        println!("Recovery USB created successfully!");
        println!("  Disk: /dev/{}", disk);
        println!("  Volume: /Volumes/BACKUPSHIELD");
        println!();
        println!("To use for recovery:");
        println!("  1. Insert the USB drive");
        println!("  2. Restart while holding the Option (⌥) key");
        println!("  3. Select 'BACKUPSHIELD' from the startup menu");
        println!("  4. Run recovery commands from Terminal");
        println!();
        println!("Note: On Apple Silicon Macs, you may need to allow external boot in Startup Security Utility.");
    }

    #[cfg(target_os = "macos")]
    {
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (disk, force);
        bail!("create-recovery-usb is only supported on macOS");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Scan mounted volumes for backup-shield repositories.
fn scan_for_repositories() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        println!("Scanning for backup repositories...");
        let volumes = Path::new("/Volumes");
        if volumes.exists() {
            if let Ok(entries) = std::fs::read_dir(volumes) {
                for entry in entries.flatten() {
                    let vol_path = entry.path();
                    let config_path = vol_path.join("config.toml");
                    if config_path.exists() {
                        let manifest_path = vol_path.join("system-manifest.json");
                        if manifest_path.exists() {
                            println!("  Found system backup at: {:?}", vol_path);
                            return Ok(vol_path);
                        }
                        println!("  Found backup repository at: {:?}", vol_path);
                        return Ok(vol_path);
                    }
                }
            }
        }

        // Also check /Volumes/.backup-shield or other common locations
        let home_repo = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("backup-shield");
        if home_repo.join("config.toml").exists() {
            println!("  Found backup repository at: {:?}", home_repo);
            return Ok(home_repo);
        }
    }

    bail!("No backup repository found. Specify with --repo, or connect your backup drive.");
}

fn cmd_create_recovery(repo_str: &str, output_str: &str, include_binary: bool) -> Result<()> {
    let repo_path = Path::new(repo_str);
    let output_path = Path::new(output_str);

    if !repo_path.exists() {
        bail!("Repository does not exist: {}", repo_str);
    }

    let repo = Repository::open(repo_path)?;
    let stats = repo.stats();

    println!("Creating recovery bundle at: {}", output_path.display());
    println!("  Snapshots: {}", stats.snapshot_count);
    println!("  Chunks: {}", stats.total_chunks);
    println!("  Size: {}", format_size(stats.total_compressed_size));
    println!();

    // Create output directory
    fs::create_dir_all(output_path)
        .with_context(|| format!("failed to create output directory"))?;

    // Copy repository config
    let config_src = repo_path.join("config.toml");
    if config_src.exists() {
        fs::copy(&config_src, output_path.join("config.toml"))?;
        println!("  Copied config.toml");
    }

    // Copy snapshots
    let snapshots_src = repo_path.join("snapshots");
    let snapshots_dst = output_path.join("snapshots");
    if snapshots_src.exists() {
        fs::create_dir_all(&snapshots_dst)?;
        for entry in fs::read_dir(&snapshots_src)? {
            let entry = entry?;
            let name = entry.file_name();
            fs::copy(entry.path(), snapshots_dst.join(&name))?;
        }
        println!("  Copied {} snapshot(s)", stats.snapshot_count);
    }

    // Copy data (pack files) - this is the bulk
    let data_src = repo_path.join("data");
    let data_dst = output_path.join("data");
    if data_src.exists() {
        fs::create_dir_all(&data_dst)?;
        let mut bytes_copied: u64 = 0;
        for entry in fs::read_dir(&data_src)? {
            let entry = entry?;
            let name = entry.file_name();
            let size = entry.metadata()?.len();
            fs::copy(entry.path(), data_dst.join(&name))?;
            bytes_copied += size;
        }
        println!(
            "  Copied {} ({})",
            stats.pack_count,
            format_size(bytes_copied)
        );
    }

    // Copy index
    let indexes_src = repo_path.join("indexes");
    let indexes_dst = output_path.join("indexes");
    if indexes_src.exists() {
        fs::create_dir_all(&indexes_dst)?;
        for entry in fs::read_dir(&indexes_src)? {
            let entry = entry?;
            let name = entry.file_name();
            fs::copy(entry.path(), indexes_dst.join(&name))?;
        }
        println!("  Copied indexes");
    }

    // Copy parity
    let parity_src = repo_path.join("parity");
    let parity_dst = output_path.join("parity");
    if parity_src.exists() {
        fs::create_dir_all(&parity_dst)?;
        for entry in fs::read_dir(&parity_src)? {
            let entry = entry?;
            let name = entry.file_name();
            fs::copy(entry.path(), parity_dst.join(&name))?;
        }
        println!("  Copied parity data");
    }

    // Copy keys if present
    let keys_src = repo_path.join("keys");
    let keys_dst = output_path.join("keys");
    if keys_src.exists() {
        fs::create_dir_all(&keys_dst)?;
        for entry in fs::read_dir(&keys_src)? {
            let entry = entry?;
            let name = entry.file_name();
            fs::copy(entry.path(), keys_dst.join(&name))?;
        }
        println!("  Copied encryption keys (KEEP SECURE!)");
    }

    // Include binary if requested
    if include_binary {
        let current_exe = std::env::current_exe()?;

        #[cfg(target_os = "macos")]
        let recovery_exe = output_path.join("backup-shield-recovery");
        #[cfg(target_os = "windows")]
        let recovery_exe = output_path.join("backup-shield-recovery.exe");
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let recovery_exe = output_path.join("backup-shield-recovery");

        fs::copy(&current_exe, &recovery_exe)?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&recovery_exe)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&recovery_exe, perms)?;
        }

        println!("  Included backup-shield binary");
    }

    // Create a simple recovery script
    let script_content = if cfg!(target_os = "windows") {
        r#"@echo off
echo Backup-Shield Recovery
echo.
echo To restore your latest backup:
echo   backup-shield-recovery.exe restore <snapshot-id> --target <path>
echo.
echo Example:
echo   backup-shield-recovery.exe restore latest --target C:\Users\YourName\Restored
pause
"#
    } else {
        r#"#!/bin/bash
# BackupShield Recovery Script
# Copyright (c) 2026 André Willy Rizzo. All rights reserved.

BINARY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BINARY_DIR"

echo "============================================"
echo "   BackupShield Recovery"
echo "   Copyright (c) 2026 André Willy Rizzo"
echo "============================================"
echo ""
echo "This bundle contains a full system backup."
echo ""
echo "Available commands:"
echo ""
echo "  System restore (from macOS Recovery):"
echo "    ./backup-shield-recovery restore-system --repo \"$PWD\" --target /Volumes/MacintoshHD"
echo ""
echo "  File restore:"
echo "    ./backup-shield-recovery restore latest --target /path/to/restore --repo \"$PWD\""
echo ""
echo "  List snapshots:"
echo "    ./backup-shield-recovery snapshots --repo \"$PWD\""
echo ""
echo "  Verify backup integrity:"
echo "    ./backup-shield-recovery verify --repo \"$PWD\""
echo ""
echo "  Show system info:"
echo "    ./backup-shield-recovery restore-system --repo \"$PWD\" --info"
echo ""
echo "For guided recovery, run:"
echo "    ./recovery-macos.sh"
echo ""
echo "Press Enter to exit..."
read
"#
    };

    let script_path = if cfg!(target_os = "windows") {
        output_path.join("recovery.bat")
    } else {
        output_path.join("recovery.sh")
    };

    fs::write(&script_path, script_content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms)?;
    }
    println!("  Created recovery script");

    // Copy recovery-macos.sh script to the bundle (if it exists)
    let script_sources = [("scripts/recovery-macos.sh", "recovery-macos.sh")];
    for (src_relative, dst_name) in &script_sources {
        let current_exe_dir = std::env::current_exe()?
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        // Look relative to the binary or the working directory
        let src_candidates = [
            current_exe_dir
                .join("..")
                .join("scripts")
                .join(src_relative),
            Path::new(src_relative).to_path_buf(),
        ];
        for src in &src_candidates {
            if src.exists() {
                let dst = output_path.join(dst_name);
                fs::copy(src, &dst)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = fs::metadata(&dst)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&dst, perms)?;
                }
                println!("  Copied {}", dst_name);
                break;
            }
        }
    }

    // Create a manifest
    let manifest = format!(
        r#"# Backup-Shield Recovery Bundle
# Created: {}
# Version: {}
#
# This is a portable recovery bundle containing:
# - All snapshots
# - All backup data (pack files)
# - Index files
# - Parity data for error correction
# - Encryption keys (if any)
# - System manifest (system state info)
#
# Recovery options:
#
# 1. Full system restore (macOS):
#    ./backup-shield-recovery restore-system --repo . --target /Volumes/Target
#
# 2. File restore:
#    ./backup-shield-recovery restore latest --target /path/to/restore --repo .
#
# 3. Interactive guided recovery:
#    ./recovery-macos.sh
#
# 4. List available backups:
#    ./backup-shield-recovery snapshots --repo .
#
# 5. Verify backup integrity:
#    ./backup-shield-recovery verify --repo .
#
# For Windows, use backup-shield-recovery.exe with the same commands.
#
# Repository stats:
#   Snapshots: {}
#   Chunks: {}
#   Total size: {}
#   System backup: {}
"#,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        env!("CARGO_PKG_VERSION"),
        stats.snapshot_count,
        stats.total_chunks,
        format_size(stats.total_compressed_size),
        if backup_shield_core::system::SystemManifest::exists(repo_path) {
            "Yes (system manifest present)"
        } else {
            "No (file-only backup)"
        }
    );

    fs::write(output_path.join("RECOVERY_MANIFEST.md"), manifest)?;
    println!("  Created manifest");

    println!();
    println!("Recovery bundle created successfully!");
    println!("  Total size: {}", format_size(repo.calculate_disk_usage()));
    println!();
    println!("To use for recovery:");
    if cfg!(target_os = "windows") {
        println!("  1. Copy this folder to a USB drive");
        println!("  2. Boot from Windows installation media");
        println!("  3. Run recovery.bat and follow instructions");
    } else {
        println!("  1. Copy this folder to a USB drive");
        println!("  2. Boot from recovery partition or macOS Recovery");
        println!("  3. Run ./recovery.sh and follow instructions");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Backup pipeline helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Recursively build a snapshot tree, applying compression and encryption to
/// each chunk before storing it in the repository.
/// If `previous_snapshot` is provided, files that haven't changed (same size/mtime)
/// will reuse chunk hashes from the previous snapshot (hard link optimization).
#[allow(clippy::too_many_arguments)]
fn build_snapshot_tree(
    path: &Path,
    chunker: &Chunker,
    repo: &mut Repository,
    comp_level: CompressionLevel,
    encryption_key: Option<&[u8; 32]>,
    encryption_enabled: bool,
    parity_buffer: &mut Vec<Vec<u8>>,
    parity_hash_buffer: &mut Vec<String>,
    parity_groups: &mut Vec<ParityGroup>,
    parity_manager: &ParityManager,
    group_id_counter: &mut u32,
    data_shards: usize,
    stats: &mut BackupStats,
    progress: &mut BackupProgress,
    previous_snapshot: Option<&Snapshot>,
    exclude: &[String],
) -> Result<SnapshotNode> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to read metadata for {:?}", path))?;

    // Symlink.
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)
            .with_context(|| format!("failed to read symlink {:?}", path))?
            .to_string_lossy()
            .to_string();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        return Ok(SnapshotNode::Symlink(SnapshotSymlink { name, target }));
    }

    // Directory.
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
        let mode = unix_mode(&metadata);

        let mut children = Vec::new();
        let entries =
            fs::read_dir(path).with_context(|| format!("failed to read directory {:?}", path))?;
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

            // Skip if entry matches an exclude pattern
            if !exclude.is_empty() {
                if let Some(name) = child_path.file_name().and_then(|n| n.to_str()) {
                    if matches_filter(name, exclude) {
                        log::info!("excluded: {:?}", child_path);
                        continue;
                    }
                }
            }

            match build_snapshot_tree(
                &child_path,
                chunker,
                repo,
                comp_level,
                encryption_key,
                encryption_enabled,
                parity_buffer,
                parity_hash_buffer,
                parity_groups,
                parity_manager,
                group_id_counter,
                data_shards,
                stats,
                &mut *progress,
                previous_snapshot,
                exclude,
            ) {
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
        let mode = unix_mode(&metadata);

        stats.files_count += 1;
        stats.total_raw_size += size;

        progress.update(1, size);

        // Check if file is unchanged from previous snapshot (hard link optimization)
        let mut chunk_hashes: Vec<String> = Vec::new();
        let mut versions: Vec<FileVersion> = Vec::new();
        let is_unchanged = if let Some(prev) = previous_snapshot {
            let rel_path = path
                .file_name()
                .map(|n| PathBuf::from(n.to_string_lossy().to_string()))
                .unwrap_or_default();
            if let Some((prev_size, prev_modified, prev_hashes)) = prev.find_file(&rel_path) {
                if prev_size == size && prev_modified == modified {
                    // File is unchanged - reuse chunk hashes
                    chunk_hashes = prev_hashes;
                    stats.duplicate_chunks += chunk_hashes.len() as u64;
                    true
                } else {
                    // File has changed - save previous version
                    if !prev_hashes.is_empty() {
                        let prev_file_hash = compute_file_hash(&prev_hashes);
                        versions.push(FileVersion {
                            snapshot_id: prev.id.clone(),
                            timestamp: prev_modified,
                            size: prev_size,
                            chunk_hashes: prev_hashes,
                            file_hash: prev_file_hash,
                        });
                    }
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if is_unchanged {
            // Reuse chunk hashes from previous snapshot - just update ref counts
            for hash in &chunk_hashes {
                if let Some(meta) = repo.index.get_mut(hash) {
                    meta.refs += 1;
                }
            }
            let file_hash = compute_file_hash(&chunk_hashes);

            #[cfg(target_os = "windows")]
            let windows_attributes = backup_shield_core::windows_attrs::read_file_attributes(path)
                .ok()
                .flatten();
            #[cfg(target_os = "windows")]
            let windows_acl = backup_shield_core::windows_attrs::read_security_descriptor(path)
                .ok()
                .flatten();
            #[cfg(target_os = "windows")]
            let windows_ads = backup_shield_core::windows_attrs::read_alternate_data_streams(path)
                .ok()
                .flatten();

            return Ok(SnapshotNode::File(SnapshotFile {
                name,
                size,
                modified,
                mode,
                chunk_hashes,
                file_hash,
                versions: vec![],
                #[cfg(target_os = "windows")]
                windows_attributes,
                #[cfg(target_os = "windows")]
                windows_acl,
                #[cfg(target_os = "windows")]
                windows_ads,
            }));
        }

        // Chunk the file.
        let chunks = chunker.chunk_file(path)?;
        chunk_hashes = Vec::with_capacity(chunks.len());

        for raw_chunk in &chunks {
            // Process: compress then encrypt.
            let stored_data = process_chunk(raw_chunk, comp_level, encryption_key)?;

            stats.total_stored_size += stored_data.len() as u64;

            // Store the processed chunk.
            let existed = repo.chunk_exists(&compute_hash(&stored_data));
            let hash = repo.store_chunk(&stored_data)?;

            if existed {
                stats.duplicate_chunks += 1;
            } else {
                stats.new_chunks += 1;
            }

            chunk_hashes.push(hash.clone());

            // Accumulate for parity.
            parity_buffer.push(stored_data.clone());
            parity_hash_buffer.push(hash.clone());

            if parity_buffer.len() == data_shards {
                flush_parity_group(
                    parity_buffer,
                    parity_hash_buffer,
                    parity_groups,
                    parity_manager,
                    group_id_counter,
                    repo,
                )?;
            }
        }

        let file_hash = compute_file_hash(&chunk_hashes);

        #[cfg(target_os = "windows")]
        let windows_attributes = backup_shield_core::windows_attrs::read_file_attributes(path)
            .ok()
            .flatten();
        #[cfg(target_os = "windows")]
        let windows_acl = backup_shield_core::windows_attrs::read_security_descriptor(path)
            .ok()
            .flatten();
        #[cfg(target_os = "windows")]
        let windows_ads = backup_shield_core::windows_attrs::read_alternate_data_streams(path)
            .ok()
            .flatten();

        return Ok(SnapshotNode::File(SnapshotFile {
            name,
            size,
            modified,
            mode,
            chunk_hashes,
            file_hash,
            versions,
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

/// Build a snapshot tree from **multiple** source paths, creating a virtual root.
///
/// Each source path becomes a child directory of the virtual root, named after the
/// source's own basename (e.g. `C:\Docs` → `Docs/`).  This prevents path collisions
/// when sources reside on different volumes or in unrelated directories.
///
/// ## Restore behaviour
///
/// Restoring this snapshot produces:
///
/// ```text
/// <target_base>/
///   <source1_basename>/  ← e.g. `Docs/`
///     (original files)
///   <source2_basename>/  ← e.g. `Photos/`
///     (original files)
/// ```
fn build_multi_source_tree(
    sources: &[&Path],
    chunker: &Chunker,
    repo: &mut Repository,
    comp_level: CompressionLevel,
    encryption_key: Option<&[u8; 32]>,
    encryption_enabled: bool,
    parity_buffer: &mut Vec<Vec<u8>>,
    parity_hash_buffer: &mut Vec<String>,
    parity_groups: &mut Vec<ParityGroup>,
    parity_manager: &ParityManager,
    group_id_counter: &mut u32,
    data_shards: usize,
    stats: &mut BackupStats,
    progress: &mut BackupProgress,
    previous_snapshot: Option<&Snapshot>,
    exclude: &[String],
) -> Result<SnapshotNode> {
    let virtual_root_name = format!(
        "MultiSource-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );

    let mut children = Vec::new();

    for src in sources {
        let subtree = build_snapshot_tree(
            src,
            chunker,
            repo,
            comp_level,
            encryption_key,
            encryption_enabled,
            parity_buffer,
            parity_hash_buffer,
            parity_groups,
            parity_manager,
            group_id_counter,
            data_shards,
            stats,
            progress,
            previous_snapshot,
            exclude,
        )?;

        // If the source is a single file or symlink, add it directly.
        // If it's a directory, the subtree's root name is the directory basename,
        // which is exactly what we want as the child name.
        children.push(subtree);
    }

    let now: DateTime<Utc> = Utc::now();
    Ok(SnapshotNode::Directory(SnapshotDir {
        name: virtual_root_name,
        modified: now,
        mode: 0o755,
        children,
    }))
}

/// Apply compression and (optionally) encryption to a raw chunk.
fn process_chunk(
    raw_data: &[u8],
    comp_level: CompressionLevel,
    encryption_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    // Compress.
    let compressed = compress_chunk(raw_data, comp_level)
        .map_err(|e| anyhow::anyhow!("compression failed: {}", e))?;

    // Encrypt if key is available.
    match encryption_key {
        Some(key) => {
            let encrypted = encrypt_chunk(&compressed, key)
                .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;
            Ok(encrypted)
        }
        None => Ok(compressed),
    }
}

/// Flush the current parity buffer: compute parity, store parity chunks, and
/// record the parity group.
fn flush_parity_group(
    parity_buffer: &mut Vec<Vec<u8>>,
    parity_hash_buffer: &mut Vec<String>,
    parity_groups: &mut Vec<ParityGroup>,
    parity_manager: &ParityManager,
    group_id_counter: &mut u32,
    repo: &mut Repository,
) -> Result<()> {
    if parity_buffer.is_empty() {
        return Ok(());
    }

    let data_chunks: Vec<Vec<u8>> = parity_buffer.drain(..).collect();
    let data_hashes: Vec<String> = parity_hash_buffer.drain(..).collect();

    // Compute parity.
    let parity_chunks = parity_manager
        .compute_parity(&data_chunks)
        .map_err(|e| anyhow::anyhow!("parity computation failed: {}", e))?;

    let chunk_size = data_chunks.iter().map(|c| c.len()).max().unwrap_or(0);

    // Store parity chunks in the repository.
    let mut parity_hashes = Vec::with_capacity(parity_chunks.len());
    for parity_data in &parity_chunks {
        let hash = repo.store_chunk(parity_data)?;
        parity_hashes.push(hash);
    }

    // Create the parity group record.
    let group = parity_manager.create_parity_group(
        *group_id_counter,
        &data_chunks,
        &parity_chunks,
        chunk_size,
    );

    // Update parity_group field in chunk metadata.
    for hash in &data_hashes {
        if let Some(meta) = repo.index.get_mut(hash) {
            meta.parity_group = *group_id_counter;
        }
    }
    for hash in &parity_hashes {
        if let Some(meta) = repo.index.get_mut(hash) {
            meta.parity_group = *group_id_counter;
        }
    }

    parity_groups.push(group);
    *group_id_counter += 1;

    log::debug!(
        "flushed parity group {} with {} data + {} parity chunks",
        *group_id_counter - 1,
        data_hashes.len(),
        parity_hashes.len()
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Schedule setup (launchd / Task Scheduler)
// ═══════════════════════════════════════════════════════════════════════════════

fn setup_schedule(
    source_path: &str,
    repo_str: &str,
    tags: &[String],
    schedule: Schedule,
    exclude: &[String],
) -> Result<()> {
    let binary_path = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("failed to get current binary path: {}", e))?;

    let schedule_name = format!(
        "com.backup-shield.{}",
        match schedule {
            Schedule::Hourly => "hourly",
            Schedule::Daily => "daily",
            Schedule::Weekly => "weekly",
        }
    );

    #[cfg(target_os = "macos")]
    {
        setup_launchd(
            &schedule_name,
            &binary_path,
            source_path,
            repo_str,
            tags,
            schedule,
            exclude,
        )?;
    }

    #[cfg(target_os = "windows")]
    {
        setup_windows_task(
            &schedule_name,
            &binary_path,
            source_path,
            repo_str,
            tags,
            schedule,
            exclude,
        )?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        bail!("Automatic scheduling is only supported on macOS and Windows");
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn setup_launchd(
    name: &str,
    binary_path: &Path,
    source_path: &str,
    repo_str: &str,
    tags: &[String],
    schedule: Schedule,
    exclude: &[String],
) -> Result<()> {
    let hour = match schedule {
        Schedule::Hourly => None,
        Schedule::Daily => Some(2),
        Schedule::Weekly => Some(3),
    };

    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot find home directory"))?;

    let launchd_dir = home.join("Library/LaunchAgents");
    let log_dir = home.join("Library/Logs/backup-shield");

    let plist_path = launchd_dir.join(format!("{}.plist", name));

    std::fs::create_dir_all(&launchd_dir)
        .with_context(|| format!("failed to create LaunchAgents directory"))?;
    std::fs::create_dir_all(&log_dir).with_context(|| format!("failed to create log directory"))?;

    let mut base_args: Vec<String> = vec![
        "backup".to_string(),
        source_path.to_string(),
        "--repo".to_string(),
        repo_str.to_string(),
    ];
    for tag in tags {
        base_args.push("-t".to_string());
        base_args.push(tag.clone());
    }
    for pat in exclude {
        base_args.push("--exclude".to_string());
        base_args.push(pat.clone());
    }
    let args: Vec<String> = base_args;

    // Use the repository directory (or source parent) as the working directory.
    // Fall back to current directory if neither is suitable.
    let work_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));

    let stdout_path = log_dir.join("backup-shield.log");
    let stderr_path = log_dir.join("backup-shield-error.log");

    let mut plist = String::new();
    plist.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    plist.push_str("\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
    plist.push_str("\n<plist version=\"1.0\">\n<dict>\n");
    plist.push_str(&format!(
        "    <key>Label</key>\n    <string>{}</string>\n",
        name
    ));
    plist.push_str("    <key>ProgramArguments</key>\n    <array>\n");
    plist.push_str(&format!(
        "        <string>{}</string>\n",
        binary_path.display()
    ));
    for arg in &args {
        plist.push_str(&format!("        <string>{}</string>\n", arg));
    }
    plist.push_str("    </array>\n");
    plist.push_str(&format!(
        "    <key>WorkingDirectory</key>\n    <string>{}</string>\n",
        work_dir.display()
    ));
    plist.push_str("    <key>RunAtLoad</key>\n    <false/>\n");

    if let Some(h) = hour {
        plist.push_str("    <key>StartCalendarInterval</key>\n    <dict>\n");
        plist.push_str(&format!(
            "        <key>Hour</key>\n        <integer>{}</integer>\n",
            h
        ));
        plist.push_str("        <key>Minute</key>\n        <integer>0</integer>\n");
        plist.push_str("    </dict>\n");
    } else if matches!(schedule, Schedule::Hourly) {
        plist.push_str("    <key>StartInterval</key>\n    <integer>3600</integer>\n");
    }

    plist.push_str(&format!(
        "    <key>StandardOutPath</key>\n    <string>{}</string>\n",
        stdout_path.display()
    ));
    plist.push_str(&format!(
        "    <key>StandardErrorPath</key>\n    <string>{}</string>\n",
        stderr_path.display()
    ));
    plist.push_str("</dict>\n</plist>\n");

    std::fs::write(&plist_path, plist)
        .with_context(|| format!("failed to write plist to {:?}", plist_path))?;

    println!("Created launchd agent: {}", plist_path.display());

    // Load the launchd agent
    let load_status = std::process::Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .status()
        .with_context(|| format!("failed to execute launchctl load for {:?}", plist_path))?;

    if !load_status.success() {
        // Clean up the plist on failure
        let _ = std::fs::remove_file(&plist_path);
        bail!("launchctl load failed for {}", plist_path.display());
    }

    // Verify the job was loaded
    let verify_output = std::process::Command::new("launchctl")
        .args(["list", name])
        .output()
        .with_context(|| format!("failed to verify launchd job '{}'", name))?;

    if verify_output.status.success() {
        let stdout = String::from_utf8_lossy(&verify_output.stdout);
        if stdout.contains(name) || stdout.trim().is_empty() {
            println!(
                "  ✓ Launchd job '{}' loaded and verified successfully.",
                name
            );
        } else {
            println!("  ⚠ Launchd job '{}' may not be loaded correctly.", name);
        }
    } else {
        let stderr = String::from_utf8_lossy(&verify_output.stderr);
        println!("  ⚠ Could not verify job: {}", stderr.trim());
    }

    println!("  Logs: {}", log_dir.display());
    println!("  Job:  {}", plist_path.display());

    Ok(())
}

#[cfg(target_os = "macos")]
fn unschedule_launchd(schedule: Option<Schedule>) -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot find home directory"))?;

    let launchd_dir = home.join("Library/LaunchAgents");

    let schedule_names: Vec<String> = match schedule {
        Some(sched) => vec![format!(
            "com.backup-shield.{}",
            match sched {
                Schedule::Hourly => "hourly",
                Schedule::Daily => "daily",
                Schedule::Weekly => "weekly",
            }
        )],
        None => vec![
            "com.backup-shield.hourly".to_string(),
            "com.backup-shield.daily".to_string(),
            "com.backup-shield.weekly".to_string(),
        ],
    };

    for name in &schedule_names {
        let plist_path = launchd_dir.join(format!("{}.plist", name));

        if !plist_path.exists() {
            println!("  No plist found for '{}', skipping.", name);
            continue;
        }

        // Unload the launchd agent
        let unload_status = std::process::Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&plist_path)
            .status()
            .with_context(|| format!("failed to execute launchctl unload for {:?}", plist_path))?;

        if unload_status.success() {
            println!("  Unloaded launchd job '{}'", name);
        } else {
            println!("  ⚠ launchctl unload reported an issue for '{}'", name);
        }

        // Delete the plist file after unload
        std::fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove plist {:?}", plist_path))?;
        println!("  Removed plist: {}", plist_path.display());
    }

    if schedule_names.is_empty() {
        println!("No scheduled backups found to remove.");
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn setup_windows_task(
    name: &str,
    binary_path: &Path,
    source_path: &str,
    repo_str: &str,
    tags: &[String],
    schedule: Schedule,
    exclude: &[String],
) -> Result<()> {
    // Generate the command-line arguments that will be embedded in the task.
    let mut args = format!(
        "backup \"{}\" --repo \"{}\"",
        source_path, repo_str
    );
    for tag in tags {
        args.push_str(&format!(" -t \"{}\"", tag));
    }
    for pat in exclude {
        args.push_str(&format!(" --exclude \"{}\"", pat));
    }

    // Determine start boundary and schedule XML.
    // Each schedule provides its own StartBoundary to avoid duplicates.
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let (freq, interval_xml) = match schedule {
        Schedule::Hourly => (
            "Hourly",
            format!(
                r#"<StartBoundary>{}T00:00:00</StartBoundary>
      <Interval>PT1H</Interval>"#,
                today
            ),
        ),
        Schedule::Daily => (
            "Daily",
            format!(
                r#"<StartBoundary>{}T02:00:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>"#,
                today
            ),
        ),
        Schedule::Weekly => (
            "Weekly",
            format!(
                r#"<StartBoundary>{}T03:00:00</StartBoundary>
      <ScheduleByWeek><DaysOfWeek><Sunday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"#,
                today
            ),
        ),
    };

    // Use the current Windows user instead of LOCAL_SYSTEM for safety.
    let current_user = std::env::var("USERDOMAIN")
        .unwrap_or_else(|_| ".".to_string())
        + "\\"
        + &std::env::var("USERNAME").unwrap_or_else(|_| "SYSTEM".to_string());

    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>BackupShield</Author>
    <Description>BackupShield {} automatic backup of "{}" to "{}"</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <Enabled>true</Enabled>
      {}
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{}</UserId>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        freq,
        source_path,
        repo_str,
        interval_xml,
        current_user,
        binary_path.display(),
        args,
    );

    // Write XML to a temporary file.
    let temp_dir = std::env::temp_dir();
    let xml_path = temp_dir.join(format!("backupshield_task_{}.xml", name));
    std::fs::write(&xml_path, &task_xml)
        .with_context(|| format!("failed to write task XML to {:?}", xml_path))?;

    println!("Creating Windows scheduled task '{}'...", name);
    println!("  Source:    {}", source_path);
    println!("  Repository: {}", repo_str);
    println!("  Schedule:  {}", freq);
    println!("  XML:       {}", xml_path.display());

    // Execute schtasks.exe to import the XML.
    let output = std::process::Command::new("schtasks.exe")
        .args([
            "/create",
            "/xml",
            &xml_path.to_string_lossy(),
            "/tn",
            name,
            "/f",
        ])
        .output()
        .with_context(|| "failed to execute schtasks.exe — ensure the process is running as Administrator")?;

    // Clean up the temp XML file.
    let _ = std::fs::remove_file(&xml_path);

    if output.status.success() {
        println!("  ✓ Scheduled task '{}' created successfully.", name);
        println!();
        println!("  To run manually:   schtasks /run /tn \"{}\"", name);
        println!("  To disable:        schtasks /change /tn \"{}\" /disable", name);
        println!("  To view:           schtasks /query /tn \"{}\"", name);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "schtasks.exe failed to create task '{}'.\n\
             This command requires Administrator privileges.\n\
             stderr: {}",
            name,
            stderr.trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn unschedule_windows_task(schedule: Option<Schedule>) -> Result<()> {
    let schedule_names: Vec<String> = match schedule {
        Some(sched) => vec![format!(
            "com.backup-shield.{}",
            match sched {
                Schedule::Hourly => "hourly",
                Schedule::Daily => "daily",
                Schedule::Weekly => "weekly",
            }
        )],
        None => vec![
            "com.backup-shield.hourly".to_string(),
            "com.backup-shield.daily".to_string(),
            "com.backup-shield.weekly".to_string(),
        ],
    };

    let mut any_failed = false;
    for name in &schedule_names {
        println!("Removing scheduled task '{}'...", name);

        let output = std::process::Command::new("schtasks.exe")
            .args(["/delete", "/tn", name, "/f"])
            .output()
            .with_context(|| format!("failed to execute schtasks.exe to delete '{}'", name))?;

        if output.status.success() {
            println!("  ✓ Task '{}' removed.", name);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("does not exist") || stderr.contains("not found") {
                println!("  - Task '{}' does not exist, skipping.", name);
            } else {
                eprintln!("  ✗ Failed to remove task '{}': {}", name, stderr.trim());
                any_failed = true;
            }
        }
    }

    if any_failed {
        anyhow::bail!("One or more scheduled tasks could not be removed. Try running as Administrator.");
    }

    Ok(())
}

/// Remove a scheduled automatic backup.
fn cmd_unschedule(schedule: Option<Schedule>) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return unschedule_launchd(schedule);
    }

    #[cfg(target_os = "windows")]
    {
        return unschedule_windows_task(schedule);
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        bail!("Automatic scheduling is only supported on macOS and Windows");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Prompt for or return the password.
///
/// Uses `rpassword::prompt_password` to read securely from the terminal
/// without echoing the input. If a password was already provided via CLI
/// argument (e.g. `--password`), it is returned directly so that scripts
/// and automated tools can supply passwords non-interactively.
fn get_password(password: Option<String>) -> Result<String> {
    match password {
        Some(p) => Ok(p),
        None => rpassword::prompt_password("Enter encryption password: ")
            .context("failed to read password from terminal"),
    }
}

/// Resolve the encryption key: load existing key material or derive a new one.
fn resolve_encryption_key(repo_path: &Path, password: &str) -> Result<Option<[u8; 32]>> {
    let key_path = repo_path.join("keys").join("master.key");
    if key_path.exists() {
        let key_material = load_key_material(&key_path, password)
            .map_err(|e| anyhow::anyhow!("failed to load encryption key: {}", e))?;
        let key: [u8; 32] = key_material
            .key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key size"))?;
        Ok(Some(key))
    } else {
        let key_material = derive_key(password, None)
            .map_err(|e| anyhow::anyhow!("failed to derive key: {}", e))?;
        save_key_material(&key_material, &key_path)
            .map_err(|e| anyhow::anyhow!("failed to save key material: {}", e))?;
        let key: [u8; 32] = key_material
            .key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key size"))?;
        Ok(Some(key))
    }
}

/// Generate a unique snapshot ID (time-based with xorshift mixing).
fn generate_snapshot_id() -> String {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = duration.as_nanos() as u64;
    let mut s = nanos.wrapping_mul(0x517CC1B727220A95);
    let mut result = String::with_capacity(32);
    for _ in 0..2 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        result.push_str(&format!("{:016x}", s));
    }
    result
}

/// Compute SHA-256 of a byte slice, returning hex.
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute the file hash: SHA-256 of the concatenation of chunk hash strings.
fn compute_file_hash(chunk_hashes: &[String]) -> String {
    let mut hasher = Sha256::new();
    for h in chunk_hashes {
        hasher.update(h.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Recursively compute total size and chunk count from a snapshot tree.
fn compute_tree_stats(node: &SnapshotNode) -> (u64, u64) {
    match node {
        SnapshotNode::File(f) => (f.size, f.chunk_hashes.len() as u64),
        SnapshotNode::Directory(d) => {
            let mut total_size = 0u64;
            let mut total_chunks = 0u64;
            for child in &d.children {
                let (s, c) = compute_tree_stats(child);
                total_size += s;
                total_chunks += c;
            }
            (total_size, total_chunks)
        }
        SnapshotNode::Symlink(_) => (0, 0),
    }
}

/// Count files in a snapshot tree.
fn count_files(node: &SnapshotNode) -> u64 {
    match node {
        SnapshotNode::File(_) => 1,
        SnapshotNode::Directory(d) => d.children.iter().map(count_files).sum(),
        SnapshotNode::Symlink(_) => 0,
    }
}

/// Extract unix mode bits from metadata (0 on Windows).
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0o644
    }
}

/// Restore Windows-specific file attributes after writing a file during restore.
#[cfg(target_os = "windows")]
fn restore_windows_attrs(
    path: &Path,
    attributes: Option<u32>,
    acl: Option<&[u8]>,
    ads: Option<&[(String, Vec<u8>)]>,
    result: &mut RestoreResultInternal,
) {
    // Apply file attributes (hidden, readonly, system, etc.).
    if let Some(attrs) = attributes {
        if let Err(e) = backup_shield_core::windows_attrs::apply_file_attributes(path, attrs) {
            result.errors.push(format!(
                "failed to set Windows attributes for {}: {}",
                path.display(),
                e
            ));
        }
    }

    // Apply security descriptor (ACL).
    if let Some(sd) = acl {
        if !sd.is_empty() {
            if let Err(e) = backup_shield_core::windows_attrs::apply_security_descriptor(path, sd) {
                result.errors.push(format!(
                    "failed to set security descriptor for {}: {}",
                    path.display(),
                    e
                ));
            }
        }
    }

    // Write alternate data streams.
    if let Some(streams) = ads {
        for (name, content) in streams {
            if let Err(e) =
                backup_shield_core::windows_attrs::write_alternate_data_stream(path, name, content)
            {
                result.errors.push(format!(
                    "failed to write ADS '{}' for {}: {}",
                    name,
                    path.display(),
                    e
                ));
            }
        }
    }
}

/// Set file/directory permissions on Unix. No-op on Windows.
fn set_permissions(path: &Path, mode: u32, result: &mut RestoreResultInternal) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode);
        if let Err(e) = fs::set_permissions(path, perms) {
            result.errors.push(format!(
                "failed to set permissions for {}: {}",
                path.display(),
                e
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode, result);
    }
}

/// Format a byte count as a human-readable string.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a plist string the same way setup_launchd does (but without
    /// writing it to disk, and using test doubles for paths we control).
    fn generate_test_plist(
        name: &str,
        binary: &str,
        args: &[&str],
        work_dir: &str,
        stdout_path: &str,
        stderr_path: &str,
        schedule: Schedule,
    ) -> String {
        let hour = match schedule {
            Schedule::Hourly => None,
            Schedule::Daily => Some(2),
            Schedule::Weekly => Some(3),
        };

        let mut plist = String::new();
        plist.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        plist.push_str("\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
        plist.push_str("\n<plist version=\"1.0\">\n<dict>\n");
        plist.push_str(&format!(
            "    <key>Label</key>\n    <string>{}</string>\n",
            name
        ));
        plist.push_str("    <key>ProgramArguments</key>\n    <array>\n");
        plist.push_str(&format!("        <string>{}</string>\n", binary));
        for arg in args {
            plist.push_str(&format!("        <string>{}</string>\n", arg));
        }
        plist.push_str("    </array>\n");
        plist.push_str(&format!(
            "    <key>WorkingDirectory</key>\n    <string>{}</string>\n",
            work_dir
        ));
        plist.push_str("    <key>RunAtLoad</key>\n    <false/>\n");

        if let Some(h) = hour {
            plist.push_str("    <key>StartCalendarInterval</key>\n    <dict>\n");
            plist.push_str(&format!(
                "        <key>Hour</key>\n        <integer>{}</integer>\n",
                h
            ));
            plist.push_str("        <key>Minute</key>\n        <integer>0</integer>\n");
            plist.push_str("    </dict>\n");
        } else if matches!(schedule, Schedule::Hourly) {
            plist.push_str("    <key>StartInterval</key>\n    <integer>3600</integer>\n");
        }

        plist.push_str(&format!(
            "    <key>StandardOutPath</key>\n    <string>{}</string>\n",
            stdout_path
        ));
        plist.push_str(&format!(
            "    <key>StandardErrorPath</key>\n    <string>{}</string>\n",
            stderr_path
        ));
        plist.push_str("</dict>\n</plist>\n");

        plist
    }

    #[test]
    fn test_plist_valid_xml() {
        let plist = generate_test_plist(
            "com.backup-shield.hourly",
            "/usr/local/bin/backup-shield",
            &[
                "backup",
                "/Users/test/Documents",
                "--repo",
                "/Users/test/backups",
            ],
            "/Users/test",
            "/Users/test/Library/Logs/backup-shield/backup-shield.log",
            "/Users/test/Library/Logs/backup-shield/backup-shield-error.log",
            Schedule::Hourly,
        );

        // Verify XML structure
        assert!(plist.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(plist.contains("<plist version=\"1.0\">"));
        assert!(plist.contains("</plist>"));
        assert!(plist.contains("<dict>"));
        assert!(plist.contains("</dict>"));
        assert!(plist.contains("<array>"));
        assert!(plist.contains("</array>"));

        // Verify balanced tags (simple check)
        let open_dict = plist.matches("<dict>").count();
        let close_dict = plist.matches("</dict>").count();
        assert_eq!(open_dict, close_dict, "dict tags must be balanced");

        let open_array = plist.matches("<array>").count();
        let close_array = plist.matches("</array>").count();
        assert_eq!(open_array, close_array, "array tags must be balanced");
    }

    #[test]
    fn test_plist_label_matches_name() {
        let name = "com.backup-shield.daily";
        let plist = generate_test_plist(
            name,
            "/opt/bin/backup-shield",
            &["backup", "/src", "--repo", "/repo"],
            "/work",
            "/logs/out.log",
            "/logs/err.log",
            Schedule::Daily,
        );

        assert!(
            plist.contains(&format!("<string>{}</string>", name)),
            "plist should contain the label string"
        );
    }

    #[test]
    fn test_plist_paths_are_absolute() {
        // All paths in the plist must be absolute (start with '/')
        let binary = "/usr/local/bin/backup-shield";
        let work_dir = "/Users/test/project";
        let stdout_path = "/Users/test/Library/Logs/backup-shield/backup-shield.log";
        let stderr_path = "/Users/test/Library/Logs/backup-shield/backup-shield-error.log";

        let plist = generate_test_plist(
            "com.backup-shield.weekly",
            binary,
            &[
                "backup",
                "/Users/test/Documents",
                "--repo",
                "/Users/test/backups",
            ],
            work_dir,
            stdout_path,
            stderr_path,
            Schedule::Weekly,
        );

        // Extract all <string> elements between <key>ProgramArguments</key> and next key
        // The first <string> after ProgramArguments is the binary path
        let program_section = plist
            .split("<key>ProgramArguments</key>")
            .nth(1)
            .unwrap_or("")
            .split("<key>WorkingDirectory</key>")
            .next()
            .unwrap_or("");

        // Check binary path
        assert!(
            program_section.contains(&format!("<string>{}</string>", binary)),
            "binary path must be absolute"
        );

        // Check WorkingDirectory is absolute
        assert!(
            plist.contains(&format!("<string>{}</string>", work_dir)),
            "WorkingDirectory must be absolute"
        );

        // Check StandardOutPath is absolute
        assert!(
            plist.contains(&format!("<string>{}</string>", stdout_path)),
            "StandardOutPath must be absolute"
        );

        // Check StandardErrorPath is absolute
        assert!(
            plist.contains(&format!("<string>{}</string>", stderr_path)),
            "StandardErrorPath must be absolute"
        );
    }

    #[test]
    fn test_plist_hourly_has_start_interval() {
        let plist = generate_test_plist(
            "com.backup-shield.hourly",
            "/usr/local/bin/backup-shield",
            &[],
            "/tmp",
            "/tmp/out.log",
            "/tmp/err.log",
            Schedule::Hourly,
        );

        assert!(
            plist.contains("<key>StartInterval</key>"),
            "hourly schedule should use StartInterval"
        );
        assert!(
            plist.contains("<integer>3600</integer>"),
            "hourly interval should be 3600 seconds"
        );
        assert!(
            !plist.contains("<key>StartCalendarInterval</key>"),
            "hourly schedule should NOT use StartCalendarInterval"
        );
    }

    #[test]
    fn test_plist_daily_has_calendar_interval() {
        let plist = generate_test_plist(
            "com.backup-shield.daily",
            "/usr/local/bin/backup-shield",
            &[],
            "/tmp",
            "/tmp/out.log",
            "/tmp/err.log",
            Schedule::Daily,
        );

        assert!(
            plist.contains("<key>StartCalendarInterval</key>"),
            "daily schedule should use StartCalendarInterval"
        );
        assert!(
            plist.contains("<integer>2</integer>"),
            "daily schedule should run at hour 2"
        );
        assert!(
            !plist.contains("<key>StartInterval</key>"),
            "daily schedule should NOT use StartInterval"
        );
    }

    #[test]
    fn test_plist_weekly_has_calendar_interval() {
        let plist = generate_test_plist(
            "com.backup-shield.weekly",
            "/usr/local/bin/backup-shield",
            &[],
            "/tmp",
            "/tmp/out.log",
            "/tmp/err.log",
            Schedule::Weekly,
        );

        assert!(
            plist.contains("<key>StartCalendarInterval</key>"),
            "weekly schedule should use StartCalendarInterval"
        );
        assert!(
            plist.contains("<integer>3</integer>"),
            "weekly schedule should run at hour 3"
        );
    }

    #[test]
    fn test_plist_contains_label() {
        let name = "com.backup-shield.hourly";
        let plist = generate_test_plist(
            name,
            "/test/binary",
            &[],
            "/tmp",
            "/tmp/out.log",
            "/tmp/err.log",
            Schedule::Hourly,
        );

        assert!(plist.contains(&format!("<key>Label</key>\n    <string>{}</string>", name)));
    }

    #[test]
    fn test_plist_run_at_load_false() {
        let plist = generate_test_plist(
            "com.backup-shield.hourly",
            "/test/binary",
            &[],
            "/tmp",
            "/tmp/out.log",
            "/tmp/err.log",
            Schedule::Hourly,
        );

        assert!(plist.contains("<key>RunAtLoad</key>\n    <false/>"));
    }

    #[test]
    fn test_plist_working_directory_present() {
        let work_dir = "/Users/andrerizzo/Documents/Projects/Backup-shield";
        let plist = generate_test_plist(
            "com.backup-shield.hourly",
            "/test/binary",
            &[],
            work_dir,
            "/tmp/out.log",
            "/tmp/err.log",
            Schedule::Hourly,
        );

        assert!(
            plist.contains("<key>WorkingDirectory</key>"),
            "plist must have WorkingDirectory key"
        );
        assert!(
            plist.contains(&format!("<string>{}</string>", work_dir)),
            "WorkingDirectory value must be present"
        );
    }

    #[test]
    fn test_plist_log_paths_in_home_library_logs() {
        let stdout_path = "/Users/test/Library/Logs/backup-shield/backup-shield.log";
        let stderr_path = "/Users/test/Library/Logs/backup-shield/backup-shield-error.log";

        let plist = generate_test_plist(
            "com.backup-shield.hourly",
            "/usr/local/bin/backup-shield",
            &["backup", "/Users/test"],
            "/Users/test",
            stdout_path,
            stderr_path,
            Schedule::Hourly,
        );

        assert!(
            plist.contains(&format!("<string>{}</string>", stdout_path)),
            "StandardOutPath must be in ~/Library/Logs/backup-shield/"
        );
        assert!(
            plist.contains(&format!("<string>{}</string>", stderr_path)),
            "StandardErrorPath must be in ~/Library/Logs/backup-shield/"
        );
        assert!(
            stderr_path.contains("backup-shield-error.log"),
            "stderr log file should be named backup-shield-error.log"
        );
    }

    #[test]
    fn test_plist_has_all_required_keys() {
        let plist = generate_test_plist(
            "com.backup-shield.hourly",
            "/usr/local/bin/backup-shield",
            &["backup", "/src", "--repo", "/repo"],
            "/work",
            "/logs/out.log",
            "/logs/err.log",
            Schedule::Hourly,
        );

        let required_keys = [
            "<key>Label</key>",
            "<key>ProgramArguments</key>",
            "<key>WorkingDirectory</key>",
            "<key>RunAtLoad</key>",
            "<key>StandardOutPath</key>",
            "<key>StandardErrorPath</key>",
        ];

        for key in &required_keys {
            assert!(plist.contains(key), "plist missing required key: {}", key);
        }
    }

    #[test]
    fn test_generate_snapshot_id_not_empty() {
        let id = generate_snapshot_id();
        assert!(!id.is_empty(), "snapshot ID should not be empty");
        assert!(id.len() >= 16, "snapshot ID should be at least 16 chars");
    }

    #[test]
    fn test_generate_snapshot_id_unique() {
        let id1 = generate_snapshot_id();
        let id2 = generate_snapshot_id();
        assert_ne!(id1, id2, "consecutive snapshot IDs should differ");
    }

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1), "1 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kb() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1024 * 1024 - 1), "1024.00 KB");
    }

    #[test]
    fn test_format_size_mb() {
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 10), "10.00 MB");
    }

    #[test]
    fn test_format_size_gb() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2.00 GB");
    }

    #[test]
    fn test_format_size_tb() {
        let tb = 1024u64 * 1024 * 1024 * 1024;
        assert_eq!(format_size(tb), "1.00 TB");
        assert_eq!(format_size(2 * tb), "2.00 TB");
    }

    #[test]
    fn test_compute_tree_stats_empty_dir() {
        let now = Utc::now();
        let dir = SnapshotNode::Directory(SnapshotDir {
            name: "".to_string(),
            modified: now,
            mode: 0o755,
            children: vec![],
        });
        let (size, chunks) = compute_tree_stats(&dir);
        assert_eq!(size, 0);
        assert_eq!(chunks, 0);
    }

    #[test]
    fn test_compute_tree_stats_single_file() {
        let now = Utc::now();
        let file = SnapshotNode::File(SnapshotFile {
            name: "test.txt".to_string(),
            size: 100,
            modified: now,
            mode: 0o644,
            chunk_hashes: vec!["abc".to_string(), "def".to_string()],
            file_hash: "".to_string(),
            versions: vec![],
            #[cfg(target_os = "windows")]
            windows_attributes: None,
            #[cfg(target_os = "windows")]
            windows_acl: None,
            #[cfg(target_os = "windows")]
            windows_ads: None,
        });
        let (size, chunks) = compute_tree_stats(&file);
        assert_eq!(size, 100);
        assert_eq!(chunks, 2);
    }

    #[test]
    fn test_count_files_single_file() {
        let now = Utc::now();
        let file = SnapshotNode::File(SnapshotFile {
            name: "a.txt".to_string(),
            size: 10,
            modified: now,
            mode: 0o644,
            chunk_hashes: vec![],
            file_hash: "".to_string(),
            versions: vec![],
            #[cfg(target_os = "windows")]
            windows_attributes: None,
            #[cfg(target_os = "windows")]
            windows_acl: None,
            #[cfg(target_os = "windows")]
            windows_ads: None,
        });
        assert_eq!(count_files(&file), 1);
    }

    #[test]
    fn test_count_files_symlink() {
        let sym = SnapshotNode::Symlink(SnapshotSymlink {
            name: "link".to_string(),
            target: "/nonexistent".to_string(),
        });
        assert_eq!(count_files(&sym), 0);
    }

    #[test]
    fn test_compute_hash() {
        let hash = compute_hash(b"hello world");
        assert_eq!(hash.len(), 64);
        // Known SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_file_hash() {
        let hashes = vec!["a".to_string(), "b".to_string()];
        let result = compute_file_hash(&hashes);
        assert_eq!(result.len(), 64);
    }
}
