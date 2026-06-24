<div align="center">
  <h1>🛡️ BackupShield</h1>
  <p><strong>Cross‑platform incremental backup with data integrity and auto‑repair.</strong></p>

  <p>
    <a href="https://github.com/andrewilly/backup-shield/actions"><img src="https://img.shields.io/github/actions/workflow/status/andrewilly/backup-shield/ci.yml?branch=main&label=CI&logo=github" alt="CI"></a>
    <a href="https://github.com/andrewilly/backup-shield/releases"><img src="https://img.shields.io/github/v/release/andrewilly/backup-shield?logo=rust" alt="Release"></a>
    <a href="https://github.com/andrewilly/backup-shield/blob/main/LICENSE.txt"><img src="https://img.shields.io/badge/license-proprietary-red.svg" alt="License"></a>
    <br>
    <img src="https://img.shields.io/badge/macOS-Intel%20%7C%20Apple%20Silicon-lightgrey?logo=apple" alt="macOS">
    <img src="https://img.shields.io/badge/Linux-x86__64-lightgrey?logo=linux" alt="Linux">
    <img src="https://img.shields.io/badge/Windows-x86__64-lightgrey?logo=windows" alt="Windows">
  </p>
</div>

---

BackupShield is a **cross‑platform incremental backup engine** written in Rust. It combines content‑defined chunking, zstd compression, AES‑256‑GCM encryption, Reed–Solomon erasure coding, and three‑level integrity verification to keep your data safe — whether you're backing up a laptop, a server, or a multi‑OS environment.

## ✨ Features

| Capability | Detail |
|---|---|
| **Incremental backups** | Content‑defined chunking (Buzhash) — only changed data is stored |
| **Deduplication** | Identical chunks are stored once, regardless of which files reference them |
| **Compression** | Per‑chunk zstd compression (levels 1–22, default 3) |
| **Encryption** | AES‑256‑GCM with random 12‑byte nonce per chunk |
| **Integrity verification** | 3‑level: chunk SHA‑256 → file hash → snapshot structure |
| **Self‑healing** | Reed–Solomon erasure coding (64+8 shards) repairs corrupt or missing chunks |
| **Periodic scrubbing** | Scans all chunks, verifies pack file checksums, auto‑repairs via parity |
| **Atomic writes** | Every write uses tmp‑file + fsync + rename — no partial writes |
| **Filesystem snapshots** | APFS snapshots (macOS), VSS (Windows, stub) |
| **Automatic scheduling** | Launchd (macOS) or Task Scheduler (Windows) |
| **CLI interface** | Full command‑line tool with subcommands |
| **Cross‑platform** | macOS (Intel + Apple Silicon), Linux, Windows |

## 📦 Download

Get the latest binary from the [Releases page](https://github.com/andrewilly/backup-shield/releases/latest).

| Platform | File | Architecture |
|---|---|---|
| **macOS** | `backup-shield-macos-universal.gz` | Intel + Apple Silicon (universal) |
| **Linux** | `backup-shield-linux-amd64.gz` | x86_64 |
| **Windows** | `backup-shield-windows-amd64.gz` | x86_64 |

```bash
# macOS / Linux
gunzip -c backup-shield-macos-universal.gz > backup-shield
chmod +x ./backup-shield
sudo mv ./backup-shield /usr/local/bin/

# Verify it works
backup-shield --help
```

## 🚀 Quick Start

```bash
# 1. Create a backup repository
backup-shield init --repo /path/to/backups

# 2. Back up a directory
backup-shield backup /path/to/source --repo /path/to/backups

# 3. List all snapshots
backup-shield snapshots --repo /path/to/backups

# 4. Verify integrity
backup-shield verify --repo /path/to/backups

# 5. Restore the latest snapshot
backup-shield restore latest --repo /path/to/backups --target /path/to/restore

# 6. Periodic scrub (verifies + repairs via parity)
backup-shield scrub --repo /path/to/backups
```

### With encryption

```bash
backup-shield init --repo /path/to/backups
backup-shield backup /path/to/source --repo /path/to/backups --encrypt
# You will be prompted for a password
```

### With compression

```bash
backup-shield backup /path/to/source --repo /path/to/backups --compression 9
```

### Automatic scheduling

```bash
# Schedule hourly backups (macOS: launchd, Windows: Task Scheduler)
backup-shield schedule hourly --repo /path/to/backups --source /path/to/source

# Remove all schedules
backup-shield unschedule
```

## 🧱 Architecture

```
backup-shield/
├── crates/
│   ├── core/          # Chunker, repository, pack files, snapshots, file watcher
│   ├── crypto/        # AES-256-GCM encryption, Argon2 key derivation
│   ├── compression/   # zstd compress / decompress with size‑limited allocator
│   ├── ecc/           # Reed–Solomon erasure coding (Vandermonde matrix)
│   ├── storage/       # Local backend (S3, SFTP, WebDAV stubs)
│   ├── verify/        # 3‑level integrity checker + periodic scrubber
│   ├── restore/       # File and directory restore with Windows attrs support
│   └── cli/           # Command‑line interface (clap)
├── scripts/           # Helper scripts (web GUI, scheduling, recovery)
└── tests/             # Integration tests (CLI, end‑to‑end, paths)
```

### Storage Layout

```
<repo_path>/
├── config.toml          # Repository configuration
├── .backup-shield.lock  # Exclusive flock
├── data/
│   ├── pack-000001.pack # Chunk pack files (~20 MB each)
│   └── pack-000002.pack
├── snapshots/
│   └── <snapshot_id>.json  # Snapshot metadata
├── indexes/
│   └── chunk_index.json    # Hash → (pack_id, offset, size)
├── parity/
│   └── parity_index.json   # Reed–Solomon parity groups
└── keys/
    └── master.key          # Encrypted master key (Argon2id)
```

## 🔒 Integrity Chain

Every file is protected by a three‑level integrity chain:

```
Level 1 — Chunk        SHA‑256(chunk_content) == chunk_hash
Level 2 — File         SHA‑256(concatenated chunk_hashes) == file_hash in snapshot
Level 3 — Snapshot     Snapshot JSON is structurally valid
```

When `scrub` detects corruption, Reed–Solomon parity automatically repairs the damaged chunks.

## 🛠️ Building from Source

### Prerequisites

- **Rust 1.75+** ([rustup.rs](https://rustup.rs))
- **C compiler** (for zstd‑sys)

### Build

```bash
git clone https://github.com/andrewilly/backup-shield.git
cd backup-shield
cargo build --release -p backup-shield-cli
```

The binary is at `target/release/backup-shield` (or `backup-shield.exe` on Windows).

### Run tests

```bash
cargo test --release
```

## ⚙️ Configuration

Repository settings are stored in `config.toml`:

```toml
compression_level = 3           # zstd level (1–22)
chunk_min_size = 65536          # 64 KB
chunk_target_size = 524288      # 512 KB
chunk_max_size = 8388608        # 8 MB
ecc_data_shards = 64            # Reed–Solomon data shards
ecc_parity_shards = 8           # Reed–Solomon parity shards
pack_target_size = 20971520     # 20 MB per pack file
```

## 📜 License

Copyright (c) 2026 André Willy Rizzo. All rights reserved.

---

<div align="center">
  <sub>Built with ❤️ and 🦀 Rust</sub>
</div>
