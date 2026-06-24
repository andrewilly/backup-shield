# BackupShield

**Cross-platform incremental backup with data integrity and auto-repair.**

BackupShield è un sistema di backup incrementale scritto in Rust, progettato per macOS, Windows e Linux. Protegge i tuoi dati con deduplicazione content-defined, crittografia AES-256-GCM, compressione zstd, verifica d'integrità gerarchica e riparazione automatica tramite Reed-Solomon.

## Caratteristiche principali

- **Backup incrementale** con chunking content-defined (Buzhash) — solo i dati cambiati vengono salvati
- **Deduplicazione** a livello di chunk — risparmio di spazio su versioni multiple
- **Crittografia AES-256-GCM** — ogni chunk è cifrato con nonce casuale (12 byte)
- **Compressione zstd** — compressione rapida con livelli 1–22
- **Verifica d'integrità** a 3 livelli (chunk → file → snapshot)
- **Auto-riparazione** con codici Reed-Solomon (64+8 shard) — ripara chunk corrotti/mancanti
- **Scrub periodico** — verifica e ripara automaticamente i dati archiviati
- **Snapshot APFS** (macOS) — backup point-in-time del filesystem
- **VSS** (Windows) — Volume Shadow Copy (stub, richiede crate windows aggiornato)
- **Cross-platform** — funziona su macOS, Windows e Linux
- **CLI completa** con scheduling automatico (Launchd su macOS, Task Scheduler su Windows)

## Installazione

```bash
git clone https://github.com/andrewilly/backup-shield.git
cd backup-shield
cargo build --release -p backup-shield-cli
```

Il binario si trova in `target/release/backup-shield`.

## Utilizzo rapido

```bash
# Inizializza un repository
backup-shield init --repo /path/to/repo

# Esegui un backup
backup-shield backup /path/to/source --repo /path/to/repo

# Verifica l'integrità
backup-shield verify --repo /path/to/repo

# Elenca gli snapshot
backup-shield snapshots --repo /path/to/repo

# Ripristina l'ultimo snapshot
backup-shield restore latest --repo /path/to/repo --target /path/to/restore

# Scrub periodico (verifica + ripara)
backup-shield scrub --repo /path/to/repo
```

## Architettura

```
backup-shield/
├── crates/
│   ├── core/        — chunker, repository, pack, snapshot, watcher
│   ├── crypto/      — AES-256-GCM, Argon2 key derivation
│   ├── compression/ — zstd compress/decompress
│   ├── ecc/         — Reed-Solomon erasure coding
│   ├── storage/     — backend locale, S3, SFTP (stub), WebDAV (stub)
│   ├── verify/      — verifica 3 livelli + scrub
│   ├── restore/     — ripristino file e directory
│   └── cli/         — interfaccia a riga di comando
├── scripts/         — helper script (GUI web, scheduling, recovery)
└── tests/           — test di integrazione
```

## Licenza

Copyright (c) 2026 André Willy Rizzo. All rights reserved.
