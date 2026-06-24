# Roadmap alla Produzione — BackupShield v1.0

> Stato attuale: **v0.7.0 — Beta avanzata** (maturità 5/10)
> Target: **v1.0.0 — Produzione** (maturità 8/10+)
> 
> Questa roadmap è il risultato di un audit completo del codice (31 file .rs, ~13.000 righe Rust, 162 test, script Python/shell/batch, scheduling macOS/Windows).
> 
> **Priorità**: P0 = bloccante (produzione impossibile), P1 = critico, P2 = importante, P3 = miglioramento

---

## Indice

1. [Bloccanti trasversali (P0)](#1-bloccanti-trasversali-p0)
2. [MacOS (@macos-dev)](#2-macos)
3. [Windows (@windows-dev)](#3-windows)
4. [Core (entrambi)](#4-core-da-coordinare-tra-i-dev)
5. [Testing](#5-testing)
6. [Infrastruttura](#6-infrastruttura)
7. [Roadmap temporale](#7-roadmap-temporale)

---

## 1. Bloccanti Trasversali (P0)

Questi blocchi impediscono *qualsiasi* uso in produzione, su qualsiasi piattaforma.

### 1.1 File locking — assente ❌

**Problema**: Due processi BackupShield che scrivono concorrentemente sullo stesso repository corrompono l'indice. Non esiste alcun meccanismo di locking (file lock, flock, lock file).

**File coinvolti**:
- `crates/core/src/repository.rs` — `save_index()` scrive `indexes/chunk_index.json` senza lock
- `crates/core/src/repository.rs` — `pack_writer.flush()` scrive pack senza rename atomico
- `crates/core/src/pack.rs:192-203` — checksum del pack scritto in una finestra separata
- `crates/core/src/pack.rs:522-528` — `compact_packs()` cancella pack mentre altri leggono

**Fix richiesto**:
1. Introdurre `fs2` crate (o `rustix`) per `flock()`/`lock_exclusive()` sul repository
2. Scrivere i pack file con `.tmp` estensione e rinominarli atomicamente
3. Usare write-ahead log per l'indice chunk (o quantomeno un lock scrittore)
4. Aggiungere test di concorrenza

### 1.2 Storage remoti — stub, non implementati ❌

**Problema**: I backend S3, SFTP e WebDAV sono stub al 100% — ogni metodo ritorna `StorageError::NotImplemented`.

**File coinvolti**:
- `crates/storage/src/s3.rs` — 16 metodi stub
- `crates/storage/src/sftp.rs` — 16 metodi stub
- `crates/storage/src/webdav.rs` — 16 metodi stub

**Fix richiesto**: Implementare almeno **un** backend remoto (S3 è il priority #1). Il trait `StorageBackend` è ben progettato, manca solo l'implementazione.

**Consiglio**: Iniziare con `reqwest` + `aws-sdk-s3` (o `rust-s3` crate) per S3. SFTP può usare `ssh2` crate. WebDAV con `reqwest` + `webdav-handler`.

### 1.3 `free_space()` ritorna sempre `u64::MAX` ❌

**Problema**: `LocalStorage::free_space()` in `crates/storage/src/local.rs:326` ignora silenziosamente l'errore di `fs::metadata()` e ritorna `u64::MAX`. Il controllo limite spazio non funziona.

**Fix**: Implementare `fs::available_space()` (stabilizzato in Rust 1.75+) o usare `fs2::available_space()`.

### 1.4 `panic!()` nella GF(256) arithmetic (produzione) ❌

**Problema**: `crates/ecc/src/reed_solomon.rs:76,91` contiene `panic!("GF(256) division by zero")` e `panic!("GF(256) inverse of zero is undefined")`. In produzione, dati corrotti in input possono far panicare l'intero processo.

**Fix**: Sostituire con `Result<_, EccError>`. Aggiungere validazione input a monte.

### 1.5 Password in chiaro nel terminale ❌

**Problema**: `main.rs:3102-3106` — `get_password()` fa l'echo della password in terminale. Nessun uso di `rpassword` o `-silent`.

**Fix**: Usare `rpassword` crate per `read_password()`. Nascondere l'input.

### 1.6 Snapshot ID con PRNG debole ⚠️

**Problema**: `main.rs:3136-3150` — `generate_snapshot_id()` usa xorshift basato su timestamp. Le snapshot ID sono prevedibili. Inconsistenza: `Snapshot::generate_id()` in `snapshot.rs` usa correttamente `OsRng`.

**Fix**: Usare `OsRng` uniformemente. Rimuovere la funzione in linea e chiamare `Snapshot::generate_id()`.

---

## 2. macOS (@macos-dev)

### 2.1 File watching FSEvents (P1)

**Obbiettivo**: Backup incrementali senza scansionare l'intero albero.

**Da fare**:
1. Aggiungere dipendenza da `core-foundation` e `fsevents-sys` (o usare `notify` crate con backend FSEvents)
2. Creare un modulo `watcher` che registri callback FSEvents per le directory sorgente
3. Integrare col backup: alla ricezione di eventi, accumulare path modificati e al prossimo backup processare solo quelli
4. Aggiungere un flag `--watch` o un demone `backup-shieldd`
5. Test: creare file, modificare, rinominare, cancellare — verificare che solo i file cambiati vengano processati

**File**: Nuovo file `crates/core/src/watcher.rs` (o crate separato `backup-shield-watcher`)

### 2.2 Integrazione APFS Snapshot (P1)

**Obbiettivo**: Backup atomici point-in-time usando snapshot nativi APFS.

**Da fare**:
1. Usare `tmutil localsnapshot` per creare snapshot APFS del volume sorgente
2. Montare lo snapshot APFS in `/tmp/.backupshield-snapshot-XXXX/`
3. Eseguire il backup sullo snapshot montato (garanzia di consistenza)
4. Smontare e cancellare lo snapshot APFS a backup completato
5. Aggiungere opzione `--apfs-snapshot` a `backup` e `system-backup`
6. Test con `diskutil apfs listSnapshots`

### 2.3 Scheduling launchd nativo (P1)

**Problema attuale**: `main.rs:2977` genera un `.plist` ma non lo carica automaticamente.

**Da fare**:
1. Completare `setup_schedule()` su macOS: dopo aver scritto il `.plist`, eseguire `launchctl load -w /Users/.../Library/LaunchAgents/com.backupshield.daemon.plist`
2. Aggiungere `launchctl start com.backupshield.daemon`
3. Aggiungere `launchctl unload` per `unschedule`
4. Verificare permessi e path assoluti nel plist

### 2.4 Integrazione Recovery Mode (P2)

**Problema**: Lo script di recovery esiste (`scripts/recovery-macos.sh`) ma ha un loop infinito e non è integrato col flusso principale.

**Da fare**:
1. Fixare lo script recovery (bug loop infinito a linea 43)
2. Completare `cmd_create_recovery_usb` in `main.rs:2182-2277`
3. Assicurarsi che la chiave di crittografia venga copiata in modo sicuro (oggi viene stampata in chiaro)
4. Testare su una VM macOS: boot da Recovery USB, eseguire restore

### 2.5 Path hardcoded macOS (P2)

**Da fare**: Sostituire tutti i path Unix hardcoded con costanti configurabili:

| File | Line | Path | Fix |
|------|------|------|-----|
| `crates/core/src/system.rs` | 132 | `/Applications` | Usare `SystemManifest` con enumerazione |
| `crates/core/src/system.rs` | 169-173 | `/Applications`, `/Library`, `/Users`, `/usr/local` | Rendere configurabili |
| `crates/cli/src/main.rs` | 2245-2259 | `/Volumes/BACKUPSHIELD` | Parametrizzare il mount point |
| `crates/cli/src/main.rs` | 2977 | `Library/LaunchAgents` | Usare `dirs::home_dir()` |

### 2.6 Performance profiling (P3)

**Da fare**:
1. Usare Instruments (xctrace) per profilare backup/restore
2. Ottimizzare chunking per file grandi (buffer mmap vs read)
3. Benchmark: 10GB di file misti, misurare throughput MB/s
4. Confrontare con restic, kopia, Borg

---

## 3. Windows (@windows-dev)

### 3.1 Volume Shadow Copy (VSS) (P0-P1)

**Obbiettivo**: Backup consistenti di file aperti.

**Da fare**:
1. Usare `winapi` / `windows-rs` crate per interfacciarsi con Volume Shadow Copy Service
2. Creare uno snapshot VSS del volume sorgente
3. Eseguire backup sul mount point dello snapshot
4. Rilasciare lo snapshot
5. Aggiungere flag `--vss` a `backup`
6. Test con file lockati (Outlook PST, DB SQLite, etc.)

### 3.2 Attributi NTFS (P1)

**Problema**: Permessi e attributi Windows non sono mai letti né scritti.

**Da fare**:
1. Aggiungere lettura di: ACL (`GetNamedSecurityInfo`), ADS (`BackupRead`), attributi di compressione/cifratura
2. Arricchire `FileEntry` nel chunk index con metadati Windows
3. Durante restore: applicare ACL e attributi via `SetNamedSecurityInfo`
4. Test: backup/restore di file con permessi granulari, file con ADS, file compressi

### 3.3 Symlink su Windows (P1)

**Problema**: `main.rs:1370-1376` e `restore.rs:599-606` loggano un warning e **saltano** i symlink su Windows.

**Da fare**:
1. Sostituire `#[cfg(not(unix))] { warn!("...") }` con implementazione reale:
   ```rust
   #[cfg(windows)]
   fn create_symlink(target: &Path, link: &Path) -> io::Result<()> {
       if target.is_dir() {
           std::os::windows::fs::symlink_dir(target, link)
       } else {
           std::os::windows::fs::symlink_file(target, link)
       }
   }
   ```
2. Test: creare symlink, backup, restore su Windows, verificare integrità

### 3.4 Task Scheduler funzionante (P1)

**Problema**: `main.rs:3037-3091` (`setup_windows_task()`) stampa solo istruzioni, non crea il task.

**Da fare**:
1. Usare `windows-rs` (o `schannel`) per creare il task programmaticamente via Task Scheduler COM interface
2. Alternativa: generare XML valido e importarlo con `schtasks.exe /create`
3. Aggiungere `unschedule` su Windows che cancella il task
4. Test: creazione task, esecuzione schedulata, cancellazione

### 3.5 Path separators (P1)

**Verificare** che tutti i path costruiti usino `Path::join()` e non string concatenation. I test esistenti non coprono percorsi Windows.

**Da fare**:
1. Aggiungere test case con `\` separators, drive letters (`C:`), UNC paths (`\\server\share`)
2. Verificare `validate_symlink_target()` su Windows path
3. Controllare `chunk_subdir()` in `local.rs` (usa format! con `/`)

### 3.6 Binary name e permessi (P2)

**Problema**: `main.rs:2432` fa `chmod +x` che non esiste su Windows.

**Fix**: Già gestito con `#[cfg(unix)]` ma va verificato che il `.exe` su Windows abbia estensione corretta (giusto a riga 2422-2427, ma controllare che sia sempre `.exe` anche in altri punti).

### 3.7 Stato attuale script batch (.bat/.ps1) (P2)

**Problemi dall'audit**:
- `scripts/install-schedule.ps1:5` — path binario `backup-shield` vs `backup-shield.exe`
- `scripts/install-schedule.ps1:14` — scrive in `$env:USERPROFILE\AppData\Roaming\backup-shield-config.json` ma non è chiaro se la struttura config matcha
- `scripts/backup-shield.bat:58` — errore di sintassi nel batch

**Da fare**: Testare TUTTI gli script su una Windows VM, fixare errori, documentare prerequisiti PowerShell version.

---

## 4. Core (da coordinare tra i dev)

### 4.1 Remove dead code (P2)

**Da fare**:
1. Verificare se `crates/restore/src/restore.rs` è usato — il CLI ha la propria logica di restore in linea. Se non usato, rimuovere o refactorizzare il CLI per usare la crate.
2. `Snapshot::build_from_path()` in `snapshot.rs:149-173` — non chiamato dal CLI (che ha `build_snapshot_tree()`). Rimuovere o unificare.
3. `Snapshot::get_all_versions()` in `snapshot.rs:391-406` — commento dice "implemented in CLI". Rimuovere.

### 4.2 Eliminare `std::mem::forget(dir)` nei test (P2)

**Problema**: `pack.rs:617-623`, `checker.rs:572`, `scrub.rs:412` usano `std::mem::forget(dir)` per evitare cleanup. Perdita di risorse.

**Fix**: Refactorizzare i test con `TestRepoBuilder` o assicurarsi che TempDir venga droppato correttamente.

### 4.3 Codice duplicato: `validate_symlink_target()` (P2)

**Problema**: Stessa identica funzione in `main.rs:1111-1129` e `restore.rs:10-27`.

**Fix**: Estrarre in `crates/core/src/` (o `crates/storage/src/fs_utils.rs`) e importare da entrambi i punti.

### 4.4 Config: compression_level 0 non valido (P3)

**Problema**: `config.rs:78` richiede `compression_level >= 1`, ma Zstandard accetta livello 0 (nessuna compressione). Utile per debug o dati già compressi.

### 4.5 Gestione errori silenziosi (P1)

**Da fare**: Sostituire i pattern `.filter_map(|e| e.ok())` in tutto il codebase con log più espliciti. Almeno `log::warn!()` per ogni errore saltato.

**File principali**:
- `main.rs:2672` — `filter_map(|e| e.ok())` nella directory listing
- `repository.rs:489,517,526,535,544` — `stats()` e `calculate_disk_usage()` saltano errori
- `snapshot.rs:207,217,247,422` — scansione directory e snapshot

### 4.6 `restore` crate non gestisce crittografia (P1)

**Problema**: `restore.rs:441` chiama `repo.read_chunk(chunk_hash)` che ritorna dati cifrati, ma non chiama mai `decrypt_chunk()`. La decifratura è fatta solo nel CLI inline.

**Fix**: Aggiungere `decrypt_chunk()` in restore con parametro `is_encrypted` dal config, oppure far sì che il CLI usi la `restore` crate invece del suo restore inline.

---

## 5. Testing

### 5.1 Test end-to-end (P0)

**Da creare**: Un test che esegue l'intero pipeline:
```rust
#[test]
fn test_end_to_end_backup_restore() {
    let tmp = TempDir::new()?;
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    let restore_path = tmp.path().join("restore");
    
    // 1. Crea file di test (testo, binario, vuoto, symlink, permessi vari)
    create_test_files(&source);
    
    // 2. Init repository
    let repo = init_repo(repo_path, compression, encryption)?;
    
    // 3. Backup
    let snapshot_id = backup_directory(&repo, &source)?;
    
    // 4. Verify
    let verifier = Verifier::new(&repo_path)?;
    verifier.verify(VerifyLevel::Full)?;
    
    // 5. Scrub & repair (con corruzione introdotta)
    
    // 6. Restore
    restore_snapshot(&repo, &snapshot_id, &restore_path)?;
    
    // 7. Byte-compare source vs restored
    assert_directories_equal(&source, &restore_path)?;
}
```

### 5.2 Test CLI (P0)

**Da creare**: Test per ogni comando della CLI (argparse + esecuzione base):
- `cmd_init`, `cmd_backup`, `cmd_restore`, `cmd_verify`, `cmd_repair`, `cmd_prune`, `cmd_compact`
- Flag obbligatori/mancanti
- Path non validi
- Opzioni di compressione/crittografia

**Suggerimento**: Usare `assert_cmd` o `trycmd` crate per test di integrazione CLI.

### 5.3 Test prune/compact (P1)

**Da creare**:
1. Creare N snapshot, eseguire prune con retention giornaliera/settimanale/mensile, verificare che solo quelli giusti sopravvivano
2. Creare chunk orfani, eseguire compact, verificare che i pack vengano riscritti
3. Test auto-prune per limite di spazio

### 5.4 Test concorrenza (P1)

**Da creare**:
1. Due thread che scrivono chunk concorrentemente
2. Scrittura e lettura concorrente
3. Backup mentre un altro processo fa prune

### 5.5 Test corruzione e riparazione (P1)

**Da creare**:
1. Backup file, corrompere chunk su disco (bit flip), eseguire verify -> deve rilevare
2. Eseguire repair -> deve ricostruire da parity
3. Fare restore -> file deve essere identico all'originale

### 5.6 Test path cross-platform (P1)

**Da creare** (eseguibili su CI Windows e macOS):
- Path con spazi, caratteri Unicode, emoji, punti iniziali
- Path lunghi (>260 char su Windows, >1024 su Unix)
- Drive letters su Windows

### 5.7 Migliorare harness di test (P2)

**Da fare**: Centralizzare in `test_utils.rs` o `TestRepoBuilder`:
- `TestRepoBuilder::new()` -> `build()` che crea tempdir + init repo
- `TestRepoBuilder::with_compression()` / `with_encryption()`
- `TestRepoBuilder::with_source_files()` per creare fixture

---

## 6. Infrastruttura

### 6.1 CI/CD (P0)

**Da creare**: workflow GitHub Actions (`.github/workflows/ci.yml`) con:
1. `cargo check` su macOS, Windows, Linux (matrix)
2. `cargo test --all` su tutte le piattaforme
3. `cargo clippy -- -D warnings`
4. `cargo fmt --check`
5. Build degli script e verifica sintassi

### 6.2 Clippy lint (P1)

**Da fare**: Eseguire `cargo clippy -- -D warnings` e fixare tutti i warning. I warn più probabili:
- `unwrap_used` (da abilitare `#[deny(unwrap_used)]` nelle crate production)
- `panic` prevention
- `filter_map_next`

### 6.3 Secure memory per chiavi (P1)

**Problema**: `s3.rs:29-31`, `webdav.rs:24-25` tengono secret key/password in `String` plaintext.

**Fix**: Usare `secrecy` crate (`SecretString` che zeroa su drop) per tutte le credenziali. Applicare anche a master key in memoria.

### 6.4 Gitignore + repo init (P2)

**Da creare**:
- `.gitignore` standard per Rust (`/target/`, `*.pyc`, etc.)
- Inizializzare il repository git con messaggio significativo

### 6.5 Documentazione utente (P2)

**Da creare**:
- `docs/quickstart.md` — esempio concreto: init, backup, restore
- `docs/configuration.md` — spiegazione di tutti i parametri di config
- `docs/security.md` — come funziona la crittografia, gestione chiavi
- `docs/recovery.md` — come fare restore da Recovery Mode (macOS) o Recovery Environment (Windows)
- `docs/integrity.md` — spiegazione di Reed-Solomon, parity, scrub, repair

### 6.6 Dockerfile (P2)

**Opzionale**: Container per eseguire backup schedulati in ambienti server/Linux.

### 6.7 Release automation (P3)

**Da creare**:
- Script di release che produce `.tar.gz` (macOS/Linux) e `.zip` (Windows) con binario + scripts
- Alternativa: usare `cargo-dist` per automazione release su GitHub

---

## 7. Roadmap Temporale

### Fase 1 — Fundamento (2-3 settimane, lavoro parallelo)

| Task | Chi | Priorità |
|------|-----|----------|
| File locking + atomic writes | Core | P0 |
| `free_space()` | Core | P0 |
| Clippy + fix panic GF256 | Core | P0 |
| Password non in chiaro | Core | P0 |
| CI/CD GitHub Actions | Infra | P0 |
| Test end-to-end | Testing | P0 |
| Test CLI | Testing | P0 |

### Fase 2 — Piattaforma macOS (2 settimane)

| Task | Chi | Priorità |
|------|-----|----------|
| FSEvents file watching | @macos-dev | P1 |
| APFS snapshot integration | @macos-dev | P1 |
| launchd scheduling completo | @macos-dev | P1 |
| Fix path hardcoded | @macos-dev | P2 |
| Fix recovery script | @macos-dev | P2 |

### Fase 3 — Piattaforma Windows (2-3 settimane)

| Task | Chi | Priorità |
|------|-----|----------|
| VSS integration | @windows-dev | P0-P1 |
| Symlink su Windows | @windows-dev | P1 |
| Attributi NTFS | @windows-dev | P1 |
| Task Scheduler reale | @windows-dev | P1 |
| Path separators | @windows-dev | P1 |
| Fix script .bat/.ps1 | @windows-dev | P2 |

### Fase 4 — Storage remoto (2-3 settimane)

| Task | Chi | Priorità |
|------|-----|----------|
| Backend S3 funzionante | Core | P1 |
| Secure memory credenziali | Core | P1 |
| Test network failure | Core | P1 |

### Fase 5 — Robustezza (2 settimane)

| Task | Chi | Priorità |
|------|-----|----------|
| Remove dead code | Core | P2 |
| Elimina codice duplicato | Core | P2 |
| Error handling silenziosi | Core | P1 |
| Fix `restore` + crittografia | Core | P1 |
| Test corruzione/riparazione | Testing | P1 |
| Test prune/compact | Testing | P1 |
| Test concorrenza | Testing | P1 |
| Test path cross-platform | Testing | P1 |

### Fase 6 — Documentazione e release (1 settimana)

| Task | Chi | Priorità |
|------|-----|----------|
| Documentazione utente | Core | P2 |
| Release automation | Infra | P3 |
| Benchmark prestazioni | Core | P3 |

---

## Riepilogo Bloccanti per la Produzione

Per passare da "prototipo funzionante" a "strumento production-ready", i **blocchi reali** sono:

1. **File locking** — senza, due backup concorrenti corrompono il repository
2. **CI/CD** — senza, ogni modifica è un atto di fede su Windows e Linux
3. **Test end-to-end** — oggi 0 test che eseguono l'intero pipeline
4. **Un backend remoto** (S3) — il tool è confinato a backup locali

Tutto il resto (FSEvents, VSS, APFS snapshot) sono miglioramenti importanti ma non bloccanti: il tool **funziona già** su macOS senza di essi, solo meno efficientemente.

---

*Roadmap generata il 25 Maggio 2026 — Andre Willy Rizzo*
