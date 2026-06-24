# Build Backup-shield su Windows

## Requisiti
- Rust 1.75+ (installato tramite https://rustup.rs)
- Visual Studio Build Tools o Visual Studio con workload "Desktop development with C++"
- Git (opzionale)

## Passi

```cmd
:: 1. Installare Rust (se non già installato)
::    Scaricare e seguire le istruzioni su https://rustup.rs

:: 2. Clonare o estrarre il progetto
cd C:\path\to\project

:: 3. Compilare (release)
cargo build --release --manifest-path Backup-shield\Cargo.toml -p backup-shield-cli

:: 4. Il binario si trova in
Backup-shield\target\release\backup-shield.exe
```

## Note
- Per VSS (Volume Shadow Copy): il modulo è uno stub. Serve Windows 10+ e admin.
- Per creazione symlink in restore: serve Windows 10+ in Developer Mode o Admin.
- Per schedulazione automatica: `setup-windows-task` richiede Admin.
