# Windows Compilation Fixes — BackupShield v0.8.0

## Problema
Il progetto compilava su macOS ma non su Windows a causa di API changes nella crate `windows` 0.62.2 e assenza di `#[cfg]` gates su codice macOS-specifico.

---

## 1. `crates/core/Cargo.toml`

| Modifica | Dettaglio |
|----------|-----------|
| Aggiunto | `"Win32_Security_Authorization"` — necessario per `GetNamedSecurityInfoW`, `SetNamedSecurityInfoW`, `SE_FILE_OBJECT` che in windows 0.62 sono stati spostati da `Security` a `Security::Authorization` |
| Rimosso | `"Win32_System_Memory"` — inutilizzato (`LocalFree` è ora in `Foundation`) |

---

## 2. `crates/core/src/vss.rs`

| Errore | Fix |
|--------|-----|
| `unresolved import windows::Win32::System::Vss` | Il modulo VSS è in `Storage::Vss`, non `System::Vss` |
| `IVssBackupComponents`, `VssBackupComponents` non esistono in windows 0.62.2 | **Modulo riscritto come stub.** La crate windows 0.62.2 non include i bindings COM per `IVssBackupComponents`. A runtime restituisce un errore. Per una VSS funzionante serve un upgrade della crate windows (es. ≥ 0.60 ha cambiato struttura). |

---

## 3. `crates/core/src/windows_attrs.rs`

### Import
| Simbolo | Dove era | Dove è ora |
|---------|----------|------------|
| `GetNamedSecurityInfoW` | `windows::Win32::Security` | `windows::Win32::Security::Authorization` |
| `SetNamedSecurityInfoW` | `windows::Win32::Security` | `windows::Win32::Security::Authorization` |
| `SE_FILE_OBJECT` | `windows::Win32::Security` | `windows::Win32::Security::Authorization` |
| `LocalFree` | `windows::Win32::System::Memory` | `windows::Win32::Foundation` |
| `SetFileSecurityW` | `windows::Win32::Storage::FileSystem` | `windows::Win32::Security` |
| `ERROR_MORE_DATA` | (importato) | rimosso (inutilizzato) |
| `OsStr` | (importato) | rimosso (inutilizzato) |

### API changes windows 0.62.2

| Funzione | Cambiamento | Fix |
|----------|-------------|-----|
| `GetFileAttributesW` | Torna `u32`, non `FILE_FLAGS_AND_ATTRIBUTES`. `INVALID_FILE_ATTRIBUTES` è `u32::MAX`, non un tipo separato. | Confronto con `u32::MAX`. |
| `SetFileAttributesW` | Torna `Result<()>`, non BOOL. | Usato `.is_err()` invece di `.as_bool()`. |
| `FILE_ATTRIBUTE_*` | Sono `FILE_FLAGS_AND_ATTRIBUTES(pub u32)` (newtype). | Accesso a `.0` per bitwise, costruzione con `FILE_FLAGS_AND_ATTRIBUTES(valore)`. |
| `WIN32_ERROR` | Non implementa `Display`. | Uso di `{:?}` (Debug). |
| `GetSecurityDescriptorLength` | Parametro vuole `PSECURITY_DESCRIPTOR` non `*mut SECURITY_DESCRIPTOR`. | Cambiato tipo variabile. |
| `LocalFree` | Prende `Option<HLOCAL>`. | Usato `LocalFree(Some(HLOCAL(sd.0)))`. |
| `FindFirstStreamW` | `dwflags` è `Option<u32>` non `0`. Stream data è `*mut c_void`. | Cast esplicito, `Some(0)`. |
| `FindNextStreamW` | Torna `Result<()>` non HRESULT. Stream data è `*mut c_void`. | Cast esplicito, `match` su Result. |
| `FindClose` | Torna `Result<()>`. | Ignorato con `let _ =`. |
| `STREAM_INFO_LEVELS_ALL` | Rimosso, ora è `STREAM_INFO_LEVELS(0)` (tuple struct). | |
| `WIN32_FIND_STREAM_DATA.StreamName` | Rinominato in `cStreamName`. | |
| `GetNamedSecurityInfoW` | Parametri SID: `Option<*mut PSID>`. | Variabili cambiate da `*mut SID` a `PSID`. |
| `GetLastError` | Torna `WIN32_ERROR`, chiamata diretta. | `windows::Win32::Foundation::GetLastError()`. |
| `SetFileSecurityW` | Torna `BOOL`, non `Result`. | `.as_bool()` funziona su BOOL (è un metodo valido). |

---

## 4. `crates/core/src/system.rs`

| Errore | Fix |
|--------|-----|
| `duplicate definitions for capture_with_config` | La versione macOS mancava di `#[cfg(target_os = "macos")]` — competeva con la fallback Windows. Aggiunto il gate. |
| `borrow of moved value: hostname` | `hostname` veniva spostato in `SystemManifest { hostname, ... }` e poi usato come `hostname.clone()`. Anticipato il clone in `let computer_name = hostname.clone()`. |
| `unused import: PathBuf` | Gated con `#[cfg(target_os = "macos")]` (usato solo in codice macOS). |

---

## 5. `crates/core/src/apfs.rs`

| Errore | Fix |
|--------|-----|
| `cannot find function unmount_apfs_snapshot` | `cleanup()` chiamava `unmount_apfs_snapshot` (definita solo macOS). Intero corpo del cleanup gated con `#[cfg(target_os = "macos")]`. |
| `unused import: Command` | Gated con `#[cfg(target_os = "macos")]`. |
| `unused imports: bail, Context` | `bail` sostituito con `anyhow::bail!` (le fallback già lo usavano). `Context` gated con `#[allow(unused_imports)]`. |

---

## 6. Warning minori (non bloccanti)

### `crates/restore/src/restore.rs`
- `validate_symlink_target` mai usata su Windows → gated con `#[cfg(unix)]`.

### `crates/cli/src/main.rs`
- `Ok(())` irraggiungibile dopo `bail!` in `cmd_create_recovery_usb` → ristrutturato con due blocchi `#[cfg]` espliciti.
- `disk_dev` unused → gated con `#[cfg(target_os = "macos")]`.
- `disk` unused su non-macOS → soppresso in `let _ = (disk, force)`.

---

## Stato finale

```
cargo build --release -p backup-shield-cli
    Finished `release` profile [optimized] target(s)
    → 0 errori, 0 warning
```
