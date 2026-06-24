# BackupShield Scripts

This directory contains helper scripts for running BackupShield on Windows.

## Prerequisites

1. **BackupShield binary**: Build the `backup-shield.exe` binary first:
   ```
   cargo build --release
   ```
   The binary will be at `target/release/backup-shield.exe`.

2. **Windows**: All scripts are designed for Windows Command Prompt (`.bat`) or PowerShell (`.ps1`).

## Scripts

### `backup-shield.bat`

Main backup script for Windows. Performs backup, prune, and verify in sequence.

```batch
backup-shield.bat <source_path> <repo_path> [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `-t, --tag TAG` | Tag for this backup |
| `--keep-daily N` | Number of daily backups to keep (default: 7) |
| `--keep-weekly N` | Number of weekly backups to keep (default: 4) |

**Example:**
```batch
backup-shield.bat C:\Users\YourName\Documents D:\Backups\repo -t "daily backup"
```

**What it does:**
1. Runs `backup-shield backup <source> --repo <repo>`
2. Runs `backup-shield prune <repo> --keep-daily N --keep-weekly N`
3. Runs `backup-shield verify <repo> --quick`
4. Shows repository stats

---

### `install-schedule.ps1`

Installs or removes a scheduled backup task using Windows Task Scheduler.

```powershell
.\install-schedule.ps1 -Schedule daily -RepoPath "D:\Backups\repo" -SourcePath "C:\Users\YourName\Documents"
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-Schedule` | `hourly`, `daily`, or `weekly` |
| `-RepoPath` | Path to the BackupShield repository |
| `-SourcePath` | Path to back up |
| `-Tag` | Tag for scheduled backups (default: "automatic") |
| `-Uninstall` | Switch to remove the scheduled task |

**Examples:**
```powershell
# Install a daily backup at 2:00 AM
.\install-schedule.ps1 -Schedule daily -RepoPath "D:\Backups\repo" -SourcePath "C:\Users\YourName\Documents"

# Remove the scheduled task
.\install-schedule.ps1 -Schedule daily -Uninstall
```

**Note:** Requires Administrator privileges. Run PowerShell as Administrator before executing.

---

### `init-repo.bat`

Initializes a new BackupShield repository.

```batch
init-repo.bat <repo_path> [--encrypt]
```

**Example:**
```batch
init-repo.bat D:\Backups\repo
init-repo.bat D:\Backups\repo --encrypt
```

## Common Workflow

1. **Initialize a repository:**
   ```batch
   init-repo.bat D:\Backups\repo
   ```

2. **Run a manual backup:**
   ```batch
   backup-shield.bat C:\Users\YourName\Documents D:\Backups\repo -t "manual"
   ```

3. **Schedule automatic backups (as Administrator):**
   ```powershell
   .\install-schedule.ps1 -Schedule daily -RepoPath "D:\Backups\repo" -SourcePath "C:\Users\YourName\Documents"
   ```

## Notes

- All scripts automatically locate `backup-shield.exe` in the project's `target/release/` directory.
- The scripts assume the repository has already been initialized with `init-repo.bat` or `backup-shield init`.
- For encrypted repositories, you will be prompted for a password.
