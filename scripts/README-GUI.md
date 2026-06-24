# BackupShield GUI

A cross-platform graphical user interface for BackupShield.

## Requirements

- Python 3.8 or later
- Tkinter (usually included with Python)
- BackupShield binary compiled (`cargo build --release`)

## Usage

### Windows
```bash
python backup-shield-gui.py
```

### macOS / Linux
```bash
python3 backup-shield-gui.py
```

## Features

The GUI provides easy access to all BackupShield features:

### Navigation (Left Sidebar)
- **Dashboard** - Overview of repository status
- **Snapshots** - List all backup snapshots
- **Files** - Browse files in snapshots
- **Versions** - View file version history
- **Statistics** - Repository statistics

### Quick Actions
- **New Backup** - Start a new backup
- **Verify** - Check repository integrity
- **Create Recovery** - Make a portable recovery bundle

### Menu Features
- **File** - Open/create repositories
- **Backup** - Start backups, schedule automatic ones
- **Tools** - Recovery, verify, compact, settings

## First Steps

1. **Compile BackupShield**:
   ```bash
   cd backup-shield
   cargo build --release
   ```

2. **Run the GUI**:
   ```bash
   cd scripts
   python backup-shield-gui.py   # Windows
   python3 backup-shield-gui.py  # macOS/Linux
   ```

3. **Create a Repository**:
   - Click `File > New Repository` or use the dashboard
   - Select a folder to store backups

4. **Start Backing Up**:
   - Click `📁 New Backup` or use `Backup > Start Backup`
   - Select the folder you want to back up

## Screenshots

The GUI includes:
- Clean dashboard with repository stats
- Snapshot list with timestamps and tags
- File browser with size and date info
- Version history viewer
- Settings configuration

## Platform Notes

### Windows
- Uses native file dialogs
- Binary should be named `backup-shield.exe`

### macOS
- Native file dialogs
- Binary should be named `backup-shield`

### Linux
- Native file dialogs
- Binary should be named `backup-shield`

## Troubleshooting

### "Binary not found" warning
Make sure you've compiled BackupShield:
```bash
cargo build --release
```

The GUI looks for:
1. `./target/release/backup-shield` (or `.exe`)
2. `./backup-shield` in current directory
3. System PATH

### Tkinter not found
On some Linux systems, you may need to install tkinter:
```bash
# Debian/Ubuntu
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter
```

## Exit
Close the window or use `File > Exit` to quit.