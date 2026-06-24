#!/usr/bin/env python3
"""
BackupShield GUI - Cross-platform Backup Manager
Requirements: Python 3.8+
Usage: python backup-shield-gui.py

Works on: Windows, macOS, Linux
"""

import os
import sys
import subprocess
import threading
import json
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

# Try to get bundled binary, fall back to system PATH
def get_binary_path():
    """Find backup-shield binary."""
    # Check release folder
    base_dir = Path(__file__).parent.parent
    binary_name = "backup-shield.exe" if sys.platform == "win32" else "backup-shield"
    
    release_bin = base_dir / "target" / "release" / binary_name
    if release_bin.exists():
        return str(release_bin)
    
    # Check current directory
    if Path(binary_name).exists():
        return binary_name
    
    # Try PATH
    import shutil
    return shutil.which(binary_name) or binary_name


class BackupShieldGUI:
    """Main GUI Application."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("BackupShield v0.6.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        self.binary = get_binary_path()
        self.current_repo = None
        
        # Style
        self.setup_styles()
        
        # Layout
        self.create_menu()
        self.create_sidebar()
        self.create_main_area()
        self.create_status_bar()
        
        # Apply theme
        self.apply_theme()
    
    def setup_styles(self):
        """Setup custom styles."""
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Helvetica", 14, "bold"))
        style.configure("Header.TLabel", font=("Helvetica", 11, "bold"))
        style.configure("Action.TButton", padding=10)
        style.configure("Success.TLabel", foreground="#2e7d32")
        style.configure("Error.TLabel", foreground="#c62828")
    
    def create_menu(self):
        """Create menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Repository...", command=self.open_repo)
        file_menu.add_command(label="New Repository...", command=self.new_repo)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Backup menu
        backup_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Backup", menu=backup_menu)
        backup_menu.add_command(label="Start Backup...", command=self.start_backup)
        backup_menu.add_command(label="Schedule Backup...", command=self.schedule_backup)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Create Recovery Bundle...", command=self.create_recovery)
        tools_menu.add_command(label="Verify Repository...", command=self.verify_repo)
        tools_menu.add_command(label="Compact Repository...", command=self.compact_repo)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings...", command=self.show_settings)
    
    def create_sidebar(self):
        """Create left sidebar with navigation."""
        sidebar = ttk.Frame(self.root, width=200)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        sidebar.pack_propagate(False)
        
        # Logo/Title
        title_frame = ttk.Frame(sidebar, padding=20)
        title_frame.pack(fill=tk.X)
        ttk.Label(title_frame, text="BackupShield", 
                  font=("Helvetica", 16, "bold")).pack()
        ttk.Label(title_frame, text="v0.6.0", 
                  font=("Helvetica", 9)).pack()
        
        # Separator
        ttk.Separator(sidebar).pack(fill=tk.X, padx=10, pady=10)
        
        # Navigation buttons
        self.nav_buttons = {}
        
        nav_items = [
            ("Dashboard", self.show_dashboard),
            ("Snapshots", self.show_snapshots),
            ("Files", self.show_files),
            ("Versions", self.show_versions),
            ("Statistics", self.show_stats),
        ]
        
        for text, cmd in nav_items:
            btn = ttk.Button(sidebar, text=text, command=cmd, width=20)
            btn.pack(padx=10, pady=3)
            self.nav_buttons[text] = btn
        
        # Separator
        ttk.Separator(sidebar).pack(fill=tk.X, padx=10, pady=10)
        
        # Quick actions
        ttk.Label(sidebar, text="Quick Actions", font=("Helvetica", 10, "bold")).pack(pady=5)
        
        ttk.Button(sidebar, text="📁 New Backup", 
                   command=self.start_backup).pack(padx=10, pady=3, fill=tk.X)
        ttk.Button(sidebar, text="🔄 Verify", 
                   command=self.verify_repo).pack(padx=10, pady=3, fill=tk.X)
        ttk.Button(sidebar, text="💾 Create Recovery", 
                   command=self.create_recovery).pack(padx=10, pady=3, fill=tk.X)
    
    def create_main_area(self):
        """Create main content area."""
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Start with dashboard
        self.show_dashboard()
    
    def create_status_bar(self):
        """Create bottom status bar."""
        status_frame = ttk.Frame(self.root, relief=tk.SUNKEN)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        self.repo_label = ttk.Label(status_frame, text="No repository open")
        self.repo_label.pack(side=tk.RIGHT, padx=5, pady=2)
    
    def apply_theme(self):
        """Apply a clean theme."""
        try:
            self.root.tk.call("ttk::style", "theme", "use", "clam")
        except:
            pass
        
        # Configure colors
        self.root.configure(bg="#f5f5f5")
    
    # ==================== Navigation ====================
    
    def clear_main(self):
        """Clear main content area."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def show_dashboard(self):
        """Show dashboard view."""
        self.clear_main()
        
        # Header
        header = ttk.Frame(self.main_frame)
        header.pack(fill=tk.X, pady=(0, 20))
        
        if self.current_repo:
            ttk.Label(header, text=f"Repository: {self.current_repo}", 
                     font=("Helvetica", 14, "bold")).pack(side=tk.LEFT)
            ttk.Button(header, text="Change", command=self.open_repo).pack(side=tk.RIGHT)
        else:
            ttk.Label(header, text="Welcome to BackupShield", 
                     font=("Helvetica", 14, "bold")).pack(side=tk.LEFT)
        
        # Quick stats cards
        cards_frame = ttk.Frame(self.main_frame)
        cards_frame.pack(fill=tk.X, pady=10)
        
        if self.current_repo:
            stats = self.get_repo_stats()
            
            for title, value, color in [
                ("Snapshots", str(stats.get("snapshot_count", 0)), "#2196f3"),
                ("Total Size", self.format_size(stats.get("total_size", 0)), "#4caf50"),
                ("Chunks", str(stats.get("total_chunks", 0)), "#ff9800"),
                ("Deduplication", f"{stats.get('dedup_ratio', 1.0):.1f}x", "#9c27b0")
            ]:
                self.create_stat_card(cards_frame, title, value, color)
        else:
            # Welcome cards
            for title, desc in [
                ("🚀 Get Started", "Open or create a repository to begin"),
                ("📋 Features", "Incremental backups, versioning, recovery"),
            ]:
                self.create_welcome_card(cards_frame, title, desc)
        
        # Recent activity / Info
        info_frame = ttk.LabelFrame(self.main_frame, text="Information", padding=15)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=20)
        
        info_text = """BackupShield v0.6.0

Features:
• Incremental backups with hard link optimization
• File versioning and history
• Compression and encryption support
• Reed-Solomon error correction
• Automatic storage management
• Recovery bundle creation
• Cross-platform (Windows, macOS, Linux)

Use the sidebar to navigate between features.
Click "New Backup" to start protecting your files.
"""
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)
    
    def show_snapshots(self):
        """Show snapshots list."""
        self.clear_main()
        
        ttk.Label(self.main_frame, text="Snapshots", 
                 font=("Helvetica", 14, "bold")).pack(pady=(0, 10))
        
        if not self.current_repo:
            ttk.Label(self.main_frame, text="No repository open").pack()
            return
        
        try:
            result = self.run_command(["snapshots", "--repo", self.current_repo])
            text = scrolledtext.ScrolledText(self.main_frame, height=30, width=80)
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(1.0, result if result else "No snapshots found.")
            text.config(state=tk.DISABLED)
        except Exception as e:
            ttk.Label(self.main_frame, text=f"Error: {e}").pack()
    
    def show_files(self):
        """Show files in latest snapshot."""
        self.clear_main()
        
        ttk.Label(self.main_frame, text="Files in Latest Snapshot", 
                 font=("Helvetica", 14, "bold")).pack(pady=(0, 10))
        
        if not self.current_repo:
            ttk.Label(self.main_frame, text="No repository open").pack()
            return
        
        # Filter input
        filter_frame = ttk.Frame(self.main_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(filter_frame, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        def run_files():
            pattern = filter_entry.get()
            cmd = ["files", "--repo", self.current_repo, "--long"]
            if pattern:
                cmd.extend(["--filter", pattern])
            
            try:
                result = self.run_command(cmd)
                text.config(state=tk.NORMAL)
                text.delete(1.0, tk.END)
                text.insert(1.0, result if result else "No files found.")
                text.config(state=tk.DISABLED)
            except Exception as e:
                text.config(state=tk.NORMAL)
                text.delete(1.0, tk.END)
                text.insert(1.0, f"Error: {e}")
                text.config(state=tk.DISABLED)
        
        ttk.Button(filter_frame, text="Search", command=run_files).pack(side=tk.LEFT)
        
        text = scrolledtext.ScrolledText(self.main_frame, height=25, width=80)
        text.pack(fill=tk.BOTH, expand=True, pady=10)
    
    def show_versions(self):
        """Show file versioning."""
        self.clear_main()
        
        ttk.Label(self.main_frame, text="File Version History", 
                 font=("Helvetica", 14, "bold")).pack(pady=(0, 10))
        
        if not self.current_repo:
            ttk.Label(self.main_frame, text="No repository open").pack()
            return
        
        # File selection
        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="File path:").pack(side=tk.LEFT)
        file_entry = ttk.Entry(input_frame, width=40)
        file_entry.pack(side=tk.LEFT, padx=5)
        
        def show_versions_cmd():
            filepath = file_entry.get()
            if not filepath:
                messagebox.showwarning("Warning", "Please enter a file path")
                return
            
            try:
                result = self.run_command([
                    "versions", "--repo", self.current_repo, 
                    "--snapshot", "latest", filepath
                ])
                text.config(state=tk.NORMAL)
                text.delete(1.0, tk.END)
                text.insert(1.0, result if result else "No version history found.")
                text.config(state=tk.DISABLED)
            except Exception as e:
                text.config(state=tk.NORMAL)
                text.delete(1.0, tk.END)
                text.insert(1.0, f"Error: {e}")
                text.config(state=tk.DISABLED)
        
        ttk.Button(input_frame, text="Show Versions", 
                   command=show_versions_cmd).pack(side=tk.LEFT)
        
        text = scrolledtext.ScrolledText(self.main_frame, height=20, width=80)
        text.pack(fill=tk.BOTH, expand=True, pady=10)
    
    def show_stats(self):
        """Show repository statistics."""
        self.clear_main()
        
        ttk.Label(self.main_frame, text="Repository Statistics", 
                 font=("Helvetica", 14, "bold")).pack(pady=(0, 10))
        
        if not self.current_repo:
            ttk.Label(self.main_frame, text="No repository open").pack()
            return
        
        try:
            result = self.run_command(["stats", "--repo", self.current_repo])
            text = scrolledtext.ScrolledText(self.main_frame, height=30, width=80)
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(1.0, result)
            text.config(state=tk.DISABLED)
        except Exception as e:
            ttk.Label(self.main_frame, text=f"Error: {e}").pack()
    
    # ==================== Actions ====================
    
    def new_repo(self):
        """Create new repository."""
        path = filedialog.askdirectory(title="Select Repository Location")
        if not path:
            return
        
        try:
            self.set_status("Creating repository...")
            result = self.run_command(["init", path])
            messagebox.showinfo("Success", f"Repository created at:\n{path}")
            self.current_repo = path
            self.repo_label.config(text=f"Repository: {path}")
            self.show_dashboard()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create repository:\n{e}")
        finally:
            self.set_status("Ready")
    
    def open_repo(self):
        """Open existing repository."""
        path = filedialog.askdirectory(title="Select Repository Folder")
        if not path:
            return
        
        config_file = os.path.join(path, "config.toml")
        if not os.path.exists(config_file):
            messagebox.showerror("Error", "Not a valid BackupShield repository (no config.toml)")
            return
        
        self.current_repo = path
        self.repo_label.config(text=f"Repository: {path}")
        self.set_status(f"Opened: {path}")
        self.show_dashboard()
    
    def start_backup(self):
        """Start new backup."""
        if not self.current_repo:
            messagebox.showwarning("Warning", "Please open a repository first")
            self.open_repo()
            return
        
        source = filedialog.askdirectory(title="Select Folder to Backup")
        if not source:
            return
        
        # Tag dialog
        tag = tk.simpledialog.askstring("Backup Tag", "Enter a tag for this backup:", parent=self.root)
        
        # Progress window
        progress = tk.Toplevel(self.root)
        progress.title("Backup in Progress")
        progress.geometry("400x150")
        
        ttk.Label(progress, text="Running backup...", font=("Helvetica", 11)).pack(pady=20)
        
        progress_text = scrolledtext.ScrolledText(progress, height=6, width=50)
        progress_text.pack(padx=10, pady=10)
        
        def run_backup():
            try:
                cmd = ["backup", source, "--repo", self.current_repo]
                if tag:
                    cmd.extend(["-t", tag])
                
                result = self.run_command(cmd, capture=True)
                progress_text.insert(tk.END, result + "\n")
                progress_text.see(tk.END)
                
                self.root.after(0, lambda: messagebox.showinfo("Success", "Backup completed!"))
                self.root.after(0, self.show_dashboard)
            except Exception as e:
                progress_text.insert(tk.END, f"Error: {e}\n")
            finally:
                self.root.after(0, progress.destroy)
        
        threading.Thread(target=run_backup, daemon=True).start()
    
    def schedule_backup(self):
        """Schedule automatic backups."""
        if not self.current_repo:
            messagebox.showwarning("Warning", "Please open a repository first")
            return
        
        # Simple dialog for schedule
        dialog = tk.Toplevel(self.root)
        dialog.title("Schedule Backup")
        dialog.geometry("350x250")
        
        ttk.Label(dialog, text="Schedule Automatic Backup", 
                  font=("Helvetica", 12, "bold")).pack(pady=10)
        
        ttk.Label(dialog, text="This will create a scheduled task on your system.").pack(pady=5)
        
        # Schedule options
        schedule_var = tk.StringVar(value="daily")
        
        for text, value in [("Hourly", "hourly"), ("Daily (2am)", "daily"), ("Weekly (Sunday 3am)", "weekly")]:
            ttk.Radiobutton(dialog, text=text, variable=schedule_var, value=value).pack(anchor=tk.W, padx=20)
        
        ttk.Label(dialog, text="Source folder:").pack(pady=(20, 5))
        source_entry = ttk.Entry(dialog, width=40)
        source_entry.pack()
        
        def do_schedule():
            source = source_entry.get()
            if not source:
                messagebox.showwarning("Warning", "Please select a source folder")
                return
            
            schedule = schedule_var.get()
            
            # Use CLI to create schedule
            try:
                result = self.run_command([
                    "backup", source, "--repo", self.current_repo,
                    "--schedule", schedule
                ])
                messagebox.showinfo("Success", f"Backup scheduled ({schedule})!\n\nSee console for details.")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to schedule:\n{e}")
        
        ttk.Button(dialog, text="Create Schedule", command=do_schedule).pack(pady=20)
    
    def verify_repo(self):
        """Verify repository integrity."""
        if not self.current_repo:
            return
        
        if not messagebox.askyesno("Verify", "Run repository verification? This may take a while."):
            return
        
        try:
            self.set_status("Verifying repository...")
            result = self.run_command(["verify", "--repo", self.current_repo, "--full"])
            
            result_win = tk.Toplevel(self.root)
            result_win.title("Verification Results")
            result_win.geometry("500x400")
            
            text = scrolledtext.ScrolledText(result_win, height=20, width=60)
            text.pack(padx=10, pady=10)
            text.insert(1.0, result)
            text.config(state=tk.DISABLED)
            
            self.set_status("Ready")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed:\n{e}")
            self.set_status("Ready")
    
    def create_recovery(self):
        """Create recovery bundle."""
        if not self.current_repo:
            return
        
        output = filedialog.askdirectory(title="Select Recovery Bundle Output Folder")
        if not output:
            return
        
        try:
            self.set_status("Creating recovery bundle...")
            result = self.run_command([
                "create-recovery", "--repo", self.current_repo, 
                "--output", output
            ])
            messagebox.showinfo("Success", f"Recovery bundle created at:\n{output}")
            self.set_status("Ready")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create recovery bundle:\n{e}")
            self.set_status("Ready")
    
    def compact_repo(self):
        """Compact repository."""
        if not self.current_repo:
            return
        
        if not messagebox.askyesno("Compact", "Compact repository to reclaim space?"):
            return
        
        try:
            self.set_status("Compacting repository...")
            result = self.run_command(["compact", "--repo", self.current_repo])
            messagebox.showinfo("Success", "Repository compacted!")
            self.set_status("Ready")
        except Exception as e:
            messagebox.showerror("Error", f"Compaction failed:\n{e}")
            self.set_status("Ready")
    
    def show_settings(self):
        """Show settings dialog."""
        if not self.current_repo:
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Repository Settings")
        dialog.geometry("400x350")
        
        ttk.Label(dialog, text="Repository Settings", 
                  font=("Helvetica", 12, "bold")).pack(pady=10)
        
        # Get current config
        try:
            result = self.run_command(["config", "--repo", self.current_repo, "--show"])
            
            text = scrolledtext.ScrolledText(dialog, height=15, width=45)
            text.pack(padx=20, pady=10)
            text.insert(1.0, result)
            text.config(state=tk.DISABLED)
        except Exception as e:
            ttk.Label(dialog, text=f"Error: {e}").pack()
        
        # Modify settings
        ttk.Label(dialog, text="Max Size (GB):").pack()
        size_entry = ttk.Entry(dialog)
        size_entry.pack(pady=5)
        
        def save_settings():
            size = size_entry.get()
            try:
                cmd = ["config", "--repo", self.current_repo]
                if size:
                    cmd.extend(["--max-size-gb", size])
                self.run_command(cmd)
                messagebox.showinfo("Success", "Settings saved!")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save:\n{e}")
        
        ttk.Button(dialog, text="Save", command=save_settings).pack(pady=10)
    
    # ==================== Helpers ====================
    
    def run_command(self, args, capture=False):
        """Run backup-shield command."""
        cmd = [self.binary] + args
        
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        
        result = subprocess.run(cmd)
        if result.returncode != 0:
            raise Exception(f"Command failed: {' '.join(cmd)}")
        
        return ""
    
    def get_repo_stats(self):
        """Get repository statistics."""
        if not self.current_repo:
            return {}
        
        try:
            result = self.run_command(["stats", "--repo", self.current_repo], capture=True)
            
            stats = {}
            for line in result.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "Total chunks":
                        stats["total_chunks"] = int(value)
                    elif key == "Total size":
                        stats["total_size"] = self.parse_size(value)
                    elif key == "Snapshot count":
                        stats["snapshot_count"] = int(value)
                    elif key == "Dedup ratio":
                        stats["dedup_ratio"] = float(value.rstrip('x'))
            
            return stats
        except:
            return {}
    
    def parse_size(self, size_str):
        """Parse size string like '10.5 MB' to bytes."""
        size_str = size_str.strip()
        
        units = {
            'B': 1,
            'KB': 1024,
            'MB': 1024**2,
            'GB': 1024**3,
            'TB': 1024**4
        }
        
        for unit, multiplier in units.items():
            if unit in size_str:
                value = float(size_str.replace(unit, '').strip())
                return int(value * multiplier)
        
        return 0
    
    def format_size(self, size):
        """Format size in bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def set_status(self, text):
        """Update status bar."""
        self.status_label.config(text=text)
        self.root.update()
    
    def create_stat_card(self, parent, title, value, color):
        """Create a statistics card."""
        card = tk.Frame(parent, bg=color, bd=0, relief=tk.RAISED)
        card.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)
        
        tk.Label(card, text=title, bg=color, fg="white", 
                font=("Helvetica", 9)).pack(pady=(10, 5))
        tk.Label(card, text=value, bg=color, fg="white", 
                font=("Helvetica", 16, "bold")).pack(pady=(0, 10))
    
    def create_welcome_card(self, parent, title, desc):
        """Create a welcome/info card."""
        card = tk.Frame(parent, bg="white", bd=1, relief=tk.RAISED)
        card.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)
        
        tk.Label(card, text=title, bg="white", fg="#1976d2", 
                font=("Helvetica", 11, "bold")).pack(pady=(15, 5))
        tk.Label(card, text=desc, bg="white", fg="#666", 
                font=("Helvetica", 9)).pack(pady=(0, 15))


def main():
    """Main entry point."""
    root = tk.Tk()
    
    # Check for binary
    binary = get_binary_path()
    if not Path(binary).exists():
        messagebox.showwarning(
            "Binary Not Found",
            "backup-shield binary not found!\n\n"
            "Please compile with: cargo build --release\n"
            "Expected location: target/release/backup-shield"
        )
    
    app = BackupShieldGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()