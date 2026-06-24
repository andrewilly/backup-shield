// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

/// Information about a storage device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub size: u64,
    pub identifier: String,
    pub partitions: Vec<PartitionInfo>,
}

/// Information about a partition / volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub name: String,
    pub size: u64,
    pub mount_point: Option<String>,
    pub filesystem: String,
}

/// Information about an installed application bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub bundle_id: Option<String>,
}

/// Information about a system user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub home_directory: String,
    pub full_name: Option<String>,
}

/// Network interface information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub hardware: String,
    pub ip_address: Option<String>,
}

/// Network configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub computer_name: String,
}

/// Complete system manifest captured during a system backup.
///
/// Contains hardware info, OS version, disk layout, installed apps,
/// user accounts, and network configuration needed for full system recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemManifest {
    /// macOS version number (e.g. "15.5").
    pub os_version: String,
    /// macOS build number (e.g. "24F2037").
    pub build_number: String,
    /// Darwin kernel version.
    pub kernel_version: String,
    /// System hostname.
    pub hostname: String,
    /// Hardware model identifier (e.g. "MacBookPro18,3").
    pub hardware_model: String,
    /// CPU description (e.g. "Apple M3 Pro").
    pub cpu_type: String,
    /// Total physical memory in bytes.
    pub memory_bytes: u64,
    /// List of physical disks and their partitions.
    pub disks: Vec<DiskInfo>,
    /// Whether FileVault full-disk encryption is enabled.
    pub filevault_enabled: bool,
    /// Whether System Integrity Protection is enabled.
    pub sip_enabled: bool,
    /// When this manifest was captured.
    pub captured_at: DateTime<Utc>,
    /// Installed applications in /Applications.
    pub applications: Vec<AppInfo>,
    /// Local user accounts.
    pub users: Vec<UserInfo>,
    /// Network configuration snapshot.
    pub network: NetworkInfo,
    /// Path to the current startup disk.
    pub startup_disk: String,
    /// Directories included in the system backup.
    pub backup_sources: Vec<String>,
}

/// Configuration for system backup paths on macOS.
///
/// Allows users to customise which directories are included in a
/// full system backup.  The defaults match the standard macOS layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBackupConfig {
    /// Directories to include in the system backup (e.g. `/Applications`,
    /// `/Library`, …).
    pub source_paths: Vec<String>,
    /// Path to the directory whose children are treated as "applications".
    /// On macOS this is typically `/Applications`.
    pub applications_path: String,
}

impl Default for SystemBackupConfig {
    fn default() -> Self {
        Self {
            source_paths: default_system_backup_sources(),
            applications_path: "/Applications".to_string(),
        }
    }
}

/// Return the default set of system backup source directories for macOS.
///
/// These directories cover the core operating system components, installed
/// applications, user data, and locally-built software:
///
///   - `/Applications`   — system-wide applications
///   - `/Library`        — system and application support files
///   - `/Users`          — user home directories (data, config, …)
///   - `/usr/local`      — locally compiled / Homebrew software
pub fn default_system_backup_sources() -> Vec<String> {
    vec![
        "/Applications".to_string(),
        "/Library".to_string(),
        "/Users".to_string(),
        "/usr/local".to_string(),
    ]
}

impl SystemManifest {
    /// Capture system information on macOS by running system commands.
    #[cfg(target_os = "macos")]
    pub fn capture() -> Result<Self> {
        let config = SystemBackupConfig::default();
        Self::capture_with_config(&config)
    }

    /// Capture system information using a custom [`SystemBackupConfig`].
    ///
    /// This allows callers to override the default source directories and
    /// applications path when a non-standard macOS layout is in use.
    #[cfg(target_os = "macos")]
    pub fn capture_with_config(config: &SystemBackupConfig) -> Result<Self> {
        let os_version = run_cmd("sw_vers", &["-productVersion"])?;
        let build_number = run_cmd("sw_vers", &["-buildVersion"])?;
        let kernel_version = run_cmd("uname", &["-r"])?;
        let hostname = run_cmd("hostname", &[])?;
        let hardware_model = run_cmd("sysctl", &["-n", "hw.model"])?;
        let cpu_type = run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"])?;
        let mem_str = run_cmd("sysctl", &["-n", "hw.memsize"])?;
        let memory_bytes: u64 = mem_str.trim().parse().unwrap_or(0);

        let filevault_status = run_cmd("fdesetup", &["status"])?;
        let filevault_enabled = filevault_status.contains("FileVault is On");

        let sip_status = run_cmd("csrutil", &["status"])?;
        let sip_enabled = sip_status.contains("enabled") && !sip_status.contains("disabled");

        let startup_disk =
            run_cmd("diskutil", &["info", "-plist", "/"]).unwrap_or_else(|_| "unknown".to_string());
        let startup_disk_name = if startup_disk.contains("Volume Name") {
            extract_plist_value(&startup_disk, "Volume Name").unwrap_or_else(|| "/".to_string())
        } else {
            "/".to_string()
        };

        let disk_output = run_cmd("diskutil", &["list"])?;
        let disks = parse_diskutil_output(&disk_output);

        let app_output = run_cmd("ls", &[&config.applications_path])?;
        let applications: Vec<AppInfo> = app_output
            .lines()
            .filter(|l| l.ends_with(".app"))
            .map(|name| AppInfo {
                name: name.trim_end_matches(".app").to_string(),
                path: format!(
                    "{}/{}",
                    config.applications_path.trim_end_matches('/'),
                    name
                ),
                version: None,
                bundle_id: None,
            })
            .collect();

        let dscl_output = run_cmd("dscl", &[".", "list", "/Users"])?;
        let users = parse_users_output(&dscl_output);

        let network_output = run_cmd("networksetup", &["-listallhardwareports"])?;
        let network = parse_network_output(&network_output, &hostname);

        let captured_at = Utc::now();

        Ok(SystemManifest {
            os_version: os_version.trim().to_string(),
            build_number: build_number.trim().to_string(),
            kernel_version: kernel_version.trim().to_string(),
            hostname: hostname.trim().to_string(),
            hardware_model: hardware_model.trim().to_string(),
            cpu_type: cpu_type.trim().to_string(),
            memory_bytes,
            disks,
            filevault_enabled,
            sip_enabled,
            captured_at,
            applications,
            users,
            network,
            startup_disk: startup_disk_name,
            backup_sources: config.source_paths.clone(),
        })
    }

    /// Fallback for non-macOS platforms: return a minimal manifest.
    #[cfg(not(target_os = "macos"))]
    pub fn capture() -> Result<Self> {
        Self::capture_with_config(&SystemBackupConfig::default())
    }

    /// Fallback for non-macOS platforms: accepts config but ignores it.
    #[cfg(not(target_os = "macos"))]
    pub fn capture_with_config(_config: &SystemBackupConfig) -> Result<Self> {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let computer_name = hostname.clone();
        Ok(SystemManifest {
            os_version: std::env::consts::OS.to_string(),
            build_number: "unknown".to_string(),
            kernel_version: String::new(),
            hostname,
            hardware_model: String::new(),
            cpu_type: String::new(),
            memory_bytes: 0,
            disks: Vec::new(),
            filevault_enabled: false,
            sip_enabled: false,
            captured_at: Utc::now(),
            applications: Vec::new(),
            users: Vec::new(),
            network: NetworkInfo {
                interfaces: Vec::new(),
                computer_name,
            },
            startup_disk: String::new(),
            backup_sources: Vec::new(),
        })
    }

    /// Save the manifest as JSON in the repository.
    pub fn save(&self, repo_path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).context("failed to serialize system manifest")?;
        let path = repo_path.join("system-manifest.json");
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write system manifest to {:?}", path))
    }

    /// Load the manifest from a repository.
    pub fn load(repo_path: &Path) -> Result<Self> {
        let path = repo_path.join("system-manifest.json");
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read system manifest from {:?}", path))?;
        let manifest: SystemManifest =
            serde_json::from_str(&json).context("failed to parse system manifest")?;
        Ok(manifest)
    }

    /// Check if a manifest exists in the repository.
    pub fn exists(repo_path: &Path) -> bool {
        repo_path.join("system-manifest.json").exists()
    }

    /// Print a human-readable summary of the manifest.
    pub fn print_summary(&self) {
        println!("System Information:");
        println!(
            "  OS:           {} (build {})",
            self.os_version, self.build_number
        );
        println!("  Kernel:       {}", self.kernel_version);
        println!("  Hostname:     {}", self.hostname);
        println!("  Hardware:     {}", self.hardware_model);
        println!("  CPU:          {}", self.cpu_type);
        println!("  Memory:       {} GB", self.memory_bytes / 1_073_741_824);
        println!("  Startup disk: {}", self.startup_disk);
        println!(
            "  FileVault:    {}",
            if self.filevault_enabled { "On" } else { "Off" }
        );
        println!(
            "  SIP:          {}",
            if self.sip_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!();
        println!("Disks ({}):", self.disks.len());
        for disk in &self.disks {
            println!(
                "  {} ({}): {}",
                disk.name,
                disk.identifier,
                format_size(disk.size)
            );
            for part in &disk.partitions {
                let mount = part.mount_point.as_deref().unwrap_or("-");
                println!(
                    "    {} [{}] mounted at {} ({})",
                    part.name,
                    part.filesystem,
                    mount,
                    format_size(part.size)
                );
            }
        }
        println!();
        println!("Applications: {}", self.applications.len());
        for app in self.applications.iter().take(10) {
            println!("  {}", app.name);
        }
        if self.applications.len() > 10 {
            println!("  ... and {} more", self.applications.len() - 10);
        }
        println!();
        println!("Users ({}):", self.users.len());
        for user in &self.users {
            println!("  {} (uid={})", user.username, user.uid);
        }
        println!();
        println!("Network interfaces ({}):", self.network.interfaces.len());
        for iface in &self.network.interfaces {
            let ip = iface.ip_address.as_deref().unwrap_or("none");
            println!("  {} ({}): {}", iface.name, iface.hardware, ip);
        }
        println!();
        println!("Backup sources:");
        for src in &self.backup_sources {
            println!("  {}", src);
        }
    }
}

/// Format a byte count as a human-readable string (e.g. "1.5 GB").
fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

#[cfg(target_os = "macos")]
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to run: {} {:?}", cmd, args))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{} failed: {}", cmd, stderr.trim())
    }
}

#[cfg(target_os = "macos")]
fn extract_plist_value(plist: &str, key: &str) -> Option<String> {
    for line in plist.lines() {
        let trimmed = line.trim();
        if trimmed.contains(key) {
            if let Some(next) = plist.lines().skip_while(|l| l.trim() != trimmed).nth(1) {
                let val = next.trim().trim_matches('<').trim_matches('>');
                if val.starts_with("string") || val.starts_with("key") {
                    continue;
                }
                return Some(val.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parse_diskutil_output(output: &str) -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    let mut current_disk: Option<DiskInfo> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !trimmed.starts_with('/') {
            if let Some(disk) = current_disk.take() {
                disks.push(disk);
            }

            if trimmed.starts_with("/dev/disk") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let identifier = parts.first().unwrap_or(&"").trim_start_matches("/dev/");
                let size_str = parts.get(1).unwrap_or(&"");
                let name = parts.get(2..).unwrap_or(&[]).join(" ").trim().to_string();
                let size = parse_size(size_str);
                current_disk = Some(DiskInfo {
                    name,
                    size,
                    identifier: identifier.to_string(),
                    partitions: Vec::new(),
                });
            }
        } else if let Some(ref mut disk) = current_disk {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts.first().unwrap_or(&"").to_string();
                let size_str = parts.get(1).unwrap_or(&"");
                let rest = parts.get(2..).unwrap_or(&[]).join(" ");
                let (filesystem, mount_point) = if rest.contains("(") {
                    let fs_end = rest.find('(').unwrap_or(rest.len());
                    let fs = rest[..fs_end].trim().to_string();
                    let mount = rest
                        .trim_end_matches(')')
                        .split('(')
                        .last()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    (fs, if mount.is_empty() { None } else { Some(mount) })
                } else {
                    (rest.clone(), None)
                };
                disk.partitions.push(PartitionInfo {
                    name,
                    size: parse_size(size_str),
                    mount_point,
                    filesystem,
                });
            }
        }
    }
    if let Some(disk) = current_disk {
        disks.push(disk);
    }
    disks
}

#[cfg(target_os = "macos")]
fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    let (num_str, unit) = if s.ends_with('B') {
        let len = s.len();
        let unit_start = len - 2;
        if unit_start > 0
            && s.as_bytes()[unit_start..]
                .iter()
                .any(|c| c.is_ascii_alphabetic())
        {
            let unit_start = s
                .find(|c: char| c.is_ascii_alphabetic())
                .unwrap_or(len.saturating_sub(2));
            (&s[..unit_start], &s[unit_start..])
        } else {
            (s, "")
        }
    } else {
        (s, "")
    };
    let num: f64 = num_str.trim().parse().unwrap_or(0.0);
    match unit {
        "KB" | "Ki" => (num * 1024.0) as u64,
        "MB" | "Mi" => (num * 1024.0 * 1024.0) as u64,
        "GB" | "Gi" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
        "TB" | "Ti" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => num as u64,
    }
}

#[cfg(target_os = "macos")]
fn parse_users_output(output: &str) -> Vec<UserInfo> {
    let mut users = Vec::new();
    for line in output.lines() {
        let username = line.trim();
        if username.is_empty()
            || username.starts_with('_')
            || username == "daemon"
            || username == "nobody"
            || username == "root"
        {
            continue;
        }
        // Build the home directory path using Path::join instead of string concatenation.
        // Under macOS the standard parent is `/Users`, but we use `/Users` as default base
        // so the path is always constructed correctly.
        let home = PathBuf::from("/Users")
            .join(username)
            .to_string_lossy()
            .to_string();
        let uid = 501; // approximate
        users.push(UserInfo {
            username: username.to_string(),
            uid,
            home_directory: home,
            full_name: None,
        });
    }
    users
}

#[cfg(target_os = "macos")]
fn parse_network_output(output: &str, default_hostname: &str) -> NetworkInfo {
    let mut interfaces = Vec::new();
    let mut current_hardware = String::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Hardware Port:") {
            current_hardware = trimmed
                .trim_start_matches("Hardware Port:")
                .trim()
                .to_string();
        } else if trimmed.starts_with("Device:") {
            let name = trimmed.trim_start_matches("Device:").trim().to_string();
            let ip_address = get_ip_for_interface(&name);
            interfaces.push(NetworkInterface {
                name,
                hardware: current_hardware.clone(),
                ip_address,
            });
        }
    }
    NetworkInfo {
        interfaces,
        computer_name: default_hostname.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn get_ip_for_interface(iface: &str) -> Option<String> {
    if let Ok(output) = std::process::Command::new("ipconfig")
        .args(["getifaddr", iface])
        .output()
    {
        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout);
            let ip = ip.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    None
}
