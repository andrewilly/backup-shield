#![cfg(target_os = "windows")]

use anyhow::Result;
use std::path::{Path, PathBuf};

pub struct VssSnapshot {
    mount_point: PathBuf,
}

impl VssSnapshot {
    pub fn create(_path: &Path) -> Result<Self> {
        anyhow::bail!(
            "VSS snapshots require the windows crate with full IVssBackupComponents bindings, \
             which are not available in windows 0.62.2. Upgrade to a newer version of the \
             windows crate for VSS support."
        );
    }

    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    pub fn volume_root(&self) -> &Path {
        &self.mount_point
    }

    pub fn delete(&mut self) -> Result<()> {
        Ok(())
    }
}
