// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.
//
//! Windows-specific file attribute reading/writing (ACL, ADS, file attributes).
//!
//! This module provides functions for reading and writing Windows-specific
//! file metadata that has no Unix equivalent:
//!
//! - **File attributes** (`FILE_ATTRIBUTE_*`) — e.g. hidden, system, read-only.
//! - **Security descriptors (ACL)** — NTFS permission entries.
//! - **Alternate Data Streams (ADS)** — named data forks on NTFS.
//!
//! All functions are no-ops on non-Windows platforms.
//!
//! # Requirements
//!
//! - Windows only (compiled with `#[cfg(target_os = "windows")]`).
//! - Some operations (reading/writing security descriptors) require the
//!   process to have `SeSecurityPrivilege` or appropriate rights.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows::core::PWSTR;
use windows::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_HANDLE_EOF, ERROR_SUCCESS, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    GetSecurityDescriptorLength, SetFileSecurityW, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstStreamW, FindNextStreamW, GetFileAttributesW, SetFileAttributesW,
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_FLAGS_AND_ATTRIBUTES, STREAM_INFO_LEVELS,
    WIN32_FIND_STREAM_DATA,
};

// ── File attributes ───────────────────────────────────────────────────────────

/// Read Windows file attributes (`FILE_ATTRIBUTE_*`) for a path.
///
/// Returns `Ok(Some(attributes))` on success, or `Ok(None)` if the file
/// does not exist or is a reparse point (e.g. a symlink or mount point).
pub fn read_file_attributes(path: &Path) -> Result<Option<u32>> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let attrs = unsafe { GetFileAttributesW(PWSTR::from_raw(wide.as_ptr() as *mut u16)) };

    if attrs == u32::MAX {
        let err = unsafe { GetLastError() };
        log::warn!("GetFileAttributesW failed for {:?}: {:?}", path, err);
        return Ok(None);
    }

    Ok(Some(attrs))
}

/// Write Windows file attributes for a path.
///
/// Only the following flags are typically restored:
/// - `FILE_ATTRIBUTE_READONLY`
/// - `FILE_ATTRIBUTE_HIDDEN`
/// - `FILE_ATTRIBUTE_SYSTEM`
/// - `FILE_ATTRIBUTE_ARCHIVE`
/// - `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`
///
/// Attributes like `FILE_ATTRIBUTE_COMPRESSED`, `FILE_ATTRIBUTE_ENCRYPTED`,
/// or `FILE_ATTRIBUTE_DIRECTORY` are **not** applied via this function.
pub fn apply_file_attributes(path: &Path, attributes: u32) -> Result<()> {
    let mask = FILE_ATTRIBUTE_READONLY.0
        | FILE_ATTRIBUTE_HIDDEN.0
        | FILE_ATTRIBUTE_SYSTEM.0
        | FILE_ATTRIBUTE_ARCHIVE.0
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0;

    let safe_value = attributes & mask;
    if safe_value == 0 {
        return Ok(());
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        SetFileAttributesW(
            PWSTR::from_raw(wide.as_ptr() as *mut u16),
            FILE_FLAGS_AND_ATTRIBUTES(safe_value),
        )
    };

    if result.is_err() {
        let err = unsafe { GetLastError() };
        anyhow::bail!("SetFileAttributesW failed for {:?}: error {:?}", path, err);
    }

    Ok(())
}

// ── Security descriptors (ACL) ────────────────────────────────────────────────

/// Read the security descriptor (DACL) for a path.
///
/// Returns the raw security descriptor bytes, which can be passed back to
/// [`apply_security_descriptor`] during restore.
pub fn read_security_descriptor(path: &Path) -> Result<Option<Vec<u8>>> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let mut _owner: windows::Win32::Security::PSID =
        windows::Win32::Security::PSID(ptr::null_mut());
    let mut _group: windows::Win32::Security::PSID =
        windows::Win32::Security::PSID(ptr::null_mut());

    let security_info = windows::Win32::Security::DACL_SECURITY_INFORMATION
        | windows::Win32::Security::OWNER_SECURITY_INFORMATION
        | windows::Win32::Security::GROUP_SECURITY_INFORMATION
        | windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;

    let result = unsafe {
        GetNamedSecurityInfoW(
            PWSTR::from_raw(wide.as_ptr() as *mut u16),
            SE_FILE_OBJECT,
            security_info,
            Some(&mut _owner as *mut windows::Win32::Security::PSID),
            Some(&mut _group as *mut windows::Win32::Security::PSID),
            None,
            None,
            &mut sd,
        )
    };

    if result != ERROR_SUCCESS {
        log::warn!(
            "GetNamedSecurityInfoW failed for {:?}: error {}",
            path,
            result.0
        );
        return Ok(None);
    }

    if sd.0.is_null() {
        return Ok(None);
    }

    let sd_len = unsafe { GetSecurityDescriptorLength(sd) };

    let bytes = unsafe { std::slice::from_raw_parts(sd.0 as *const u8, sd_len as usize).to_vec() };

    unsafe {
        LocalFree(Some(HLOCAL(sd.0)));
    }

    Ok(Some(bytes))
}

/// Apply a previously saved security descriptor to a path.
///
/// `sd_bytes` must be the raw bytes of a self-relative security descriptor
/// previously returned by [`read_security_descriptor`].
pub fn apply_security_descriptor(path: &Path, sd_bytes: &[u8]) -> Result<()> {
    if sd_bytes.is_empty() {
        return Ok(());
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let sd_ptr = sd_bytes.as_ptr() as *mut core::ffi::c_void;
    let sd = PSECURITY_DESCRIPTOR(sd_ptr);

    // Use the same security info flags as read_security_descriptor,
    // including PROTECTED_DACL to preserve the original protected ACL
    // (without it, restored files would inherit parent ACLs).
    let security_info = windows::Win32::Security::DACL_SECURITY_INFORMATION
        | windows::Win32::Security::OWNER_SECURITY_INFORMATION
        | windows::Win32::Security::GROUP_SECURITY_INFORMATION
        | windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;

    let result2 = unsafe {
        SetFileSecurityW(
            PWSTR::from_raw(wide.as_ptr() as *mut u16),
            security_info,
            sd,
        )
    };

    if !result2.as_bool() {
        let err = unsafe { GetLastError() };
        anyhow::bail!("SetFileSecurityW failed for {:?}: error {:?}", path, err);
    }

    Ok(())
}

// ── Alternate Data Streams (ADS) ──────────────────────────────────────────────

/// Read all alternate data streams from a file.
///
/// Returns a vector of `(stream_name, content)` pairs for each stream found.
/// The main stream (`::$DATA`) is **not** included.
pub fn read_alternate_data_streams(path: &Path) -> Result<Option<Vec<(String, Vec<u8>)>>> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut stream_data = WIN32_FIND_STREAM_DATA::default();
    let stream_data_ptr = &mut stream_data as *mut WIN32_FIND_STREAM_DATA as *mut core::ffi::c_void;
    let handle = unsafe {
        FindFirstStreamW(
            PWSTR::from_raw(wide.as_ptr() as *mut u16),
            STREAM_INFO_LEVELS(0),
            stream_data_ptr,
            Some(0),
        )
    };

    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            let win32_err = WIN32_ERROR((e.code().0 as u32) & 0xFFFF);
            if win32_err != ERROR_HANDLE_EOF {
                log::warn!("FindFirstStreamW failed for {:?}: {:?}", path, win32_err);
            }
            return Ok(None);
        }
    };

    let mut streams = Vec::new();

    loop {
        let name_len = stream_data
            .cStreamName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(stream_data.cStreamName.len());
        let name_utf16 = &stream_data.cStreamName[..name_len];
        let name = String::from_utf16_lossy(name_utf16);

        if !name.is_empty() && name != "::$DATA" {
            let ads_path = format!("{}:{}", path.display(), name.trim_start_matches(':'));
            match std::fs::read(&ads_path) {
                Ok(content) => {
                    let clean_name = name
                        .trim_start_matches(':')
                        .trim_end_matches(":$DATA")
                        .to_string();
                    streams.push((clean_name, content));
                }
                Err(e) => {
                    log::warn!("failed to read ADS '{}' for {:?}: {}", name, path, e);
                }
            }
        }

        let mut next_data = WIN32_FIND_STREAM_DATA::default();
        let next_data_ptr = &mut next_data as *mut WIN32_FIND_STREAM_DATA as *mut core::ffi::c_void;
        let hr = unsafe { FindNextStreamW(handle, next_data_ptr) };

        match hr {
            Ok(()) => {
                stream_data = next_data;
            }
            Err(e) => {
                let win32_err = WIN32_ERROR((e.code().0 as u32) & 0xFFFF);
                if win32_err == ERROR_HANDLE_EOF {
                    break;
                }
                log::warn!("FindNextStreamW error for {:?}: {:?}", path, win32_err);
                break;
            }
        }
    }

    let _ = unsafe { FindClose(handle) };

    if streams.is_empty() {
        return Ok(None);
    }

    Ok(Some(streams))
}

/// Write an alternate data stream to a file.
///
/// Creates or overwrites the named ADS `name` on `path` with the given `content`.
pub fn write_alternate_data_stream(path: &Path, name: &str, content: &[u8]) -> Result<()> {
    let ads_path = format!("{}:{}", path.display(), name);
    std::fs::write(&ads_path, content)
        .with_context(|| format!("failed to write ADS '{}' for {:?}", name, path))?;
    Ok(())
}
