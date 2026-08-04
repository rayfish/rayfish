#![cfg(windows)]

//! Win32 security descriptors used before creating privileged IPC and state.

use std::ffi::OsStr;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

pub(crate) const PROTECTED_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
pub(crate) const PROTECTED_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub(crate) struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    pub(crate) fn from_sddl(sddl: &str) -> Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        let mut descriptor_size = 0;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                &mut descriptor_size,
            )
        };
        anyhow::ensure!(
            ok != 0 && !descriptor.is_null(),
            "failed to build Windows security descriptor"
        );
        Ok(Self(descriptor))
    }

    pub(crate) fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.cast(),
            bInheritHandle: 0,
        }
    }

    fn dacl(&self) -> Result<*mut windows_sys::Win32::Security::ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        let ok =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        anyhow::ensure!(ok != 0 && present != 0, "security descriptor has no DACL");
        Ok(dacl)
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.cast()) };
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

pub(crate) fn pipe_descriptor(operator_sid: Option<&str>) -> Result<OwnedSecurityDescriptor> {
    let sddl = match operator_sid {
        Some(sid) => format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})"),
        None => "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_owned(),
    };
    OwnedSecurityDescriptor::from_sddl(&sddl)
}

pub(crate) fn ensure_protected_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path.parent().context("config directory has no parent")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        let mut descriptor = OwnedSecurityDescriptor::from_sddl(PROTECTED_DIR_SDDL)?;
        let attrs = descriptor.attributes();
        let ok = unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &attrs) };
        if ok == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("creating protected {}", path.display()));
        }
    }
    protect_path(path, PROTECTED_DIR_SDDL)
}

pub(crate) fn create_protected_file(path: &Path) -> Result<File> {
    let mut descriptor = OwnedSecurityDescriptor::from_sddl(PROTECTED_FILE_SDDL)?;
    let attrs = descriptor.attributes();
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            &attrs,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("creating protected {}", path.display()));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(crate) fn protect_file(path: &Path) -> Result<()> {
    protect_path(path, PROTECTED_FILE_SDDL)
}

/// Atomically publish a complete sibling temp file without replacing an
/// existing destination. `false` means another caller won the claim race.
pub(crate) fn move_no_replace(from: &Path, to: &Path) -> Result<bool> {
    let ok = unsafe {
        MoveFileExW(
            wide(from.as_os_str()).as_ptr(),
            wide(to.as_os_str()).as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok != 0 {
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS {
        return Ok(false);
    }
    Err(std::io::Error::from_raw_os_error(error as i32))
        .with_context(|| format!("publishing protected {}", to.display()))
}

fn protect_path(path: &Path, sddl: &str) -> Result<()> {
    let descriptor = OwnedSecurityDescriptor::from_sddl(sddl)?;
    let result = unsafe {
        SetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            descriptor.dacl()?,
            std::ptr::null_mut(),
        )
    };
    anyhow::ensure!(
        result == 0,
        "failed to protect {}: {result}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_are_protected_and_exclude_regular_users() {
        for sddl in [PROTECTED_FILE_SDDL, PROTECTED_DIR_SDDL] {
            assert!(sddl.starts_with("D:P"));
            assert!(sddl.contains(";;;SY)"));
            assert!(sddl.contains(";;;BA)"));
            assert!(!sddl.contains(";;;BU)"));
            assert!(!sddl.contains(";;;WD)"));
        }
    }

    #[test]
    fn pipe_descriptor_accepts_zero_one_operator() {
        pipe_descriptor(None).unwrap();
        pipe_descriptor(Some("S-1-5-18")).unwrap();
        assert!(pipe_descriptor(Some("not-a-sid")).is_err());
    }
}
