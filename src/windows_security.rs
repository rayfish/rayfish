#![cfg(windows)]

//! Win32 security descriptors used before creating privileged IPC and state.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE,
    GetLastError, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
    SetSecurityInfo,
};
#[cfg(test)]
use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING,
    READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};

const PROTECTED_FILE_DACL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
const PROTECTED_DIR_DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const PROTECTED_DACL_SECURITY_INFO: u32 =
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrustedOwner {
    LocalSystem,
    Administrators,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerAction {
    Keep(TrustedOwner),
    Set(TrustedOwner),
}

fn owner_action(
    existing: Option<TrustedOwner>,
    current: Option<TrustedOwner>,
) -> Result<OwnerAction> {
    if let Some(owner) = existing {
        return Ok(OwnerAction::Keep(owner));
    }
    current.map(OwnerAction::Set).context(
        "config owner is untrusted and the current process is not LocalSystem or elevated Administrator",
    )
}

fn protected_sddl(owner: TrustedOwner, directory: bool) -> String {
    let owner = match owner {
        TrustedOwner::LocalSystem => "SY",
        TrustedOwner::Administrators => "BA",
    };
    let dacl = if directory {
        PROTECTED_DIR_DACL
    } else {
        PROTECTED_FILE_DACL
    };
    format!("O:{owner}{dacl}")
}

fn current_trusted_owner() -> Option<TrustedOwner> {
    if crate::windows_identity::current_user_sid().as_deref() == Some("S-1-5-18") {
        Some(TrustedOwner::LocalSystem)
    } else if crate::windows_identity::is_current_process_elevated_admin() {
        Some(TrustedOwner::Administrators)
    } else {
        None
    }
}

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

    #[cfg_attr(test, allow(dead_code))]
    fn dacl(&self) -> Result<*mut windows_sys::Win32::Security::ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        let ok =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        anyhow::ensure!(ok != 0 && present != 0, "security descriptor has no DACL");
        Ok(dacl)
    }

    fn owner(&self) -> Result<PSID> {
        let mut owner = std::ptr::null_mut();
        let mut defaulted = 0;
        let ok = unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) };
        anyhow::ensure!(
            ok != 0 && !owner.is_null(),
            "security descriptor has no owner"
        );
        Ok(owner)
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

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn ensure_protected_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path.parent().context("config directory has no parent")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        let owner = current_trusted_owner().context(
            "creating the protected config directory requires LocalSystem or elevated Administrator",
        )?;
        let mut descriptor = OwnedSecurityDescriptor::from_sddl(&protected_sddl(owner, true))?;
        let attrs = descriptor.attributes();
        let ok = unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &attrs) };
        if ok == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("creating protected {}", path.display()));
        }
    }
    protect_path(path, true)
}

/// Atomically creates a new protected regular file without following a reparse
/// point. Existing names always fail; callers generate unguessable names.
pub(crate) fn create_protected_new_file(path: &Path) -> Result<File> {
    let owner = current_trusted_owner().context(
        "creating protected config files requires LocalSystem or elevated Administrator",
    )?;
    let mut descriptor = OwnedSecurityDescriptor::from_sddl(&protected_sddl(owner, false))?;
    let attrs = descriptor.attributes();
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("creating protected new file {}", path.display()));
    }
    let file = unsafe { File::from_raw_handle(handle) };
    verify_open_protected_file(&file, path)?;
    Ok(file)
}

/// Reopens a protected file without following a reparse point and keeps a
/// non-delete-sharing handle alive across the privileged consumer operation.
pub(crate) fn open_protected_file_no_follow(path: &Path) -> Result<File> {
    protect_path_with_owner_policy(path, false, false)?;
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening protected file {}", path.display()));
    }
    let file = unsafe { File::from_raw_handle(handle) };
    verify_open_protected_file(&file, path)?;
    Ok(file)
}

pub(crate) struct OperatorFileLock {
    _file: File,
}

pub(crate) fn lock_operator_file(path: &Path) -> Result<OperatorFileLock> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let owner = current_trusted_owner()
            .context("creating the operator lock requires LocalSystem or elevated Administrator")?;
        let mut descriptor = OwnedSecurityDescriptor::from_sddl(&protected_sddl(owner, false))?;
        let attrs = descriptor.attributes();
        let handle = unsafe {
            CreateFileW(
                wide(path.as_os_str()).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                0,
                &attrs,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            let file = unsafe { File::from_raw_handle(handle) };
            protect_open_handle(&file, path, false, true)?;
            verify_open_protected_file(&file, path)?;
            return Ok(OperatorFileLock { _file: file });
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_SHARING_VIOLATION || std::time::Instant::now() >= deadline {
            return Err(std::io::Error::from_raw_os_error(error as i32))
                .with_context(|| format!("locking {}", path.display()));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn verify_open_protected_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    validate_config_file_attributes(metadata.file_attributes(), path)?;
    anyhow::ensure!(
        metadata.is_file(),
        "protected path is not a regular file: {}",
        path.display()
    );
    verify_handle_security(file, path, false)
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn protect_file(path: &Path) -> Result<()> {
    protect_path(path, false)
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

#[cfg_attr(test, allow(dead_code))]
fn protect_path(path: &Path, directory: bool) -> Result<()> {
    protect_path_with_owner_policy(path, directory, true)
}

fn protect_path_with_owner_policy(
    path: &Path,
    directory: bool,
    allow_owner_change: bool,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {} before ACL repair", path.display()))?;
    validate_config_file_attributes(metadata.file_attributes(), path)?;
    let handle = open_security_handle(path, directory, allow_owner_change)?;
    protect_open_handle(&handle, path, directory, allow_owner_change)
}

fn open_security_handle(path: &Path, directory: bool, allow_owner_change: bool) -> Result<File> {
    let flags = FILE_ATTRIBUTE_NORMAL
        | FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let access = READ_CONTROL | WRITE_DAC | if allow_owner_change { WRITE_OWNER } else { 0 };
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening {} for ACL repair", path.display()));
    }
    let file = unsafe { File::from_raw_handle(handle) };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {} during ACL repair", path.display()))?;
    validate_config_file_attributes(metadata.file_attributes(), path)?;
    anyhow::ensure!(
        metadata.is_dir() == directory,
        "protected path type changed during ACL repair: {}",
        path.display()
    );
    Ok(file)
}

fn protect_open_handle(
    file: &File,
    path: &Path,
    directory: bool,
    allow_owner_change: bool,
) -> Result<()> {
    let handle = file.as_raw_handle();
    let current_owner = if allow_owner_change {
        current_trusted_owner()
    } else {
        None
    };
    let action = owner_action(handle_trusted_owner(handle)?, current_owner)?;
    let owner = match action {
        OwnerAction::Keep(owner) | OwnerAction::Set(owner) => owner,
    };
    let descriptor = OwnedSecurityDescriptor::from_sddl(&protected_sddl(owner, directory))?;
    if matches!(action, OwnerAction::Set(_)) {
        let owner_result = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                descriptor.owner()?,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        anyhow::ensure!(
            owner_result == 0,
            "failed to set trusted owner on {}: {owner_result}",
            path.display()
        );
    }
    let dacl_result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            PROTECTED_DACL_SECURITY_INFO,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            descriptor.dacl()?,
            std::ptr::null_mut(),
        )
    };
    anyhow::ensure!(
        dacl_result == 0,
        "failed to protect {}: {dacl_result}",
        path.display()
    );
    verify_handle_security(file, path, directory)
}

fn handle_trusted_owner(handle: std::os::windows::io::RawHandle) -> Result<Option<TrustedOwner>> {
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    anyhow::ensure!(
        result == 0 && !descriptor.is_null() && !owner.is_null(),
        "failed to read config owner: {result}"
    );
    let mut text = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(owner, &mut text) };
    let parsed = (|| -> Result<Option<TrustedOwner>> {
        anyhow::ensure!(
            converted != 0 && !text.is_null(),
            "failed to render config owner SID"
        );
        let mut len = 0;
        unsafe {
            while *text.add(len) != 0 {
                len += 1;
            }
        }
        let sid = OsString::from_wide(unsafe { std::slice::from_raw_parts(text, len) })
            .to_string_lossy()
            .into_owned();
        Ok(match sid.as_str() {
            "S-1-5-18" => Some(TrustedOwner::LocalSystem),
            "S-1-5-32-544" => Some(TrustedOwner::Administrators),
            _ => None,
        })
    })();
    unsafe {
        if !text.is_null() {
            LocalFree(text.cast());
        }
        LocalFree(descriptor.cast());
    }
    parsed
}

fn verify_handle_security(file: &File, path: &Path, directory: bool) -> Result<()> {
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    anyhow::ensure!(
        result == 0 && !descriptor.is_null(),
        "failed to verify {}: {result}",
        path.display()
    );
    let mut text = std::ptr::null_mut();
    let mut text_len = 0;
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            &mut text_len,
        )
    };
    let verification = (|| -> Result<()> {
        anyhow::ensure!(ok != 0 && !text.is_null(), "failed to render final ACL");
        let actual = OsString::from_wide(unsafe {
            std::slice::from_raw_parts(text, text_len.saturating_sub(1) as usize)
        })
        .to_string_lossy()
        .into_owned();
        anyhow::ensure!(
            actual.contains("O:SY") || actual.contains("O:BA"),
            "config owner is not trusted: {actual}"
        );
        anyhow::ensure!(
            actual.contains("D:P"),
            "config DACL is not protected: {actual}"
        );
        anyhow::ensure!(
            actual.matches("(A;").count() == 2,
            "config DACL has unexpected ACEs: {actual}"
        );
        anyhow::ensure!(
            actual.contains(";;;SY)") && actual.contains(";;;BA)"),
            "config DACL lacks trusted principals: {actual}"
        );
        if directory {
            anyhow::ensure!(
                actual.matches("OICI").count() == 2,
                "config directory ACEs do not inherit: {actual}"
            );
        }
        Ok(())
    })();
    unsafe {
        if !text.is_null() {
            LocalFree(text.cast());
        }
        LocalFree(descriptor.cast());
    }
    verification
}

fn validate_config_file_attributes(attributes: u32, path: &Path) -> Result<()> {
    anyhow::ensure!(
        attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to secure reparse-point config path {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_are_protected_and_exclude_regular_users() {
        for sddl in [
            protected_sddl(TrustedOwner::LocalSystem, false),
            protected_sddl(TrustedOwner::Administrators, true),
        ] {
            assert!(sddl.starts_with("O:SYD:P") || sddl.starts_with("O:BAD:P"));
            assert!(sddl.contains(";;;SY)"));
            assert!(sddl.contains(";;;BA)"));
            assert!(!sddl.contains(";;;BU)"));
            assert!(!sddl.contains(";;;WD)"));
        }
    }

    #[test]
    fn dacl_update_flags_disable_inheritance() {
        assert_eq!(
            PROTECTED_DACL_SECURITY_INFO,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        );
        assert_ne!(
            PROTECTED_DACL_SECURITY_INFO & PROTECTED_DACL_SECURITY_INFORMATION,
            0
        );
        assert_eq!(
            PROTECTED_DACL_SECURITY_INFO & UNPROTECTED_DACL_SECURITY_INFORMATION,
            0
        );
    }

    #[test]
    fn trusted_owner_decision_matrix() {
        assert_eq!(
            owner_action(Some(TrustedOwner::LocalSystem), None).unwrap(),
            OwnerAction::Keep(TrustedOwner::LocalSystem)
        );
        assert_eq!(
            owner_action(Some(TrustedOwner::Administrators), None).unwrap(),
            OwnerAction::Keep(TrustedOwner::Administrators)
        );
        assert_eq!(
            owner_action(None, Some(TrustedOwner::LocalSystem)).unwrap(),
            OwnerAction::Set(TrustedOwner::LocalSystem)
        );
        assert_eq!(
            owner_action(None, Some(TrustedOwner::Administrators)).unwrap(),
            OwnerAction::Set(TrustedOwner::Administrators)
        );
        assert!(owner_action(None, None).is_err());
    }

    #[test]
    fn pipe_descriptor_accepts_zero_one_operator() {
        pipe_descriptor(None).unwrap();
        pipe_descriptor(Some("S-1-5-18")).unwrap();
        assert!(pipe_descriptor(Some("not-a-sid")).is_err());
    }

    #[test]
    fn zombie_reparse_policy_fails_closed() {
        let path = Path::new(r"C:\ProgramData\rayfish");
        assert!(validate_config_file_attributes(0, path).is_ok());
        assert!(validate_config_file_attributes(FILE_ATTRIBUTE_REPARSE_POINT, path).is_err());
    }
}
