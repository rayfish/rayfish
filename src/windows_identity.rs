#![cfg(windows)]

//! Win32 token identity helpers shared by service bootstrap and named-pipe IPC.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetTokenInformation,
    LookupAccountNameW, RevertToSelf, SecurityIdentification, TOKEN_DUPLICATE, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

#[derive(Clone, Debug)]
pub(crate) struct WindowsPeerIdentity {
    pub(crate) sid: String,
    pub(crate) is_local_system: bool,
    pub(crate) is_elevated_admin: bool,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe { RevertToSelf() };
    }
}

fn token_sid(token: HANDLE) -> Option<String> {
    let mut bytes = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes);
    }
    if bytes < std::mem::size_of::<TOKEN_USER>() as u32 {
        return None;
    }
    let words = (bytes as usize).div_ceil(std::mem::size_of::<u64>());
    let mut buffer = vec![0u64; words];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    };
    if ok == 0 {
        return None;
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_to_string(user.User.Sid)
}

fn sid_to_string(sid: windows_sys::Win32::Security::PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut sid_text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 || sid_text.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *sid_text.add(len) != 0 {
            len += 1;
        }
    }
    let value = OsString::from_wide(unsafe { std::slice::from_raw_parts(sid_text, len) })
        .to_string_lossy()
        .into_owned();
    unsafe { LocalFree(sid_text.cast()) };
    Some(value)
}

fn token_is_admin(token: HANDLE) -> bool {
    let mut sid_size = 0u32;
    unsafe {
        let _ = CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sid_size,
        );
    }
    if sid_size == 0 {
        return false;
    }
    let words = (sid_size as usize).div_ceil(std::mem::size_of::<u64>());
    let mut sid = vec![0u64; words];
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
        )
    } == 0
    {
        return false;
    }
    let mut is_member = 0;
    let ok = unsafe { CheckTokenMembership(token, sid.as_mut_ptr().cast(), &mut is_member) };
    ok != 0 && is_member != 0
}

fn process_token(access: u32) -> Option<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 || token.is_null()
    {
        return None;
    }
    Some(OwnedHandle(token))
}

pub fn current_user_sid() -> Option<String> {
    process_token(TOKEN_QUERY).and_then(|token| token_sid(token.0))
}

pub fn is_current_process_elevated_admin() -> bool {
    let Some(token) = process_token(TOKEN_DUPLICATE) else {
        return false;
    };
    let mut impersonation = std::ptr::null_mut();
    if unsafe { DuplicateToken(token.0, SecurityIdentification, &mut impersonation) } == 0
        || impersonation.is_null()
    {
        return false;
    }
    token_is_admin(OwnedHandle(impersonation).0)
}

pub fn account_sid(account: &OsStr) -> Result<String> {
    let account: Vec<u16> = account.encode_wide().chain(std::iter::once(0)).collect();
    let mut sid_size = 0u32;
    let mut domain_size = 0u32;
    let mut sid_use = 0;
    unsafe {
        let _ = LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    anyhow::ensure!(
        sid_size > 0,
        "account was not found (Win32 error {})",
        unsafe { GetLastError() }
    );
    let sid_words = (sid_size as usize).div_ceil(std::mem::size_of::<u64>());
    let mut sid = vec![0u64; sid_words];
    let mut domain = vec![0u16; domain_size as usize];
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    };
    anyhow::ensure!(ok != 0, "account lookup failed (Win32 error {})", unsafe {
        GetLastError()
    });
    sid_to_string(sid.as_mut_ptr().cast()).context("account lookup returned an invalid SID")
}

pub(crate) fn named_pipe_client_identity(pipe: HANDLE) -> Result<WindowsPeerIdentity> {
    anyhow::ensure!(
        unsafe { ImpersonateNamedPipeClient(pipe) } != 0,
        "failed to impersonate named-pipe client (Win32 error {})",
        unsafe { GetLastError() }
    );
    let _guard = ImpersonationGuard;
    let mut token = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0
            && !token.is_null(),
        "failed to open named-pipe client token (Win32 error {})",
        unsafe { GetLastError() }
    );
    let token = OwnedHandle(token);
    let sid = token_sid(token.0).context("named-pipe client token has no SID")?;
    Ok(WindowsPeerIdentity {
        is_local_system: sid == "S-1-5-18",
        is_elevated_admin: token_is_admin(token.0),
        sid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_sid_is_a_nonempty_windows_sid() {
        let sid = current_user_sid().expect("the test process should have a token SID");
        assert!(sid.starts_with("S-"), "unexpected SID format: {sid}");
        assert!(sid.split('-').count() >= 4);
    }

    #[test]
    fn current_account_round_trips_through_lookup() {
        let account = std::env::var_os("USERNAME").expect("USERNAME");
        assert_eq!(account_sid(&account).unwrap(), current_user_sid().unwrap());
    }

    #[test]
    fn invalid_named_pipe_handle_fails_closed() {
        assert!(named_pipe_client_identity(std::ptr::null_mut()).is_err());
    }

    #[test]
    fn process_token_can_be_duplicated_for_membership_checks() {
        let token = process_token(TOKEN_DUPLICATE).expect("current process token");
        let mut duplicate = std::ptr::null_mut();
        assert_ne!(
            unsafe { DuplicateToken(token.0, SecurityIdentification, &mut duplicate) },
            0,
            "DuplicateToken failed with Win32 error {}",
            unsafe { GetLastError() }
        );
        assert!(!duplicate.is_null());
        drop(OwnedHandle(duplicate));
    }
}
