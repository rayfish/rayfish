#![cfg(windows)]

//! Small Win32 identity helpers shared by the service and named-pipe IPC.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

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
    if user.User.Sid.is_null() {
        return None;
    }
    let mut sid_text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 || sid_text.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *sid_text.add(len) != 0 {
            len += 1;
        }
    }
    let sid = OsString::from_wide(unsafe { std::slice::from_raw_parts(sid_text, len) })
        .to_string_lossy()
        .into_owned();
    unsafe {
        LocalFree(sid_text.cast());
    }
    Some(sid)
}

fn process_sid(process: HANDLE) -> Option<String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return None;
    }
    let sid = token_sid(token);
    unsafe {
        CloseHandle(token);
    }
    sid
}

pub(crate) fn current_user_sid() -> Option<String> {
    process_sid(unsafe { GetCurrentProcess() })
}

pub(crate) fn named_pipe_client_sid(pipe: HANDLE) -> Option<String> {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return None;
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let sid = process_sid(process);
    unsafe {
        CloseHandle(process);
    }
    sid
}
