//! Start the installed service when needed. Connection readiness comes from IPC.

use std::io::Error as IoError;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_START,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED, StartServiceW,
};

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns an open SCM or service handle.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn open_service(access: u32) -> Result<Option<ServiceHandle>> {
    // SAFETY: Null machine and database names select the local SCM.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(IoError::last_os_error()).context("opening Windows Service Control Manager");
    }
    let manager = ServiceHandle(manager);
    let name: Vec<_> = "rayfish".encode_utf16().chain(Some(0)).collect();
    // SAFETY: The service name is terminated and the SCM handle is open.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if service.is_null() {
        let error = IoError::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
            return Ok(None);
        }
        return Err(error).context("opening the Rayfish Windows service");
    }
    Ok(Some(ServiceHandle(service)))
}

fn stopped(service: &ServiceHandle) -> Result<bool> {
    // SAFETY: SERVICE_STATUS_PROCESS contains only integer fields; zero is valid.
    let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
    let mut needed = 0;
    // SAFETY: The status buffer is writable for the declared size and lives
    // through the synchronous query. The service handle is open.
    let queried = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            u32::try_from(size_of::<SERVICE_STATUS_PROCESS>())?,
            &mut needed,
        )
    };
    if queried == 0 {
        return Err(IoError::last_os_error()).context("reading Rayfish Windows service state");
    }
    Ok(status.dwCurrentState == SERVICE_STOPPED)
}

pub(crate) fn is_stopped() -> Result<bool> {
    match open_service(SERVICE_QUERY_STATUS)? {
        Some(service) => stopped(&service),
        None => Ok(true),
    }
}

pub(crate) fn ensure_running() -> Result<()> {
    let service = open_service(SERVICE_QUERY_STATUS | SERVICE_START)?.context(
        "The Rayfish Windows service is not installed. Repair the Rayfish installation.",
    )?;
    if stopped(&service)? {
        // SAFETY: The service handle grants SERVICE_START. No arguments are supplied.
        if unsafe { StartServiceW(service.0, 0, null_mut()) } == 0 {
            let error = IoError::last_os_error();
            if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
                return Err(error).context("starting the Rayfish Windows service");
            }
        }
    }
    Ok(())
}
