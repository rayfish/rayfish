//! Local-account S4U logon for sessions authorized by the mesh SSH policy.

use std::ffi::{OsString, c_void};
use std::io::Error as IoError;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{copy_nonoverlapping, null, null_mut};
use std::slice;

use anyhow::{Context, Result, bail, ensure};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, HANDLE, LUID, LocalFree,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetInfo, UF_ACCOUNTDISABLE, UF_LOCKOUT, UF_NORMAL_ACCOUNT, USER_INFO_1,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_STRING, LSA_UNICODE_STRING, LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser,
    LsaLookupAuthenticationPackage, LsaNtStatusToWinError, LsaRegisterLogonProcess,
    MSV1_0_S4U_LOGON, MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS, MsV1_0S4ULogon, SECURITY_LOGON_TYPE,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    AllocateLocallyUniqueId, DuplicateTokenEx, EqualSid, GetSidIdentifierAuthority,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, IsWellKnownSid,
    LookupAccountNameW, LookupAccountSidW, PSID, QUOTA_LIMITS, SID_AND_ATTRIBUTES,
    SecurityImpersonation, SidTypeUser, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TOKEN_SOURCE, TOKEN_USER, TokenGroups, TokenPrimary, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;
use windows_sys::Win32::UI::Shell::{CreateProfile, GetUserProfileDirectoryW};

const MAX_NAME_UNITS: usize = 256;
const MAX_PROFILE_UNITS: usize = 32_768;
const MAX_TOKEN_BYTES: usize = 1024 * 1024;

pub(super) struct LoginInfo {
    pub(super) token: OwnedHandle,
    pub(super) name: String,
    pub(super) shell: PathBuf,
    home: Option<PathBuf>,
    account: Account,
}

impl LoginInfo {
    pub(super) fn token_handle(&self) -> HANDLE {
        self.token.as_raw_handle()
    }

    pub(super) fn home(&self) -> Result<&Path> {
        self.home
            .as_deref()
            .context("The Windows user profile has not been prepared.")
    }

    pub(super) fn prepare_profile(&mut self) -> Result<()> {
        if self.home.is_none() {
            let sid = self.account.sid.to_string()?;
            let sid = wide(&sid)?;
            let name = wide(&self.name)?;
            let mut path = vec![0u16; MAX_PROFILE_UNITS];
            // SAFETY: Both strings are terminated, the account SID was verified
            // against this token, and the output buffer has the declared size.
            // The caller invokes this only after its SSH account policy allows it.
            let result = unsafe {
                CreateProfile(
                    sid.as_ptr(),
                    name.as_ptr(),
                    path.as_mut_ptr(),
                    u32::try_from(path.len())?,
                )
            };
            // Another authorized session may have created this SID's profile.
            // Re-read by token; never infer a home from an account-name path.
            self.home = profile_directory(self.token_handle())?;
            ensure!(
                self.home.is_some(),
                "Windows could not create the requested user profile (HRESULT {result:08x})."
            );
        }
        let home = self.home()?;
        ensure!(
            home.is_absolute() && home.is_dir(),
            "The Windows user profile directory is unavailable."
        );
        Ok(())
    }

    pub(super) fn matches_account(&self, grant: &str) -> Result<bool> {
        let grant = resolve_account(grant)?;
        // SAFETY: Both Account values own valid SID buffers for this call.
        Ok(unsafe { EqualSid(self.account.sid.as_psid(), grant.sid.as_psid()) } != 0)
    }

    pub(super) fn is_privileged(&self) -> Result<bool> {
        let information = token_information(self.token_handle(), TokenGroups)?;
        ensure!(
            information.len >= offset_of!(TOKEN_GROUPS, Groups),
            "Windows returned an incomplete group token."
        );
        // SAFETY: GroupCount is the first u32 in the aligned TOKEN_GROUPS
        // header. Reading it does not form a reference to its flexible array.
        let count = usize::try_from(unsafe { *information.words.as_ptr().cast::<u32>() })?;
        let required = count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|size| size.checked_add(offset_of!(TOKEN_GROUPS, Groups)))
            .context("The Windows group token size overflowed.")?;
        ensure!(
            required <= information.len,
            "Windows returned an incomplete group list."
        );
        // SAFETY: GetTokenInformation supplies valid group SID pointers within
        // its buffer. The checked count fits the live, aligned allocation.
        let groups = unsafe {
            slice::from_raw_parts(
                information
                    .words
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset_of!(TOKEN_GROUPS, Groups))
                    .cast::<SID_AND_ATTRIBUTES>(),
                count,
            )
        };
        // A UAC-filtered administrator remains privileged for SSH wildcard policy,
        // even when its administrators SID is marked deny-only in this token.
        Ok(groups.iter().any(|group| {
            // SAFETY: The OS supplied this SID and the allocation is still live.
            unsafe { IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid) != 0 }
        }))
    }
}

struct Sid {
    words: Vec<u64>,
}

impl Sid {
    fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }

    fn to_string(&self) -> Result<String> {
        let mut text = null_mut();
        // SAFETY: The account lookup produced this valid owned SID.
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut text) } == 0 {
            return Err(IoError::last_os_error()).context("formatting the Windows account SID");
        }
        ensure!(!text.is_null(), "Windows returned no account SID text.");
        // SAFETY: ConvertSidToStringSidW returns a terminated LocalAlloc string.
        let value = unsafe {
            let mut length = 0;
            while *text.add(length) != 0 {
                length += 1;
            }
            let value = String::from_utf16(slice::from_raw_parts(text, length));
            LocalFree(text.cast());
            value
        };
        value.context("reading the Windows account SID text")
    }
}

struct Account {
    sid: Sid,
    name: String,
}

pub(super) fn resolve_login(user: &str) -> Result<LoginInfo> {
    require_system()?;
    let account = resolve_account(user)?;
    check_account_policy(&account.name)?;
    let token = s4u_logon(&account.name)?;
    let actual = token_information(token.as_raw_handle(), TokenUser)?;
    ensure!(
        actual.len >= size_of::<TOKEN_USER>(),
        "Windows returned an incomplete user token."
    );
    // SAFETY: GetTokenInformation supplies an aligned TOKEN_USER containing a
    // valid SID pointer whose allocation remains live through EqualSid.
    let matches = unsafe {
        let actual = &*actual.words.as_ptr().cast::<TOKEN_USER>();
        EqualSid(actual.User.Sid, account.sid.as_psid()) != 0
    };
    ensure!(
        matches,
        "Windows logged on a different account than requested."
    );
    let home = profile_directory(token.as_raw_handle())?;
    let shell = system_shell()?;
    Ok(LoginInfo {
        name: account.name.clone(),
        token,
        home,
        shell,
        account,
    })
}

fn require_system() -> Result<()> {
    let mut token = null_mut();
    // SAFETY: The pseudo-handle is valid and token points to writable storage.
    let thread_token = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    if thread_token == 0 {
        let error = IoError::last_os_error();
        ensure!(
            error.raw_os_error() == Some(i32::try_from(ERROR_NO_TOKEN)?),
            "Could not inspect the effective Windows identity: {error}"
        );
        // SAFETY: The pseudo-handle is valid and token points to writable storage.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(IoError::last_os_error()).context("opening the Windows service token");
        }
    }
    // SAFETY: A successful token-open call transferred an owned valid handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let information = token_information(token.as_raw_handle(), TokenUser)?;
    ensure!(
        information.len >= size_of::<TOKEN_USER>(),
        "Windows returned an incomplete service token."
    );
    // SAFETY: TOKEN_USER and its SID are valid within this live OS-filled buffer.
    let system = unsafe {
        let user = &*information.words.as_ptr().cast::<TOKEN_USER>();
        IsWellKnownSid(user.User.Sid, WinLocalSystemSid) != 0
    };
    ensure!(
        system,
        "Passwordless Windows SSH logon requires the LocalSystem service."
    );
    Ok(())
}

fn resolve_account(user: &str) -> Result<Account> {
    ensure!(
        !user.is_empty() && !user.contains(['\0', '/', '@']),
        "Enter a local Windows account name."
    );
    let machine = computer_name()?;
    let name = if let Some((domain, name)) = user.split_once('\\') {
        ensure!(
            domain == "." || domain.eq_ignore_ascii_case(&machine),
            "Only local Windows user accounts are supported."
        );
        ensure!(
            !name.is_empty() && !name.contains('\\'),
            "Enter a local Windows account name."
        );
        name
    } else {
        user
    };
    ensure!(
        name.encode_utf16().count() < MAX_NAME_UNITS,
        "The Windows account name is too long."
    );
    let qualified = wide(&format!("{machine}\\{name}"))?;
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    // SAFETY: The name is terminated. Null output buffers request their sizes.
    let probed = unsafe {
        LookupAccountNameW(
            null(),
            qualified.as_ptr(),
            null_mut(),
            &mut sid_size,
            null_mut(),
            &mut domain_size,
            &mut kind,
        )
    };
    if probed == 0 {
        let error = IoError::last_os_error();
        if error.raw_os_error() != Some(i32::try_from(ERROR_INSUFFICIENT_BUFFER)?) {
            return Err(error).context("looking up the local Windows account");
        }
    }
    ensure!(
        sid_size > 0 && sid_size <= 1024 && domain_size <= u32::try_from(MAX_NAME_UNITS)?,
        "The local Windows account was not found."
    );
    let sid = Sid {
        words: vec![0u64; usize::try_from(sid_size)?.div_ceil(size_of::<u64>())],
    };
    let mut domain = vec![0u16; usize::try_from(domain_size)?.max(1)];
    // SAFETY: The output buffers are aligned and sized from the lookup probe.
    if unsafe {
        LookupAccountNameW(
            null(),
            qualified.as_ptr(),
            sid.as_psid(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(IoError::last_os_error()).context("resolving the local Windows account");
    }
    // Local SAM users have a machine domain, unlike well-known/service identities.
    ensure!(
        kind == SidTypeUser && wide_string(&domain)?.eq_ignore_ascii_case(&machine),
        "SSH requires a local user account, not a service account or group."
    );
    // SAFETY: LookupAccountNameW returned this SID in the owned aligned buffer.
    ensure!(
        unsafe { IsValidSid(sid.as_psid()) } != 0,
        "Windows returned an invalid account SID."
    );
    // SAFETY: A valid SID exposes its authority and sub-authority count. Only
    // local SAM user SIDs are accepted, excluding all service and well-known SIDs.
    let local_user_sid = unsafe {
        let authority = &*GetSidIdentifierAuthority(sid.as_psid());
        let count = *GetSidSubAuthorityCount(sid.as_psid());
        authority.Value == [0, 0, 0, 0, 0, 5]
            && count == 5
            && *GetSidSubAuthority(sid.as_psid(), 0) == 21
    };
    ensure!(
        local_user_sid,
        "SSH does not permit service or system account SIDs."
    );
    let canonical_name = account_name(&sid, &machine)?;
    Ok(Account {
        name: canonical_name,
        sid,
    })
}

fn account_name(sid: &Sid, machine: &str) -> Result<String> {
    let mut name = vec![0u16; MAX_NAME_UNITS];
    let mut domain = vec![0u16; MAX_NAME_UNITS];
    let mut name_len = u32::try_from(name.len())?;
    let mut domain_len = u32::try_from(domain.len())?;
    let mut kind = 0;
    // SAFETY: The SID is valid and both writable buffers have their declared size.
    if unsafe {
        LookupAccountSidW(
            null(),
            sid.as_psid(),
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } == 0
    {
        return Err(IoError::last_os_error()).context("reading the canonical Windows account name");
    }
    ensure!(
        kind == SidTypeUser && wide_string(&domain)?.eq_ignore_ascii_case(machine),
        "SSH requires a local Windows user."
    );
    wide_string(&name)
}

fn check_account_policy(name: &str) -> Result<()> {
    let name = wide(name)?;
    let mut buffer = null_mut();
    // SAFETY: The username is terminated, and level one returns USER_INFO_1.
    let status = unsafe { NetUserGetInfo(null(), name.as_ptr(), 1, &mut buffer) };
    ensure!(
        status == 0 && !buffer.is_null(),
        "Could not read local Windows account policy (Windows error {status})."
    );
    let owned = NetBuffer(buffer);
    // SAFETY: A successful level-one query returned an owned USER_INFO_1 buffer.
    let flags = unsafe { &*owned.0.cast::<USER_INFO_1>() }.usri1_flags;
    ensure!(
        flags & UF_NORMAL_ACCOUNT != 0,
        "SSH requires a normal local Windows account."
    );
    ensure!(
        flags & UF_ACCOUNTDISABLE == 0,
        "The Windows account is disabled."
    );
    ensure!(flags & UF_LOCKOUT == 0, "The Windows account is locked.");
    Ok(())
}

struct NetBuffer(*mut u8);
impl Drop for NetBuffer {
    fn drop(&mut self) {
        // SAFETY: This is the allocation returned by NetUserGetInfo.
        unsafe {
            NetApiBufferFree(self.0.cast());
        }
    }
}

struct TokenInformation {
    words: Vec<u64>,
    len: usize,
}

fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<TokenInformation> {
    let mut bytes = 0;
    // SAFETY: A null buffer probes the required information size.
    let probed = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut bytes) };
    if probed == 0 {
        let error = IoError::last_os_error();
        if error.raw_os_error() != Some(i32::try_from(ERROR_INSUFFICIENT_BUFFER)?) {
            return Err(error).context("inspecting the Windows token");
        }
    }
    ensure!(
        bytes > 0 && usize::try_from(bytes)? <= MAX_TOKEN_BYTES,
        "Windows returned an invalid token-information size."
    );
    let mut words = vec![0u64; usize::try_from(bytes)?.div_ceil(size_of::<u64>())];
    // SAFETY: The buffer is aligned and has the size returned by the probe.
    if unsafe { GetTokenInformation(token, class, words.as_mut_ptr().cast(), bytes, &mut bytes) }
        == 0
    {
        return Err(IoError::last_os_error()).context("reading the Windows token");
    }
    Ok(TokenInformation {
        words,
        len: usize::try_from(bytes)?,
    })
}

struct LsaHandle(HANDLE);
impl Drop for LsaHandle {
    fn drop(&mut self) {
        // SAFETY: This handle came from LsaRegisterLogonProcess, not OpenHandle.
        unsafe {
            LsaDeregisterLogonProcess(self.0);
        }
    }
}

struct LsaBuffer(*mut c_void);
impl Drop for LsaBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: LsaLogonUser allocated this optional return buffer.
            unsafe {
                LsaFreeReturnBuffer(self.0);
            }
        }
    }
}

fn s4u_logon(name: &str) -> Result<OwnedHandle> {
    let mut process_bytes = *b"rayfish\0";
    let process = lsa_string(&mut process_bytes)?;
    let mut handle = null_mut();
    let mut mode = 0;
    // SAFETY: The counted name and output pointers remain valid for this call.
    let status = unsafe { LsaRegisterLogonProcess(&process, &mut handle, &mut mode) };
    check_lsa_status(status, "registering Windows SSH logon")?;
    let handle = LsaHandle(handle);
    let mut package_bytes = *b"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0\0";
    let package = lsa_string(&mut package_bytes)?;
    let mut package_id = 0;
    // SAFETY: The LSA handle and counted package name are valid.
    let status = unsafe { LsaLookupAuthenticationPackage(handle.0, &package, &mut package_id) };
    check_lsa_status(status, "finding the Windows logon package")?;
    let authentication = logon_buffer(name)?;
    let mut source = TOKEN_SOURCE {
        SourceName: process_bytes.map(|byte| i8::from_ne_bytes([byte])),
        ..Default::default()
    };
    // SAFETY: The writable LUID output belongs to the source structure.
    if unsafe { AllocateLocallyUniqueId(&mut source.SourceIdentifier) } == 0 {
        return Err(IoError::last_os_error()).context("allocating a Windows logon identifier");
    }
    let mut origin_bytes = *b"rayfish-ssh\0";
    let origin = lsa_string(&mut origin_bytes)?;
    let mut profile = null_mut();
    let mut profile_size = 0;
    let mut logon_id = LUID::default();
    let mut token = null_mut();
    let mut quotas = QUOTA_LIMITS::default();
    let mut substatus = 0;
    // SAFETY: The auth structure and its strings share one aligned allocation;
    // all output pointers are writable and every backing allocation outlives
    // the synchronous call. No password or inherited user token is supplied.
    let status = unsafe {
        LsaLogonUser(
            handle.0,
            &origin,
            SECURITY_LOGON_TYPE::Network,
            package_id,
            authentication.words.as_ptr().cast(),
            authentication.len,
            null(),
            &source,
            &mut profile,
            &mut profile_size,
            &mut logon_id,
            &mut token,
            &mut quotas,
            &mut substatus,
        )
    };
    let _profile = LsaBuffer(profile);
    if status != 0 {
        // A failed logon never provides a usable token.
        check_lsa_status(
            if substatus != 0 { substatus } else { status },
            "Windows rejected SSH logon",
        )?;
    }
    ensure!(!token.is_null(), "Windows returned no account token.");
    // SAFETY: A successful LSA logon transferred ownership of this token.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut primary = null_mut();
    let access = TOKEN_QUERY
        | TOKEN_DUPLICATE
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_IMPERSONATE
        | TOKEN_ADJUST_DEFAULT;
    // SAFETY: The source is an owned token, no custom attributes are supplied,
    // and primary points to writable storage for the new owned handle.
    if unsafe {
        DuplicateTokenEx(
            token.as_raw_handle(),
            access,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    } == 0
    {
        return Err(IoError::last_os_error()).context("creating the SSH primary user token");
    }
    // SAFETY: DuplicateTokenEx succeeded and transferred this primary token.
    Ok(unsafe { OwnedHandle::from_raw_handle(primary) })
}

struct LogonBuffer {
    words: Vec<u64>,
    len: u32,
}

fn logon_buffer(name: &str) -> Result<LogonBuffer> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let domain = [u16::from(b'.')];
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .context("The Windows account name is too large.")?;
    let domain_bytes = size_of::<u16>();
    let total = size_of::<MSV1_0_S4U_LOGON>()
        .checked_add(name_bytes)
        .and_then(|len| len.checked_add(domain_bytes))
        .context("The Windows logon buffer is too large.")?;
    let mut words = vec![0u64; total.div_ceil(size_of::<u64>())];
    // SAFETY: The u64 allocation aligns the structure and both UTF-16 strings.
    // Checked sizes reserve the header followed by the two counted strings.
    unsafe {
        let base = words.as_mut_ptr().cast::<u8>();
        let name_ptr = base.add(size_of::<MSV1_0_S4U_LOGON>()).cast::<u16>();
        let domain_ptr = name_ptr.add(name.len());
        copy_nonoverlapping(name.as_ptr(), name_ptr, name.len());
        copy_nonoverlapping(domain.as_ptr(), domain_ptr, domain.len());
        base.cast::<MSV1_0_S4U_LOGON>().write(MSV1_0_S4U_LOGON {
            MessageType: MsV1_0S4ULogon,
            Flags: MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS,
            UserPrincipalName: LSA_UNICODE_STRING {
                Length: u16::try_from(name_bytes)?,
                MaximumLength: u16::try_from(name_bytes)?,
                Buffer: name_ptr,
            },
            DomainName: LSA_UNICODE_STRING {
                Length: u16::try_from(domain_bytes)?,
                MaximumLength: u16::try_from(domain_bytes)?,
                Buffer: domain_ptr,
            },
        });
    }
    Ok(LogonBuffer {
        words,
        len: u32::try_from(total)?,
    })
}

fn lsa_string(bytes: &mut [u8]) -> Result<LSA_STRING> {
    let counted = bytes
        .strip_suffix(&[0])
        .context("The Windows logon label is not terminated.")?;
    Ok(LSA_STRING {
        Length: u16::try_from(counted.len())?,
        MaximumLength: u16::try_from(bytes.len())?,
        Buffer: bytes.as_mut_ptr().cast(),
    })
}

fn check_lsa_status(status: i32, operation: &str) -> Result<()> {
    if status != 0 {
        // SAFETY: The function only converts the numeric NTSTATUS value.
        let code = unsafe { LsaNtStatusToWinError(status) };
        bail!("{operation} failed (LSA status {status:08x}, Windows error {code}).");
    }
    Ok(())
}

fn profile_directory(token: HANDLE) -> Result<Option<PathBuf>> {
    let mut length = 0;
    // SAFETY: Null output probes the required UTF-16 buffer length for this token.
    unsafe {
        GetUserProfileDirectoryW(token, null_mut(), &mut length);
    }
    if length == 0 {
        let error = IoError::last_os_error();
        if matches!(error.raw_os_error(), Some(2 | 3 | 1168)) {
            return Ok(None);
        }
        return Err(error).context("finding the Windows user profile");
    }
    ensure!(
        usize::try_from(length)? <= MAX_PROFILE_UNITS,
        "The Windows user profile path is too long."
    );
    let mut path = vec![0u16; usize::try_from(length)?];
    // SAFETY: The output buffer is writable for the length returned by the probe.
    if unsafe { GetUserProfileDirectoryW(token, path.as_mut_ptr(), &mut length) } == 0 {
        return Err(IoError::last_os_error()).context("reading the Windows user profile");
    }
    let path = PathBuf::from(wide_os_string(&path));
    ensure!(
        path.is_absolute(),
        "Windows returned a relative user profile path."
    );
    Ok(Some(path))
}

fn computer_name() -> Result<String> {
    let mut name = [0u16; MAX_NAME_UNITS];
    let mut length = u32::try_from(name.len())?;
    // SAFETY: The writable UTF-16 buffer has the declared capacity.
    if unsafe { GetComputerNameW(name.as_mut_ptr(), &mut length) } == 0 {
        return Err(IoError::last_os_error()).context("reading the local Windows account domain");
    }
    wide_string(&name)
}

fn system_shell() -> Result<PathBuf> {
    let directory = system_directory()?;
    let shell = directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    ensure!(
        shell.is_file(),
        "Windows PowerShell is unavailable in the system directory."
    );
    Ok(shell)
}

pub(super) fn sftp_server() -> Result<Option<PathBuf>> {
    let server = system_directory()?.join("OpenSSH").join("sftp-server.exe");
    Ok(server.is_file().then_some(server))
}

fn system_directory() -> Result<PathBuf> {
    let mut directory = vec![0u16; MAX_PROFILE_UNITS];
    // SAFETY: The writable UTF-16 buffer has the declared capacity.
    let length =
        unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), u32::try_from(directory.len())?) };
    if length == 0 {
        return Err(IoError::last_os_error()).context("resolving the Windows system directory");
    }
    ensure!(
        usize::try_from(length)? < directory.len(),
        "The Windows system directory path is too long."
    );
    let directory = PathBuf::from(wide_os_string(&directory));
    ensure!(
        directory.is_absolute(),
        "Windows returned a relative system directory path."
    );
    Ok(directory)
}

fn wide(value: &str) -> Result<Vec<u16>> {
    ensure!(
        !value.contains('\0'),
        "Windows account text contains a null character."
    );
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

fn wide_os_string(value: &[u16]) -> OsString {
    OsString::from_wide(
        &value[..value
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(value.len())],
    )
}

fn wide_string(value: &[u16]) -> Result<String> {
    wide_os_string(value)
        .into_string()
        .map_err(|_| anyhow::anyhow!("Windows returned invalid account text."))
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Security::{TOKEN_TYPE, TokenType};

    use super::*;

    #[test]
    fn non_system_callers_cannot_mint_passwordless_tokens() {
        if require_system().is_ok() {
            return;
        }
        assert!(resolve_login("example-user").is_err());
    }

    #[test]
    fn service_and_group_names_are_not_local_login_accounts() {
        for name in [
            "NT AUTHORITY\\SYSTEM",
            "NT AUTHORITY\\LOCAL SERVICE",
            "NT SERVICE\\rayfish",
            "BUILTIN\\Administrators",
            "S-1-5-18",
            ".\\",
            "user@example.invalid",
        ] {
            assert!(
                resolve_account(name).is_err(),
                "service/group account was accepted"
            );
        }
    }

    #[test]
    fn s4u_strings_are_contiguous_counted_and_preserve_local_domain() {
        let buffer = logon_buffer("example-user").unwrap();
        // SAFETY: logon_buffer constructed the aligned structure and strings.
        unsafe {
            let header = &*buffer.words.as_ptr().cast::<MSV1_0_S4U_LOGON>();
            let name = slice::from_raw_parts(
                header.UserPrincipalName.Buffer,
                usize::from(header.UserPrincipalName.Length) / 2,
            );
            let domain = slice::from_raw_parts(
                header.DomainName.Buffer,
                usize::from(header.DomainName.Length) / 2,
            );
            assert_eq!(String::from_utf16(name).unwrap(), "example-user");
            assert_eq!(String::from_utf16(domain).unwrap(), ".");
            assert_eq!(header.Flags, MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS);
        }
    }

    #[test]
    #[ignore = "Requires LocalSystem and a disposable local account in RAYFISH_SSH_TEST_USER."]
    fn resolve_local_s4u_login() {
        require_system().unwrap();
        let name = std::env::var("RAYFISH_SSH_TEST_USER")
            .expect("The SYSTEM smoke test supplies a disposable local user.");
        let mut login = resolve_login(&name).unwrap();
        assert!(login.matches_account(&name).unwrap());
        let information = token_information(login.token_handle(), TokenType).unwrap();
        // SAFETY: TokenType returned a properly aligned TOKEN_TYPE value.
        assert_eq!(
            unsafe { *information.words.as_ptr().cast::<TOKEN_TYPE>() },
            TokenPrimary
        );
        login.prepare_profile().unwrap();
        assert!(login.home().unwrap().is_absolute());
        assert!(login.home().unwrap().is_dir());
        assert!(login.shell.is_absolute());
        assert!(login.shell.is_file());
    }
}
