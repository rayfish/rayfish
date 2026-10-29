//! User-token process creation and cancellable SSH session I/O on Windows.

use std::collections::BTreeMap;
use std::ffi::{OsStr, c_void};
use std::io::Error as IoError;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::abort;
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use russh::server::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::watch;
use tokio::task::{JoinSet, spawn_blocking};
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LUID, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, ImpersonateSelf, IsWellKnownSid,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED,
    SE_RESTORE_NAME, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetCurrentThread, GetExitCodeProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{LoadUserProfileW, PROFILEINFOW, UnloadUserProfile};

use super::login::LoginInfo;

const PIPE_BUFFER: u32 = 64 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub(super) struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
}

impl TerminalSize {
    fn coord(self) -> Result<COORD> {
        ensure!(
            self.cols > 0 && self.rows > 0,
            "The terminal size must be positive."
        );
        Ok(COORD {
            X: i16::try_from(self.cols)?,
            Y: i16::try_from(self.rows)?,
        })
    }
}

pub(super) struct SessionSpec {
    pub login: Arc<LoginInfo>,
    pub program: Option<PathBuf>,
    pub command: Option<String>,
    pub terminal: Option<TerminalSize>,
    pub env: Vec<(String, String)>,
}

struct OwnedHandle(HANDLE);

// SAFETY: The wrapper owns a kernel handle. Its APIs permit cross-thread use;
// ownership keeps CloseHandle from racing a borrowed handle operation.
unsafe impl Send for OwnedHandle {}
// SAFETY: Shared operations query kernel objects; mutation is synchronized by
// the Windows APIs, and closing requires exclusive ownership of this wrapper.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the live handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl OwnedHandle {
    fn duplicate(handle: HANDLE) -> Result<Self> {
        let mut duplicate = null_mut();
        // SAFETY: The source belongs to this process and the output is writable.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(IoError::last_os_error()).context("duplicating an SSH pipe handle");
        }
        Ok(Self(duplicate))
    }
}

struct PipePair {
    parent: NamedPipeServer,
    child: OwnedHandle,
    control: OwnedHandle,
}

async fn pipe(parent_reads: bool) -> Result<PipePair> {
    let path = format!(r"\\.\pipe\rayfish-ssh-{:032x}", rand::random::<u128>());
    let name = wide(OsStr::new(&path));
    let parent = ServerOptions::new()
        .first_pipe_instance(true)
        .access_inbound(parent_reads)
        .access_outbound(!parent_reads)
        .in_buffer_size(PIPE_BUFFER)
        .out_buffer_size(PIPE_BUFFER)
        .reject_remote_clients(true)
        .create(&path)
        .context("creating a private SSH I/O pipe")?;
    let child = {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        // SAFETY: The terminated private pipe name and attributes outlive the call.
        // No OVERLAPPED flag is set on the child end, as required by ConPTY.
        let child = unsafe {
            CreateFileW(
                name.as_ptr(),
                if parent_reads {
                    GENERIC_WRITE
                } else {
                    GENERIC_READ
                },
                0,
                &attributes,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if child == INVALID_HANDLE_VALUE {
            return Err(IoError::last_os_error()).context("opening the child SSH I/O pipe");
        }
        OwnedHandle(child)
    };
    parent
        .connect()
        .await
        .context("connecting the private SSH I/O pipe")?;
    let control = OwnedHandle::duplicate(parent.as_raw_handle() as HANDLE)?;
    Ok(PipePair {
        parent,
        child,
        control,
    })
}

struct Profile {
    login: Arc<LoginInfo>,
    handle: HANDLE,
}

// SAFETY: A profile handle is owned and may be unloaded on the cleanup worker.
unsafe impl Send for Profile {}

impl Profile {
    fn load(login: Arc<LoginInfo>) -> Result<Self> {
        reject_system(login.token_handle())?;
        let _privileges = ProfilePrivileges::enable()?;
        let mut name = wide(OsStr::new(&login.name));
        let mut info = PROFILEINFOW {
            dwSize: u32::try_from(size_of::<PROFILEINFOW>())?,
            dwFlags: 1,
            lpUserName: name.as_mut_ptr(),
            ..Default::default()
        };
        // SAFETY: The primary token, profile structure and username are live.
        if unsafe { LoadUserProfileW(login.token_handle(), &mut info) } == 0 {
            return Err(IoError::last_os_error()).context("loading the SSH user's Windows profile");
        }
        Ok(Self {
            login,
            handle: info.hProfile,
        })
    }

    fn unload(&mut self) -> Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        let _privileges = ProfilePrivileges::enable()?;
        // SAFETY: This owns a successful LoadUserProfile handle and its token.
        if unsafe { UnloadUserProfile(self.login.token_handle(), self.handle) } == 0 {
            return Err(IoError::last_os_error())
                .context("unloading the SSH user's Windows profile");
        }
        self.handle = null_mut();
        Ok(())
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        if let Err(error) = self.unload() {
            tracing::warn!(%error, "could not unload an SSH user profile");
        }
    }
}

// Privileges are enabled on a private impersonation token for this blocking
// thread. Other concurrent sessions never observe privilege changes.
struct ProfilePrivileges;

impl ProfilePrivileges {
    fn enable() -> Result<Self> {
        // SAFETY: The blocking thread has no client impersonation context.
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err(IoError::last_os_error()).context("preparing SSH profile privileges");
        }
        let guard = Self;
        let mut token = null_mut();
        // SAFETY: The thread now owns an impersonation token; token is writable.
        if unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                1,
                &mut token,
            )
        } == 0
        {
            return Err(IoError::last_os_error()).context("opening SSH profile privileges");
        }
        let token = OwnedHandle(token);
        for name in [SE_BACKUP_NAME, SE_RESTORE_NAME] {
            let mut luid = LUID::default();
            // SAFETY: Names are static, terminated Windows privilege names.
            if unsafe { LookupPrivilegeValueW(null(), name, &mut luid) } == 0 {
                return Err(IoError::last_os_error()).context("finding SSH profile privileges");
            }
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: The owned token and privilege structure are live. Even
            // success may report ERROR_NOT_ALL_ASSIGNED through GetLastError.
            let ok = unsafe {
                AdjustTokenPrivileges(token.0, 0, &privileges, 0, null_mut(), null_mut())
            };
            // SAFETY: Read the immediately preceding API's thread-local error.
            let error = unsafe { GetLastError() };
            ensure!(
                ok != 0 && error == 0,
                "Could not enable SSH profile privileges (Windows error {error})."
            );
        }
        Ok(guard)
    }
}

impl Drop for ProfilePrivileges {
    fn drop(&mut self) {
        // SAFETY: This guard owns this blocking thread's impersonation context.
        if unsafe { RevertToSelf() } == 0 {
            // Continuing a shared worker with an unknown token is unsafe.
            abort();
        }
    }
}

fn reject_system(token: HANDLE) -> Result<()> {
    let mut size = 0;
    // SAFETY: The first call obtains the required TOKEN_USER buffer length.
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
    }
    ensure!(
        size >= u32::try_from(size_of::<TOKEN_USER>())?,
        "Could not inspect the SSH login token."
    );
    let mut storage = vec![0_usize; usize::try_from(size)?.div_ceil(size_of::<usize>())];
    // SAFETY: The aligned storage is writable for the queried size.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(IoError::last_os_error()).context("inspecting the SSH login token");
    }
    // SAFETY: GetTokenInformation initialized TOKEN_USER and its SID in storage.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: The SID belongs to the initialized token buffer.
    ensure!(
        unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) } == 0,
        "SSH commands must not run as LocalSystem."
    );
    Ok(())
}

struct Environment(*mut c_void);

impl Drop for Environment {
    fn drop(&mut self) {
        // SAFETY: CreateEnvironmentBlock allocated this block.
        unsafe {
            DestroyEnvironmentBlock(self.0);
        }
    }
}

fn environment(login: &LoginInfo, extra: &[(String, String)]) -> Result<Vec<u16>> {
    ensure!(extra.len() <= 128, "Too many SSH environment variables.");
    let mut raw = null_mut();
    // SAFETY: The token is a prepared primary user token and raw is writable.
    if unsafe { CreateEnvironmentBlock(&mut raw, login.token_handle(), 0) } == 0 {
        return Err(IoError::last_os_error()).context("building the SSH user's environment");
    }
    let block = Environment(raw);
    let mut values = BTreeMap::new();
    let mut offset = 0;
    loop {
        let mut end = offset;
        // SAFETY: CreateEnvironmentBlock returns a double-NUL-terminated UTF-16 block.
        while unsafe { *block.0.cast::<u16>().add(end) } != 0 {
            end += 1;
        }
        if end == offset {
            break;
        }
        // SAFETY: The terminated entry lies within the environment block.
        let line = String::from_utf16_lossy(unsafe {
            slice::from_raw_parts(block.0.cast::<u16>().add(offset), end - offset)
        });
        if let Some((name, value)) = line.split_once('=')
            && !name.is_empty()
        {
            values.insert(
                name.to_ascii_lowercase(),
                (name.to_owned(), value.to_owned()),
            );
        }
        offset = end + 1;
    }
    for (name, value) in extra {
        ensure!(
            !name.is_empty()
                && name.len() <= 256
                && !name.contains(['=', '\0'])
                && value.len() <= 8192
                && !value.contains('\0'),
            "Invalid SSH environment variable."
        );
        values.insert(name.to_ascii_lowercase(), (name.clone(), value.clone()));
    }
    let home = login.home()?.to_string_lossy();
    values.insert("home".into(), ("HOME".into(), home.into_owned()));
    let mut result = Vec::new();
    for (_, (name, value)) in values {
        result.extend(format!("{name}={value}").encode_utf16());
        result.push(0);
    }
    result.push(0);
    ensure!(result.len() <= 262_144, "The SSH environment is too large.");
    Ok(result)
}

struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}

impl Attributes {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0;
        // SAFETY: Query the variable-sized attribute-list allocation.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size);
        }
        let mut attributes = Self {
            storage: vec![0; size.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        // SAFETY: Aligned storage has the size requested by the API.
        if unsafe { InitializeProcThreadAttributeList(attributes.pointer(), count, 0, &mut size) }
            == 0
        {
            return Err(IoError::last_os_error()).context("initializing SSH process attributes");
        }
        attributes.initialized = true;
        Ok(attributes)
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }

    fn update(&mut self, attribute: u32, value: *const c_void, size: usize) -> Result<()> {
        // SAFETY: The caller keeps the pointed-to attribute value alive until spawn.
        if unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                attribute as usize,
                value,
                size,
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(IoError::last_os_error()).context("setting SSH process attributes");
        }
        Ok(())
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: This owns an initialized attribute list and its backing memory.
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

struct PseudoConsole {
    handle: HPCON,
    output: OwnedHandle,
}

// SAFETY: A single owner performs console operations on the cleanup worker.
unsafe impl Send for PseudoConsole {}

impl PseudoConsole {
    fn finish(mut self) {
        // SAFETY: Output is drained concurrently. The session owns a duplicate
        // server handle that disconnects output if draining reaches its bound.
        unsafe {
            ClosePseudoConsole(self.handle);
        }
        self.handle = 0;
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: On startup failure no drain task exists. Disconnecting
            // output first prevents ClosePseudoConsole from waiting forever.
            unsafe {
                DisconnectNamedPipe(self.output.0);
                ClosePseudoConsole(self.handle);
            }
        }
    }
}

struct Process {
    handle: OwnedHandle,
    job: OwnedHandle,
    pipes: Vec<OwnedHandle>,
    console: Option<PseudoConsole>,
    profile: Profile,
}

// SAFETY: Process/Job handles are thread-safe and ConPTY operations are serialized
// by the single session owner. Profile unloading occurs on the cleanup worker.
unsafe impl Send for Process {}

impl Process {
    fn spawn(
        spec: SessionSpec,
        input: OwnedHandle,
        output: OwnedHandle,
        error: Option<OwnedHandle>,
        controls: Vec<OwnedHandle>,
    ) -> Result<Self> {
        let profile = Profile::load(Arc::clone(&spec.login))?;
        let env = environment(&spec.login, &spec.env)?;
        let home = wide(spec.login.home()?.as_os_str());
        let program = spec.program.as_deref().unwrap_or(&spec.login.shell);
        ensure!(
            program.is_absolute(),
            "The SSH program path must be absolute."
        );
        ensure!(
            spec.program.is_none() || (spec.command.is_none() && spec.terminal.is_none()),
            "A direct SSH helper cannot use a shell command or terminal."
        );
        let application = wide(program.as_os_str());
        let mut command = if spec.program.is_some() {
            program_line(program)?
        } else {
            command_line(program, spec.command.as_deref(), spec.terminal.is_some())?
        };
        // SAFETY: Null names/security create an unnamed, owned job.
        let job = unsafe { CreateJobObjectW(null(), null()) };
        ensure!(
            !job.is_null(),
            "Could not create the SSH process job: {}",
            IoError::last_os_error()
        );
        let job = OwnedHandle(job);
        // SAFETY: This POD limit structure accepts zero initialization.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: The job and correctly sized limit structure are live.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                u32::try_from(size_of_val(&limits))?,
            )
        } == 0
        {
            return Err(IoError::last_os_error()).context("configuring the SSH process job");
        }
        let console = if let Some(size) = spec.terminal {
            let control = OwnedHandle::duplicate(controls[1].0)?;
            let mut handle = 0;
            // SAFETY: ConPTY receives synchronous child pipe ends and a writable handle.
            let result =
                unsafe { CreatePseudoConsole(size.coord()?, input.0, output.0, 0, &mut handle) };
            ensure!(
                result >= 0,
                "Could not create the SSH pseudoconsole (HRESULT {result:#x})."
            );
            Some(PseudoConsole {
                handle,
                output: control,
            })
        } else {
            None
        };
        let mut attributes = Attributes::new(1)?;
        let handles = [
            input.0,
            output.0,
            error.as_ref().map_or(output.0, |handle| handle.0),
        ];
        if let Some(console) = &console {
            attributes.update(
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                console.handle as *const c_void,
                size_of::<HPCON>(),
            )?;
        } else {
            attributes.update(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr().cast(),
                size_of_val(&handles),
            )?;
        }
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())?;
        startup.lpAttributeList = attributes.pointer();
        if console.is_none() {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = input.0;
            startup.StartupInfo.hStdOutput = output.0;
            startup.StartupInfo.hStdError = handles[2];
        }
        let mut info = PROCESS_INFORMATION::default();
        let flags = CREATE_SUSPENDED
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT
            | if console.is_none() {
                CREATE_NO_WINDOW
            } else {
                0
            };
        // SAFETY: All strings are terminated, env is double-terminated, the token
        // is a verified non-System primary token and attribute values stay live.
        if unsafe {
            CreateProcessAsUserW(
                spec.login.token_handle(),
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                i32::from(console.is_none()),
                flags,
                env.as_ptr().cast(),
                home.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(IoError::last_os_error()).context("creating the SSH user's process");
        }
        let process = OwnedHandle(info.hProcess);
        let thread = OwnedHandle(info.hThread);
        // SAFETY: The child is suspended and has not executed user code.
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            let failure = IoError::last_os_error();
            // SAFETY: This owns the suspended child; no user code has run.
            unsafe {
                TerminateProcess(process.0, 1);
                WaitForSingleObject(process.0, 5000);
            }
            return Err(failure).context("assigning the SSH process to its job");
        }
        // SAFETY: The owned initial thread is suspended and now belongs to the job.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = IoError::last_os_error();
            // SAFETY: No child instruction has executed; this owns its job.
            unsafe {
                TerminateJobObject(job.0, 1);
                WaitForSingleObject(process.0, 5000);
            }
            return Err(error).context("starting the SSH user's process");
        }
        Ok(Self {
            handle: process,
            job,
            pipes: controls,
            console,
            profile,
        })
    }

    fn exit_code(&self) -> Result<Option<u32>> {
        // SAFETY: A zero-time wait queries the owned process without blocking.
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                // SAFETY: The process is signaled and code is writable.
                if unsafe { GetExitCodeProcess(self.handle.0, &mut code) } == 0 {
                    return Err(IoError::last_os_error())
                        .context("reading SSH process exit status");
                }
                Ok(Some(code))
            }
            _ => Err(IoError::last_os_error()).context("waiting for SSH process exit"),
        }
    }

    fn resize(&self, size: TerminalSize) -> Result<()> {
        if let Some(console) = &self.console {
            // SAFETY: The session owner serializes resize and console destruction.
            let result = unsafe { ResizePseudoConsole(console.handle, size.coord()?) };
            ensure!(
                result >= 0,
                "Could not resize the SSH pseudoconsole (HRESULT {result:#x})."
            );
        }
        Ok(())
    }

    fn terminate(&self) {
        // SAFETY: This owns the job; terminating it includes all descendants.
        unsafe {
            TerminateJobObject(self.job.0, 1);
        }
    }

    fn disconnect(&mut self) {
        disconnect(&self.pipes);
        self.pipes.clear();
        self.console.take();
    }

    fn finish(mut self) -> Result<()> {
        self.terminate();
        if let Some(console) = self.console.take() {
            console.finish();
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: This owns the job and the writable accounting structure
            // has the size required for this information class.
            if unsafe {
                QueryInformationJobObject(
                    self.job.0,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    u32::try_from(size_of_val(&accounting))?,
                    null_mut(),
                )
            } == 0
            {
                return Err(IoError::last_os_error())
                    .context("waiting for SSH process descendants");
            }
            if accounting.ActiveProcesses == 0 {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "The SSH process job did not exit during cleanup."
            );
            // This finite loop runs only on the dedicated cleanup worker.
            sleep(Duration::from_millis(10));
        }
        // The child ends are closed, but their final bytes can still be in the
        // pipe buffers. Leave disconnection to the async drain owner.
        self.pipes.clear();
        self.profile.unload()?;
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.terminate();
        self.disconnect();
    }
}

fn command_line(shell: &Path, command: Option<&str>, terminal: bool) -> Result<Vec<u16>> {
    let shell = shell
        .to_str()
        .context("The SSH shell path is not valid Unicode.")?;
    ensure!(!shell.contains(['"', '\0']), "Invalid SSH shell path.");
    let mut line = format!("\"{shell}\" -NoLogo -NoProfile -OutputFormat Text -InputFormat Text");
    if let Some(command) = command {
        ensure!(
            command.len() <= 32 * 1024 && !command.contains('\0'),
            "The SSH command is too large or contains NUL."
        );
        if !terminal {
            line.push_str(" -NonInteractive");
        }
        let script = if terminal {
            format!(
                "[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); {command}"
            )
        } else {
            // Redirected streams have valid pipe handles but no console code
            // page. Install UTF-8 readers/writers without invoking console APIs.
            format!(
                "$ProgressPreference='SilentlyContinue'; $rayfishEncoding=[System.Text.UTF8Encoding]::new($false); \
                 $rayfishOut=[System.IO.StreamWriter]::new([Console]::OpenStandardOutput(),$rayfishEncoding,4096,$true); \
                 $rayfishOut.AutoFlush=$true; [Console]::SetOut($rayfishOut); \
                 $rayfishErr=[System.IO.StreamWriter]::new([Console]::OpenStandardError(),$rayfishEncoding,4096,$true); \
                 $rayfishErr.AutoFlush=$true; [Console]::SetError($rayfishErr); \
                 [Console]::SetIn([System.IO.StreamReader]::new([Console]::OpenStandardInput(),$rayfishEncoding,$false,4096,$true)); {command}"
            )
        };
        let bytes: Vec<_> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        line.push_str(" -EncodedCommand ");
        line.push_str(&STANDARD.encode(bytes));
    }
    let result = wide(OsStr::new(&line));
    ensure!(
        result.len() <= 32_767,
        "The SSH command exceeds the Windows command-line limit."
    );
    Ok(result)
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

fn program_line(program: &Path) -> Result<Vec<u16>> {
    let program = program
        .to_str()
        .context("The SSH helper path is not valid Unicode.")?;
    ensure!(!program.contains(['"', '\0']), "Invalid SSH helper path.");
    Ok(wide(OsStr::new(&format!("\"{program}\""))))
}

fn disconnect(pipes: &[OwnedHandle]) {
    for pipe in pipes {
        // SAFETY: These are duplicates of this session's named pipe server
        // ends. Disconnection intentionally releases pending I/O at shutdown.
        unsafe {
            DisconnectNamedPipe(pipe.0);
        }
    }
}

async fn pump(
    mut pipe: NamedPipeServer,
    mut output: impl AsyncWrite + Unpin,
    cancel: CancellationToken,
) -> Result<()> {
    let mut bytes = vec![0; 16 * 1024];
    loop {
        let read = tokio::select! { _ = cancel.cancelled() => return Ok(()), result = pipe.read(&mut bytes) => result };
        let count = match read {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if matches!(error.raw_os_error(), Some(109 | 232 | 233)) => return Ok(()),
            Err(error) => return Err(error).context("reading SSH process output"),
        };
        tokio::select! { _ = cancel.cancelled() => return Ok(()), result = output.write_all(&bytes[..count]) => result.context("sending SSH process output")? }
    }
}

pub(super) async fn run_session(
    channel: Channel<Msg>,
    spec: SessionSpec,
    mut resize_rx: watch::Receiver<TerminalSize>,
    cancel: CancellationToken,
) -> Result<u32> {
    ensure!(!cancel.is_cancelled(), "The SSH session was cancelled.");
    let PipePair {
        parent: mut stdin,
        child: input,
        control: input_control,
    } = pipe(false).await?;
    let PipePair {
        parent: stdout,
        child: output,
        control: output_control,
    } = pipe(true).await?;
    let mut controls = vec![input_control, output_control];
    let mut stderr = None;
    let mut error_child = None;
    if spec.terminal.is_none() {
        let PipePair {
            parent,
            child,
            control,
        } = pipe(true).await?;
        stderr = Some(parent);
        error_child = Some(child);
        controls.push(control);
    }
    // Keep independent server handles so a bounded drain can interrupt a
    // ClosePseudoConsole running on the cleanup worker.
    let shutdown_pipes = controls
        .iter()
        .map(|pipe| OwnedHandle::duplicate(pipe.0))
        .collect::<Result<Vec<_>>>()?;
    let creating_cancel = cancel.clone();
    let process = spawn_blocking(move || {
        ensure!(
            !creating_cancel.is_cancelled(),
            "The SSH session was cancelled."
        );
        Process::spawn(spec, input, output, error_child, controls)
    })
    .await
    .context("joining SSH process creation")??;
    let (mut incoming, outgoing) = channel.split();
    let output_cancel = cancel.child_token();
    let input_cancel = cancel.child_token();
    let close_cancel = cancel.child_token();
    let mut outputs = JoinSet::new();
    outputs.spawn(pump(stdout, outgoing.make_writer(), output_cancel.clone()));
    if let Some(stderr) = stderr {
        outputs.spawn(pump(
            stderr,
            outgoing.make_writer_ext(Some(1)),
            output_cancel.clone(),
        ));
    }
    let reading_cancel = input_cancel.clone();
    let closing_cancel = close_cancel.clone();
    let mut input_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut eof = false;
        loop {
            let message = tokio::select! { _ = reading_cancel.cancelled() => return Ok::<_, anyhow::Error>(()), message = incoming.wait() => message };
            match message {
                Some(ChannelMsg::Data { data }) if !eof => {
                    tokio::select! { _ = reading_cancel.cancelled() => return Ok(()), result = stdin.write_all(&data) => result.context("writing SSH process input")? }
                }
                Some(ChannelMsg::Eof) if !eof => {
                    stdin.disconnect().context("closing SSH process input")?;
                    eof = true;
                }
                Some(ChannelMsg::Close) | None => {
                    closing_cancel.cancel();
                    return Ok(());
                }
                _ => {}
            }
        }
    }));
    let mut input_result = None;
    let mut poll = interval(Duration::from_millis(25));
    let mut resize_open = true;
    let result = loop {
        tokio::select! {
            _ = close_cancel.cancelled() => break Err(anyhow::anyhow!("The SSH session was cancelled.")),
            _ = poll.tick() => match process.exit_code() { Ok(Some(code)) => break Ok(code), Ok(None) => {}, Err(error) => break Err(error) },
            changed = resize_rx.changed(), if resize_open => {
                if changed.is_err() { resize_open = false; }
                else if let Err(error) = process.resize(*resize_rx.borrow_and_update()) { break Err(error); }
            },
            input = &mut input_task, if input_result.is_none() => {
                let input = input.context("joining SSH process input").and_then(|result| result);
                input_result = Some(Ok(()));
                break input.and(Err(anyhow::anyhow!("The SSH input stream ended before the process exited.")));
            },
            output = outputs.join_next(), if !outputs.is_empty() => match output {
                Some(Ok(Ok(()))) => {},
                Some(Ok(Err(error))) => break Err(error),
                Some(Err(error)) => break Err(error.into()),
                None => {},
            },
        }
    };
    input_cancel.cancel();
    process.terminate();
    // A killed descendant cannot retain stdout/stderr. Close ConPTY on a
    // blocking worker while output continues draining, including its final
    // terminal frame. Deadline expiry disconnects the pipes to unblock it.
    let cleanup = spawn_blocking(move || process.finish());
    let drained = timeout(CLEANUP_TIMEOUT, async {
        while let Some(output) = outputs.join_next().await {
            output??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    output_cancel.cancel();
    disconnect(&shutdown_pipes);
    outputs.abort_all();
    while outputs.join_next().await.is_some() {}
    let input_result = match input_result {
        Some(result) => result,
        None => input_task
            .await
            .context("joining SSH process input")
            .and_then(|result| result),
    };
    let reaped = cleanup
        .await
        .context("joining SSH process cleanup")
        .and_then(|result| result);
    result.and_then(|code| {
        input_result?;
        reaped?;
        drained.context("SSH output did not finish during cleanup")??;
        Ok(code)
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    use super::*;

    #[test]
    fn commands_are_encoded_in_one_argument_and_sizes_are_bounded() {
        let line = command_line(
            Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            Some("Write-Output 'quoted \"text\"'; exit 7"),
            false,
        )
        .unwrap();
        let text = String::from_utf16(&line[..line.len() - 1]).unwrap();
        let encoded = text.split(" -EncodedCommand ").nth(1).unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        let words: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert!(
            String::from_utf16(&words)
                .unwrap()
                .ends_with("Write-Output 'quoted \"text\"'; exit 7")
        );
        assert!(TerminalSize { cols: 0, rows: 80 }.coord().is_err());
        assert!(
            TerminalSize {
                cols: u16::MAX,
                rows: 80
            }
            .coord()
            .is_err()
        );
    }

    #[tokio::test]
    async fn synchronous_child_pipe_preserves_binary_bytes_and_closes() {
        let PipePair {
            parent,
            child,
            control,
        } = pipe(true).await.unwrap();
        let mut flags = 0;
        // SAFETY: Both owned handles are live and flags is writable.
        assert_ne!(unsafe { GetHandleInformation(child.0, &mut flags) }, 0);
        assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
        // The shutdown duplicate must never reach a child process.
        assert_ne!(unsafe { GetHandleInformation(control.0, &mut flags) }, 0);
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let data = vec![0, 0xff, b'\r', b'\n', 0x80, 0, 7];
        let expected = data.clone();
        let writer = spawn_blocking(move || {
            let handle = child;
            let mut count = 0;
            // SAFETY: This is a synchronous handle, the byte slice stays live,
            // and count is writable. The short write fits the pipe's buffer.
            let ok = unsafe {
                WriteFile(
                    handle.0,
                    data.as_ptr(),
                    u32::try_from(data.len()).unwrap(),
                    &mut count,
                    null_mut(),
                )
            };
            assert_ne!(ok, 0, "{}", IoError::last_os_error());
            assert_eq!(usize::try_from(count).unwrap(), data.len());
        });
        let (output, mut received) = duplex(1024);
        timeout(
            CLEANUP_TIMEOUT,
            pump(parent, output, CancellationToken::new()),
        )
        .await
        .unwrap()
        .unwrap();
        writer.await.unwrap();
        let mut actual = Vec::new();
        received.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn disconnect_interrupts_a_pending_output_read() {
        let PipePair {
            parent,
            child,
            control,
        } = pipe(true).await.unwrap();
        let (output, _) = duplex(1024);
        let pump = pump(parent, output, CancellationToken::new());
        tokio::pin!(pump);
        // Poll the real asynchronous read before releasing it through the
        // separate control handle, without a timing-based synchronization.
        assert!(futures::poll!(&mut pump).is_pending());
        disconnect(&[control]);
        timeout(CLEANUP_TIMEOUT, pump).await.unwrap().unwrap();
        drop(child);
    }
}
