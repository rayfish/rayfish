//! Native protocol tests run as LocalSystem with a disposable local account.

use std::ffi::OsStr;
use std::io::Error as IoError;

use russh::client::{self, Msg as ClientMsg};
use russh::keys::PublicKeyOrCertificate;
use russh::{ChannelMsg, Disconnect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, spawn_blocking};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use super::*;

const DEADLINE: Duration = Duration::from_secs(30);
const MAX_OUTPUT: usize = 128 * 1024;

struct AcceptTestHost {
    forwarded: Option<mpsc::Sender<Channel<ClientMsg>>>,
}

impl client::Handler for AcceptTestHost {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Only an ephemeral loopback test server is reachable through this client.
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)]
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<ClientMsg>,
        _address: &str,
        _port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if let Some(forwarded) = &self.forwarded {
            reply.accept().await;
            forwarded
                .try_send(channel)
                .map_err(|_| russh::Error::SendError)?;
        }
        Ok(())
    }
}

struct TestServer {
    address: SocketAddr,
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl TestServer {
    async fn start(user: &str, authorized: bool) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let stopped = cancel.clone();
        let user = user.to_owned();
        let task = tokio::spawn(async move {
            let (stream, _) = timeout(DEADLINE, listener.accept()).await??;
            serve_test_connection(stream, &user, authorized, stopped).await
        });
        Ok(Self {
            address,
            cancel,
            task: Some(task),
        })
    }

    async fn connect(&self) -> Result<client::Handle<AcceptTestHost>> {
        self.connect_with_forwarding(None).await
    }

    async fn connect_with_forwarding(
        &self,
        forwarded: Option<mpsc::Sender<Channel<ClientMsg>>>,
    ) -> Result<client::Handle<AcceptTestHost>> {
        timeout(
            DEADLINE,
            client::connect(
                Arc::new(client::Config::default()),
                self.address,
                AcceptTestHost { forwarded },
            ),
        )
        .await
        .context("the test SSH handshake timed out")?
        .context("connecting to the native SSH test server")
    }

    async fn stop(mut self) -> Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            timeout(DEADLINE, task)
                .await
                .context("the SSH test server did not stop")?
                .context("joining the SSH test server")??;
        }
        Ok(())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn test_account() -> Result<String> {
    anyhow::ensure!(
        crate::windows_identity::current_user_sid().as_deref() == Some("S-1-5-18"),
        "Windows SSH integration tests must run as LocalSystem"
    );
    let user = std::env::var("RAYFISH_SSH_TEST_USER")
        .context("set RAYFISH_SSH_TEST_USER to a disposable local account")?;
    anyhow::ensure!(
        user.starts_with("ssh-test-"),
        "the integration account must be a disposable ssh-test account"
    );
    Ok(user)
}

struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: Option<u32>,
}

async fn drain(channel: &mut Channel<ClientMsg>) -> Result<Output> {
    timeout(DEADLINE, async {
        let mut output = Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            status: None,
        };
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    anyhow::ensure!(
                        output.stdout.len() + data.len() <= MAX_OUTPUT,
                        "SSH output exceeded the test bound"
                    );
                    output.stdout.extend_from_slice(&data);
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    anyhow::ensure!(
                        output.stderr.len() + data.len() <= MAX_OUTPUT,
                        "SSH stderr exceeded the test bound"
                    );
                    output.stderr.extend_from_slice(&data);
                }
                ChannelMsg::Failure => anyhow::bail!("the SSH server rejected the channel request"),
                ChannelMsg::ExitStatus { exit_status } => output.status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(output)
    })
    .await
    .context("the SSH channel did not complete")?
}

#[tokio::test]
#[ignore = "requires LocalSystem and the disposable CI account"]
async fn windows_ssh_exec_and_interactive_powershell_use_the_login_account() -> Result<()> {
    let user = test_account()?;
    let expected_sid = crate::windows_identity::account_sid(OsStr::new(&user))?;
    let server = TestServer::start(&user, true).await?;
    let mut client = server.connect().await?;
    anyhow::ensure!(
        client.authenticate_none(user).await?.success(),
        "the allowed local account could not authenticate"
    );

    let mut command = client.channel_open_session().await?;
    command.exec(true, "if ([string]::IsNullOrWhiteSpace($env:USERPROFILE) -or $env:USERPROFILE -match 'systemprofile') { exit 99 }; [Console]::WriteLine(('rayfish-' + 'exec-ok')); [Console]::Error.WriteLine('rayfish-stderr-ok'); [Console]::WriteLine([Security.Principal.WindowsIdentity]::GetCurrent().User.Value); exit 23").await?;
    let output = drain(&mut command).await?;
    let stdout = String::from_utf8(output.stdout).context("exec output is not UTF-8")?;
    anyhow::ensure!(
        stdout.contains("rayfish-exec-ok"),
        "the SSH exec command did not run"
    );
    anyhow::ensure!(
        stdout.lines().any(|line| line.trim() == expected_sid),
        "SSH exec ran under the wrong account token"
    );
    anyhow::ensure!(
        output.status == Some(23),
        "SSH exec did not preserve its exit status"
    );

    anyhow::ensure!(
        String::from_utf8_lossy(&output.stderr).contains("rayfish-stderr-ok"),
        "SSH exec did not forward stderr separately"
    );

    let mut terminal = client.channel_open_session().await?;
    terminal
        .request_pty(true, "xterm-256color", 120, 30, 0, 0, &[])
        .await?;
    terminal.request_shell(true).await?;
    terminal.window_change(132, 40, 0, 0).await?;
    // The complete marker is absent from the input, so console input echo cannot
    // make a shell that never executes commands pass this assertion.
    terminal.data(&b"[Console]::WriteLine(('rayfish-' + 'pty-ok')); [Console]::WriteLine([Security.Principal.WindowsIdentity]::GetCurrent().User.Value); exit 17\r\n"[..]).await?;
    let output = drain(&mut terminal).await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    anyhow::ensure!(
        stdout.contains("rayfish-pty-ok"),
        "the interactive PowerShell command did not run"
    );
    anyhow::ensure!(
        stdout.contains(&expected_sid),
        "the interactive shell ran under the wrong account token"
    );
    anyhow::ensure!(
        output.status == Some(17),
        "the interactive shell did not preserve its exit status"
    );
    client
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await?;
    server.stop().await
}

#[tokio::test]
#[ignore = "requires LocalSystem and the disposable CI account"]
async fn windows_ssh_denies_unlisted_users_and_unapproved_peers() -> Result<()> {
    let user = test_account()?;
    for authorized in [true, false] {
        let server = TestServer::start(&user, authorized).await?;
        let mut client = server.connect().await?;
        let account = if authorized {
            "ssh-denied-placeholder"
        } else {
            &user
        };
        anyhow::ensure!(
            !client.authenticate_none(account).await?.success(),
            "an unauthorized SSH login was accepted"
        );
        client
            .disconnect(Disconnect::ByApplication, "test complete", "en")
            .await?;
        server.stop().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires LocalSystem and the disposable CI account"]
async fn windows_ssh_direct_and_reverse_forwarding_carry_real_tcp_bytes() -> Result<()> {
    let user = test_account()?;
    let server = TestServer::start(&user, true).await?;
    let (opened, mut forwarded) = mpsc::channel(1);
    let mut client = server.connect_with_forwarding(Some(opened)).await?;
    anyhow::ensure!(
        client.authenticate_none(user).await?.success(),
        "the forwarding test account could not authenticate"
    );

    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let destination = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = timeout(DEADLINE, echo.accept()).await??;
        let mut input = [0; 4];
        timeout(DEADLINE, socket.read_exact(&mut input)).await??;
        anyhow::ensure!(
            &input == b"ping",
            "the direct forward changed its input bytes"
        );
        socket.write_all(b"pong").await?;
        Ok::<_, anyhow::Error>(())
    });
    let loopback = Ipv4Addr::LOCALHOST.to_string();
    let channel = client
        .channel_open_direct_tcpip(
            loopback.clone(),
            u32::from(destination.port()),
            loopback.clone(),
            0,
        )
        .await?;
    let mut direct = channel.into_stream();
    direct.write_all(b"ping").await?;
    let mut response = [0; 4];
    timeout(DEADLINE, direct.read_exact(&mut response)).await??;
    anyhow::ensure!(
        &response == b"pong",
        "the direct forward changed its response bytes"
    );
    timeout(DEADLINE, echo_task).await???;
    direct.shutdown().await?;

    let port = client.tcpip_forward(loopback.clone(), 0).await?;
    let port_number =
        u16::try_from(port).context("the reverse forward returned an invalid port")?;
    let mut socket = timeout(
        DEADLINE,
        TcpStream::connect((Ipv4Addr::LOCALHOST, port_number)),
    )
    .await??;
    socket.write_all(b"ping").await?;
    let channel = timeout(DEADLINE, forwarded.recv())
        .await?
        .context("the reverse forward did not open an SSH channel")?;
    let mut reverse = channel.into_stream();
    let mut input = [0; 4];
    timeout(DEADLINE, reverse.read_exact(&mut input)).await??;
    anyhow::ensure!(
        &input == b"ping",
        "the reverse forward changed its input bytes"
    );
    reverse.write_all(b"pong").await?;
    timeout(DEADLINE, socket.read_exact(&mut response)).await??;
    anyhow::ensure!(
        &response == b"pong",
        "the reverse forward changed its response bytes"
    );
    reverse.shutdown().await?;
    socket.shutdown().await?;
    client.cancel_tcpip_forward(loopback, port).await?;
    client
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await?;
    server.stop().await
}

struct ProcessProof(HANDLE);

// SAFETY: This wrapper owns its kernel handle and transfers it without sharing
// mutation; Windows permits waiting and closing from another thread.
unsafe impl Send for ProcessProof {}

impl ProcessProof {
    fn open(pid: u32) -> Result<Self> {
        // SAFETY: No handle ownership is transferred to OpenProcess.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        anyhow::ensure!(
            !handle.is_null(),
            "opening the test process: {}",
            IoError::last_os_error()
        );
        let proof = Self(handle);
        // SAFETY: The live handle is owned by this wrapper.
        anyhow::ensure!(
            unsafe { WaitForSingleObject(proof.0, 0) } == WAIT_TIMEOUT,
            "the test command did not stay alive"
        );
        Ok(proof)
    }

    async fn exited(self) -> Result<()> {
        spawn_blocking(move || self.wait_for_exit())
            .await
            .context("joining the test process wait")?
    }

    fn wait_for_exit(&self) -> Result<()> {
        // SAFETY: The handle remains owned and live for the bounded wait.
        anyhow::ensure!(
            unsafe { WaitForSingleObject(self.0, 10_000) } == WAIT_OBJECT_0,
            "an SSH command process survived channel cleanup"
        );
        Ok(())
    }
}

impl Drop for ProcessProof {
    fn drop(&mut self) {
        // SAFETY: This wrapper closes its owned handle exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[tokio::test]
#[ignore = "requires LocalSystem and the disposable CI account"]
async fn windows_ssh_channel_close_kills_the_command_and_its_descendant() -> Result<()> {
    let user = test_account()?;
    let server = TestServer::start(&user, true).await?;
    let mut client = server.connect().await?;
    anyhow::ensure!(
        client.authenticate_none(user).await?.success(),
        "the test account could not authenticate"
    );
    let mut channel = client.channel_open_session().await?;
    channel.exec(true, "$child=Start-Process powershell.exe -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 300' -PassThru; [Console]::WriteLine(('RAYFISH-PIDS:{0}:{1}' -f $PID,$child.Id)); Start-Sleep -Seconds 300").await?;
    let ids = timeout(DEADLINE, async {
        let mut stdout = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    anyhow::ensure!(
                        stdout.len() + data.len() <= MAX_OUTPUT,
                        "the test process output exceeded its bound"
                    );
                    stdout.extend_from_slice(&data);
                    let text = String::from_utf8_lossy(&stdout);
                    if let Some(line) = text.split_inclusive('\n').find(|line| {
                        line.ends_with('\n')
                            && line.starts_with("RAYFISH-PIDS:")
                            && line.matches(':').count() == 2
                    }) {
                        let mut ids = line.trim().split(':').skip(1);
                        let parent = ids
                            .next()
                            .context("missing test parent PID")?
                            .parse::<u32>()?;
                        let descendant = ids
                            .next()
                            .context("missing test descendant PID")?
                            .parse::<u32>()?;
                        return Ok::<_, anyhow::Error>((
                            ProcessProof::open(parent)?,
                            ProcessProof::open(descendant)?,
                        ));
                    }
                }
                ChannelMsg::Failure => {
                    anyhow::bail!("the SSH server rejected the cleanup test command")
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        anyhow::bail!("the cleanup test command did not report its process identifiers")
    })
    .await
    .context("the cleanup test command did not start")??;
    channel.close().await?;
    let (parent, descendant) = ids;
    tokio::try_join!(parent.exited(), descendant.exited())?;
    client
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await?;
    server.stop().await
}
