//! Real unprivileged daemon lifecycle, private IPC and CLI instance selection.
#![cfg(all(target_os = "linux", feature = "desktop"))]

use base64::{Engine, engine::general_purpose::STANDARD};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use ray_proto::ipc::{self, IpcMessage};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const RAY: &str = env!("CARGO_BIN_EXE_ray");

fn command(directory: &Path) -> Command {
    let mut command = Command::new(RAY);
    command
        .env("RAYFISH_ROOTLESS_DIR", directory)
        .env("RUST_LOG", "rayfish=info")
        .env_remove("RAYFISH_CONFIG_DIR")
        .kill_on_drop(true);
    command
}

struct Running {
    child: Child,
    logs: JoinHandle<()>,
    socks: SocketAddr,
    http: SocketAddr,
    stdout: String,
}

#[derive(Debug)]
struct Addresses {
    socks: SocketAddr,
    http: SocketAddr,
    stdout: String,
}

fn listening_address(line: &str) -> SocketAddr {
    line.split("address=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

async fn start(directory: &Path) -> Running {
    start_with_command(command(directory)).await
}

async fn start_with_command(mut command: Command) -> Running {
    let mut child = command
        .args([
            "rootless",
            "--socks5",
            "127.0.0.1:0",
            "--http",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let (ready, waiting) = oneshot::channel();
    let logs = tokio::spawn(async move {
        let mut ready = Some(ready);
        let mut socks = None;
        let mut http = None;
        let mut stdout = String::new();
        while let Some(line) = lines.next_line().await.unwrap() {
            if ready.is_some() {
                stdout.push_str(&line);
                stdout.push('\n');
            }
            if line.contains("rootless SOCKS5 listening") {
                socks = Some(listening_address(&line));
            }
            if line.contains("rootless HTTP proxy listening") {
                http = Some(listening_address(&line));
            }
            if line.contains("rootless userspace networking ready")
                && let Some(ready) = ready.take()
            {
                ready
                    .send(Addresses {
                        socks: socks.take().unwrap(),
                        http: http.take().unwrap(),
                        stdout: std::mem::take(&mut stdout),
                    })
                    .unwrap();
            }
        }
    });
    let addresses = timeout(Duration::from_secs(30), waiting)
        .await
        .unwrap()
        .unwrap();
    Running {
        child,
        logs,
        socks: addresses.socks,
        http: addresses.http,
        stdout: addresses.stdout,
    }
}

async fn cli(directory: &Path, args: &[&str]) -> Output {
    timeout(
        Duration::from_secs(15),
        command(directory).arg("--rootless").args(args).output(),
    )
    .await
    .unwrap()
    .unwrap()
}

fn live_status(output: &Output) -> Option<serde_json::Value> {
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    // A missing daemon currently renders human output even with --json.
    if stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        == Some("\u{2717} daemon not running")
    {
        return None;
    }
    Some(serde_json::from_str(stdout).expect("a running daemon must return valid status JSON"))
}

async fn request(directory: &Path, message: IpcMessage) -> IpcMessage {
    let stream = UnixStream::connect(directory.join("run/rayfish.sock"))
        .await
        .unwrap();
    let mut framed = ipc::framed(stream);
    ipc::send(&mut framed, message).await.unwrap();
    timeout(Duration::from_secs(10), ipc::recv(&mut framed))
        .await
        .unwrap()
        .unwrap()
}

async fn stop(mut running: Running, directory: &Path) {
    let output = cli(directory, &["stop"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        timeout(Duration::from_secs(15), running.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    running.logs.await.unwrap();
    assert!(!directory.join("run/rayfish.sock").exists());
}

#[tokio::test]
async fn independent_rootless_instances_have_private_state_and_safe_lifecycle() {
    if uzers::get_effective_uid() == 0 {
        eprintln!("rootless lifecycle test requires an unprivileged test user");
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let first_path = temporary.path().join("first");
    let second_path = temporary.path().join("second");
    let missing_path = temporary.path().join("missing");
    let missing = cli(&missing_path, &["status", "--json"]).await;
    assert!(String::from_utf8_lossy(&missing.stdout).contains("daemon not running"));
    assert!(live_status(&missing).is_none());
    assert!(!missing_path.exists(), "a CLI read must not create state");
    let first = start(&first_path).await;
    let second = start(&second_path).await;
    for path in [&first_path, &second_path] {
        for private in [path.to_path_buf(), path.join("run"), path.join("logs")] {
            let metadata = std::fs::metadata(private).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), uzers::get_effective_uid());
        }
        for private in [path.join("run/rayfish.sock"), path.join("proxy-password")] {
            assert_eq!(
                std::fs::metadata(private).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let first_status = cli(&first_path, &["status", "--json"]).await;
    assert!(first_status.status.success());
    let first_status: serde_json::Value = serde_json::from_slice(&first_status.stdout).unwrap();
    let automatic = timeout(
        Duration::from_secs(15),
        command(&first_path).args(["status", "--json"]).output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(automatic.status.success());
    let automatic: serde_json::Value = serde_json::from_slice(&automatic.stdout).unwrap();
    assert_eq!(automatic["endpoint"], first_status["endpoint"]);
    assert_eq!(automatic["rootless"], true);
    let system = timeout(
        Duration::from_secs(15),
        command(&first_path)
            .args(["--system", "status", "--json"])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    if system.status.success()
        && let Some(system) = live_status(&system)
    {
        assert_ne!(system["rootless"], true);
        assert_ne!(system["endpoint"], first_status["endpoint"]);
    }
    for running in [&first, &second] {
        assert!(!running.stdout.contains("metrics server started"));
        assert!(!running.stdout.contains("failed to start metrics server"));
        assert!(running.stdout.contains("ray join <network-key>"));
        assert!(running.stdout.contains("ray status"));
        assert!(running.stdout.contains("ray --system status"));
        assert!(running.stdout.contains(&format!(
            "curl --proxy socks5h://{} --proxy-user ray",
            running.socks
        )));
        assert!(running.stdout.contains(&format!(
            "curl --proxy http://{} --proxy-user ray",
            running.http
        )));
    }
    assert!(
        first
            .stdout
            .contains(&first_path.join("proxy-password").display().to_string())
    );
    let secret = std::fs::read_to_string(first_path.join("proxy-password")).unwrap();
    assert!(
        !first.stdout.contains(&secret),
        "startup must never print the password"
    );
    let second_status = cli(&second_path, &["status", "--json"]).await;
    let second_status: serde_json::Value = serde_json::from_slice(&second_status.stdout).unwrap();
    assert_eq!(first_status["rootless"], true);
    assert_ne!(first_status["endpoint"], second_status["endpoint"]);
    let duplicate = timeout(
        Duration::from_secs(15),
        command(&first_path).arg("rootless").output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already running"));
    let mut socks = TcpStream::connect(first.socks).await.unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(socks.read_u16().await.unwrap(), 0x05ff);
    let password = std::fs::read(first_path.join("proxy-password")).unwrap();
    let mut socks = TcpStream::connect(first.socks).await.unwrap();
    socks.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(socks.read_u16().await.unwrap(), 0x0502);
    socks
        .write_all(&[
            1,
            3,
            b'r',
            b'a',
            b'y',
            u8::try_from(password.len()).unwrap(),
        ])
        .await
        .unwrap();
    socks.write_all(&password).await.unwrap();
    assert_eq!(socks.read_u16().await.unwrap(), 0x0100);
    // An IPv4 CONNECT request is explicitly rejected, never sent over the host network.
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut reply = [0; 22];
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 8);
    let mut http = TcpStream::connect(first.http).await.unwrap();
    http.write_all(b"GET http://peer.network.ray/ HTTP/1.1\r\nHost: peer.network.ray\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    http.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 407"));
    let mut http = TcpStream::connect(first.http).await.unwrap();
    let credentials = STANDARD.encode([b"ray:".as_slice(), &password].concat());
    http.write_all(format!("CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nProxy-Authorization: Basic {credentials}\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    http.read_to_string(&mut response).await.unwrap();
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "HTTP must not connect through the host network"
    );
    assert!(matches!(
        request(&first_path, IpcMessage::Down).await,
        IpcMessage::Ok { .. }
    ));
    assert!(matches!(
        request(&first_path, IpcMessage::Up { hostname: None }).await,
        IpcMessage::Ok { .. }
    ));
    assert!(matches!(
        request(
            &first_path,
            IpcMessage::ExitNodeUse {
                network: "mesh".into(),
                peer: Some("peer".into())
            }
        )
        .await,
        IpcMessage::Error { .. }
    ));
    stop(first, &first_path).await;
    assert!(
        cli(&second_path, &["status", "--json"])
            .await
            .status
            .success()
    );
    let mut crashed = start(&first_path).await;
    crashed.child.start_kill().unwrap();
    crashed.child.wait().await.unwrap();
    crashed.logs.await.unwrap();
    assert!(first_path.join("run/rayfish.sock").exists());
    assert!(
        cli(&second_path, &["status", "--json"])
            .await
            .status
            .success()
    );
    let restarted = start(&first_path).await;
    let status = cli(&first_path, &["status", "--json"]).await;
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["endpoint"], first_status["endpoint"]);
    assert_ne!(
        std::fs::read(first_path.join("proxy-password")).unwrap(),
        password
    );
    stop(restarted, &first_path).await;
    stop(second, &second_path).await;
}

#[tokio::test]
async fn automatic_selection_falls_back_without_creating_user_state() {
    if uzers::get_effective_uid() == 0 {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("instance");
    async fn status(directory: &Path, system: bool) -> Output {
        let mut cmd = command(directory);
        if system {
            cmd.arg("--system");
        }
        timeout(
            Duration::from_secs(15),
            cmd.args(["status", "--json"]).output(),
        )
        .await
        .unwrap()
        .unwrap()
    }
    fn assert_system_result(automatic: &Output, system: &Output) {
        assert_eq!(automatic.status.success(), system.status.success());
        if automatic.status.success() {
            match (live_status(automatic), live_status(system)) {
                (Some(automatic), Some(system)) => {
                    assert_eq!(automatic["endpoint"], system["endpoint"]);
                    assert_ne!(automatic["rootless"], true);
                }
                (None, None) => assert_eq!(automatic.stdout, system.stdout),
                _ => panic!("automatic selection must use the same system daemon"),
            }
        }
    }
    let system = status(&directory, true).await;
    assert_system_result(&status(&directory, false).await, &system);
    assert!(!directory.exists(), "discovery must not create state");

    let runtime = directory.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("rayfish.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    assert_system_result(&status(&directory, false).await, &system);
    assert!(!directory.join("secret_key").exists());

    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
    let rejected = status(&directory, false).await;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("rootless runtime directory"));
    assert_system_result(&status(&directory, true).await, &system);
}

#[tokio::test]
async fn rootless_network_changes_leave_host_dns_untouched() {
    use std::ffi::OsString;

    if uzers::get_effective_uid() == 0 {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("state");
    let bin = temporary.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let resolvectl = bin.join("resolvectl");
    std::fs::write(
        &resolvectl,
        "#!/bin/sh\nprintf '%s\n' \"$*\" >> \"$ROOTLESS_DNS_CALLS\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&resolvectl, std::fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("dns-calls");
    let mut path = OsString::from(bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let mut daemon = command(&directory);
    daemon
        .env("PATH", path)
        .env("ROOTLESS_DNS_CALLS", &calls)
        // Disable access to the real system bus even when a host TUN is present.
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            format!(
                "unix:path={}",
                temporary.path().join("no-system-bus").display()
            ),
        );
    let running = start_with_command(daemon).await;
    let created = cli(
        &directory,
        &["create", "--name", "mesh", "--hostname", "peer"],
    )
    .await;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(
        !calls.exists(),
        "rootless startup and network creation must not configure host DNS"
    );
    stop(running, &directory).await;
    assert!(
        !calls.exists(),
        "rootless shutdown must not configure host DNS"
    );
}
