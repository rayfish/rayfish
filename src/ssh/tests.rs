use std::net::Ipv4Addr;
use std::process::{Command as StdCommand, Stdio};

use russh::client;
use russh::keys::PublicKeyOrCertificate;
use russh::{ChannelMsg, client::Msg as ClientMsg};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use super::*;

fn id(seed: u8) -> EndpointId {
    let mut b = [0u8; 32];
    b[0] = seed;
    iroh::SecretKey::from(b).public()
}

#[test]
fn banner_tells_an_unauthorized_peer_why_and_how_to_fix_it() {
    // The whole point: without this the client only sees a password prompt
    // from the system sshd and reads the refusal as a network problem.
    let peer = id(7);
    let nets = [SmolStr::new("trade"), SmolStr::new("homelab")];
    let banner = auth_banner(&UserPolicy::default(), &peer, &nets)
        .expect("an unauthorized peer must be told");
    assert!(banner.contains("not authorized"));
    assert!(banner.contains(&peer.fmt_short().to_string()));
    assert!(banner.contains("ray firewall ssh allow homelab"));
    assert!(banner.contains("system sshd"));
}

#[test]
fn no_banner_for_authorized_peers() {
    let peer = id(8);
    let mut policy = UserPolicy::default();
    policy.add(&[]);
    assert_eq!(auth_banner(&policy, &peer, &[SmolStr::new("trade")]), None);

    let mut named = UserPolicy::default();
    named.add(&["deploy".to_string(), "ci".to_string()]);
    assert_eq!(auth_banner(&named, &peer, &[SmolStr::new("trade")]), None);

    let mut any = UserPolicy::default();
    any.add(&["*".to_string()]);
    assert_eq!(auth_banner(&any, &peer, &[SmolStr::new("trade")]), None);
}

fn rule(peer: &str, users: &[&str]) -> crate::config::SshRule {
    crate::config::SshRule {
        peer: peer.to_string(),
        users: users.iter().map(|u| u.to_string()).collect(),
    }
}

#[test]
fn authz_matches_identity_and_wildcard_per_network() {
    let alice = id(1);
    let bob = id(2);
    let authz = new_authz();
    let mut map = HashMap::new();
    // `net1` authorizes alice explicitly; `net2` authorizes any peer.
    map.insert("net1".to_string(), vec![rule(&alice.to_string(), &[])]);
    map.insert("net2".to_string(), vec![rule("*", &[])]);
    authz.store(Arc::new(map));

    let authorized = |u, nets: &[&str]| {
        let nets: Vec<SmolStr> = nets.iter().map(SmolStr::new).collect();
        resolve_user_policy(&authz, u, &nets).authorized()
    };
    // alice on net1 → allowed; bob on net1 → denied.
    assert!(authorized(&alice, &["net1"]));
    assert!(!authorized(&bob, &["net1"]));
    // wildcard on net2 → anyone allowed.
    assert!(authorized(&bob, &["net2"]));
    // a network with no allow list → denied.
    assert!(!authorized(&alice, &["net3"]));
    // union across shared networks: alice shares net3 (no rule) + net2 (*).
    assert!(authorized(&alice, &["net3", "net2"]));
}

#[test]
fn parse_sftp_subsystem_keeps_the_command_and_its_arguments() {
    // `/bin/sh` stands in for sftp-server: the parser only requires an
    // absolute path that exists, and every unix host has this one.
    let dump = "permitrootlogin no\nsubsystem sftp /bin/sh -f AUTH -l INFO\n";
    assert_eq!(
        parse_sftp_subsystem(dump).as_deref(),
        Some("/bin/sh -f AUTH -l INFO")
    );
}

#[test]
fn parse_sftp_subsystem_rejects_what_it_cannot_spawn() {
    // internal-sftp is code inside sshd, not a binary.
    assert_eq!(parse_sftp_subsystem("subsystem sftp internal-sftp\n"), None);
    // A path this host doesn't have (sshd config copied from elsewhere).
    assert_eq!(
        parse_sftp_subsystem("subsystem sftp /nonexistent/sftp-server\n"),
        None
    );
    // Another subsystem, and a bare directive, must not match.
    assert_eq!(parse_sftp_subsystem("subsystem netconf /bin/sh\n"), None);
    assert_eq!(parse_sftp_subsystem("subsystem\nsubsystem sftp\n"), None);
    assert_eq!(parse_sftp_subsystem(""), None);
}

#[test]
fn parse_hostkey_paths_extracts_hostkey_lines() {
    // `sshd -T` prints one lowercase directive per line; only `hostkey`
    // lines carry a path, and there can be several. Other directives and
    // blank lines are ignored.
    let dump = "port 22\n\
        hostkey /etc/ssh/ssh_host_rsa_key\n\
        hostkey /etc/ssh/ssh_host_ecdsa_key\n\
        HostKey /etc/ssh/ssh_host_ed25519_key\n\
        hostkeyalgorithms ssh-ed25519\n\
        permitrootlogin no\n";
    let paths = parse_hostkey_paths(dump);
    assert_eq!(
        paths,
        vec![
            PathBuf::from("/etc/ssh/ssh_host_rsa_key"),
            PathBuf::from("/etc/ssh/ssh_host_ecdsa_key"),
            PathBuf::from("/etc/ssh/ssh_host_ed25519_key"),
        ]
    );
}

#[test]
fn parse_hostkey_paths_empty_when_no_hostkey() {
    assert!(parse_hostkey_paths("port 22\npermitrootlogin no\n").is_empty());
}

#[test]
fn host_key_paths_fall_back_when_sshd_dump_fails() {
    assert_eq!(
        host_key_paths(None),
        vec![
            PathBuf::from("/etc/ssh/ssh_host_ed25519_key"),
            PathBuf::from("/usr/local/etc/ssh/ssh_host_ed25519_key"),
        ]
    );
}

#[test]
fn host_key_paths_use_sshd_configuration_when_available() {
    assert_eq!(
        host_key_paths(Some("hostkey /custom/ssh_host_ed25519_key\n")),
        vec![PathBuf::from("/custom/ssh_host_ed25519_key")]
    );
}

#[test]
fn user_policy_default_is_nonroot() {
    // An allow rule with no explicit users grants any non-root user but not
    // root, enforced by uid (so a uid-0 account under any name is blocked).
    let alice = id(1);
    let authz = new_authz();
    authz.store(Arc::new(HashMap::from([(
        "net".to_string(),
        vec![rule(&alice.to_string(), &[])],
    )])));
    let p = resolve_user_policy(&authz, &alice, &[SmolStr::new("net")]);
    assert!(p.permits("deploy", 1000), "non-root user allowed");
    assert!(!p.permits("root", 0), "root (uid 0) blocked by default");
    assert!(
        !p.permits("toor", 0),
        "any uid-0 account blocked, not just 'root'"
    );
}

/// Client side of the loopback tests: the host key is generated per test,
/// so there is nothing to verify against. Channels the *server* opens back
/// to us (reverse forwards, agent connections) are handed to whichever test
/// asked to watch for them.
struct AcceptAnyHost {
    opened: Option<mpsc::UnboundedSender<Channel<ClientMsg>>>,
}

impl client::Handler for AcceptAnyHost {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<ClientMsg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if let Some(tx) = &self.opened {
            let _ = tx.send(channel);
        }
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<ClientMsg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if let Some(tx) = &self.opened {
            let _ = tx.send(channel);
        }
        Ok(())
    }
}

/// The account the tests log in as: the one running them, which is also the
/// one the server runs as, so the session needs no privilege drop.
fn test_account() -> String {
    let uid = uzers::get_effective_uid();
    uzers::get_user_by_uid(uid)
        .expect("these tests need a passwd entry for the uid running them")
        .name()
        .to_string_lossy()
        .to_string()
}

/// Run a self-SSH server on loopback that admits each connection the way
/// the daemon does: as the local uid owning the client socket, or not at
/// all. Returns the address clients dial.
#[cfg(target_os = "linux")]
fn spawn_self_ssh_server() -> Result<SocketAddr> {
    let mesh = local::bind(Ipv6Addr::LOCALHOST, 0)?;
    let local = local::bind(Ipv6Addr::LOCALHOST, 0)?;
    let address = local.local_addr()?;
    let config = Arc::new(server_config(PrivateKey::random(
        &mut rand::rng(),
        Algorithm::Ed25519,
    )?));
    tokio::spawn(async move {
        loop {
            let Ok((stream, client)) = local::accept(&mesh, Some(&local)).await else {
                return;
            };
            let server = stream.local_addr().expect("server address");
            let Some(uid) = local::uid(client, server).await else {
                continue;
            };
            let handler = SshHandler::new(
                UserPolicy::local(uid),
                id(1),
                None,
                Origin { client, server },
            );
            tokio::spawn(serve(Arc::clone(&config), stream, handler, LOGIN_GRACE));
        }
    });
    Ok(address)
}

/// An SSH client to `address` whose TCP socket belongs to an `nc` child,
/// as a real self-SSH client's does. `None` without `nc`.
#[cfg(target_os = "linux")]
async fn self_ssh_client(
    address: SocketAddr,
) -> Result<Option<(tokio::process::Child, client::Handle<AcceptAnyHost>)>> {
    let Some(mut nc) = local::tests::nc_client(address) else {
        return Ok(None);
    };
    let stdout = nc.stdout.take().expect("piped stdout");
    let stdin = nc.stdin.take().expect("piped stdin");
    let handle = client::connect_stream(
        Arc::new(client::Config::default()),
        tokio::io::join(stdout, stdin),
        AcceptAnyHost { opened: None },
    )
    .await?;
    Ok(Some((nc, handle)))
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn self_ssh_authenticates_the_socket_owner_and_executes() -> Result<()> {
    let address = spawn_self_ssh_server()?;
    if uzers::get_effective_uid() != 0 {
        let Some((_nc, mut denied)) = self_ssh_client(address).await? else {
            return Ok(());
        };
        assert!(!denied.authenticate_none("root").await?.success());
    }
    let Some((_nc, mut handle)) = self_ssh_client(address).await? else {
        return Ok(());
    };
    assert!(handle.authenticate_none(test_account()).await?.success());
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, "printf self-ssh-ok").await?;
    let (output, code) = drain(&mut channel).await;
    assert_eq!(output, "self-ssh-ok");
    assert_eq!(code, Some(0));
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_forward_into_self_ssh_is_not_a_login_as_the_daemon() -> Result<()> {
    // `ssh -J host host` or `-L` to this host's own SSH port: the daemon
    // dials it as root, and must not be taken for a local root client.
    let address = spawn_self_ssh_server()?;
    let peer = connect_to_test_server().await;
    let tunnel = peer
        .channel_open_direct_tcpip(
            address.ip().to_string(),
            address.port().into(),
            "127.0.0.1",
            1,
        )
        .await?;
    let attempt = client::connect_stream(
        Arc::new(client::Config::default()),
        tunnel.into_stream(),
        AcceptAnyHost { opened: None },
    )
    .await;
    let admitted = match attempt {
        Ok(mut handle) => matches!(
            handle.authenticate_none(test_account()).await,
            Ok(result) if result.success()
        ),
        Err(_) => false,
    };
    assert!(!admitted, "a daemon-dialed connection logged in");
    Ok(())
}

/// Serve the real [`SshHandler`] on loopback and return an authenticated
/// client connection to it. The peer is authorized for any user, the same
/// state a live mesh connection reaches before it opens a channel.
async fn connect_to_test_server() -> client::Handle<AcceptAnyHost> {
    connect_watching_openings(None, test_account(), LOGIN_GRACE).await
}

/// The same, plus the channels the server opens back to the client: what a
/// reverse forward and agent forwarding deliver.
async fn connect_and_watch_openings() -> (
    client::Handle<AcceptAnyHost>,
    mpsc::UnboundedReceiver<Channel<ClientMsg>>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        connect_watching_openings(Some(tx), test_account(), LOGIN_GRACE).await,
        rx,
    )
}

async fn connect_watching_openings(
    opened: Option<mpsc::UnboundedSender<Channel<ClientMsg>>>,
    login_as: String,
    grace: Duration,
) -> client::Handle<AcceptAnyHost> {
    let addr = serve_one(grace).await;
    let mut handle = client::connect(
        Arc::new(client::Config {
            nodelay: true,
            ..client::Config::default()
        }),
        addr,
        AcceptAnyHost { opened },
    )
    .await
    .expect("client connect");
    assert!(
        handle
            .authenticate_none(login_as)
            .await
            .expect("auth")
            .success(),
        "the `none` method is the mesh SSH auth gate"
    );
    handle
}

/// Serve one connection with a short login grace and hand back the client
/// socket, so a test can stall the handshake the way a black-holed mesh
/// path does and watch the server let go.
async fn connect_with_grace(grace: Duration) -> TcpStream {
    let addr = serve_one(grace).await;
    TcpStream::connect(addr).await.expect("client connect")
}

/// Serve the next connection on a loopback port, with every login allowed,
/// and return the address to dial.
async fn serve_one(grace: Duration) -> SocketAddr {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let config = Arc::new(Config {
        auth_rejection_time: Duration::ZERO,
        ..server_config(key)
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(async move {
        let (stream, client) = listener.accept().await.expect("accept");
        disable_nagle(&stream);
        let mut policy = UserPolicy::default();
        policy.add(&["*".to_string()]);
        // The same origin the live path builds: the client's real address,
        // and :22 for our side, which is where the client thinks it is.
        let origin = Origin {
            client,
            server: SocketAddr::new(addr.ip(), SSH_PORT),
        };
        let handler = SshHandler::new(policy, id(1), None, origin);
        serve(config, stream, handler, grace).await;
    });
    addr
}

/// Read until the server hangs up, or fail. `read_to_end` returning at all
/// is the assertion: it means the socket is gone.
async fn wait_for_hangup(sock: &mut TcpStream) {
    let mut sink = Vec::new();
    timeout(Duration::from_secs(10), sock.read_to_end(&mut sink))
        .await
        .expect("the server held a stalled handshake open past the login grace")
        .ok();
}

#[tokio::test]
async fn an_authenticated_session_outlives_the_login_grace() {
    // The grace has to stop counting once a peer is admitted, or every
    // session would be cut off partway through whatever it was doing.
    // Allow the cryptographic handshake to complete under parallel test
    // load, then wait past the same grace before using the session.
    let grace = Duration::from_secs(2);
    let handle = connect_watching_openings(None, test_account(), grace).await;
    tokio::time::sleep(grace + Duration::from_millis(100)).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open a session channel after the grace has passed");
    channel.exec(true, "echo alive").await.expect("exec");
    let (out, code) = drain(&mut channel).await;
    assert!(out.contains("alive"), "output after the grace: {out}");
    assert_eq!(code, Some(0));
}

#[tokio::test]
async fn keepalives_preserve_idle_sessions_and_close_unresponsive_clients() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let interval = Duration::from_millis(250);
    let config = Arc::new(Config {
        keepalive_interval: Some(interval),
        auth_rejection_time: Duration::ZERO,
        ..server_config(key)
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, client) = listener.accept().await.unwrap();
        let mut policy = UserPolicy::default();
        policy.add(&["*".to_string()]);
        let origin = Origin {
            client,
            server: SocketAddr::new(addr.ip(), SSH_PORT),
        };
        serve(
            config,
            stream,
            SshHandler::new(policy, id(1), None, origin),
            LOGIN_GRACE,
        )
        .await;
    });

    // A transparent proxy can swallow replies without closing TCP. The
    // client still receives probes and answers them, just as it would on
    // a mesh path whose return traffic has stopped reaching the server.
    let upstream = TcpStream::connect(addr).await.unwrap();
    let (client_stream, proxy_stream) = tokio::io::duplex(65536);
    let blackhole = Arc::new(AtomicBool::new(false));
    let drop_replies = Arc::clone(&blackhole);
    let proxy = tokio::spawn(async move {
        let (mut client_read, mut client_write) = tokio::io::split(proxy_stream);
        let (mut server_read, mut server_write) = upstream.into_split();
        let forward_replies = async {
            let mut buf = [0u8; 8192];
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<_, std::io::Error>(());
                }
                if !drop_replies.load(Ordering::Relaxed) {
                    server_write.write_all(&buf[..n]).await?;
                }
            }
        };
        let _ = tokio::try_join!(
            forward_replies,
            tokio::io::copy(&mut server_read, &mut client_write)
        );
    });
    let mut handle = client::connect_stream(
        Arc::new(client::Config::default()),
        client_stream,
        AcceptAnyHost { opened: None },
    )
    .await
    .unwrap();
    assert!(
        handle
            .authenticate_none(test_account())
            .await
            .unwrap()
            .success()
    );

    // More than two failure windows with no application traffic. Only
    // automatic SSH replies keep this session alive.
    tokio::time::sleep(interval * 9).await;
    assert!(!server.is_finished(), "responsive idle client was dropped");
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo alive").await.unwrap();
    let (out, code) = drain(&mut channel).await;
    assert!(out.contains("alive"));
    assert_eq!(code, Some(0));

    blackhole.store(true, Ordering::Relaxed);
    timeout(interval * 6, server)
        .await
        .expect("unresponsive client survived the keepalive failure window")
        .unwrap();
    proxy.abort();
}

#[tokio::test]
async fn a_peer_that_never_sends_its_version_string_is_dropped() {
    // Both halves of the handshake need their own bound, and this is the
    // half russh runs before there is a session: without the grace it sits
    // here indefinitely, holding the socket.
    let mut sock = connect_with_grace(Duration::from_millis(200)).await;
    wait_for_hangup(&mut sock).await;
}

#[tokio::test]
async fn a_peer_that_never_authenticates_is_dropped() {
    // The other half: the version exchange completes, so russh owns a
    // session task, and then nothing else arrives. This is the shape of the
    // real hang, where the mesh path stops carrying the flow mid-handshake.
    let mut sock = connect_with_grace(Duration::from_millis(200)).await;
    sock.write_all(b"SSH-2.0-stalls_here\r\n")
        .await
        .expect("write version string");
    wait_for_hangup(&mut sock).await;
}

/// Drain one channel to its close, returning what the command wrote to
/// stdout and the exit status it reported. Bounded: a channel that never
/// finishes is exactly the bug under test, and it must fail, not hang.
async fn drain(channel: &mut Channel<ClientMsg>) -> (String, Option<u32>) {
    let collect = async {
        let mut out = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        (String::from_utf8_lossy(&out).to_string(), code)
    };
    timeout(Duration::from_secs(20), collect)
        .await
        .expect("the channel never finished: no output, no exit status, no close")
}

#[tokio::test]
async fn every_channel_on_one_connection_runs_its_command() {
    // The `ssh -M` / ControlMaster case, and what Zed remote development
    // does: several commands in a row, each its own session channel on one
    // connection. Run beyond the former limit, including finished commands.
    let handle = connect_to_test_server().await;
    for n in 1..=12 {
        let mut channel = handle
            .channel_open_session()
            .await
            .expect("open session channel");
        channel
            .exec(true, format!("echo ran-{n}"))
            .await
            .expect("exec");
        let (out, code) = drain(&mut channel).await;
        assert!(
            out.contains(&format!("ran-{n}")),
            "channel {n} output: {out}"
        );
        assert_eq!(code, Some(0), "channel {n} exit status");
    }
}

#[tokio::test]
async fn concurrent_channels_keep_their_own_output_and_pty() {
    // Both channels are open before either one starts a command, so a
    // single per-connection slot would let the second clobber the first.
    // `$TERM` is the tell: it is set only for a PTY session, so the pipe
    // channel seeing it would mean the PTY request leaked across channels.
    let handle = connect_to_test_server().await;
    let mut tty = handle
        .channel_open_session()
        .await
        .expect("open pty channel");
    let mut pipe = handle
        .channel_open_session()
        .await
        .expect("open pipe channel");

    tty.request_pty(true, "xterm-rayfish", 80, 24, 0, 0, &[])
        .await
        .expect("request pty");
    tty.exec(true, "echo on-tty term=$TERM")
        .await
        .expect("exec");
    pipe.exec(true, "echo on-pipe term=$TERM")
        .await
        .expect("exec");

    let (tty_out, tty_code) = drain(&mut tty).await;
    let (pipe_out, pipe_code) = drain(&mut pipe).await;

    assert!(tty_out.contains("on-tty"), "pty channel output: {tty_out}");
    assert!(!tty_out.contains("on-pipe"), "cross-talk: {tty_out}");
    assert!(
        tty_out.contains("term=xterm-rayfish"),
        "the pty channel gets its terminal: {tty_out}"
    );
    assert_eq!(tty_code, Some(0));

    assert!(
        pipe_out.contains("on-pipe"),
        "pipe channel output: {pipe_out}"
    );
    assert!(!pipe_out.contains("on-tty"), "cross-talk: {pipe_out}");
    assert!(
        !pipe_out.contains("xterm-rayfish"),
        "the pty must not leak onto the other channel: {pipe_out}"
    );
    assert!(
        !pipe_out.contains('\r'),
        "a pipe session is not line-translated: {pipe_out:?}"
    );
    assert_eq!(pipe_code, Some(0));
}

#[tokio::test]
async fn direct_tcpip_channel_carries_a_forwarded_connection() {
    // `ssh -L`, `ssh -D` and `ProxyJump` all open this channel type. With
    // no handler for it russh refuses the open ("administratively
    // prohibited"), so every forward through a mesh host failed.
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo listener");
    let port = echo.local_addr().expect("echo address").port();
    tokio::spawn(async move {
        let (mut sock, _) = echo.accept().await.expect("accept forwarded connection");
        let (mut r, mut w) = sock.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });

    let handle = connect_to_test_server().await;
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 1234)
        .await
        .expect("open direct-tcpip channel");

    let mut stream = channel.into_stream();
    stream.write_all(b"ping").await.expect("write to forward");
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
        .await
        .expect("the forwarded connection never answered")
        .expect("read from forward");
    assert_eq!(&buf, b"ping", "bytes come back off the forwarded socket");
}

#[tokio::test]
async fn direct_tcpip_open_fails_when_the_target_refuses() {
    // Nothing listens on the port. The open must fail as "connect failed",
    // which is what `ssh -L` prints, rather than hand the client a channel
    // that will never carry data.
    let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind to claim a port");
    let port = dead.local_addr().expect("address").port();
    drop(dead);

    let handle = connect_to_test_server().await;
    let opened = timeout(
        Duration::from_secs(20),
        handle.channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 1234),
    )
    .await
    .expect("a forward to a refused port must not hang");
    assert!(
        matches!(
            opened,
            Err(russh::Error::ChannelOpenFailure(
                ChannelOpenFailure::ConnectFailed
            ))
        ),
        "want a connect-failed refusal, got {:?}",
        opened.map(|c| c.id())
    );
}

#[tokio::test]
async fn reverse_forward_carries_a_connection_back_to_the_client() {
    // `ssh -R`: this host listens, and each connection to the bound port
    // becomes a channel the *server* opens to the client.
    let (handle, mut opened) = connect_and_watch_openings().await;
    let port = handle
        .tcpip_forward("localhost", 0)
        .await
        .expect("reverse forward request");
    assert_ne!(port, 0, "a port-0 request must come back with the real one");

    let mut local = TcpStream::connect((Ipv4Addr::LOCALHOST, port as u16))
        .await
        .expect("connect to the reverse-forwarded port");
    let channel = timeout(Duration::from_secs(20), opened.recv())
        .await
        .expect("no forwarded channel arrived")
        .expect("the connection dropped");

    let mut stream = channel.into_stream();
    local.write_all(b"ping").await.expect("write on the socket");
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
        .await
        .expect("the forwarded bytes never arrived")
        .expect("read from the channel");
    assert_eq!(&buf, b"ping");

    stream.write_all(b"pong").await.expect("write back");
    timeout(Duration::from_secs(20), local.read_exact(&mut buf))
        .await
        .expect("nothing came back the other way")
        .expect("read from the socket");
    assert_eq!(&buf, b"pong", "the forward carries both directions");

    handle
        .cancel_tcpip_forward("localhost", port)
        .await
        .expect("cancel the forward");
    // The listener goes with the cancellation, so the port stops answering.
    let mut refused = false;
    for _ in 0..40 {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port as u16))
            .await
            .is_err()
        {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "a cancelled forward must release its port");
}

#[tokio::test]
async fn direct_streamlocal_channel_reaches_a_unix_socket() {
    // `ssh -L <port>:/path/to.sock`: docker, gpg-agent, database sockets.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("echo.sock");
    let echo = UnixListener::bind(&path).expect("bind echo socket");
    tokio::spawn(async move {
        let (mut sock, _) = echo.accept().await.expect("accept");
        let (mut r, mut w) = sock.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });

    let handle = connect_to_test_server().await;
    let channel = handle
        .channel_open_direct_streamlocal(path.display().to_string())
        .await
        .expect("open direct-streamlocal channel");

    let mut stream = channel.into_stream();
    stream.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
        .await
        .expect("the forwarded socket never answered")
        .expect("read");
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn a_forwarded_socket_is_dialed_by_a_process_running_as_the_login_account() {
    // A root daemon dialing for the peer would show up as uid 0 to a
    // service that authorizes by SO_PEERCRED (the ray IPC socket, the
    // system bus). The dial has to come from a separate process that has
    // already become the login account.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("cred.sock");
    let listener = UnixListener::bind(&path).expect("bind socket");
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        let _ = tx.send(sock.peer_cred().expect("peer credentials"));
    });

    let handle = connect_to_test_server().await;
    handle
        .channel_open_direct_streamlocal(path.display().to_string())
        .await
        .expect("open direct-streamlocal channel");
    let cred = timeout(Duration::from_secs(20), rx)
        .await
        .expect("the forward never dialed the socket")
        .expect("accept task ended");
    assert_ne!(cred.pid(), Some(std::process::id() as i32));
    assert_eq!(cred.uid(), uzers::get_effective_uid());
}

#[tokio::test]
async fn a_connection_can_open_more_than_ten_session_channels() {
    let handle = connect_to_test_server().await;
    let mut open = Vec::new();
    for _ in 0..12 {
        open.push(
            handle
                .channel_open_session()
                .await
                .expect("open a concurrent session"),
        );
    }
}

#[tokio::test]
async fn a_connection_cannot_hold_unbounded_reverse_forwards() {
    let handle = connect_to_test_server().await;
    for _ in 0..MAX_REVERSE_FORWARDS {
        handle
            .tcpip_forward("localhost", 0)
            .await
            .expect("a reverse forward within the limit");
    }
    assert!(
        handle.tcpip_forward("localhost", 0).await.is_err(),
        "a reverse forward past the limit must be refused"
    );
}

#[tokio::test]
async fn a_held_socket_forward_can_be_replaced_at_the_limit() {
    // Re-requesting a forward the connection already holds replaces it;
    // it does not count as one more.
    let handle = connect_to_test_server().await;
    for _ in 1..MAX_REVERSE_FORWARDS {
        handle
            .tcpip_forward("localhost", 0)
            .await
            .expect("a reverse forward within the limit");
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("r.sock").display().to_string();
    handle
        .streamlocal_forward(path.clone())
        .await
        .expect("the last forward within the limit");
    handle
        .streamlocal_forward(path)
        .await
        .expect("replacing a held forward at the limit");
}

#[tokio::test]
async fn a_reverse_forward_cannot_carry_unbounded_connections() {
    // Anyone on this host can connect to a `-R` port; each connection
    // becomes a channel to the client, under the same cap as `-L`.
    let (handle, mut opened) = connect_and_watch_openings().await;
    let port = handle
        .tcpip_forward("localhost", 0)
        .await
        .expect("reverse forward request");
    let mut held = Vec::new();
    let mut channels = Vec::new();
    for _ in 0..MAX_FORWARDED_CHANNELS {
        held.push(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port as u16))
                .await
                .expect("connect"),
        );
        channels.push(
            timeout(Duration::from_secs(20), opened.recv())
                .await
                .expect("no forwarded channel")
                .expect("connection dropped"),
        );
    }
    let mut extra = TcpStream::connect((Ipv4Addr::LOCALHOST, port as u16))
        .await
        .expect("connect");
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(20), extra.read(&mut byte))
        .await
        .expect("a connection past the limit must be closed");
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn a_connection_cannot_carry_unbounded_forwarded_channels() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind target");
    let port = listener.local_addr().expect("target address").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    let handle = connect_to_test_server().await;
    let mut open = Vec::new();
    for _ in 0..MAX_FORWARDED_CHANNELS {
        open.push(
            handle
                .channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1)
                .await
                .expect("a forwarded channel within the limit"),
        );
    }
    assert!(
        handle
            .channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 1)
            .await
            .is_err(),
        "a forwarded channel past the limit must be refused"
    );
}

/// Root only: run as `sudo <test binary> --ignored root_forwards`. The
/// daemon side is root and logs in as `nobody`, so every check below is the
/// kernel's answer for that account rather than for root.
#[tokio::test]
#[ignore]
async fn root_forwards_use_the_login_accounts_permissions() {
    if uzers::get_effective_uid() != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let nobody = uzers::get_user_by_name("nobody").expect("a nobody account");
    // A root-only directory: mode bits inside it say "anyone", but nobody
    // cannot even reach them.
    let private = tempfile::tempdir().expect("temp dir");
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod private dir");
    let hidden = private.path().join("hidden.sock");
    let _hidden_listener = UnixListener::bind(&hidden).expect("bind hidden socket");
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o666))
        .expect("chmod hidden socket");
    let open_dir = private.path().join("open");
    std::fs::create_dir(&open_dir).expect("create open dir");
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777))
        .expect("chmod open dir");

    // A socket nobody can reach, which reports who dialed it.
    let public = tempfile::tempdir().expect("temp dir");
    std::fs::set_permissions(public.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod public dir");
    let cred_path = public.path().join("cred.sock");
    let cred_listener = UnixListener::bind(&cred_path).expect("bind cred socket");
    std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o666))
        .expect("chmod cred socket");
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (sock, _) = cred_listener.accept().await.expect("accept");
        let _ = tx.send(sock.peer_cred().expect("peer credentials"));
    });

    let handle = connect_watching_openings(None, "nobody".to_string(), LOGIN_GRACE).await;
    handle
        .channel_open_direct_streamlocal(cred_path.display().to_string())
        .await
        .expect("open direct-streamlocal channel");
    let cred = timeout(Duration::from_secs(20), rx)
        .await
        .expect("the forward never dialed the socket")
        .expect("accept task ended");
    assert_eq!(
        cred.uid(),
        nobody.uid(),
        "the dial must not carry root's uid"
    );

    // `-L` to a socket the account cannot reach: refused, either at the
    // open or by the channel closing without a byte.
    if let Ok(channel) = handle
        .channel_open_direct_streamlocal(hidden.display().to_string())
        .await
    {
        let mut stream = channel.into_stream();
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(20), stream.read(&mut buf))
            .await
            .expect("the refused forward never closed");
        assert!(matches!(read, Ok(0) | Err(_)), "reached a hidden socket");
    }

    // `-R` into a directory the account cannot reach.
    let reverse = open_dir.join("reverse.sock");
    assert!(
        handle
            .streamlocal_forward(reverse.display().to_string())
            .await
            .is_err(),
        "bound a socket where nobody cannot"
    );
    assert!(!reverse.exists());

    // `-R` on a privileged port.
    assert!(
        handle.tcpip_forward("localhost", 1023).await.is_err(),
        "nobody must not bind a privileged port"
    );
}

#[tokio::test]
async fn session_env_takes_locale_and_drops_the_rest() {
    // `SendEnv`/`SetEnv` may describe the client's locale, not steer the
    // login shell: a peer that could set LD_PRELOAD would be running its
    // own code inside every session.
    let handle = connect_to_test_server().await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    channel
        .set_env(false, "LC_RAYFISH", "kept")
        .await
        .expect("set an accepted variable");
    channel
        .set_env(false, "LD_PRELOAD", "/tmp/evil.so")
        .await
        .expect("set a rejected variable");
    channel
        .exec(true, "echo env:$LC_RAYFISH:$LD_PRELOAD:")
        .await
        .expect("exec");
    let (out, code) = drain(&mut channel).await;
    assert!(out.contains("env:kept::"), "session environment: {out}");
    assert_eq!(code, Some(0));
}

#[tokio::test]
async fn a_signal_request_reaches_the_session_process() {
    // The client asking to kill what it started, and the exit reported as
    // the signal it was rather than an invented status code.
    let handle = connect_to_test_server().await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    channel.exec(true, "sleep 30").await.expect("exec");

    // The signal is repeated because it is only deliverable once the child
    // exists, and nothing on the wire says when that is.
    let mut signalled = None;
    for _ in 0..100 {
        let _ = channel.signal(Sig::TERM).await;
        match timeout(Duration::from_millis(200), channel.wait()).await {
            Ok(Some(ChannelMsg::ExitSignal { signal_name, .. })) => {
                signalled = Some(format!("{signal_name:?}"));
            }
            Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => continue,
        }
    }
    assert_eq!(
        signalled.as_deref(),
        Some("TERM"),
        "the session must end reported as killed by SIGTERM"
    );
}

#[tokio::test]
async fn a_completed_command_removes_its_agent_socket_on_a_reused_connection() {
    let handle = connect_to_test_server().await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    channel.agent_forward(true).await.expect("request an agent");
    channel
        .exec(true, "printf '%s' \"$SSH_AUTH_SOCK\"")
        .await
        .expect("exec");
    let (path, code) = drain(&mut channel).await;
    assert_eq!(code, Some(0));
    assert!(!path.is_empty(), "the command must receive an agent socket");
    timeout(Duration::from_secs(20), async {
        while tokio::fs::try_exists(&path)
            .await
            .expect("check agent socket")
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the agent socket outlived its command");

    handle
        .channel_open_session()
        .await
        .expect("the connection must remain reusable");
}

#[tokio::test]
async fn agent_forwarding_hands_the_session_a_socket_that_reaches_the_client() {
    // `ssh -A`: the session gets an SSH_AUTH_SOCK whose other end is the
    // client's agent, so a key never has to live on this host.
    let (handle, mut opened) = connect_and_watch_openings().await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    channel.agent_forward(true).await.expect("request an agent");
    channel
        .exec(true, "printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 5")
        .await
        .expect("exec");

    // Read the path the session was given, while it is still running (the
    // socket lives exactly as long as the channel).
    let mut path = String::new();
    for _ in 0..100 {
        match timeout(Duration::from_secs(20), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                path.push_str(&String::from_utf8_lossy(&data));
                if path.contains('\n') {
                    break;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    let path = path.trim().to_string();
    assert!(
        path.starts_with("/tmp/rayfish-ssh-agent."),
        "the session's SSH_AUTH_SOCK: {path:?}"
    );

    let mut sock = UnixStream::connect(&path)
        .await
        .expect("the session's agent socket must accept connections");
    let agent = timeout(Duration::from_secs(20), opened.recv())
        .await
        .expect("no agent channel reached the client")
        .expect("the connection dropped");

    // What the session writes to the socket comes out on the client's side
    // of the agent channel, which is where a real ssh-agent would answer.
    sock.write_all(b"ping").await.expect("write to the socket");
    let mut stream = agent.into_stream();
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
        .await
        .expect("the agent bytes never arrived")
        .expect("read from the agent channel");
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn openssh_exits_after_using_a_forwarded_agent() {
    // OpenSSH closes an agent channel once the agent connection ends and
    // waits for the server to close it back before exiting. A server that
    // drops the channel without answering leaves `ssh -A host cmd` hanging
    // after `cmd` has finished. Needs the OpenSSH client and agent.
    if StdCommand::new("ssh").arg("-V").output().is_err()
        || StdCommand::new("ssh-agent").arg("-k").output().is_err()
    {
        eprintln!("skipping: no OpenSSH client or agent");
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let agent_sock = dir.path().join("agent.sock");
    let mut agent = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&agent_sock)
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start ssh-agent");
    // It prints its environment once the socket is listening.
    let mut ready = String::new();
    BufReader::new(agent.stdout.take().expect("agent stdout is piped"))
        .read_line(&mut ready)
        .await
        .expect("read ssh-agent output");
    assert!(
        ready.starts_with("SSH_AUTH_SOCK="),
        "ssh-agent said: {ready}"
    );

    let addr = serve_one(LOGIN_GRACE).await;
    let run = Command::new("ssh")
        .env("SSH_AUTH_SOCK", &agent_sock)
        .args(["-A", "-F", "/dev/null", "-p", &addr.port().to_string()])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .args(["-o", "BatchMode=yes", "-o", "PreferredAuthentications=none"])
        .args(["-o", "LogLevel=ERROR"])
        .arg(format!("{}@{}", test_account(), addr.ip()))
        .arg("ssh-add -l; echo agent-rc=$?")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = timeout(Duration::from_secs(20), run)
        .await
        .expect("ssh -A did not exit after its command finished")
        .expect("run ssh");
    let _ = agent.kill().await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    // ssh-add exits 1 for an empty agent it reached and 2 for no agent.
    assert!(
        stdout.contains("agent-rc=1"),
        "the session did not reach the agent: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "ssh exit: {:?}", out.status);
}

/// Kept out of the normal run: an interactive login shell depends on the
/// host's shell and its rc files, and as root it goes through `login(1)`,
/// which writes real utmp/wtmp records. Run it deliberately, as root, to
/// exercise the login handoff:
///
/// ```text
/// cargo test --lib -- --ignored --exact ssh::tests::a_login_shell_runs_and_exits
/// ```
#[tokio::test]
#[ignore]
async fn a_login_shell_runs_and_exits() {
    // Reaching `login(1)` needs a root server and a non-root login, which
    // under `sudo` is the account that invoked it.
    let login_as = match uzers::get_effective_uid() {
        0 => std::env::var("SUDO_USER").unwrap_or_else(|_| test_account()),
        _ => test_account(),
    };
    let handle = connect_watching_openings(None, login_as, LOGIN_GRACE).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    channel
        .request_pty(true, "xterm-rayfish", 80, 24, 0, 0, &[])
        .await
        .expect("request pty");
    channel.request_shell(true).await.expect("request shell");
    // The quotes matter: the terminal echoes what we type, so the command
    // has to look different from its own output for the marker to mean the
    // shell ran it. And it is offered repeatedly because `login` flushes
    // the terminal before exec'ing the shell, so anything typed while it
    // was still printing the motd is gone.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut retype = tokio::time::Instant::now();
    let mut out = String::new();
    let mut ran = false;
    while tokio::time::Instant::now() < deadline {
        if !ran && tokio::time::Instant::now() >= retype {
            let _ = channel.data(&b"echo ray\"fish\"-marker\n"[..]).await;
            retype = tokio::time::Instant::now() + Duration::from_millis(500);
        }
        match timeout(Duration::from_millis(200), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                out.push_str(&String::from_utf8_lossy(&data));
                if !ran && out.contains("rayfish-marker") {
                    ran = true;
                    let _ = channel.data(&b"exit\n"[..]).await;
                }
            }
            Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => continue,
        }
    }
    assert!(ran, "the login shell never ran our command: {out:?}");
}

/// The server must offer "none" alone as its compression. Russh's zlib is
/// broken on the receive side: with `zlib@openssh.com` negotiated, the
/// second SSH_MSG_CHANNEL_DATA an OpenSSH client sends fails to decompress
/// and the connection dies with `SshEncoding: length invalid`. `Compression
/// yes` is common enough in people's ssh_config that this is the path they
/// hit first -- the session drops the moment they type a second command --
/// so the advertisement itself is what this pins. Russh's own client
/// interoperates with russh's zlib, so only the wire tells the truth here.
#[tokio::test]
async fn the_server_offers_no_compression() {
    let mut sock = connect_with_grace(LOGIN_GRACE).await;
    sock.write_all(b"SSH-2.0-rayfish-test\r\n")
        .await
        .expect("send our version string");

    // Enough for the version line and the KEXINIT behind it, which is still
    // in the clear this early.
    let mut buf = vec![0u8; 8192];
    let mut have = 0;
    let kexinit = loop {
        let n = timeout(Duration::from_secs(10), sock.read(&mut buf[have..]))
            .await
            .expect("the server never sent its KEXINIT")
            .expect("read from the server");
        assert!(n > 0, "the server hung up before its KEXINIT");
        have += n;
        if let Some(payload) = first_packet_payload(&buf[..have]) {
            break payload.to_vec();
        }
    };

    const SSH_MSG_KEXINIT: u8 = 20;
    assert_eq!(
        kexinit.first().copied(),
        Some(SSH_MSG_KEXINIT),
        "the server's first packet is its KEXINIT"
    );
    // msg type, then a 16-byte cookie, then the algorithm name-lists.
    let lists = name_lists(&kexinit[17..]);
    // kex, host key, cipher c2s, cipher s2c, mac c2s, mac s2c, then the two
    // compression lists.
    assert_eq!(
        (
            lists.get(6).map(String::as_str),
            lists.get(7).map(String::as_str)
        ),
        (Some("none"), Some("none")),
        "the server must not offer zlib: {lists:?}"
    );
}

/// Split off the payload of the first complete binary packet in `bytes`,
/// skipping the version line ahead of it. `None` until all of it has
/// arrived. Unencrypted packets only, which is all this early in a session.
fn first_packet_payload(bytes: &[u8]) -> Option<&[u8]> {
    let line_end = bytes.windows(2).position(|w| w == b"\r\n")? + 2;
    let packet = bytes.get(line_end..)?;
    let length = u32::from_be_bytes(packet.get(..4)?.try_into().ok()?) as usize;
    let padding = *packet.get(4)? as usize;
    let payload_len = length.checked_sub(padding + 1)?;
    packet.get(5..5 + payload_len)
}

/// The `name-list` sequence of a KEXINIT body: each one a u32 length and
/// that many bytes of comma-separated names.
fn name_lists(mut bytes: &[u8]) -> Vec<String> {
    let mut lists = Vec::new();
    while bytes.len() >= 4 {
        let (len_bytes, rest) = bytes.split_at(4);
        let Ok(len) = u32::from_be_bytes(len_bytes.try_into().unwrap_or([0; 4])).try_into() else {
            break;
        };
        let len: usize = len;
        if rest.len() < len {
            break;
        }
        let (list, rest) = rest.split_at(len);
        lists.push(String::from_utf8_lossy(list).into_owned());
        bytes = rest;
    }
    lists
}

#[tokio::test]
async fn a_session_knows_it_is_remote() {
    // Prompts, `screen`, and any script that asks "am I over ssh" read
    // these. A session without them looks local.
    let handle = connect_to_test_server().await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    channel
        .exec(true, "echo conn:$SSH_CONNECTION client:$SSH_CLIENT")
        .await
        .expect("exec");
    let (out, code) = drain(&mut channel).await;
    assert_eq!(code, Some(0));
    // "<client ip> <client port> <server ip> <server port>", and the server
    // port is the 22 the client dialled, not the internal listen port.
    let conn = out
        .split_whitespace()
        .find(|w| w.starts_with("conn:"))
        .map(|w| w.trim_start_matches("conn:").to_string())
        .expect("SSH_CONNECTION is set");
    assert_eq!(
        conn, "127.0.0.1",
        "SSH_CONNECTION starts at the client: {out}"
    );
    assert!(
        out.contains(&format!(" {SSH_PORT} ")) || out.ends_with(&format!(" {SSH_PORT}")),
        "the server port is the one the client dialled: {out}"
    );
    assert!(out.contains("client:127.0.0.1"), "SSH_CLIENT is set: {out}");
}

#[tokio::test]
async fn a_pty_reports_its_terminal() {
    // SSH_TTY names the pts the session runs on; `write`, `who` and
    // anything that talks to a terminal by path need it.
    let (_pty, pts) = pty_process::open().expect("open a pty");
    prepare_pts(&pts);
    let name = tty_name(&pts).expect("the child end of a pty has a name");
    assert!(name.starts_with("/dev/"), "a terminal path, got {name:?}");
}

#[test]
fn reverse_forwards_bind_loopback_only() {
    // A reverse forward publishes the peer's service on this host, so a
    // wildcard bind is narrowed, like sshd's default `GatewayPorts no`.
    assert_eq!(
        reverse_bind_addr("localhost"),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(reverse_bind_addr(""), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(reverse_bind_addr("::1"), IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(reverse_bind_addr("*"), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        reverse_bind_addr("0.0.0.0"),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        reverse_bind_addr("10.0.0.1"),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
}

#[test]
fn accepted_env_is_locale_only() {
    assert!(env_accepted("LANG"));
    assert!(env_accepted("LC_ALL"));
    assert!(env_accepted("LC_CTYPE"));
    assert!(env_accepted("TZ"));
    assert!(env_accepted("TERM"));
    // The ones that would run the peer's code inside the session.
    assert!(!env_accepted("LD_PRELOAD"));
    assert!(!env_accepted("LD_LIBRARY_PATH"));
    assert!(!env_accepted("PATH"));
    assert!(!env_accepted("BASH_ENV"));
    assert!(!env_accepted("SSH_AUTH_SOCK"));
}

#[test]
fn user_policy_explicit_and_wildcard() {
    let alice = id(1);
    let authz = new_authz();
    // net1: alice may only be `deploy`; net2: alice may be any user (`*`).
    authz.store(Arc::new(HashMap::from([
        (
            "net1".to_string(),
            vec![rule(&alice.to_string(), &["deploy"])],
        ),
        ("net2".to_string(), vec![rule(&alice.to_string(), &["*"])]),
    ])));

    // Only net1 shared → just `deploy`, root and others denied.
    let p = resolve_user_policy(&authz, &alice, &[SmolStr::new("net1")]);
    assert!(p.permits("deploy", 1000));
    assert!(!p.permits("ci", 1001));
    assert!(!p.permits("root", 0));

    // net2 shared → `*` wins, even root.
    let p = resolve_user_policy(&authz, &alice, &[SmolStr::new("net2")]);
    assert!(p.permits("root", 0));

    // Union: explicit `deploy` (net1) + `*` (net2) → `*` dominates.
    let p = resolve_user_policy(
        &authz,
        &alice,
        &[SmolStr::new("net1"), SmolStr::new("net2")],
    );
    assert!(p.permits("root", 0));
    assert!(p.permits("anyone", 1234));
}
