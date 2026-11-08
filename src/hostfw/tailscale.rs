//! Keep Tailscale from using mesh addresses as transport endpoints on Linux.
//!
//! Tailscale sets SO_MARK on its transport sockets (net/netns/netns_linux.go).
//! Match its service cgroup, reserved mark bits, UDP, TUN and mesh destinations:
//! custom Tailscale ports work, ordinary mesh UDP remains usable, and internet
//! traffic through a Rayfish exit node is unaffected. This prevents a working
//! path; it cannot stop Tailscale advertising the address in the first place.
//!
//! Prefer a separate nftables table; fall back to ip6tables for older hosts.
//! Setup replaces stale interface names, periodic reconciliation restores rules
//! after a firewall reload, and standby/crash cleanup removes only our rules.
//! The comment includes the cgroup's inode: a service restart can recreate the
//! same path with another kernel identity, which requires replacing the rule.
//! The daemon checks cgroup changes every second. Protection requires cgroup v2 and
//! the standard systemd service path. With no such cgroup, remove stale rules;
//! never fall back to a rule that identifies Tailscale by its mark alone.

use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use thiserror::Error;

const TABLE: &str = "rayfish_coexist";
const LEGACY_COMMENT: &str = "rayfish-tailscale-v1";
const COMMENT: &str = "rayfish-tailscale-v2";
const SERVICE_CGROUP: &str = "system.slice/tailscaled.service";
// Tailscale's tsconst/linuxfw.go reserves bits 16..24. Rayfish's own socket
// mark uses the low bits, so it must not match this selector.
const MARK: &str = "0x80000/0xff0000";
const IP6_DUMP: [&str; 5] = ["ip6tables", "-w", "5", "-S", "OUTPUT"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceCgroup {
    inode: u64,
}

impl ServiceCgroup {
    pub(crate) fn current() -> io::Result<Option<Self>> {
        service_cgroup(Path::new("/sys/fs/cgroup"))
    }

    fn comment(self) -> String {
        format!("{COMMENT}:{}", self.inode)
    }
}

fn service_cgroup(root: &Path) -> io::Result<Option<ServiceCgroup>> {
    if !root.join("cgroup.controllers").try_exists()? {
        return Ok(None);
    }
    match std::fs::metadata(root.join(SERVICE_CGROUP)) {
        Ok(metadata) if metadata.is_dir() => Ok(Some(ServiceCgroup {
            inode: metadata.ino(),
        })),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("{command}: {source}")]
    Io {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("{command}: {stderr}")]
    Command { command: String, stderr: String },
    #[error("nftables: {nft}; ip6tables: {ip6tables}")]
    Backends {
        nft: Box<Error>,
        ip6tables: Box<Error>,
    },
}

/// Install the guard if missing or left for another TUN. The caller serializes
/// this with teardown and runs it on the blocking pool.
pub(crate) fn ensure(tun: &str) -> Result<(), Error> {
    let cgroup = ServiceCgroup::current().map_err(|source| Error::Io {
        command: "read Tailscale service cgroup".into(),
        source,
    })?;
    ensure_with(tun, cgroup, &mut run)
}

fn ensure_with(
    tun: &str,
    cgroup: Option<ServiceCgroup>,
    run: &mut impl FnMut(&[&str]) -> Result<String, Error>,
) -> Result<(), Error> {
    let Some(cgroup) = cgroup else {
        return remove_with(run);
    };
    let label = format!("{}:{tun}", cgroup.comment());
    if run(&["nft", "list", "table", "inet", TABLE])
        .is_ok_and(|dump| dump.contains(&format!("comment {}", quote(&label))))
    {
        return remove_ip6tables(run);
    }
    match run(&["nft", &nft_script(tun, cgroup)]) {
        Ok(_) => {
            // The available backend may have changed since the last start.
            remove_ip6tables(run)?;
            Ok(())
        }
        Err(nft) => ensure_ip6tables(tun, cgroup, run).map_err(|ip6tables| Error::Backends {
            nft: Box::new(nft),
            ip6tables: Box::new(ip6tables),
        }),
    }
}

fn quote(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}

fn nft_script(tun: &str, cgroup: ServiceCgroup) -> String {
    // Creating an existing table is idempotent. Delete and replace it in the
    // same transaction so an install never leaves a half-written guard.
    format!(
        "table inet {TABLE}; delete table inet {TABLE}; \
         table inet {TABLE} {{ chain output {{ \
         type filter hook output priority 0; policy accept; \
         oifname {} ip6 daddr 200::/7 meta mark & 0xff0000 == 0x80000 \
         socket cgroupv2 level 2 {} \
         meta l4proto udp reject with icmpv6 type admin-prohibited comment {}; \
         }}; }}\n",
        quote(tun),
        quote(SERVICE_CGROUP),
        quote(&format!("{}:{tun}", cgroup.comment()))
    )
}

fn ip6_spec<'a>(tun: &'a str, comment: &'a str) -> Vec<&'a str> {
    vec![
        "OUTPUT",
        "-o",
        tun,
        "-d",
        "200::/7",
        "-p",
        "udp",
        "-m",
        "mark",
        "--mark",
        MARK,
        "-m",
        "cgroup",
        "--path",
        SERVICE_CGROUP,
        "-m",
        "comment",
        "--comment",
        comment,
        "-j",
        "REJECT",
        "--reject-with",
        "icmp6-adm-prohibited",
    ]
}

fn ensure_ip6tables(
    tun: &str,
    cgroup: ServiceCgroup,
    run: &mut impl FnMut(&[&str]) -> Result<String, Error>,
) -> Result<(), Error> {
    let comment = cgroup.comment();
    let spec = ip6_spec(tun, &comment);
    let mut check = vec!["ip6tables", "-w", "5", "-C"];
    check.extend_from_slice(&spec);
    if run(&check).is_ok() {
        return Ok(());
    }
    // Remove rules for a previous interface before adding this one. Only exact
    // comment matches are ours; a similarly named user rule is left alone.
    remove_ip6tables(run)?;
    let mut insert = vec!["ip6tables", "-w", "5", "-I"];
    insert.extend_from_slice(&spec);
    run(&insert).map(|_| ())
}

fn ip6_deletions(dump: &str) -> Vec<Vec<&str>> {
    dump.lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|words| {
            words.starts_with(&["-A", "OUTPUT"])
                && words.windows(2).any(|w| {
                    let comment = w[1]
                        .strip_prefix('"')
                        .and_then(|word| word.strip_suffix('"'))
                        .unwrap_or(w[1]);
                    w[0] == "--comment"
                        && (comment == LEGACY_COMMENT
                            || comment
                                .strip_prefix(&format!("{COMMENT}:"))
                                .is_some_and(|id| id.parse::<u64>().is_ok()))
                })
        })
        .map(|mut words| {
            words[0] = "-D";
            words
                .into_iter()
                .map(|word| word.trim_matches('"'))
                .collect()
        })
        .collect()
}

fn remove_ip6tables(run: &mut impl FnMut(&[&str]) -> Result<String, Error>) -> Result<(), Error> {
    // Missing ip6tables is normal on an nft-only host.
    if let Ok(dump) = run(&IP6_DUMP) {
        for deletion in ip6_deletions(&dump) {
            let mut args = vec!["ip6tables", "-w", "5"];
            args.extend(deletion);
            run(&args)?;
        }
    }
    Ok(())
}

/// Best-effort cleanup, also used after a crash without knowing the TUN name.
pub(crate) fn remove() {
    if let Err(error) = remove_with(&mut run) {
        tracing::warn!(%error, "failed to remove Tailscale path exclusion");
    }
}

fn remove_with(run: &mut impl FnMut(&[&str]) -> Result<String, Error>) -> Result<(), Error> {
    if run(&["nft", "list", "table", "inet", TABLE]).is_ok() {
        run(&["nft", "delete", "table", "inet", TABLE])?;
    }
    remove_ip6tables(run)
}

fn read_pipe(pipe: Option<impl Read>) -> io::Result<String> {
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut bytes)?;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn run(args: &[&str]) -> Result<String, Error> {
    let command = args[0].to_owned();
    let io_error = |source| Error::Io {
        command: command.clone(),
        source,
    };
    let mut child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io_error)?;
    // These commands return only our table or OUTPUT rules, never the full
    // ruleset. Drain both pipes while waiting so even a large OUTPUT chain
    // cannot fill a pipe and stall the child.
    std::thread::scope(|scope| {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let out = scope.spawn(move || read_pipe(stdout));
        let err = scope.spawn(move || read_pipe(stderr));
        let status =
            crate::child::wait_bounded(&mut child, Duration::from_secs(6)).map_err(io_error)?;
        let stdout = out
            .join()
            .map_err(|_| io_error(io::Error::other("stdout reader panicked")))?
            .map_err(io_error)?;
        let stderr = err
            .join()
            .map_err(|_| io_error(io::Error::other("stderr reader panicked")))?
            .map_err(io_error)?;
        if status.success() {
            Ok(stdout)
        } else {
            Err(Error::Command {
                command: command.clone(),
                stderr,
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: ServiceCgroup = ServiceCgroup { inode: 42 };

    fn failed() -> Error {
        Error::Io {
            command: "test".into(),
            source: io::ErrorKind::NotFound.into(),
        }
    }

    #[test]
    fn current_nft_guard_is_left_alone() {
        let mut calls = Vec::new();
        ensure_with("mesh0", Some(GROUP), &mut |args| {
            calls.push(args.join(" "));
            Ok(format!("comment \"{}:mesh0\"", GROUP.comment()))
        })
        .unwrap();
        assert_eq!(
            calls,
            [format!("nft list table inet {TABLE}"), IP6_DUMP.join(" ")]
        );
    }

    #[test]
    fn stale_nft_guard_is_replaced_atomically() {
        let mut calls = Vec::new();
        ensure_with("mesh0", Some(GROUP), &mut |args| {
            calls.push(args.join(" "));
            Ok(format!("comment \"{}:old0\"", GROUP.comment()))
        })
        .unwrap();
        assert_eq!(calls[1], format!("nft {}", nft_script("mesh0", GROUP)));
        assert!(nft_script("mesh\"0", GROUP).contains("oifname \"mesh\\\"0\""));
    }

    #[test]
    fn nft_failure_falls_back_to_ip6tables_without_assuming_a_port() {
        let mut calls = Vec::new();
        ensure_with("mesh0", Some(GROUP), &mut |args| {
            calls.push(args.join(" "));
            match args {
                ["ip6tables", "-w", "5", "-S", "OUTPUT"] => Ok(String::new()),
                ["ip6tables", "-w", "5", "-I", ..] => Ok(String::new()),
                _ => Err(failed()),
            }
        })
        .unwrap();
        let insert = calls.last().unwrap();
        assert!(insert.contains("-o mesh0 -d 200::/7 -p udp -m mark --mark 0x80000/0xff0000"));
        assert!(insert.contains("-j REJECT --reject-with icmp6-adm-prohibited"));
        assert!(insert.contains("-m cgroup --path system.slice/tailscaled.service"));
        assert!(!insert.contains("--dport"));
    }

    #[test]
    fn both_backend_errors_are_reported() {
        assert!(matches!(
            ensure_with("mesh0", Some(GROUP), &mut |_| Err(failed())),
            Err(Error::Backends { .. })
        ));
    }

    #[test]
    fn cleanup_matches_only_our_exact_comment() {
        let comment = GROUP.comment();
        let dump = format!(
            "-P OUTPUT ACCEPT\n\
             -A OUTPUT -o old0 -m comment --comment \"{comment}\" -j REJECT\n\
             -A OUTPUT -o other0 -m comment --comment {comment}-custom -j ACCEPT\n\
             -A OUTPUT -m comment --comment \"{comment} custom\" -j ACCEPT\n\
             -A INPUT -m comment --comment {comment} -j ACCEPT\n"
        );
        assert_eq!(
            ip6_deletions(&dump),
            [vec![
                "-D",
                "OUTPUT",
                "-o",
                "old0",
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "REJECT"
            ]]
        );
    }

    #[test]
    fn service_restart_replaces_a_rule_for_the_old_cgroup() {
        let mut calls = Vec::new();
        let new = ServiceCgroup { inode: 43 };
        ensure_with("mesh0", Some(new), &mut |args| {
            calls.push(args.join(" "));
            Ok(format!("comment \"{}:mesh0\"", GROUP.comment()))
        })
        .unwrap();
        assert_eq!(calls[1], format!("nft {}", nft_script("mesh0", new)));
    }

    #[test]
    fn no_service_removes_legacy_rules_without_installing_an_unscoped_guard() {
        let mut calls = Vec::new();
        ensure_with("mesh0", None, &mut |args| {
            calls.push(args.join(" "));
            Ok(format!(
                "-A OUTPUT -o old0 -m comment --comment {LEGACY_COMMENT} -j REJECT"
            ))
        })
        .unwrap();
        assert!(
            calls
                .iter()
                .any(|c| c == &format!("nft delete table inet {TABLE}"))
        );
        assert!(calls.iter().any(|c| c.contains("ip6tables -w 5 -D OUTPUT")));
        assert!(
            calls
                .iter()
                .all(|c| !c.contains("-I OUTPUT") && !c.contains("chain output"))
        );
    }

    #[test]
    fn cgroup_detection_requires_v2_and_the_service_directory() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        assert!(service_cgroup(root.path())?.is_none());
        std::fs::write(root.path().join("cgroup.controllers"), "")?;
        assert!(service_cgroup(root.path())?.is_none());
        std::fs::create_dir_all(root.path().join(SERVICE_CGROUP))?;
        let expected = std::fs::metadata(root.path().join(SERVICE_CGROUP))?.ino();
        assert_eq!(service_cgroup(root.path())?.unwrap().inode, expected);
        Ok(())
    }

    /// Exercise real kernel rejection and delivery, not just rule text. The
    /// wrapper runs only this test in a container without external networking.
    #[tokio::test]
    #[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
    async fn marked_udp_is_excluded_from_mesh_paths() -> anyhow::Result<()> {
        use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};

        use socket2::SockRef;
        use tokio::net::TcpSocket;
        use tokio::time::timeout;

        use crate::tun::{self, TunRead, TunReader};

        anyhow::ensure!(
            std::env::var("RAYFISH_ISOLATED_KERNEL_TEST").as_deref() == Ok("1"),
            "run tests/tailscale-kernel.sh"
        );
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                remove();
                let root = Path::new("/sys/fs/cgroup");
                let _ = std::fs::write(root.join("cgroup.procs"), std::process::id().to_string());
                for group in [SERVICE_CGROUP, "system.slice/other.service", "system.slice"] {
                    let _ = std::fs::remove_dir(root.join(group));
                }
            }
        }
        let _cleanup = Cleanup;
        let root = Path::new("/sys/fs/cgroup");
        std::fs::create_dir_all(root.join(SERVICE_CGROUP))?;
        std::fs::create_dir(root.join("system.slice/other.service"))?;
        let enter = |group: &str| {
            std::fs::write(
                root.join(group).join("cgroup.procs"),
                std::process::id().to_string(),
            )
        };
        let local: Ipv6Addr = "200::1".parse()?;
        let peer: Ipv6Addr = "200::2".parse()?;
        let internet: Ipv6Addr = "2001:db8::2".parse()?;
        let (mut reader, _writer, tun) = tun::create(local).await?;
        tun::route_peer_range(&tun).await?;
        // An exit node can route public traffic through the same interface.
        run(&["ip", "-6", "route", "add", "2001:db8::/64", "dev", &tun])?;
        run(&["ip", "link", "add", "other0", "type", "dummy"])?;
        run(&["ip", "link", "set", "other0", "up"])?;
        run(&["ip", "-6", "route", "add", "200:1::/64", "dev", "other0"])?;

        // Socket ownership stays with its creation cgroup after the process
        // moves. Another service reusing Tailscale's mark must still work.
        enter("system.slice/other.service")?;
        let other_udp = UdpSocket::bind(SocketAddrV6::new(local, 0, 0, 0))?;
        SockRef::from(&other_udp).set_mark(0x80000)?;
        enter(SERVICE_CGROUP)?;

        let udp = |mark, dest, port| -> io::Result<usize> {
            let socket = UdpSocket::bind(SocketAddrV6::new(local, 0, 0, 0))?;
            SockRef::from(&socket).set_mark(mark)?;
            socket.send_to(b"coexistence", SocketAddrV6::new(dest, port, 0, 0))
        };
        let read_udp = async |reader: &mut TunReader, dest: Ipv6Addr| {
            timeout(Duration::from_secs(3), async {
                loop {
                    let packet = reader.read_packet().await?;
                    if packet.len() >= 48
                        && packet[0] >> 4 == 6
                        && packet[6] == 17
                        && packet[24..40] == dest.octets()
                        && packet.ends_with(b"coexistence")
                    {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            })
            .await?
        };

        for use_nft in [true, false] {
            remove();
            let cgroup = service_cgroup(root)?.expect("created service cgroup");
            let mut backend = |args: &[&str]| {
                if !use_nft && args[0] == "nft" {
                    Err(failed())
                } else {
                    run(args)
                }
            };
            ensure_with(&tun, Some(cgroup), &mut backend)?;
            ensure_with(&tun, Some(cgroup), &mut backend)?;
            // Both ports, and marks with unrelated low bits, must be rejected.
            for mark in [0x80000, 0x87261] {
                for port in [41641, 54321] {
                    let error = udp(mark, peer, port).expect_err("Tailscale must be rejected");
                    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                }
            }
            let large_udp = UdpSocket::bind(SocketAddrV6::new(local, 0, 0, 0))?;
            SockRef::from(&large_udp).set_mark(0x80000)?;
            assert_eq!(
                large_udp
                    .send_to(&[0; 1312], SocketAddrV6::new(peer, 54321, 0, 0))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            other_udp.send_to(b"coexistence", SocketAddrV6::new(peer, 41641, 0, 0))?;
            read_udp(&mut reader, peer).await?;
            for mark in [0, crate::exit_node::SOCKET_MARK, 0x40000, 0x180000] {
                udp(mark, peer, 41641)?;
                read_udp(&mut reader, peer).await?;
            }
            // Neither an exit-node route nor another interface is blocked.
            udp(0x80000, internet, 54321)?;
            read_udp(&mut reader, internet).await?;
            udp(0x80000, "200:1::2".parse()?, 54321)?;

            // Tailscale's marked TCP (e.g. a relay or control connection) also
            // remains usable. Observe its SYN on the TUN while connect waits.
            let socket = TcpSocket::new_v6()?;
            SockRef::from(&socket).set_mark(0x80000)?;
            let connect = socket.connect(SocketAddrV6::new(peer, 54321, 0, 0).into());
            tokio::pin!(connect);
            timeout(Duration::from_secs(3), async {
                loop {
                    tokio::select! {
                        result = &mut connect => anyhow::bail!("TCP never reached TUN: {result:?}"),
                        packet = reader.read_packet() => {
                            let packet = packet?;
                            if packet.len() >= 60 && packet[6] == 6 && packet[53] & 2 != 0 {
                                break Ok::<_, anyhow::Error>(());
                            }
                        }
                    }
                }
            })
            .await??;

            // A firewall reload removes the rule; the periodic ensure restores
            // it, and replacing the TUN name removes the old selector.
            if use_nft {
                run(&["nft", "delete", "table", "inet", TABLE])?;
            } else {
                let mut delete = vec!["ip6tables", "-w", "5", "-D"];
                let comment = cgroup.comment();
                delete.extend(ip6_spec(&tun, &comment));
                run(&delete)?;
            }
            ensure_with(&tun, Some(cgroup), &mut backend)?;
            assert_eq!(
                udp(0x80000, peer, 54321).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            run(&["ip", "link", "set", &tun, "name", "mesh-renamed"])?;
            ensure_with("mesh-renamed", Some(cgroup), &mut backend)?;
            assert_eq!(
                udp(0x80000, peer, 54321).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            if !use_nft {
                let dump = run(&IP6_DUMP)?;
                assert_eq!(ip6_deletions(&dump).len(), 1);
                assert!(!dump.contains(&format!("-o {tun} ")));
            }

            // A service restart recreates the path with another kernel cgroup
            // identity. Reconciliation must update both firewall backends.
            enter("")?;
            std::fs::remove_dir(root.join(SERVICE_CGROUP))?;
            std::fs::create_dir(root.join(SERVICE_CGROUP))?;
            enter(SERVICE_CGROUP)?;
            let new_cgroup = service_cgroup(root)?.expect("recreated service cgroup");
            assert_ne!(new_cgroup.inode, cgroup.inode);
            ensure_with("mesh-renamed", Some(new_cgroup), &mut backend)?;
            assert_eq!(
                udp(0x80000, peer, 54321).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            other_udp.send_to(b"coexistence", SocketAddrV6::new(peer, 41641, 0, 0))?;
            read_udp(&mut reader, peer).await?;

            remove();
            udp(0x80000, peer, 54321)?;
            read_udp(&mut reader, peer).await?;
            run(&["ip", "link", "set", "mesh-renamed", "name", &tun])?;
        }
        Ok(())
    }
}
