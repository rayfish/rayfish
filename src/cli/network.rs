//! CLI handlers for network lifecycle: create / join / nuke / leave.

use std::io::IsTerminal;

use crate::*;
use ipc::NetworkKey;

pub(crate) async fn ipc_create(
    mode: GroupMode,
    name: Option<String>,
    hostname: Option<String>,
    tor: bool,
) -> Result<()> {
    let transport = if tor {
        Some(config::TransportMode::Tor)
    } else {
        None
    };
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Create {
            mode,
            name,
            hostname,
            transport,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Created {
            name,
            network_key,
            my_ipv6,
        } => {
            let key_str = network_key.to_string();
            let short = if key_str.len() > 12 {
                format!("{}…{}", &key_str[..4], &key_str[key_str.len() - 4..])
            } else {
                key_str.clone()
            };
            println!();
            println!(
                "  {} {} {}",
                style::check(),
                style::value("created"),
                style::bold(&name)
            );
            println!(
                "    {}   {}   {}  {}",
                style::label("address"),
                style::value(&my_ipv6.to_string()),
                style::faint("·"),
                style::rose(&short),
            );
            let join = format!("ray join {network_key}");
            print_next(&[
                (&join, "share this to invite peers"),
                ("ray up", "activate the VPN"),
            ]);
            println!();
        }
        ipc::IpcMessage::Error { message } => fail_with("create failed", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_join(
    network_key: &str,
    name: Option<&str>,
    hostname: Option<String>,
    tor: bool,
    auto_accept_firewall: bool,
    auto_accept_files: bool,
) -> Result<()> {
    let transport = if tor {
        Some(config::TransportMode::Tor)
    } else {
        None
    };
    // `ray join <arg>` accepts either a bare room id (the network public key) or
    // a self-contained invite code. An invite decodes to the network key plus the
    // coordinator to dial and a one-time secret to present.
    let (network_key, invite, coordinator) = match invite::decode_invite_code(network_key) {
        Ok((net_pubkey, coord, secret)) => (net_pubkey.to_string(), Some(secret), Some(coord)),
        Err(_) => (network_key.to_string(), None, None),
    };
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Join {
            network_key,
            name: name.map(|s| s.to_string()),
            hostname,
            transport,
            invite,
            coordinator,
            auto_accept_firewall,
            auto_accept_files,
        },
    )
    .await?;
    // Joining dials the coordinator and runs the handshake daemon-side, so this
    // can take a few seconds, show a spinner while we wait.
    let spinner = progress::spinner("joining…");
    let resp = ipc::recv(&mut stream).await?;
    spinner.finish_and_clear();
    match resp {
        ipc::IpcMessage::Ok { message } => {
            println!("{}", message);
        }
        ipc::IpcMessage::Joined { name, my_ipv6 } => {
            let dns = format!("{name}.{DNS_DOMAIN}");
            println!();
            println!(
                "  {} {} {}",
                style::check(),
                style::value("joined"),
                style::bold(&name)
            );
            println!(
                "    {}   {}   {}  {}",
                style::label("address"),
                style::value(&my_ipv6.to_string()),
                style::faint("·"),
                style::value(&dns),
            );
            print_next(&[
                ("ray status", "see who's online"),
                ("ray up", "activate the VPN"),
            ]);
            println!();
        }
        ipc::IpcMessage::Error { message } => fail_with("join failed", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_nuke(name: &str, force: bool) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Nuke {
            name: name.to_string(),
            force,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// `ray kick`: remove a member, asking first when the argument names someone
/// who holds more than one device.
///
/// Membership follows the user identity, so naming a paired phone removes the
/// laptop it is paired to as well. That is deliberate (access cannot be taken
/// away one device at a time when the firewall and `ssh` resolve a device to
/// its user), but the command line does not say it: one name goes in and three
/// rows can go. So the daemon answers an unconfirmed kick that would take more
/// than one row with the set instead of taking it, and this prints that set and
/// asks. `--yes` sends the confirmed request straight away.
pub(crate) async fn ipc_kick(network: &str, peer: &str, yes: bool) -> Result<()> {
    match send_kick(network, peer, yes).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        ipc::IpcMessage::KickConfirm {
            network: net,
            display,
            targets,
        } => {
            print_kick_targets(&net, &display, &targets);
            // Nothing to read an answer from: a script piping into `ray kick`
            // would hang on the prompt or, worse, take an EOF for a yes.
            if !std::io::stdin().is_terminal() {
                fail_with(
                    "kick needs confirmation",
                    &format!(
                        "'{display}' holds {} roster rows and stdin is not a terminal; \
                         re-run with --yes to remove them all",
                        targets.len()
                    ),
                );
            }
            if !prompt_yes(&format!("kick all {} from '{net}'?", targets.len()))? {
                println!("  {}\n", style::faint("cancelled"));
                return Ok(());
            }
            match send_kick(network, peer, true).await? {
                ipc::IpcMessage::Ok { message } => println!("{}", message),
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// One `Kick` request/response round trip. Called twice when the first answer
/// is a [`ipc::IpcMessage::KickConfirm`]: the daemon re-resolves the argument on
/// the confirmed request, so the roster it acts on is the one it just read
/// rather than one cached across the prompt.
async fn send_kick(network: &str, peer: &str, confirm: bool) -> Result<ipc::IpcMessage> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Kick {
            network: network.to_string(),
            peer: peer.to_string(),
            confirm,
        },
    )
    .await?;
    ipc::recv(&mut stream).await
}

/// The rows a pending kick would take, one per line, primary first so the
/// person reading sees whose devices these are before the devices.
fn print_kick_targets(network: &str, display: &str, targets: &[ipc::KickTarget]) {
    println!();
    println!(
        "  {} is one of {} roster rows held by the same user in '{}'.",
        style::value(display),
        targets.len(),
        network
    );
    println!("  {}", style::faint("kicking removes every one of them:"));
    println!();
    let mut rows: Vec<&ipc::KickTarget> = targets.iter().collect();
    rows.sort_by_key(|t| !t.primary);
    let names: Vec<String> = rows
        .iter()
        .map(|t| t.hostname.clone().unwrap_or_else(|| t.short_id.clone()))
        .collect();
    // Pad to the longest name: styling wraps the string in escapes, so the width
    // has to be applied to the plain text, not to the styled cell.
    let width = names.iter().map(|n| n.len()).max().unwrap_or(0);
    for (t, name) in rows.iter().zip(&names) {
        let role = if t.primary { "primary" } else { "device" };
        println!(
            "    {}{}  {}  {}",
            style::value(name),
            " ".repeat(width - name.len()),
            style::rose(&t.short_id),
            style::faint(role)
        );
    }
    println!();
}

/// Ask a yes/no question on stdin, defaulting to no on anything else.
fn prompt_yes(question: &str) -> Result<bool> {
    use std::io::{BufRead, Write};
    print!("  {question} (y/N) ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub(crate) async fn ipc_leave(name: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Leave {
            name: name.to_string(),
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Render a TTL in seconds back to the largest whole `Nw`/`Nd`/`Nh` unit
/// (falling back to seconds), for display in `ray ephemeral show` and status.
pub(crate) fn format_ttl(secs: u64) -> String {
    if secs.is_multiple_of(604_800) {
        format!("{}w", secs / 604_800)
    } else if secs.is_multiple_of(86_400) {
        format!("{}d", secs / 86_400)
    } else if secs.is_multiple_of(3_600) {
        format!("{}h", secs / 3_600)
    } else {
        format!("{secs}s")
    }
}

/// `ray ephemeral <net> <duration|off|show>`: set, clear, or print a network's
/// ephemeral auto-kick TTL.
pub(crate) async fn ipc_ephemeral(network: &str, arg: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    if arg == "show" {
        ipc::send(
            &mut stream,
            ipc::IpcMessage::NetConfigGet {
                network: network.to_string(),
                key: Some(NetworkKey::EphemeralTtl),
            },
        )
        .await?;
        match ipc::recv(&mut stream).await? {
            // The key renders as the TTL in seconds, or empty when the policy is off.
            ipc::IpcMessage::ConfigValues { rows } => {
                match rows.first().map(|(_, v)| v.as_str()).unwrap_or("") {
                    "" => println!("ephemeral policy on '{network}': off"),
                    ttl => match ttl.parse::<u64>() {
                        Ok(s) => println!("ephemeral policy on '{network}': {}", format_ttl(s)),
                        Err(_) => eprintln!("Unexpected ephemeral ttl: {ttl}"),
                    },
                }
            }
            ipc::IpcMessage::Error { message } => fail_with("error", &message),
            other => fail_unexpected(&other),
        }
        return Ok(());
    }
    let ttl_secs = if arg == "off" {
        None
    } else {
        match parse_ephemeral_duration(arg) {
            Ok(s) => Some(s),
            Err(e) => {
                print_error("error", &e, None);
                return Ok(());
            }
        }
    };
    ipc::send(
        &mut stream,
        ipc::IpcMessage::NetConfigSet {
            network: network.to_string(),
            key: NetworkKey::EphemeralTtl,
            // Empty disables the policy, matching `ConfigUnset` semantics.
            value: ttl_secs.map(|s| s.to_string()).unwrap_or_default(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Parse a human duration (`Nh`/`Nd`/`Nw`) into seconds, enforcing a 1-hour
/// floor. Returns the TTL in seconds or a user-facing error string. Used by
/// `ray ephemeral <net> <duration>` to set the per-network policy.
pub(crate) fn parse_ephemeral_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| c.is_alphabetic())
        .ok_or_else(|| format!("invalid duration '{s}' (use Nh, Nd, or Nw)"))?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration '{s}' (use Nh, Nd, or Nw)"))?;
    let secs = match unit {
        "h" => n * 3600,
        "d" => n * 86_400,
        "w" => n * 604_800,
        other => return Err(format!("unknown unit '{other}' (use h, d, or w)")),
    };
    if secs < 3600 {
        return Err("minimum ephemeral TTL is 1h".to_string());
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::parse_ephemeral_duration;

    #[test]
    fn parses_valid_durations() {
        assert_eq!(parse_ephemeral_duration("12h"), Ok(43_200));
        assert_eq!(parse_ephemeral_duration("7d"), Ok(604_800));
        assert_eq!(parse_ephemeral_duration("1w"), Ok(604_800));
        assert_eq!(parse_ephemeral_duration("1h"), Ok(3_600));
        assert_eq!(parse_ephemeral_duration(" 2d "), Ok(172_800));
    }

    #[test]
    fn rejects_sub_hour_and_garbage() {
        assert!(parse_ephemeral_duration("30m").is_err()); // unknown unit
        assert!(parse_ephemeral_duration("0h").is_err()); // below floor
        assert!(parse_ephemeral_duration("garbage").is_err());
        assert!(parse_ephemeral_duration("5").is_err()); // no unit
        assert!(parse_ephemeral_duration("").is_err());
    }
}
