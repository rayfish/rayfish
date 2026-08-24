//! CLI handlers for network lifecycle: create / join / nuke / leave.

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
            read_key,
        } => {
            // What we tell people to share. On a network with a read key that is
            // the compound code, because the bare room id no longer opens the
            // roster; without one (an older network) it is still the room id.
            let share = match read_key {
                Some(rk) => {
                    invite::encode_room_code(&network_key, &groupkey::ReadKey::from_bytes(rk))
                }
                None => network_key.to_string(),
            };
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
            let join = format!("ray join {share}");
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
    // `ray join <arg>` takes a bare room id, a share code, or an invite code.
    // The compound forms are split here and never travel inward whole: the
    // daemon parses `network_key` as an `EndpointId`, slices it for a fallback
    // display name, and compares it by string equality for pending-join dedupe.
    let code = invite::decode_share_code(network_key)?;
    let network_key = code.network.to_string();
    let invite = code.invite_secret;
    let coordinator = code.coordinator;
    let read_key = code.read_key.map(|k| k.to_bytes());
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
            read_key,
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

pub(crate) async fn ipc_kick(network: &str, peer: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Kick {
            network: network.to_string(),
            peer: peer.to_string(),
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
