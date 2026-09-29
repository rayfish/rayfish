use super::*;

/// Block direct egress even when a route disappears or another VPN takes priority.
/// Only the transport mark, loopback and link configuration bypass the tunnel.
pub(super) fn client_nft_script(tun: &str) -> String {
    format!(
        "{reset}table inet {CLIENT_TABLE} {{
 chain output {{
  type filter hook output priority filter; policy drop;
  oifname \"lo\" accept
  oifname \"{tun}\" accept
  meta mark {SOCKET_MARK} accept
  udp sport 68 udp dport 67 accept
  udp sport 546 udp dport 547 accept
  icmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept
 }}
 chain forward {{
  type filter hook forward priority filter; policy drop;
  oifname \"{tun}\" accept
  meta mark {SOCKET_MARK} accept
 }}
}}
", reset = drop_table(CLIENT_TABLE))
}

/// Capture both families. A family the gateway cannot carry stays blocked.
/// Keep the firewall installed if any later step fails.
pub fn install_client_routing(tun_name: &str, _carries: ExitFamilies) -> Result<()> {
    nft_load(&client_nft_script(tun_name))?;
    ensure_ipv4_routes_available(tun_name, ipv4::AddressSpace::Client)?;
    let path = crate::config::config_dir()?.join("exit-ipv4-client-interface");
    crate::config::write_file(&path, tun_name.as_bytes(), false)?;
    run_ip(&[
        "-4",
        "addr",
        "replace",
        &format!("{}/32", ipv4::CLIENT_ADDR),
        "dev",
        tun_name,
    ])?;
    let mark = format!("{SOCKET_MARK:#x}");
    for family in ["-4", "-6"] {
        // Migrate the previous LAN, foreign-VPN and physical-source bypass rules.
        remove_client_rules(family, RuleSweep::KeepCatchAll);
        run_ip(&[
            family,
            "rule",
            "add",
            "fwmark",
            &mark,
            "table",
            "main",
            "pref",
            PREF_BYPASS,
        ])?;
        let prefix = if family == "-4" {
            ipv4::SERVER_PREFIX
        } else {
            V6_OVERLAY
        };
        run_ip(&[
            family, "rule", "add", "to", prefix, "table", "main", "pref", PREF_MAIN,
        ])?;
        // Old versions mirrored specific routes into this table. They must not
        // override the full tunnel when upgrading an active selection.
        if let Some(routes) = ip_output(&[family, "route", "show", "table", EXIT_TABLE]) {
            for line in routes.lines().filter(|line| !line.starts_with([' ', '\t'])) {
                if let Some(dest) = line.split_whitespace().next().filter(|d| *d != "default") {
                    run_ip(&[family, "route", "del", dest, "table", EXIT_TABLE])?;
                }
            }
        }
        let source = ipv4::CLIENT_ADDR.to_string();
        let mut args = vec![
            family, "route", "replace", "default", "dev", tun_name, "table", EXIT_TABLE,
        ];
        if family == "-4" {
            args.extend(["src", &source]);
        }
        run_ip(&args)?;
        if !catch_all_installed(family) {
            run_ip(&[
                family,
                "rule",
                "add",
                "table",
                EXIT_TABLE,
                "pref",
                PREF_TUNNEL,
            ])?;
        }
    }
    Ok(())
}
