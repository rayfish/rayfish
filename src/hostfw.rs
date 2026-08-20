//! Detection of host-firewall rules that would silently swallow mesh traffic.
//!
//! The mesh SSH server cannot bind `<mesh-ip>:22` while a host sshd holds
//! `0.0.0.0:22`, so it binds [`SSH_LISTEN_PORT`] and the forwarding path
//! rewrites the port (see `crate::ssh`). The kernel therefore sees inbound mesh
//! SSH as a connection to that port, not to 22, and an operator who allowed
//! "22/tcp" in ufw or firewalld has not allowed it. With a default-DROP INPUT
//! policy the SYN dies in the host firewall: our listener is up, the mesh
//! firewall permits the flow, ICMP still works, and `ssh` just hangs.
//!
//! This module only ever *reads* the host firewall and reports. rayfish never
//! edits a ruleset another tool owns; the operator gets the exact command.
//!
//! Detection is deliberately conservative. A verdict of [`Verdict::WouldBlock`]
//! requires positive evidence of a default-deny inbound policy *and* the
//! absence of anything that could let the port through. Anything unparseable or
//! unreadable is [`Verdict::Unknown`], which stays quiet: a wrong warning
//! pointing at the firewall wastes more time than no warning at all.

#[cfg(target_os = "linux")]
use std::process::Command;

/// What the host firewall would do to an inbound mesh connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No host firewall, or one that lets the port through.
    Clear,
    /// A default-deny inbound policy with nothing permitting this port.
    WouldBlock {
        /// The firewall front-end we recognised, for the message.
        manager: Manager,
        /// Copy-pasteable command that opens the port on the mesh interface.
        fix: String,
    },
    /// Could not read the ruleset (missing tool, no permission, unknown format).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Ufw,
    Firewalld,
    Iptables,
    Nftables,
}

impl Manager {
    pub fn as_str(self) -> &'static str {
        match self {
            Manager::Ufw => "ufw",
            Manager::Firewalld => "firewalld",
            Manager::Iptables => "iptables",
            Manager::Nftables => "nftables",
        }
    }

    /// The command that opens `port` for inbound TCP on `tun` only. Mesh SSH
    /// binds the overlay's IPv6 address, so `ip6tables` is the only raw ruleset
    /// that can drop the connection. ufw and firewalld apply to both families
    /// from one command and so name neither.
    /// Only the Linux detector builds a fix; elsewhere nothing constructs a
    /// `WouldBlock`, and this module's tests are Linux-only too (they parse
    /// `iptables`/`ufw` output), so off Linux nothing calls this at all.
    #[cfg(target_os = "linux")]
    fn fix_command(self, tun: &str, port: u16) -> String {
        match self {
            Manager::Ufw => format!("ufw allow in on {tun} to any port {port} proto tcp"),
            Manager::Firewalld => format!(
                "firewall-cmd --permanent --zone=trusted --add-interface={tun} && firewall-cmd --reload"
            ),
            Manager::Iptables => {
                format!("ip6tables -I INPUT -i {tun} -p tcp --dport {port} -j ACCEPT")
            }
            Manager::Nftables => {
                format!("nft add rule inet filter input iifname \"{tun}\" tcp dport {port} accept")
            }
        }
    }
}

impl Verdict {
    /// The warning to show an operator, or `None` when there is nothing wrong.
    pub fn warning(&self, port: u16) -> Option<String> {
        match self {
            Verdict::WouldBlock { manager, fix } => Some(format!(
                "{} is blocking inbound TCP port {port} on the mesh interface, which is where \
                 mesh SSH actually listens (mesh `:22` is mapped to {port} internally, so an \
                 \"allow 22\" rule does not cover it). Connections will hang until you run:\n  {fix}",
                manager.as_str(),
            )),
            _ => None,
        }
    }
}

/// Whether the host firewall would drop inbound TCP to `port` arriving on `tun`.
///
/// `v6` selects the family the mesh SSH server listens on. The two rulesets are
/// independent, and reading the wrong one is worse than reading none: an
/// IPv6-only data plane behind a permissive `iptables` and a default-DROP
/// `ip6tables` is exactly the silent hang this module exists to catch, and it
/// would report [`Verdict::Clear`].
///
/// Runs the firewall CLIs read-only. Linux-only in substance: macOS ships pf
/// disabled by default and BSD hosts do not run the mesh SSH NAT, so elsewhere
/// this reports [`Verdict::Unknown`] rather than guessing.
#[cfg(target_os = "linux")]
pub fn check_inbound_tcp(tun: &str, port: u16) -> Verdict {
    // ufw and firewalld both render into iptables/nft, so the ruleset below is
    // the ground truth either way. Identify the front-end first purely so the
    // fix we print is the one the operator's own tooling will accept: telling a
    // ufw user to run `iptables -I` invites a rule their next `ufw reload`
    // silently discards.
    let manager = detect_manager();

    if let Some(rules) = run(&["ip6tables", "-S"])
        && let Some(blocked) = iptables_blocks_port(&rules, tun, port)
    {
        return verdict(blocked, manager.unwrap_or(Manager::Iptables), tun, port);
    }

    // `nft list ruleset` prints every family at once, and the `inet` tables both
    // distros and we generate cover v4 and v6 together, so this rung needs no
    // family split.
    if let Some(ruleset) = run(&["nft", "list", "ruleset"])
        && let Some(blocked) = nft_blocks_port(&ruleset, tun, port)
    {
        return verdict(blocked, manager.unwrap_or(Manager::Nftables), tun, port);
    }

    Verdict::Unknown
}

#[cfg(not(target_os = "linux"))]
pub fn check_inbound_tcp(_tun: &str, _port: u16) -> Verdict {
    Verdict::Unknown
}

#[cfg(target_os = "linux")]
fn verdict(blocked: bool, manager: Manager, tun: &str, port: u16) -> Verdict {
    if blocked {
        Verdict::WouldBlock {
            manager,
            fix: manager.fix_command(tun, port),
        }
    } else {
        Verdict::Clear
    }
}

/// Which front-end owns the ruleset, if we can tell. Only affects the wording of
/// the suggested fix.
#[cfg(target_os = "linux")]
fn detect_manager() -> Option<Manager> {
    if run(&["ufw", "status"]).is_some_and(|s| s.contains("Status: active")) {
        return Some(Manager::Ufw);
    }
    if run(&["firewall-cmd", "--state"]).is_some_and(|s| s.trim() == "running") {
        return Some(Manager::Firewalld);
    }
    None
}

#[cfg(target_os = "linux")]
fn run(argv: &[&str]) -> Option<String> {
    let out = Command::new(argv[0]).args(&argv[1..]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `Some(true)` if this iptables ruleset drops inbound TCP to `port` on `tun`,
/// `Some(false)` if it lets it through, `None` if the dump says nothing about an
/// INPUT policy (so the caller should try another backend).
#[cfg(target_os = "linux")]
fn iptables_blocks_port(rules: &str, tun: &str, port: u16) -> Option<bool> {
    let policy = rules
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("-P INPUT "))?;
    // An ACCEPT policy cannot be the thing swallowing the packet: even with no
    // matching rule the packet is delivered.
    if !policy.ends_with(" DROP") && !policy.ends_with(" REJECT") {
        return Some(false);
    }
    Some(!rules.lines().any(|l| iptables_line_permits(l, tun, port)))
}

/// Whether one `iptables -S` line could let our port in. Interface-wide accepts
/// count: an operator who trusted the whole TUN has already made the decision.
#[cfg(target_os = "linux")]
fn iptables_line_permits(line: &str, tun: &str, port: u16) -> bool {
    if !line.contains("-j ACCEPT") {
        return false;
    }
    let fields: Vec<&str> = line.split_whitespace().collect();
    let has_flag = |flag: &str, want: &str| {
        fields
            .windows(2)
            .any(|w| w[0] == flag && w[1].trim_end_matches('/') == want)
    };
    // `-i tun0 -j ACCEPT` with no port restriction: everything on the TUN is in.
    if has_flag("-i", tun) && !fields.contains(&"--dport") {
        return true;
    }
    has_flag("--dport", &port.to_string())
}

/// The nftables equivalent. `None` when no input chain declares a policy.
#[cfg(target_os = "linux")]
fn nft_blocks_port(ruleset: &str, tun: &str, port: u16) -> Option<bool> {
    let mut saw_input_policy = false;
    let mut deny_policy = false;
    for line in ruleset.lines().map(str::trim) {
        if line.contains("hook input") {
            saw_input_policy = true;
            if line.contains("policy drop") || line.contains("policy reject") {
                deny_policy = true;
            }
        }
    }
    if !saw_input_policy {
        return None;
    }
    if !deny_policy {
        return Some(false);
    }
    Some(!ruleset.lines().any(|l| nft_line_permits(l, tun, port)))
}

#[cfg(target_os = "linux")]
fn nft_line_permits(line: &str, tun: &str, port: u16) -> bool {
    if !line.contains("accept") || line.contains("hook input") {
        return false;
    }
    if line.contains(&format!("dport {port}")) {
        return true;
    }
    // A blanket `iifname "tun0" ... accept` with no port match.
    line.contains(&format!("iifname \"{tun}\"")) && !line.contains("dport")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // The ruleset from the host that prompted this module: ufw active, default
    // deny inbound, "22/tcp ALLOW" and nothing else. Mesh SSH listens on 30022.
    const UFW_DENY_ALLOWING_22: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N ufw-user-input
-A INPUT -j ufw-before-input
-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
";

    #[test]
    fn allowing_22_does_not_cover_the_nat_port() {
        // The exact failure: `ufw allow 22/tcp` is present, the operator
        // believes SSH is open, and the mesh SSH port is still dropped.
        assert_eq!(
            iptables_blocks_port(UFW_DENY_ALLOWING_22, "tun0", 30022),
            Some(true)
        );
        assert_eq!(
            iptables_blocks_port(UFW_DENY_ALLOWING_22, "tun0", 22),
            Some(false)
        );
    }

    #[test]
    fn explicit_rule_for_the_nat_port_clears_it() {
        let rules = format!(
            "{UFW_DENY_ALLOWING_22}-A ufw-user-input -p tcp -m tcp --dport 30022 -j ACCEPT\n"
        );
        assert_eq!(iptables_blocks_port(&rules, "tun0", 30022), Some(false));
    }

    #[test]
    fn trusting_the_whole_tun_clears_it() {
        // `-i tun0 -j ACCEPT` is a decision the operator already made; warning
        // them anyway would be noise.
        let rules = format!("{UFW_DENY_ALLOWING_22}-A ufw-user-input -i tun0 -j ACCEPT\n");
        assert_eq!(iptables_blocks_port(&rules, "tun0", 30022), Some(false));
        // ...but trusting a *different* interface does not.
        let other = format!("{UFW_DENY_ALLOWING_22}-A ufw-user-input -i eth0 -j ACCEPT\n");
        assert_eq!(iptables_blocks_port(&other, "tun0", 30022), Some(true));
    }

    #[test]
    fn accept_policy_is_never_a_block() {
        let rules = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
        assert_eq!(iptables_blocks_port(rules, "tun0", 30022), Some(false));
    }

    #[test]
    fn no_input_policy_line_is_inconclusive() {
        // Not "clear": we know nothing, so the caller must try nft instead of
        // reporting a firewall that lets everything through.
        assert_eq!(
            iptables_blocks_port("-P OUTPUT ACCEPT\n", "tun0", 30022),
            None
        );
    }

    #[test]
    fn a_drop_rule_for_the_port_is_not_an_accept() {
        let rules = format!(
            "{UFW_DENY_ALLOWING_22}-A ufw-user-input -p tcp -m tcp --dport 30022 -j DROP\n"
        );
        assert_eq!(iptables_blocks_port(&rules, "tun0", 30022), Some(true));
    }

    #[test]
    fn nft_deny_policy_without_the_port_blocks() {
        let ruleset = "\
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname \"lo\" accept
		ct state related,established accept
		tcp dport 22 accept
	}
}
";
        assert_eq!(nft_blocks_port(ruleset, "tun0", 30022), Some(true));
        assert_eq!(nft_blocks_port(ruleset, "tun0", 22), Some(false));
    }

    #[test]
    fn nft_accept_policy_is_clear() {
        // ufw disabled leaves the chains in place with an accept policy.
        let ruleset = "\
table ip filter {
	chain ufw-before-input {
		type filter hook input priority filter; policy accept;
	}
}
";
        assert_eq!(nft_blocks_port(ruleset, "tun0", 30022), Some(false));
    }

    #[test]
    fn nft_tun_wide_accept_clears_it() {
        let ruleset = "\
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname \"tun0\" accept
	}
}
";
        assert_eq!(nft_blocks_port(ruleset, "tun0", 30022), Some(false));
    }

    #[test]
    fn nft_without_an_input_chain_is_inconclusive() {
        let ruleset = "table ip nat {\n\tchain post {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t}\n}\n";
        assert_eq!(nft_blocks_port(ruleset, "tun0", 30022), None);
    }

    #[test]
    fn warning_names_the_port_mapping_and_the_fix() {
        let v = verdict(true, Manager::Ufw, "tun0", 30022);
        let msg = v.warning(30022).expect("blocked verdict warns");
        assert!(msg.contains("ufw allow in on tun0 to any port 30022 proto tcp"));
        assert!(msg.contains("30022"));
        assert_eq!(Verdict::Clear.warning(30022), None);
        assert_eq!(Verdict::Unknown.warning(30022), None);
    }

    #[test]
    fn the_iptables_fix_matches_the_family_ssh_listens_on() {
        // Mesh SSH binds the v6 address only, so `iptables` is not the ruleset
        // that can drop the connection and would not be the fix to print.
        assert!(
            Manager::Iptables
                .fix_command("tun0", 30022)
                .starts_with("ip6tables -I INPUT -i tun0")
        );
        // ufw covers both families from one command, so it names neither.
        assert_eq!(
            Manager::Ufw.fix_command("tun0", 30022),
            "ufw allow in on tun0 to any port 30022 proto tcp"
        );
    }
}
