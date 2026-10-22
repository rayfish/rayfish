//! illumos: take over `/etc/resolv.conf` directly.
//!
//! A non-global zone's `resolv.conf` is regenerated from the zone config at
//! boot only, so a file written here stays until the next zone boot. We list
//! our resolver first and the captured upstreams behind it, so the host keeps
//! resolving if the daemon stops answering.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::resolv_file::{
    backup_resolv_file, exists_no_follow, restore_resolv_backup, write_resolv_file,
};
use super::{DnsConfigurator, SearchDomain, resolver_addr};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const BACKUP: &str = "/etc/resolv.conf.before-rayfish";
const MARKER: &str = "# Managed by rayfish.";
/// illumos' resolver reads at most six search domains.
const MAX_SEARCH: usize = 6;

fn parse_nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let mut f = line.split('#').next()?.split_whitespace();
            (f.next()? == "nameserver").then_some(())?;
            f.next()?.parse().ok()
        })
        .collect()
}

fn parse_search(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut f = line.split('#').next()?.split_whitespace();
            matches!(f.next()?, "search" | "domain").then(|| f.map(str::to_owned).collect())
        })
        .last()
        .unwrap_or_default()
}

fn is_ours(contents: &str) -> bool {
    contents.lines().any(|l| l.trim() == MARKER)
}

/// Renders the file with the live resolver address.
fn render(search: &[String], fallbacks: &[IpAddr]) -> String {
    render_with(resolver_addr(), search, fallbacks)
}

fn render_with(resolver: IpAddr, search: &[String], fallbacks: &[IpAddr]) -> String {
    let mut out = format!("{MARKER}\n");
    if !search.is_empty() {
        out.push_str(&format!("search {}\n", search.join(" ")));
    }
    out.push_str(&format!("nameserver {resolver}\n"));
    for ip in fallbacks {
        out.push_str(&format!("nameserver {ip}\n"));
    }
    out
}

/// See [`strip_ours_with`]; uses the live resolver address.
fn strip_ours(contents: &str, host_search: &[String]) -> String {
    strip_ours_with(resolver_addr(), contents, host_search)
}

/// The file without the lines we wrote: marker and our nameserver. The search
/// line is rebuilt from the host's own domains, since ours share it; with no
/// host domains known it is left out rather than guessed.
fn strip_ours_with(ours: IpAddr, contents: &str, host_search: &[String]) -> String {
    let mut out: String = contents
        .lines()
        .filter(|l| {
            let t = l.trim();
            t != MARKER
                && !t.starts_with("search ")
                && !(t.starts_with("nameserver ")
                    && t["nameserver ".len()..].trim().parse::<IpAddr>().ok() == Some(ours))
        })
        .map(|l| format!("{l}\n"))
        .collect();
    if !host_search.is_empty() {
        out.push_str(&format!("search {}\n", host_search.join(" ")));
    }
    out
}

fn merge_search(host: &[String], ours: &[SearchDomain]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in ours
        .iter()
        .map(SearchDomain::as_str)
        .chain(host.iter().map(String::as_str))
    {
        if !d.is_empty() && !out.iter().any(|x| x == d) {
            out.push(d.to_owned());
        }
    }
    out.truncate(MAX_SEARCH);
    out
}

pub(crate) struct IllumosResolvConf {
    captured_upstreams: Vec<IpAddr>,
    /// The host's own search domains, kept so a later join/leave re-merges
    /// against them instead of piling ours on the previous render.
    captured_search: Vec<String>,
    search: Mutex<Vec<String>>,
}

impl IllumosResolvConf {
    pub(crate) async fn new() -> Self {
        let contents = tokio::fs::read_to_string(RESOLV_CONF)
            .await
            .unwrap_or_default();
        // A file we wrote earlier is not "the host's": ignore it.
        let (nameservers, search) = if is_ours(&contents) {
            (Vec::new(), Vec::new())
        } else {
            (parse_nameservers(&contents), parse_search(&contents))
        };
        // Only servers that answer are worth betting the zone's DNS on.
        let live = crate::dns::resolver::live_upstreams(&nameservers).await;
        Self {
            captured_upstreams: live,
            search: Mutex::new(search.clone()),
            captured_search: search,
        }
    }
}

#[async_trait]
impl DnsConfigurator for IllumosResolvConf {
    async fn apply(&self) -> Result<()> {
        anyhow::ensure!(
            !self.captured_upstreams.is_empty(),
            "no working DNS server found in /etc/resolv.conf, so taking it over would leave \
             this zone unable to resolve anything"
        );
        let path = Path::new(RESOLV_CONF);
        let backup = Path::new(BACKUP);
        if !exists_no_follow(backup) {
            let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
            if !current.is_empty() && !is_ours(&current) {
                backup_resolv_file(path, backup).context("backing up /etc/resolv.conf")?;
            }
        }
        let search = self.search.lock().unwrap().clone();
        write_resolv_file(path, render(&search, &self.captured_upstreams).as_bytes())
            .context("writing /etc/resolv.conf")?;
        tracing::info!(upstreams = ?self.captured_upstreams, "configured /etc/resolv.conf directly");
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        let path = Path::new(RESOLV_CONF);
        let backup = Path::new(BACKUP);
        if exists_no_follow(backup) {
            restore_resolv_backup(backup, path).context("restoring /etc/resolv.conf")?;
            if exists_no_follow(backup) {
                let _ = tokio::fs::remove_file(backup).await;
            }
            return Ok(());
        }
        // No backup: strip our lines in place rather than deleting the file.
        if let Ok(current) = tokio::fs::read_to_string(path).await
            && is_ours(&current)
        {
            write_resolv_file(path, strip_ours(&current, &self.captured_search).as_bytes())
                .context("removing our entries from /etc/resolv.conf")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "illumos-resolv.conf"
    }

    fn captured_upstreams(&self) -> Vec<IpAddr> {
        self.captured_upstreams.clone()
    }

    fn fallback_upstreams(&self) -> Vec<IpAddr> {
        self.captured_upstreams.clone()
    }

    async fn set_search_domains(&self, domains: &[SearchDomain], _tun_name: &str) -> Result<()> {
        let merged = merge_search(&self.captured_search, domains);
        *self.search.lock().unwrap() = merged.clone();
        let path = Path::new(RESOLV_CONF);
        // Only rewrite a file that is still ours.
        let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
        if !is_ours(&current) {
            return Ok(());
        }
        write_resolv_file(path, render(&merged, &self.captured_upstreams).as_bytes())
            .context("writing search domains to /etc/resolv.conf")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sd(s: &str) -> SearchDomain {
        // The field is private to `config`, which is an ancestor of this module.
        SearchDomain(smol_str::SmolStr::new(s))
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_nameservers_handles_comments_ipv6_and_junk() {
        let c = "# Auto-generated\n\
                 nameserver 10.0.0.2\n\
                 nameserver   fd00::53   # trailing comment\n\
                 nameserver not-an-ip\n\
                 nameserver\n\
                 options ndots:2\n\
                 # nameserver 1.1.1.1\n";
        assert_eq!(parse_nameservers(c), vec![ip("10.0.0.2"), ip("fd00::53")]);
    }

    #[test]
    fn parse_search_takes_the_last_search_or_domain_line() {
        assert_eq!(
            parse_search("search a.example b.example\n"),
            strs(&["a.example", "b.example"])
        );
        assert_eq!(
            parse_search("domain old.example\nsearch new.example\n"),
            strs(&["new.example"])
        );
        assert_eq!(
            parse_search("search first.example\ndomain last.example\n"),
            strs(&["last.example"])
        );
        assert!(parse_search("nameserver 10.0.0.1\n").is_empty());
    }

    #[test]
    fn is_ours_needs_the_marker_line() {
        assert!(is_ours("# Managed by rayfish.\nnameserver 200::53\n"));
        assert!(is_ours("  # Managed by rayfish.  \n"));
        assert!(!is_ours(
            "# Auto-generated from zone configuration\nnameserver 10.0.0.2\n"
        ));
    }

    #[test]
    fn render_puts_marker_search_ours_then_fallbacks() {
        let out = render_with(
            ip("200::53"),
            &strs(&["east.ray", "ray"]),
            &[ip("10.0.0.2"), ip("10.0.0.1")],
        );
        assert_eq!(
            out,
            "# Managed by rayfish.\n\
             search east.ray ray\n\
             nameserver 200::53\n\
             nameserver 10.0.0.2\n\
             nameserver 10.0.0.1\n"
        );
    }

    #[test]
    fn render_omits_an_empty_search_line() {
        let out = render_with(ip("200::53"), &[], &[ip("10.0.0.2")]);
        assert!(!out.contains("search"));
        assert!(out.starts_with("# Managed by rayfish.\n"));
    }

    #[test]
    fn rendered_file_is_recognised_as_ours_and_reparses() {
        let out = render_with(ip("200::53"), &strs(&["a", "b"]), &[ip("10.0.0.2")]);
        assert!(is_ours(&out));
        assert_eq!(parse_nameservers(&out), vec![ip("200::53"), ip("10.0.0.2")]);
        assert_eq!(parse_search(&out), strs(&["a", "b"]));
    }

    #[test]
    fn strip_ours_removes_marker_and_our_nameserver_keeps_the_rest() {
        let ours = ip("200::53");
        let file = render_with(ours, &strs(&["east.ray", "ray"]), &[ip("10.0.0.2")]);
        let out = strip_ours_with(ours, &file, &[]);
        assert!(!is_ours(&out));
        assert_eq!(parse_nameservers(&out), vec![ip("10.0.0.2")]);
        assert!(parse_search(&out).is_empty());
    }

    // Regression: a merged search line holds mesh and host domains together;
    // the revert must not drop the host's.
    #[test]
    fn strip_ours_keeps_the_host_search_domains() {
        let ours = ip("200::53");
        let host = strs(&["corp.example"]);
        let merged = merge_search(&host, &[sd("east.ray"), sd("ray")]);
        let file = render_with(ours, &merged, &[ip("10.0.0.2")]);
        assert!(parse_search(&file).contains(&"corp.example".to_string()));

        let out = strip_ours_with(ours, &file, &host);
        assert_eq!(parse_search(&out), host);
        assert_eq!(parse_nameservers(&out), vec![ip("10.0.0.2")]);
        assert!(!is_ours(&out));
    }

    #[test]
    fn strip_ours_leaves_other_resolvers_alone() {
        let ours = ip("200::53");
        let file =
            "# Managed by rayfish.\nnameserver 200::53\nnameserver 200::54\nnameserver 10.0.0.2\n";
        let out = strip_ours_with(ours, file, &[]);
        assert_eq!(parse_nameservers(&out), vec![ip("200::54"), ip("10.0.0.2")]);
    }

    #[test]
    fn merge_search_puts_ours_first_and_dedups() {
        let host = strs(&["corp.example", "ray"]);
        let out = merge_search(&host, &[sd("east.ray"), sd("ray")]);
        assert_eq!(out, strs(&["east.ray", "ray", "corp.example"]));
    }

    #[test]
    fn merge_search_truncates_to_the_resolver_limit() {
        let host = strs(&["h1", "h2", "h3", "h4", "h5", "h6"]);
        let out = merge_search(&host, &[sd("n1"), sd("n2")]);
        assert_eq!(out.len(), MAX_SEARCH);
        assert_eq!(&out[..2], &strs(&["n1", "n2"])[..]);
    }

    #[test]
    fn merge_search_skips_empty_entries() {
        let out = merge_search(&strs(&[""]), &[sd("x")]);
        assert_eq!(out, strs(&["x"]));
    }
}
