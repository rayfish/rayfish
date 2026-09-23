use super::{SearchDomain, resolver_addr};

#[cfg(target_os = "freebsd")]
const RAYFISH_MARKER: &str = "# Managed by rayfish.\n";

fn render_resolvconf(domains: &[SearchDomain]) -> String {
    let mut search = domains
        .iter()
        .map(SearchDomain::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    if search.is_empty() {
        search = SearchDomain::root().to_string();
    }
    format!("search {search}\nnameserver {}\n", resolver_addr())
}

fn local_resolver_in_use(contents: &str) -> bool {
    contents.lines().any(|line| {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        matches!(fields.next(), Some("nameserver"))
            && matches!(fields.next(), Some("127.0.0.1" | "::1"))
    })
}

fn resolvconf_updates_unbound(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        line.split_once('=')
            .is_some_and(|(key, value)| key.trim() == "unbound_conf" && !value.trim().is_empty())
    })
}

#[cfg(target_os = "freebsd")]
mod system {
    use std::fs::{self, File, OpenOptions, Permissions};
    use std::io::{ErrorKind, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Stdio, id};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use anyhow::{Context, Result};
    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    use super::{
        RAYFISH_MARKER, SearchDomain, local_resolver_in_use, render_resolvconf,
        resolvconf_updates_unbound,
    };
    use crate::dns::config::DnsConfigurator;

    const SERVICE: &str = "/usr/sbin/service";
    const SYSRC: &str = "/usr/sbin/sysrc";
    const RESOLVCONF: &str = "/sbin/resolvconf";
    const RESOLV_CONF: &str = "/etc/resolv.conf";
    const RESOLVCONF_CONF: &str = "/etc/resolvconf.conf";
    const UNBOUND_CONFIG: &str = "/var/unbound/conf.d/rayfish.conf";
    const UNBOUND_CONFIG_BODY: &str =
        "# Managed by rayfish.\nserver:\n    domain-insecure: \"ray.\"\n";

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct FreeBsdLocalUnbound {
        key: String,
        search: Arc<ArcSwap<Vec<SearchDomain>>>,
    }

    impl FreeBsdLocalUnbound {
        pub(crate) fn new(tun_name: &str) -> Self {
            Self {
                key: format!("{tun_name}.rayfish"),
                search: Arc::new(ArcSwap::from_pointee(vec![SearchDomain::root()])),
            }
        }

        async fn command_succeeds(program: &str, args: &[&str]) -> bool {
            Command::new(program)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .is_ok_and(|status| status.success())
        }

        async fn run(program: &str, args: &[&str], action: &str) -> Result<()> {
            let status = Command::new(program)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .with_context(|| action.to_string())?;
            anyhow::ensure!(status.success(), "{action} failed with {status}");
            Ok(())
        }

        async fn ensure_local_unbound(&self) -> Result<()> {
            install_unbound_config()?;

            if !Self::command_succeeds(SERVICE, &["local_unbound", "enabled"]).await {
                Self::run(
                    SYSRC,
                    &["local_unbound_enable=YES"],
                    "enabling local_unbound",
                )
                .await?;
            }

            if !Self::command_succeeds(SERVICE, &["local_unbound", "onestatus"]).await {
                Self::run(
                    SERVICE,
                    &["local_unbound", "start"],
                    "starting local_unbound",
                )
                .await?;
            }

            let resolv_conf = tokio::fs::read_to_string(RESOLV_CONF)
                .await
                .context("reading /etc/resolv.conf after starting local_unbound")?;
            anyhow::ensure!(
                local_resolver_in_use(&resolv_conf),
                "local_unbound is running, but /etc/resolv.conf does not use it; run \
                 `service local_unbound setup` once, then restart rayfish"
            );

            let resolvconf_conf = tokio::fs::read_to_string(RESOLVCONF_CONF)
                .await
                .context("reading /etc/resolvconf.conf after starting local_unbound")?;
            anyhow::ensure!(
                resolvconf_updates_unbound(&resolvconf_conf),
                "local_unbound is running, but resolvconf does not update it; run \
                 `service local_unbound setup` once, then restart rayfish"
            );
            Ok(())
        }

        async fn register(&self) -> Result<()> {
            let config = render_resolvconf(&self.search.load());
            let mut child = Command::new(RESOLVCONF)
                .args(["-p", "-a", self.key.as_str()])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("starting resolvconf for FreeBSD Magic DNS")?;
            let stdin = child
                .stdin
                .as_mut()
                .context("resolvconf stdin was not available")?;
            stdin
                .write_all(config.as_bytes())
                .await
                .context("sending FreeBSD Magic DNS configuration to resolvconf")?;
            let status = child.wait().await.context("waiting for resolvconf")?;
            anyhow::ensure!(status.success(), "resolvconf -p -a failed with {status}");
            Ok(())
        }

        async fn unregister(&self) -> Result<()> {
            Self::run(
                RESOLVCONF,
                &["-f", "-d", self.key.as_str()],
                "removing FreeBSD Magic DNS from resolvconf",
            )
            .await
        }
    }

    #[async_trait]
    impl DnsConfigurator for FreeBsdLocalUnbound {
        async fn apply(&self) -> Result<()> {
            self.ensure_local_unbound().await?;
            self.register().await?;
            tracing::info!(
                backend = "local_unbound",
                "configured FreeBSD split DNS for .ray"
            );
            Ok(())
        }

        async fn revert(&self) -> Result<()> {
            let unregister = self.unregister().await;
            let removed = remove_unbound_config();
            let reload = if removed.as_ref().is_ok_and(|removed| *removed)
                && Self::command_succeeds(SERVICE, &["local_unbound", "onestatus"]).await
            {
                Self::run(
                    SERVICE,
                    &["local_unbound", "reload"],
                    "reloading local_unbound after removing FreeBSD Magic DNS",
                )
                .await
            } else {
                Ok(())
            };
            unregister?;
            removed?;
            reload?;
            tracing::info!("reverted FreeBSD local_unbound configuration");
            Ok(())
        }

        fn name(&self) -> &'static str {
            "freebsd-local_unbound"
        }

        async fn set_search_domains(
            &self,
            domains: &[SearchDomain],
            _tun_name: &str,
        ) -> Result<()> {
            self.search.store(Arc::new(domains.to_vec()));
            self.register().await
        }
    }

    fn install_unbound_config() -> Result<()> {
        let path = Path::new(UNBOUND_CONFIG);
        match fs::read_to_string(path) {
            Ok(existing) if existing == UNBOUND_CONFIG_BODY => return Ok(()),
            Ok(existing) => anyhow::ensure!(
                existing.starts_with(RAYFISH_MARKER),
                "refusing to replace operator-managed {}",
                path.display()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        }

        let parent = path
            .parent()
            .context("local_unbound config has no parent")?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        let temp = temporary_path(parent);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .with_context(|| format!("creating {}", temp.display()))?;
            file.write_all(UNBOUND_CONFIG_BODY.as_bytes())
                .with_context(|| format!("writing {}", temp.display()))?;
            file.set_permissions(Permissions::from_mode(0o644))
                .with_context(|| format!("setting permissions on {}", temp.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing {}", temp.display()))?;
            fs::rename(&temp, path).with_context(|| format!("installing {}", path.display()))?;
            File::open(parent)
                .with_context(|| format!("opening {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("syncing {}", parent.display()))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn remove_unbound_config() -> Result<bool> {
        let path = Path::new(UNBOUND_CONFIG);
        match fs::read_to_string(path) {
            Ok(existing) if existing.starts_with(RAYFISH_MARKER) => {
                fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn temporary_path(parent: &Path) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        parent.join(format!(".rayfish.conf.tmp.{}.{}", id(), sequence))
    }
}

#[cfg(target_os = "freebsd")]
pub(super) use system::FreeBsdLocalUnbound;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_resolvconf_entry_routes_ray_and_search_domains() {
        let domains = vec![SearchDomain::for_network("home"), SearchDomain::root()];
        assert_eq!(
            render_resolvconf(&domains),
            "search home.ray ray\nnameserver 200::53\n"
        );
        assert_eq!(render_resolvconf(&[]), "search ray\nnameserver 200::53\n");
    }

    #[test]
    fn detects_local_unbound_resolver_lines() {
        assert!(local_resolver_in_use(
            "search example.test\nnameserver 127.0.0.1\n"
        ));
        assert!(local_resolver_in_use("nameserver ::1 # local_unbound\n"));
        assert!(!local_resolver_in_use("nameserver 192.0.2.53\n"));
        assert!(!local_resolver_in_use("# nameserver 127.0.0.1\n"));
    }

    #[test]
    fn detects_resolvconf_unbound_subscriber_configuration() {
        assert!(resolvconf_updates_unbound(
            "unbound_conf=\"/var/unbound/forward.conf\"\n"
        ));
        assert!(!resolvconf_updates_unbound(
            "# unbound_conf=\"/var/unbound/forward.conf\"\n"
        ));
        assert!(!resolvconf_updates_unbound(
            "unbound_conf_backup=\"/var/unbound/forward.conf\"\n"
        ));
    }
}
