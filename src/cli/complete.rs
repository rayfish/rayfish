//! Tab completion that knows which networks and peers you actually have.
//!
//! A generated script can only offer what was true when it was written, which
//! for `ray leave` or `ray ping` is nothing at all: those arguments are free-form
//! strings whose values live in the daemon. So the installed file is a stub that
//! asks this binary on every tab, and the answers come from the same
//! `IpcMessage::Status` the rest of the CLI uses.
//!
//! Two rules shape everything here, because this code runs on a keystroke:
//!
//! - A tab never starts the daemon. No socket means no candidates, not a
//!   daemon launched because someone pressed a key.
//! - A tab never blocks the shell. `ipc::connect` has no timeout of its own, so
//!   every round trip runs under [`BUDGET`]; a wedged daemon costs a pause, not
//!   a hung terminal.
//!
//! The install side lives here too. `sudo ray up` writes these stubs into the
//! directories the shells already search, so completion is simply there after an
//! install, with nothing to source and no rc file to edit.
//!
//! One upstream behaviour worth knowing: a command's visible aliases share its
//! completion id, and clap_complete shows only the first of a shared id after
//! sorting by value. So `ray <TAB>` lists `status` as `ls` and `kick` as
//! `boot`. Every name it shows is a real command and typing the canonical one
//! still completes it (`tests/completions.rs` pins both), so this is cosmetic;
//! it is not something this module chooses.

use std::ffi::OsStr;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::CommandFactory as _;
use clap_complete::engine::{ArgValueCandidates, ArgValueCompleter, CompletionCandidate};
use clap_complete::{CompleteEnv, Shell};

use crate::Cli;
use crate::*;

use ipc::{IpcMessage, NetworkStatus, NodeKey, PeerState};

/// The environment variable the installed stub sets to ask for completions.
const VAR: &str = "COMPLETE";

/// How long the daemon gets to answer. It is a unix socket and a running
/// process; longer than this means something is wrong, and a tab is not the
/// place to find out.
const BUDGET: Duration = Duration::from_millis(300);

/// DESTDIR-style prefix for the system-wide install paths. Set by the tests;
/// also what a packager would reach for.
const DESTDIR_VAR: &str = "RAYFISH_COMPLETION_DIR";

/// Answer a completion request and exit, or return and let the CLI run.
///
/// Called before the runtime starts and before the arguments are parsed: a
/// completion request is not a command line this parser would accept, and the
/// completers below want a runtime of their own.
pub(crate) fn intercept() {
    CompleteEnv::with_factory(Cli::command).var(VAR).complete();
}

// ---------------------------------------------------------------------------
// Completers
// ---------------------------------------------------------------------------

/// Network names, for the ~25 arguments that name one.
///
/// Includes networks joined but not yet admitted (`pending_networks`): they are
/// exactly what you would name in a `ray leave` to give up waiting.
pub(crate) fn networks() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| candidates(prefixed(current, network_names())))
}

/// Peers, scoped to the network already named on the line when there is one.
pub(crate) fn peers() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| peer_candidates(current, PeerFilter::Any))
}

/// Peers, plus the `*` every rule-shaped argument accepts as "anyone".
pub(crate) fn peers_or_any() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| {
        let mut found = peer_candidates(current, PeerFilter::Any);
        found.extend(candidates(prefixed(current, ["*".to_string()])));
        found
    })
}

/// Only the peers advertising themselves as exit nodes, for `exit-node use`.
pub(crate) fn exit_peers() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| peer_candidates(current, PeerFilter::ExitNodes))
}

/// This user's other paired devices, for `ray unpair`.
pub(crate) fn paired_devices() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| {
        let devices = ask(IpcMessage::ListPairedDevices, |reply| match reply {
            IpcMessage::PairedDevices { devices } => Some(devices),
            _ => None,
        })
        .unwrap_or_default();
        described(
            devices
                .into_iter()
                .map(|d| (d.hostname.unwrap_or(d.short_id), d.networks.join(", "))),
        )
        .into_iter()
        .filter(|c| starts_with(c, current))
        .collect()
    })
}

/// Node-local aliases on the network named on the line, for `alias remove`.
pub(crate) fn aliases() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| {
        let networks = status().map(|(nets, _)| nets).unwrap_or_default();
        let named = scope(&networks);
        let found = networks
            .iter()
            .filter(|net| named.is_none_or(|name| name == net.name))
            .flat_map(|net| net.aliases.iter())
            .map(|(alias, identity)| (alias.clone(), identity.clone()));
        described(found)
            .into_iter()
            .filter(|c| starts_with(c, current))
            .collect()
    })
}

/// `ray ephemeral <net> <arg>`: a duration, or the two words that aren't one.
///
/// Suggestions only. The argument takes any `Nh`/`Nd`/`Nw` duration, so this
/// must not restrict what is accepted the way a `PossibleValuesParser` would.
pub(crate) fn ephemeral_args() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| {
        candidates(prefixed(
            current,
            ["show", "off", "24h", "7d", "30d"].map(String::from),
        ))
    })
}

/// A fixed set of words the argument accepts, for an argument the parser still
/// takes anything for.
///
/// Suggestions, deliberately not a `PossibleValuesParser`: the on/off arguments
/// also accept `true`/`yes`/`1`, and the settings keys report their own error
/// naming the valid ones. Completion should make the common spelling one tab
/// away without narrowing what the command accepts.
pub(crate) fn words(values: &'static [&'static str]) -> ArgValueCandidates {
    ArgValueCandidates::new(move || {
        values
            .iter()
            .map(|word| CompletionCandidate::new(*word))
            .collect()
    })
}

/// Every node-scoped settings key, described by the registry that defines it.
///
/// `NodeKey::all()` is the same iterator `ray config get` lists and
/// `settings::node_key_help` documents, so a key added to the registry appears
/// on tab with its description and needs no edit here. No IPC either: the key
/// namespace is compiled in, so this answers with the daemon stopped.
pub(crate) fn node_settings_keys() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        NodeKey::all()
            .map(|key| CompletionCandidate::new(key.name()).help(Some(key.help().into())))
            .collect()
    })
}

/// The values a settings key accepts, for `ray config set <key> <TAB>`.
///
/// Read off the key's own help text, whose convention is to end with the domain
/// in parentheses: `(on|off)`, `(allow|deny)`. Anything that isn't a list of
/// bare words is a free-form value (a path, a URL list, a uid) and gets no
/// suggestions rather than a wrong one. Deriving it this way means the registry
/// stays the only place a key is described.
pub(crate) fn settings_values() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let words = line_words();
        let Some(key) = NodeKey::all().find(|k| words.iter().any(|w| w == k.name())) else {
            return Vec::new();
        };
        domain_of(key.help())
            .into_iter()
            .map(CompletionCandidate::new)
            .collect()
    })
}

/// The `(a|b)` domain at the end of a settings key's help, if it is one.
///
/// Kept free of I/O so the convention it relies on can be tested against every
/// key the registry actually defines.
fn domain_of(help: &str) -> Vec<String> {
    let Some(inner) = help
        .rsplit_once('(')
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.strip_suffix(')'))
    else {
        return Vec::new();
    };
    let words: Vec<String> = inner.split('|').map(str::to_string).collect();
    let bare = |word: &String| {
        !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    match words.len() > 1 && words.iter().all(bare) {
        true => words,
        false => Vec::new(),
    }
}

enum PeerFilter {
    Any,
    ExitNodes,
}

fn peer_candidates(current: &OsStr, filter: PeerFilter) -> Vec<CompletionCandidate> {
    let Some((networks, _)) = status() else {
        return Vec::new();
    };
    // The completer is handed the current word and nothing else, so the network
    // this peer belongs to has to be read back off the line being completed.
    let named = scope(&networks);
    let mut found: Vec<(String, String)> = networks
        .iter()
        .filter(|net| named.is_none_or(|name| name == net.name))
        .flat_map(|net| net.peers.iter())
        .filter(|peer| match filter {
            PeerFilter::Any => true,
            PeerFilter::ExitNodes => peer.exit_node,
        })
        .filter_map(|peer| {
            let name = peer.hostname.clone()?;
            let state = match peer.state {
                PeerState::Active => "active",
                PeerState::Idle => "idle",
                PeerState::Offline => "offline",
            };
            Some((name, format!("{}, {state}", peer.ipv6)))
        })
        .collect();
    // The same device is on the roster of every network it shares with us, and
    // a list that repeats a hostname three times is worse than useless.
    found.sort();
    found.dedup_by(|a, b| a.0 == b.0);

    described(found)
        .into_iter()
        .filter(|c| starts_with(c, current))
        .collect()
}

/// The network named on the line being completed, if exactly one is.
///
/// A completer only receives the current word, but the whole line sits in this
/// process's own arguments, after the `--` that separates our invocation from
/// theirs:
///
/// ```text
/// ray -- ray kick homelab lap
/// ```
///
/// Rather than counting positionals across the 25 commands that take a network,
/// intersect the typed words with the names we know. One match scopes the
/// answer; none or several leaves every peer on offer, which is the right
/// fallback in both directions.
fn scope(networks: &[NetworkStatus]) -> Option<&str> {
    let words = line_words();
    let mut named = networks
        .iter()
        .map(|net| net.name.as_str())
        .filter(|name| words.iter().any(|word| word == name));
    let first = named.next()?;
    named.next().is_none().then_some(first)
}

fn line_words() -> Vec<String> {
    std::env::args_os()
        .skip_while(|arg| arg != "--")
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .collect()
}

/// Network names from the daemon, or from the config it would have loaded.
///
/// The offline fallback is what makes `sudo ray leave <TAB>` work with the
/// service stopped. It is only ever a fallback: on Linux `/etc/rayfish` is
/// `0750 root:rayfish`, so an unprivileged shell cannot read it and the daemon
/// is the only source there.
fn network_names() -> Vec<String> {
    if let Some((networks, pending)) = status() {
        let mut names: Vec<String> = networks.into_iter().map(|net| net.name).collect();
        names.extend(pending);
        return names;
    }
    config::load()
        .map(|cfg| cfg.networks.into_iter().map(|net| net.name).collect())
        .unwrap_or_default()
}

/// The daemon's view of the world, or `None` if it cannot give one in time.
///
/// Every failure is the same answer here: nothing to offer. A tab is not the
/// place to explain that the daemon is down.
fn status() -> Option<(Vec<NetworkStatus>, Vec<String>)> {
    ask(IpcMessage::Status, |reply| match reply {
        IpcMessage::StatusResponse {
            networks,
            pending_networks,
            ..
        } => Some((networks, pending_networks)),
        _ => None,
    })
}

/// One request, one reply, within [`BUDGET`].
///
/// Only the open reads belong here: `Daemon::check_authorized` lets `Status` and
/// friends through for any local uid, so completion works without sudo.
fn ask<T>(request: IpcMessage, reply: impl FnOnce(IpcMessage) -> Option<T>) -> Option<T> {
    blocking(BUDGET, async {
        // No socket means no daemon. Connecting would not start one, but
        // `ipc::connect`'s error path is slower than an existence check and
        // this runs on a keystroke.
        if !ipc::socket_path().exists() {
            return None;
        }
        let mut stream = ipc::connect().await.ok()?;
        ipc::send(&mut stream, request).await.ok()?;
        reply(ipc::recv(&mut stream).await.ok()?)
    })
    .flatten()
}

/// Run one async errand to completion, or give up on it.
///
/// Completion happens before the CLI's runtime exists (see `main`), so there is
/// no runtime to be inside of here, and building one is allowed.
fn blocking<T>(budget: Duration, work: impl Future<Output = T>) -> Option<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    runtime.block_on(async { tokio::time::timeout(budget, work).await.ok() })
}

fn prefixed<I>(current: &OsStr, values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    values
        .into_iter()
        .filter(|value| value.starts_with(current))
        .collect()
}

fn candidates(values: Vec<String>) -> Vec<CompletionCandidate> {
    values.into_iter().map(CompletionCandidate::new).collect()
}

/// Candidates carrying a second column, which is what tells two offline peers
/// apart in the list a shell shows.
fn described<I>(values: I) -> Vec<CompletionCandidate>
where
    I: IntoIterator<Item = (String, String)>,
{
    values
        .into_iter()
        .map(|(value, help)| CompletionCandidate::new(value).help(Some(help.into())))
        .collect()
}

fn starts_with(candidate: &CompletionCandidate, current: &OsStr) -> bool {
    match (candidate.get_value().to_str(), current.to_str()) {
        (Some(value), Some(current)) => value.starts_with(current),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Installing the shell's side
// ---------------------------------------------------------------------------

/// The shells we can install for. Elvish and PowerShell can still be printed
/// with `ray completions <shell>`; neither has a directory to drop a file in
/// that its shell reads without being told to.
const INSTALLABLE: [Shell; 3] = [Shell::Bash, Shell::Zsh, Shell::Fish];

/// Write the shell's side of this: a stub that calls back here.
pub(crate) fn registration(shell: Shell, out: &mut dyn Write) -> Result<()> {
    let name = shell.to_string();
    let shells = clap_complete::env::Shells::builtins();
    let Some(completer) = shells.completer(&name) else {
        anyhow::bail!("no completion support for {name}");
    };
    // The completer is plain `ray` on the PATH, not the path of the binary
    // writing this: `ray update` replaces that binary, and an installed script
    // naming a path it moved away from is a script that stops working.
    completer.write_registration(VAR, "ray", "ray", "ray", out)?;
    if shell == Shell::Zsh {
        out.write_all(ZSH_AUTOLOAD_SHIM.as_bytes())?;
    }
    Ok(())
}

/// zsh's registration is written to be sourced from `.zshrc`, where `compdef`
/// runs long before the first tab. We install onto `fpath` instead, where the
/// file is autoloaded *by* the first tab, and `compdef` there only takes effect
/// from the next one. So call what it just registered, read back out of
/// `_comps` rather than by naming a function that belongs to clap_complete.
/// The file has to work both ways, since sourcing it from `.zshrc` is the other
/// way people set this up. `CURRENT` is only set while a completion is running,
/// which is what tells the two apart: sourced, this does nothing and `compdef`
/// alone is enough.
const ZSH_AUTOLOAD_SHIM: &str = r#"
# Autoloaded from fpath, `compdef` above applies from the next completion
# onwards, so run what it registered rather than letting this tab come back
# empty. Sourced from .zshrc instead, there is no completion to answer and
# `CURRENT` is unset, so this stays out of the way.
if (( ${+CURRENT} )); then
  local _ray_completer=${_comps[ray]}
  if [[ -n $_ray_completer && $_ray_completer != $0 ]]; then
    $_ray_completer "$@"
  fi
fi
"#;

/// Where each shell looks for completions installed for every user on the box.
///
/// All three are on the shells' default search path, which is the whole point:
/// nothing to source, no rc file to edit, tab completion is just there after an
/// install. On macOS that means the `/usr/local` copies of the same layout,
/// which is what the system zsh has on its default `fpath`.
fn system_path(shell: Shell) -> Option<PathBuf> {
    system_path_under(&destdir(), shell)
}

/// `system_path` with the root spelled out, so the tests can point the whole
/// install at a temp directory without touching a process-wide env var.
fn system_path_under(root: &Path, shell: Shell) -> Option<PathBuf> {
    let relative = if cfg!(target_os = "macos") {
        match shell {
            Shell::Bash => "usr/local/etc/bash_completion.d/ray",
            Shell::Zsh => "usr/local/share/zsh/site-functions/_ray",
            Shell::Fish => "usr/local/share/fish/vendor_completions.d/ray.fish",
            _ => return None,
        }
    } else {
        match shell {
            Shell::Bash => "usr/share/bash-completion/completions/ray",
            Shell::Zsh => "usr/share/zsh/site-functions/_ray",
            Shell::Fish => "usr/share/fish/vendor_completions.d/ray.fish",
            _ => return None,
        }
    };
    Some(root.join(relative))
}

fn destdir() -> PathBuf {
    std::env::var_os(DESTDIR_VAR)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Where each shell looks for completions this user installed for themselves.
///
/// Deliberately not `dirs::data_dir()`: shells follow the XDG layout on macOS
/// too, where that would point at `~/Library/Application Support`.
fn user_path(shell: Shell) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let base = |var: &str, fallback: &str| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(fallback))
    };
    let data = base("XDG_DATA_HOME", ".local/share");
    let config = base("XDG_CONFIG_HOME", ".config");
    Some(match shell {
        Shell::Bash => data.join("bash-completion/completions/ray"),
        Shell::Zsh => data.join("zsh/site-functions/_ray"),
        Shell::Fish => config.join("fish/completions/ray.fish"),
        Shell::Elvish => config.join("elvish/lib/ray.elv"),
        // PowerShell loads completions from a profile script, not a directory.
        _ => return None,
    })
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Write one stub, or leave the file alone when it already says this.
///
/// Idempotent on purpose: every `sudo ray up` and every `ray update` comes
/// through here, and rewriting three identical files on each one would churn
/// mtimes for nothing. Returns whether anything changed.
fn write_stub(shell: Shell, path: &Path) -> Result<bool> {
    let mut script = Vec::new();
    registration(shell, &mut script)?;
    if std::fs::read(path).is_ok_and(|existing| existing == script) {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    std::fs::write(path, &script).with_context(|| format!("could not write {}", path.display()))?;
    Ok(true)
}

/// Install a stub for every shell, system-wide. Root only.
///
/// Every shell, not the one running: this is invoked under `sudo`, where
/// `$SHELL` is whatever the login shell of the invoking account happens to be
/// and every other account on the box wants completion too. Three small files
/// is cheaper than guessing wrong.
///
/// Returns the paths that actually changed, so a caller can stay quiet when
/// there was nothing to do.
pub(crate) fn install_system() -> Vec<PathBuf> {
    install_system_under(&destdir())
}

fn install_system_under(root: &Path) -> Vec<PathBuf> {
    INSTALLABLE
        .iter()
        .filter_map(|&shell| {
            let path = system_path_under(root, shell)?;
            write_stub(shell, &path).ok()?.then_some(path)
        })
        .collect()
}

/// Remove the stubs `install_system` wrote. Best-effort, like the install.
pub(crate) fn uninstall_system() {
    uninstall_system_under(&destdir());
}

fn uninstall_system_under(root: &Path) {
    for shell in INSTALLABLE {
        if let Some(path) = system_path_under(root, shell) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Install completions as part of installing the service.
///
/// Best-effort and quiet, in the shape `grant_operator_to_invoking_user` already
/// has in the same function: nobody ran `sudo ray up` to get tab completion, so
/// a read-only `/usr` or a distro with no `bash-completion` must not turn a
/// working service install into a failure.
pub(crate) fn install_with_service() {
    if !is_root() {
        return;
    }
    let written = install_system();
    if !written.is_empty() {
        println!("tab completion installed — open a new shell to pick it up");
    }
}

/// `ray completions`: print the stub, or write it where the shell will find it.
pub(crate) fn cmd_completions(shell: Option<Shell>, install: bool) -> Result<()> {
    if !install {
        let Some(shell) = shell.or_else(Shell::from_env) else {
            anyhow::bail!("could not tell which shell you use; name it: ray completions zsh");
        };
        return registration(shell, &mut std::io::stdout());
    }

    // Root and no shell named: every shell, system-wide, where they are found
    // without anyone editing an rc file.
    if is_root() && shell.is_none() {
        let written = install_system();
        if written.is_empty() {
            println!("tab completion is already installed and up to date");
        }
        for path in written {
            println!("wrote {}", path.display());
        }
        println!("open a new shell to pick it up");
        return Ok(());
    }

    let Some(shell) = shell.or_else(Shell::from_env) else {
        anyhow::bail!("could not tell which shell you use; name it: ray completions zsh --install");
    };

    // A named shell under root still means system-wide: that is where root can
    // write, and where the file is found without configuration.
    let path = match is_root() {
        true => system_path(shell),
        false => user_path(shell),
    };
    let Some(path) = path else {
        anyhow::bail!(
            "no install path known for {shell}; print it and place it yourself: \
             ray completions {shell}"
        );
    };
    write_stub(shell, &path)?;
    println!("wrote {}", path.display());

    if !is_root() && shell == Shell::Zsh {
        println!(
            "zsh only reads completions on its fpath. If tab completion does not work, add this \
             to ~/.zshrc:\n\n  fpath=({} $fpath)\n  autoload -Uz compinit && compinit\n",
            path.parent().unwrap_or(&path).display()
        );
    }
    if !is_root() {
        println!("`sudo ray completions --install` installs for every shell and every user.");
    }
    println!(
        "the script asks `ray` for network and peer names as you type, so it needs ray on your PATH"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zsh_script_completes_on_the_first_tab() {
        let mut written = Vec::new();
        registration(Shell::Zsh, &mut written).unwrap();
        let script = String::from_utf8(written).unwrap();
        assert!(script.starts_with("#compdef ray"));
        assert!(script.contains(VAR));
        // The shim, without which the first tab after a shell starts is eaten.
        assert!(script.contains("_comps[ray]"));
        // Guarded, so sourcing the file from .zshrc does not run it as though a
        // completion were in progress.
        assert!(script.contains("${+CURRENT}"));
    }

    #[test]
    fn every_installable_shell_gets_a_script_that_asks_the_binary() {
        for shell in INSTALLABLE {
            let mut written = Vec::new();
            registration(shell, &mut written).unwrap();
            let script = String::from_utf8(written).unwrap();
            assert!(script.contains(VAR), "{shell}: {script}");
            assert!(script.contains("ray"), "{shell}: {script}");
        }
    }

    #[test]
    fn the_stub_names_ray_on_the_path_not_this_binary() {
        // An absolute path here would break on the next `ray update`, which
        // moves the binary out from under whatever the script points at.
        let mut written = Vec::new();
        registration(Shell::Bash, &mut written).unwrap();
        let script = String::from_utf8(written).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert!(!script.contains(&*exe.to_string_lossy()));
    }

    /// The convention `settings_values` reads, checked against the keys the
    /// registry actually defines rather than against invented strings.
    #[test]
    fn a_keys_domain_is_read_off_its_help_only_when_it_is_a_fixed_set() {
        let domain = |name: &str| {
            let key = NodeKey::all()
                .find(|k| k.name() == name)
                .unwrap_or_else(|| panic!("no such key: {name}"));
            domain_of(key.help())
        };
        assert_eq!(domain("mdns"), ["on", "off"]);
        assert_eq!(domain("firewall.default-in"), ["allow", "deny"]);

        // Free-form values: a trailing parenthesis that is prose, not a domain.
        assert!(domain("relay").is_empty());
        assert!(domain("dns-upstreams").is_empty());
        assert!(domain("download-dir").is_empty());
        assert!(domain("download-user").is_empty());

        // Nothing to read at all.
        assert!(domain_of("no parenthesis here").is_empty());
        assert!(domain_of("a single word (on)").is_empty());
    }

    #[test]
    fn every_installable_shell_has_a_system_path() {
        for shell in INSTALLABLE {
            let path = system_path(shell).unwrap_or_else(|| panic!("no system path for {shell}"));
            assert!(path.is_absolute(), "{shell}: {}", path.display());
        }
    }

    #[test]
    fn installing_creates_the_directories_and_uninstalling_takes_the_files_back_out() {
        let root = tempfile::tempdir().expect("tempdir");
        let written = install_system_under(root.path());
        assert_eq!(written.len(), INSTALLABLE.len(), "{written:?}");
        for path in &written {
            assert!(path.is_file(), "{}", path.display());
        }

        // Second time round there is nothing to do: `sudo ray up` and every
        // `ray update` come through here, and each one must not rewrite three
        // identical files.
        assert!(install_system_under(root.path()).is_empty());

        uninstall_system_under(root.path());
        for path in &written {
            assert!(!path.exists(), "left behind: {}", path.display());
        }
    }
}
