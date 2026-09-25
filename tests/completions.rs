//! Tab completion, driven the way a shell drives it.
//!
//! The completion path lives in the binary, not the library: it answers before
//! the arguments are parsed and before the runtime starts, so the only honest
//! way to test it is to run `ray` the way the installed stub does, with
//! `COMPLETE` set and the line to complete after a `--`.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use ray_proto::settings::NodeKey;

const RAY: &str = env!("CARGO_BIN_EXE_ray");

/// Run one completion request, as the stub would, and return the candidates.
///
/// The fish protocol is one candidate per line, `value` or `value<TAB>help`,
/// which is the easiest of the three to read back.
fn complete(words: &[&str]) -> Vec<String> {
    let out = Command::new(RAY)
        .env("COMPLETE", "fish")
        .arg("--")
        .arg("ray")
        .args(words)
        .output()
        .expect("run ray for completion");
    assert!(
        out.status.success(),
        "completion exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| line.split('\t').next().unwrap_or_default().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

#[test]
fn a_bare_tab_offers_the_commands() {
    let found: HashSet<String> = complete(&[""]).into_iter().collect();
    for expected in ["create", "join", "leave", "firewall", "up"] {
        assert!(found.contains(expected), "missing {expected}: {found:?}");
    }
}

/// A command with visible aliases is listed under one of its names, not all of
/// them: clap_complete gives every spelling the same id and shows the first
/// after sorting, so `status` (aliases `s`, `st`, `ls`) appears as `ls`. Every
/// name shown is a real command, and typing the canonical one still completes
/// it, which is what the next test pins.
#[test]
fn an_aliased_command_is_listed_once() {
    let found: HashSet<String> = complete(&[""]).into_iter().collect();
    let names = ["status", "s", "st", "ls"];
    let listed = names.iter().filter(|n| found.contains(**n)).count();
    assert_eq!(listed, 1, "expected exactly one of {names:?} in {found:?}");
}

#[test]
fn typing_narrows_to_what_still_matches() {
    assert_eq!(complete(&["stat"]), ["status"]);
    // A prefix that only one command has offers it, and nothing else.
    assert_eq!(complete(&["exit"]), ["exit-node"]);
}

/// Every canonical command name completes from its own spelling, alias or not.
///
/// The alias handling above means `ray <TAB>` can show `ls` where the docs say
/// `status`; what must not happen is a documented name that cannot be completed
/// at all.
#[test]
fn every_command_completes_from_its_canonical_name() {
    for name in [
        "status",
        "kick",
        "leave",
        "firewall",
        "exit-node",
        "auto-update",
        "set-operator",
        "identityof",
        "completions",
        "config",
    ] {
        let found = complete(&[name]);
        assert!(
            found.iter().any(|c| c == name),
            "{name} does not complete to itself: {found:?}"
        );
    }
}

#[test]
fn nested_subcommands_complete_too() {
    let found: HashSet<String> = complete(&["firewall", "ssh", ""]).into_iter().collect();
    for expected in ["on", "off", "allow"] {
        assert!(found.contains(expected), "missing {expected}: {found:?}");
    }
    // Two levels down, the canonical name still completes from itself.
    assert!(complete(&["firewall", "ssh", "show"]).contains(&"show".to_string()));
}

#[test]
fn fixed_domain_arguments_offer_their_words() {
    let found = complete(&["firewall", "add", ""]);
    assert!(found.contains(&"in".to_string()), "{found:?}");
    assert!(found.contains(&"out".to_string()), "{found:?}");

    let found = complete(&["firewall", "default", ""]);
    assert!(found.contains(&"allow".to_string()), "{found:?}");
    assert!(found.contains(&"deny".to_string()), "{found:?}");
}

/// Every key the settings registry defines is offered, both stores' worth.
///
/// The point of driving completion off `NodeKey::all()` is that adding a key to
/// the registry is the whole job; this fails if someone reintroduces a
/// hand-kept list here.
#[test]
fn the_settings_keys_come_from_the_registry_that_defines_them() {
    let found: HashSet<String> = complete(&["config", "set", ""]).into_iter().collect();
    for key in NodeKey::all() {
        assert!(found.contains(key.name()), "missing {key}: {found:?}");
    }
    // Both scopes, not just the globals: firewall keys are node-scoped too.
    assert!(found.contains("firewall.default-in"), "{found:?}");
}

/// A key whose domain is a fixed set completes its values; one whose domain is
/// free-form offers nothing rather than something wrong.
#[test]
fn a_settings_value_completes_when_the_key_has_a_fixed_domain() {
    assert_eq!(
        complete(&["config", "set", "mdns", ""])[..2],
        ["on".to_string(), "off".to_string()]
    );
    assert_eq!(
        complete(&["config", "set", "firewall.default-in", ""])[..2],
        ["allow".to_string(), "deny".to_string()]
    );

    // A path, a URL list and a uid are nobody's fixed set.
    for key in ["relay", "dns-upstreams", "download-dir", "download-user"] {
        let found = complete(&["config", "set", key, ""]);
        assert!(
            found.iter().all(|c| c.starts_with('-')),
            "{key} offered values: {found:?}"
        );
    }
}

/// The rule that matters most: a tab answers, or gives up, but never hangs.
///
/// `ipc::connect` has no timeout of its own, so without the budget in
/// `cli::complete` a wedged or absent daemon would freeze the user's shell.
/// This holds whether or not a daemon happens to be running on the test host.
#[test]
fn a_tab_that_needs_the_daemon_still_returns_promptly() {
    let started = Instant::now();
    let _ = complete(&["leave", ""]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "completion took {elapsed:?}"
    );
}

#[test]
fn install_writes_where_each_shell_looks() {
    let home = tempfile::tempdir().expect("tempdir");
    let data = home.path().join("data");
    let config = home.path().join("config");

    let install = |shell: &str| {
        let out = Command::new(RAY)
            .args(["completions", shell, "--install"])
            .env("XDG_DATA_HOME", &data)
            .env("XDG_CONFIG_HOME", &config)
            .env("HOME", home.path())
            .output()
            .expect("run ray completions --install");
        assert!(
            out.status.success(),
            "install {shell} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    install("zsh");
    install("bash");
    install("fish");

    let written = |path: &Path| {
        let script =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        // A stub that calls the binary back, not a script frozen at build time.
        assert!(script.contains("COMPLETE"), "{}: {script}", path.display());
        script
    };

    let zsh = written(&data.join("zsh/site-functions/_ray"));
    assert!(zsh.starts_with("#compdef ray"));
    // Installed onto fpath, so the file is autoloaded by the first tab and the
    // `compdef` in it would only bind from the next one. The shim is what makes
    // that first tab answer.
    assert!(zsh.contains("_comps[ray]"), "{zsh}");
    assert!(zsh.contains("${+CURRENT}"), "{zsh}");

    written(&data.join("bash-completion/completions/ray"));
    written(&config.join("fish/completions/ray.fish"));
}

#[test]
fn printing_a_stub_needs_no_write_access_anywhere() {
    let out = Command::new(RAY)
        .args(["completions", "zsh"])
        .output()
        .expect("run ray completions");
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);
    assert!(script.starts_with("#compdef ray"), "{script}");
    // Plain `ray` on the PATH: an absolute path here would stop working the
    // moment `ray update` replaces the binary it points at.
    assert!(!script.contains(RAY), "{script}");
}
