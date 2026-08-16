//! Grouped `-h` output, for the root and for any subcommand long enough to need
//! it.
//!
//! clap has no notion of subcommand groups: `help_heading` is an argument-only
//! attribute, and `hide_short_help` likewise, so neither grouping nor a terse
//! `-h` / full `--help` split is reachable through the derive API. The command
//! list is therefore rendered here, and the help template drops clap's own
//! `{subcommands}` block to make room for it.
//!
//! Only the *grouping* lives here. Every description is read back out of the
//! clap model, so there is no second copy of any help text to drift, and
//! subcommands stay visible in that model: `hide = true` would have suppressed
//! clap's list for us, but `clap_complete` skips hidden subcommands, which would
//! quietly gut tab completion. (Deliberately hidden commands are a separate
//! thing: a spelling kept alive for old scripts is meant to leave both the
//! listing and completion.)
//!
//! A page that is *not* in [`PAGES`] keeps clap's own flat list. That is the
//! right answer below about eight actions, where a heading per two entries is
//! noise; what those pages need instead is a one-line `about`, which
//! `tests::every_about_fits_the_listing` enforces at every depth.

use clap::{Command, CommandFactory};

use crate::Cli;

/// One page's groups: a title and the subcommands under it, in display order.
type Groups = &'static [(&'static str, &'static [&'static str])];

/// The group each top-level command is listed under.
///
/// Every visible subcommand must appear exactly once. `tests::every_command_is_grouped`
/// fails otherwise, so a newly added command cannot silently go missing from
/// `-h`, and a renamed or deleted one cannot leave a dangling entry here.
const ROOT: Groups = &[
    (
        "Networks",
        &[
            "create",
            "join",
            "leave",
            "nuke",
            "status",
            "hostname",
            "ephemeral",
        ],
    ),
    (
        "Members & access",
        &["invite", "requests", "kick", "admin", "alias", "identityof"],
    ),
    ("Devices & links", &["connect", "contact", "pair", "unpair"]),
    ("Files", &["send", "files"]),
    ("Policy", &["firewall", "exit-node", "apply"]),
    (
        "Service",
        &[
            "up",
            "down",
            "start",
            "stop",
            "restart",
            "install",
            "uninstall",
            "set-operator",
        ],
    ),
    (
        "Diagnostics",
        &["ping", "netcheck", "logs", "report", "mdns"],
    ),
    (
        "Setup",
        &["config", "update", "completions", "gui", "version"],
    ),
];

/// `ray firewall`, the one page with enough actions to need headings: rules to
/// edit, switches that change how they are enforced, the coordinator-suggestion
/// queue, and the SSH server that rides the same policy.
const FIREWALL: Groups = &[
    ("Rules", &["show", "add", "remove"]),
    ("Mode", &["on", "off", "default", "reject"]),
    (
        "Coordinator suggestions",
        &["suggest", "pending", "accept", "deny", "auto-accept"],
    ),
    ("Mesh SSH", &["ssh"]),
];

/// Every grouped help page: the command path it sits at (empty = the root) and
/// its groups. Adding a page is an entry here; the tests then hold it to the
/// same coverage rules the root has always had.
const PAGES: &[(&[&str], Groups)] = &[(&[], ROOT), (&["firewall"], FIREWALL)];

/// The help template for one page.
///
/// `{subcommands}` is deliberately absent: the grouped listing takes its place
/// through `{after-help}`, which is why that placeholder sits above `{options}`
/// rather than in its usual spot at the foot of the page. `Options:` and
/// `Arguments:` are spelled out because `{options}` / `{positionals}` render
/// their lines without a heading. `{after-help}` brings its own blank line, so
/// it sits flush against the usage line rather than being separated by one.
///
/// The `Arguments:` block appears only when the page has positionals. The root
/// has none, but omitting the block unconditionally would silently swallow
/// `<NETWORK>` the day someone groups `ray invite`.
fn template(cmd: &Command, path: &[&str]) -> String {
    let args = if cmd.get_positionals().next().is_some() {
        "\n\nArguments:\n{positionals}"
    } else {
        ""
    };
    // `ray help firewall <command>` on a nested page, `ray help <command>` at
    // the root.
    let prefix = match path.is_empty() {
        true => String::new(),
        false => format!("{} ", path.join(" ")),
    };
    format!(
        "{{about-with-newline}}\n\
         {{usage-heading}} {{usage}}{{after-help}}{args}\n\
         \n\
         Options:\n\
         {{options}}\n\
         \n\
         Run `ray help {prefix}<command>` for the full description of one command."
    )
}

/// The CLI, with a grouped command listing in place of clap's flat one on every
/// page in [`PAGES`].
pub(crate) fn command() -> Command {
    let mut cmd = Cli::command();
    for (path, groups) in PAGES {
        cmd = at(cmd, path, &|target| group(target, path, groups));
    }
    cmd
}

/// Apply `f` to the command at `path`, walking down through `mut_subcommand` so
/// nesting depth is not special-cased.
fn at(cmd: Command, path: &[&str], f: &dyn Fn(Command) -> Command) -> Command {
    match path.split_first() {
        None => f(cmd),
        Some((head, rest)) => cmd.mut_subcommand(head, |sub| at(sub, rest, f)),
    }
}

/// Swap one page's flat subcommand list for its grouped listing.
fn group(cmd: Command, path: &[&str], groups: Groups) -> Command {
    let listing = render(&cmd, groups);
    let template = template(&cmd, path);
    cmd.help_template(template).after_help(listing)
}

/// Whether `<command>` takes `--json`.
///
/// Read back out of the clap model rather than kept as a list here, so it stays
/// true by construction as commands gain or lose the flag. The GUI asks before
/// appending `--json` to a command line it is about to run: since the flag is no
/// longer global, appending it to a command that does not take one is a parse
/// error rather than something harmlessly ignored.
pub(crate) fn supports_json(command: &str) -> bool {
    Cli::command()
        .find_subcommand(command)
        .is_some_and(|sub| sub.get_arguments().any(|a| a.get_id() == "json"))
}

/// Render one page's grouped listing, pulling each description from `cmd`
/// itself.
fn render(cmd: &Command, groups: Groups) -> String {
    // One name column across every group, so the descriptions line up down the
    // whole page rather than per-group.
    let width = groups
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|n| n.len())
        .max()
        .unwrap_or(0);

    let mut blocks = Vec::new();
    for (title, names) in groups {
        let mut block = String::from(*title);
        for name in *names {
            let sub = cmd
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("`{name}` is grouped but is not a subcommand"));
            let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
            block.push_str(&format!("\n  {name:width$}  {about}"));
            // Clap's own wording, so the two halves of the page agree.
            let aliases: Vec<&str> = sub.get_visible_aliases().collect();
            match aliases.len() {
                0 => {}
                1 => block.push_str(&format!(" [alias: {}]", aliases[0])),
                _ => block.push_str(&format!(" [aliases: {}]", aliases.join(", "))),
            }
        }
        blocks.push(block);
    }
    blocks.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Clap's generated `help` subcommand, pointed at in the footer rather than
    /// grouped, so the grouping table never has to mention it.
    const GENERATED: &str = "help";

    /// The widest a listing line may be. A reader scans the name column, and a
    /// wrapped line breaks that column, so nothing may reach the width a
    /// terminal is narrowest at.
    const LIMIT: usize = 80;

    /// Resolve a page's path against the clap model.
    fn page<'a>(cmd: &'a Command, path: &[&str]) -> &'a Command {
        path.iter().fold(cmd, |parent, name| {
            parent
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("`ray {}` is a grouped page but not a command", path.join(" ")))
        })
    }

    /// How wide the trailing `[alias: …]` note renders, in `render`'s wording.
    fn alias_width(sub: &Command) -> usize {
        let aliases: Vec<&str> = sub.get_visible_aliases().collect();
        match aliases.len() {
            0 => 0,
            1 => " [alias: ]".len() + aliases[0].len(),
            n => " [aliases: ]".len() + aliases.iter().map(|a| a.len()).sum::<usize>() + 2 * (n - 1),
        }
    }

    /// The listing is only as good as its coverage: a command missing from its
    /// page's groups would vanish from `-h` entirely, since the template no
    /// longer renders clap's own list as a backstop.
    #[test]
    fn every_command_is_grouped() {
        let cmd = Cli::command();
        for (path, groups) in PAGES {
            let grouped: HashSet<&str> = groups
                .iter()
                .flat_map(|(_, names)| names.iter().copied())
                .collect();

            let missing: Vec<&str> = page(&cmd, path)
                .get_subcommands()
                .filter(|s| !s.is_hide_set() && s.get_name() != GENERATED)
                .map(|s| s.get_name())
                .filter(|n| !grouped.contains(n))
                .collect();
            assert!(
                missing.is_empty(),
                "not listed in any `ray {} -h` group: {missing:?}",
                path.join(" ")
            );
        }
    }

    /// The other direction: a renamed or deleted command must not leave an entry
    /// behind, which would panic in `render` at runtime.
    #[test]
    fn every_grouped_name_is_a_command() {
        let cmd = Cli::command();
        for (path, groups) in PAGES {
            let target = page(&cmd, path);
            let dangling: Vec<&str> = groups
                .iter()
                .flat_map(|(_, names)| names.iter().copied())
                .filter(|n| target.find_subcommand(n).is_none())
                .collect();
            assert!(
                dangling.is_empty(),
                "grouped under `ray {}` but not a subcommand of it: {dangling:?}",
                path.join(" ")
            );
        }
    }

    /// A command in two groups would be listed twice.
    #[test]
    fn no_command_is_grouped_twice() {
        for (path, groups) in PAGES {
            let mut seen = HashSet::new();
            let dupes: Vec<&str> = groups
                .iter()
                .flat_map(|(_, names)| names.iter().copied())
                .filter(|n| !seen.insert(*n))
                .collect();
            assert!(
                dupes.is_empty(),
                "listed under more than one `ray {}` group: {dupes:?}",
                path.join(" ")
            );
        }
    }

    /// A page that is not grouped still has to be scannable, and clap's own
    /// listing pads to the widest name just as `render` does. So the constraint
    /// is the same one at every depth: a subcommand's `about` has to fit beside
    /// its name inside 80 columns, and the rest belongs in the paragraph below
    /// it, where `ray help <command>` serves it as the long description.
    ///
    /// Asserted against the clap model rather than the rendered page because
    /// `about` is the thing this file controls. clap's `Arguments:` and
    /// `Options:` blocks have long lines of their own, which `wrap_help` handles
    /// at display time.
    #[test]
    fn every_about_fits_the_listing() {
        let cmd = {
            let mut c = command();
            c.build();
            c
        };

        let mut long = Vec::new();
        let mut stack = vec![(String::from("ray"), &cmd)];
        while let Some((path, parent)) = stack.pop() {
            let visible: Vec<&Command> =
                parent.get_subcommands().filter(|s| !s.is_hide_set()).collect();
            let width = visible
                .iter()
                .map(|s| s.get_name().len())
                .max()
                .unwrap_or(0);
            for sub in visible {
                let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
                // `  {name:width$}  {about}`, plus any alias note.
                let line = 2 + width + 2 + about.chars().count() + alias_width(sub);
                if line > LIMIT {
                    long.push(format!("{line} cols: `{path} {}`", sub.get_name()));
                }
                stack.push((format!("{path} {}", sub.get_name()), sub));
            }
        }
        assert!(
            long.is_empty(),
            "these `about` lines do not fit {LIMIT} columns beside their name; \
             move the detail below a blank line in the doc comment: {long:#?}"
        );
    }

    /// Grouping buys scannability, not brevity: the listing is *longer* than the
    /// flat one it replaced. That only pays off if a reader can run their eye
    /// down the name column, which a wrapped line breaks. Every line of a
    /// grouped page therefore has to fit the 80 columns a terminal is narrowest
    /// at, headings, options and footer included.
    ///
    /// The width is pinned because `wrap_help` otherwise makes this assertion
    /// depend on where it runs: clap reads the terminal at build time, so under
    /// `--nocapture` in a narrow terminal it pre-wraps the page and every line
    /// fits by construction. `term_width` propagates to subcommands through
    /// `build()`.
    #[test]
    fn no_help_line_wraps_at_eighty_columns() {
        for (path, _) in PAGES {
            let mut cmd = command().term_width(100);
            cmd.build();
            let mut target = page(&cmd, path).clone();
            let help = target.render_help().to_string();
            let long: Vec<(usize, &str)> = help
                .lines()
                .map(|l| (l.chars().count(), l))
                .filter(|(n, _)| *n > LIMIT)
                .collect();
            assert!(
                long.is_empty(),
                "these `ray {} -h` lines wrap at {LIMIT} columns: {long:#?}",
                path.join(" ")
            );
        }
    }

    /// `--json` has to be `global` *within* the command that declares it. Half
    /// these commands dispatch to an action subcommand, and the documented
    /// spelling puts the flag last (`ray firewall show --json`), which a
    /// non-global flag rejects: it would only parse before the action, as
    /// `ray firewall --json show`. Being global here does not put the flag back
    /// on the root, which is the whole point of moving it off `Cli`.
    #[test]
    fn every_json_flag_is_global_within_its_command() {
        let cmd = Cli::command();
        let local: Vec<&str> = cmd
            .get_subcommands()
            .filter(|s| {
                s.get_arguments()
                    .any(|a| a.get_id() == "json" && !a.is_global_set())
            })
            .map(|s| s.get_name())
            .collect();
        assert!(
            local.is_empty(),
            "`--json` must be global within these commands, or it will not parse \
             after their action subcommand: {local:?}"
        );
    }

    /// The spellings the e2e suite and the README actually use.
    #[test]
    fn json_parses_after_a_nested_action() {
        for line in [
            ["ray", "firewall", "show", "--json"],
            ["ray", "pair", "list", "--json"],
            ["ray", "exit-node", "status", "--json"],
        ] {
            assert!(
                command().try_get_matches_from(line).is_ok(),
                "`{}` should parse",
                line.join(" ")
            );
        }
    }

    /// A command that moved under the thing it acts on keeps its old spelling as
    /// a hidden command, so no script, README line or shell history breaks. The
    /// point of hiding it is that it leaves the listing and tab completion, not
    /// that it stops working.
    #[test]
    fn the_old_spellings_still_parse() {
        for line in [
            vec!["ray", "accept", "net", "abc123"],
            vec!["ray", "deny", "net", "abc123"],
            vec!["ray", "connections"],
            vec!["ray", "connections", "approve", "abc123"],
            vec!["ray", "auto-update", "on"],
            vec!["ray", "open", "rayfish://join/abc"],
        ] {
            assert!(
                command().try_get_matches_from(line.clone()).is_ok(),
                "`{}` must keep parsing",
                line.join(" ")
            );
        }
    }

    /// The spellings those old ones moved to.
    #[test]
    fn the_new_spellings_parse() {
        for line in [
            vec!["ray", "requests", "net"],
            vec!["ray", "requests", "net", "accept", "abc123"],
            vec!["ray", "requests", "net", "deny", "abc123"],
            vec!["ray", "connect"],
            vec!["ray", "connect", "somecontactid"],
            vec!["ray", "connect", "approve", "abc123"],
            vec!["ray", "connect", "accept", "abc123"],
            vec!["ray", "config", "set", "auto-update", "on"],
        ] {
            assert!(
                command().try_get_matches_from(line.clone()).is_ok(),
                "`{}` should parse",
                line.join(" ")
            );
        }
    }

    /// A command that prints "run this next" has to name a spelling the reader
    /// can then find. Three of them kept pointing at commands this file had just
    /// hidden (`ray connect` told you to run `ray connections approve`), which
    /// is the one way hiding a spelling can still break someone: not by failing
    /// to parse, but by being advertised and then absent from `-h` and from tab
    /// completion.
    ///
    /// Reads the handler sources rather than the clap model because the strings
    /// are `format!` templates, not data. Comment lines are skipped: the hidden
    /// variants are *documented* by their old spelling on purpose.
    #[test]
    fn no_handler_advertises_a_hidden_spelling() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli");
        let hidden = ["accept", "deny", "connections", "auto-update", "open"];

        let mut bad = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("src/cli should be readable") {
            let path = entry.expect("readable dir entry").path();
            if !matches!(path.extension().and_then(|e| e.to_str()), Some("rs")) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable source");
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for name in hidden {
                    if line.contains(&format!("ray {name}")) {
                        bad.push(format!(
                            "{}:{}: names hidden `ray {name}`",
                            path.file_name().unwrap().to_string_lossy(),
                            n + 1
                        ));
                    }
                }
            }
        }
        assert!(
            bad.is_empty(),
            "these print a spelling that is hidden from `-h` and completion; \
             point them at the command that replaced it: {bad:#?}"
        );
    }

    /// Hiding a command takes it out of the listing *and* out of the generated
    /// completion scripts, which is the whole reason `hide` is reached for here
    /// rather than left off. The inverse of the note in this module's header:
    /// commands that should still be completed must stay visible.
    #[test]
    fn the_old_spellings_are_hidden() {
        let cmd = Cli::command();
        for name in ["accept", "deny", "connections", "auto-update", "open"] {
            let sub = cmd
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("`{name}` should still exist, just hidden"));
            assert!(sub.is_hide_set(), "`ray {name}` should be hidden");
        }
    }

    /// The deliberate break: `--json` is gone from the root, so it no longer
    /// leads the line and no longer sits silently on commands that render none.
    #[test]
    fn json_is_rejected_where_it_does_nothing() {
        for line in [
            vec!["ray", "--json", "status"],
            vec!["ray", "version", "--json"],
            vec!["ray", "up", "--json"],
        ] {
            assert!(
                command().try_get_matches_from(line.clone()).is_err(),
                "`{}` should not parse",
                line.join(" ")
            );
        }
    }
}
