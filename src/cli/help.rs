//! Grouped `ray -h` output.
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
//! quietly gut tab completion.

use clap::{Command, CommandFactory};

use crate::Cli;

/// The group each subcommand is listed under, in display order.
///
/// Every visible subcommand must appear exactly once. `tests::every_command_is_grouped`
/// fails otherwise, so a newly added command cannot silently go missing from
/// `-h`, and a renamed or deleted one cannot leave a dangling entry here.
const GROUPS: &[(&str, &[&str])] = &[
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
        &[
            "invite",
            "requests",
            "accept",
            "deny",
            "kick",
            "admin",
            "alias",
            "identityof",
        ],
    ),
    (
        "Devices & links",
        &["connect", "connections", "contact", "pair", "unpair"],
    ),
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
        &[
            "config",
            "auto-update",
            "update",
            "completions",
            "gui",
            "version",
            "open",
        ],
    ),
];

/// `{subcommands}` is deliberately absent: the grouped listing takes its place
/// through `{after-help}`, which is why that placeholder sits above `{options}`
/// rather than in its usual spot at the foot of the page. `Options:` is spelled
/// out because `{options}` renders the option lines without their heading.
/// `{after-help}` brings its own blank line, so it sits flush against the usage
/// line here rather than being separated by one.
const TEMPLATE: &str = "\
{about-with-newline}
{usage-heading} {usage}{after-help}

Options:
{options}

Run `ray help <command>` for the full description of one command.";

/// The CLI, with the grouped command listing in place of clap's flat one.
pub(crate) fn command() -> Command {
    let cmd = Cli::command();
    let listing = render(&cmd);
    cmd.help_template(TEMPLATE).after_help(listing)
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

/// Render the grouped listing, pulling each description from `cmd` itself.
fn render(cmd: &Command) -> String {
    // One name column across every group, so the descriptions line up down the
    // whole page rather than per-group.
    let width = GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|n| n.len())
        .max()
        .unwrap_or(0);

    let mut groups = Vec::new();
    for (title, names) in GROUPS {
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
        groups.push(block);
    }
    groups.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Clap's generated `help` subcommand, pointed at in the footer rather than
    /// grouped, so the grouping table never has to mention it.
    const GENERATED: &str = "help";

    /// The listing is only as good as its coverage: a command missing from
    /// `GROUPS` would vanish from `-h` entirely, since the template no longer
    /// renders clap's own list as a backstop.
    #[test]
    fn every_command_is_grouped() {
        let cmd = Cli::command();
        let grouped: HashSet<&str> = GROUPS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();

        let missing: Vec<&str> = cmd
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != GENERATED)
            .map(|s| s.get_name())
            .filter(|n| !grouped.contains(n))
            .collect();
        assert!(
            missing.is_empty(),
            "not listed in any `-h` group: {missing:?}"
        );
    }

    /// The other direction: a renamed or deleted command must not leave an entry
    /// behind, which would panic in `render` at runtime.
    #[test]
    fn every_grouped_name_is_a_command() {
        let cmd = Cli::command();
        let dangling: Vec<&str> = GROUPS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .filter(|n| cmd.find_subcommand(n).is_none())
            .collect();
        assert!(
            dangling.is_empty(),
            "grouped but not a subcommand: {dangling:?}"
        );
    }

    /// A command in two groups would be listed twice.
    #[test]
    fn no_command_is_grouped_twice() {
        let mut seen = HashSet::new();
        let dupes: Vec<&str> = GROUPS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .filter(|n| !seen.insert(*n))
            .collect();
        assert!(
            dupes.is_empty(),
            "listed under more than one group: {dupes:?}"
        );
    }

    /// Grouping buys scannability, not brevity: the listing is *longer* than the
    /// flat one it replaced. That only pays off if a reader can run their eye
    /// down the name column, which a wrapped line breaks. Every line therefore
    /// has to fit the 80 columns a terminal is narrowest at, which caps how much
    /// a one-line `about` can say; the rest belongs under `ray help <command>`.
    #[test]
    fn no_help_line_wraps_at_eighty_columns() {
        let mut cmd = command();
        let help = cmd.render_help().to_string();
        let long: Vec<(usize, &str)> = help
            .lines()
            .map(|l| (l.chars().count(), l))
            .filter(|(n, _)| *n > 80)
            .collect();
        assert!(
            long.is_empty(),
            "these `ray -h` lines wrap at 80 columns: {long:#?}"
        );
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
