//! Inline interactive picker for reviewing suggested firewall rules.
//!
//! Drawn with `crossterm` in raw mode but **without** the alternate screen, so
//! the table renders in place and (once resolved) the daemon's result line stays
//! in scrollback. Only used when stdout is a TTY; non-TTY / `--json` callers use
//! the static fallback in `main`.

use std::io::{Write, stderr};

use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    queue,
    style::Print,
    terminal,
};
use ray_proto::ipc::FirewallRuleView;

use super::{layout, style};

#[derive(Clone, Copy, PartialEq)]
enum Decision {
    Undecided,
    Accept,
    Deny,
}

/// The user's per-rule decisions, split into accept/deny view lists.
pub struct Resolution {
    pub accept: Vec<FirewallRuleView>,
    pub deny: Vec<FirewallRuleView>,
}

impl Resolution {
    fn is_empty(&self) -> bool {
        self.accept.is_empty() && self.deny.is_empty()
    }
}

/// Run the picker over `rules`. Returns `None` if the user aborted (Ctrl-C): no
/// changes should be sent. Returns an empty resolution if the user quit without
/// deciding anything.
pub fn run(network: &str, rules: &[FirewallRuleView]) -> Result<Option<Resolution>> {
    let mut decisions = vec![Decision::Undecided; rules.len()];
    let mut idx = 0usize;
    let mut out = stderr();

    terminal::enable_raw_mode()?;
    let mut prev_lines = 0usize;
    let outcome = (|| -> Result<Option<()>> {
        loop {
            let frame = render(network, rules, &decisions, idx);
            if prev_lines > 0 {
                queue!(
                    out,
                    cursor::MoveToColumn(0),
                    cursor::MoveUp(prev_lines as u16)
                )?;
            }
            queue!(
                out,
                terminal::Clear(terminal::ClearType::FromCursorDown),
                Print(&frame)
            )?;
            out.flush()?;
            prev_lines = frame.matches('\n').count();

            if let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                let last = rules.len().saturating_sub(1);
                match (k.code, k.modifiers) {
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(None),
                    (KeyCode::Up, _) | (KeyCode::Char('k'), _) => idx = idx.saturating_sub(1),
                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => idx = (idx + 1).min(last),
                    (KeyCode::Enter, _) => {
                        decisions[idx] = Decision::Accept;
                        idx = (idx + 1).min(last);
                    }
                    (KeyCode::Char('d'), _) => {
                        decisions[idx] = Decision::Deny;
                        idx = (idx + 1).min(last);
                    }
                    (KeyCode::Char('a'), _) => {
                        decisions.iter_mut().for_each(|d| *d = Decision::Accept)
                    }
                    (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => break,
                    _ => {}
                }
            }
        }
        Ok(Some(()))
    })();

    // Erase the interactive frame so the caller's result line prints on a clean
    // slate, then restore the terminal regardless of how we exited.
    if prev_lines > 0 {
        let _ = queue!(
            out,
            cursor::MoveToColumn(0),
            cursor::MoveUp(prev_lines as u16)
        );
    }
    let _ = queue!(out, terminal::Clear(terminal::ClearType::FromCursorDown));
    let _ = out.flush();
    terminal::disable_raw_mode()?;

    match outcome? {
        None => Ok(None),
        Some(()) => {
            let mut res = Resolution {
                accept: Vec::new(),
                deny: Vec::new(),
            };
            for (rule, d) in rules.iter().zip(&decisions) {
                match d {
                    Decision::Accept => res.accept.push(rule.clone()),
                    Decision::Deny => res.deny.push(rule.clone()),
                    Decision::Undecided => {}
                }
            }
            // An all-undecided quit is a no-op, but still a valid (empty) result.
            let _ = res.is_empty();
            Ok(Some(res))
        }
    }
}

fn render(
    network: &str,
    rules: &[FirewallRuleView],
    decisions: &[Decision],
    cursor: usize,
) -> String {
    let n_accept = decisions.iter().filter(|d| **d == Decision::Accept).count();
    let n_deny = decisions.iter().filter(|d| **d == Decision::Deny).count();

    let mut rows: Vec<Vec<layout::Cell>> = Vec::with_capacity(rules.len());
    for (i, r) in rules.iter().enumerate() {
        let pointer = if i == cursor { "›" } else { " " };
        let (mark_plain, mark_styled) = match decisions[i] {
            Decision::Accept => ("✓", style::check()),
            Decision::Deny => ("✗", style::cross()),
            Decision::Undecided => (" ", " ".to_string()),
        };
        let port = if r.port == "*" { "*" } else { &r.port };
        let sugg = r
            .suggested_by
            .as_ref()
            .map(|s| format!("·{s}·"))
            .unwrap_or_default();
        rows.push(vec![
            layout::Cell::new(pointer, style::rose(pointer)),
            layout::Cell::new(mark_plain, mark_styled),
            layout::Cell::new(
                r.direction.to_string(),
                style::faint(&r.direction.to_string()),
            ),
            layout::Cell::new(r.action.to_string(), action_styled(&r.action.to_string())),
            layout::Cell::new(
                r.protocol.to_string(),
                style::value(&r.protocol.to_string()),
            ),
            layout::Cell::right(port, style::value(port)),
            layout::Cell::new(r.peer.clone(), style::value(&r.peer)),
            layout::Cell::new(r.network.clone(), style::faint(&r.network)),
            layout::Cell::new(sugg.clone(), style::faint(&sugg)),
        ]);
    }

    let header = format!(
        "  {} {}    {}",
        style::bold(network),
        style::faint(&format!("suggests {} rules", rules.len())),
        style::faint("↑↓ move · enter accept · d deny · a all · q done"),
    );
    let table = layout::columns(&rows, 2);
    let table = table
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\r\n");
    let footer = format!(
        "  {} accepted · {} denied",
        style::green(&n_accept.to_string()),
        style::red(&n_deny.to_string()),
    );
    // Trailing newline so cursor-line math (counting '\n') is stable.
    format!("{header}\r\n\r\n{table}\r\n\r\n{footer}\r\n")
}

fn action_styled(action: &str) -> String {
    if action == "deny" {
        style::red(action)
    } else {
        style::green(action)
    }
}
