// ported from neboto-tui src/commands.rs @ 3704675 (a1c69eb, 66458f6; rows rewritten for nebaz's keys and gates)
//! The command table: every key the `?` help lists, in one place.
//!
//! The help overlay draws its sections from [`COMMANDS`], and the status
//! bar's conditional hints (`N access`, `m metrics`, `U refs`…) come from
//! the same rows' [`Gate`]s. A gate is the `App::supports_*` check that
//! says the key works on the current selection, so one row carries both
//! the help line and the hint, and the help's "Here" section is just the
//! rows whose gate passes.
//!
//! A new `supports_*` gate goes here, on its command's row; the
//! `every_supports_gate_is_in_the_table` test fails until it does.
//!
//! The `:` key picker lists the rows it can run: a gated row runs its hint
//! key, any other row only with an explicit [`Command::runs`]. Running a
//! row replays its key, so the picker can't do anything the keyboard can't.
//! Rows that aren't one key (`j / k`, `Tab · 1–9`, mouse gestures) stay
//! help-only. It is not the `C` picker, which copies `az` commands.
//!
//! Labels are one line each, short labels, never sentences: help has no
//! word wrap and truncates with `…`.

use crate::app::App;

/// Where a command is listed in the help, in column order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    ListPane,
    DetailPane,
    Actions,
    Search,
    Context,
    Mouse,
    Audit,
}

impl Section {
    pub const LEFT: &'static [Section] = &[Section::ListPane, Section::DetailPane];
    pub const RIGHT: &'static [Section] =
        &[Section::Actions, Section::Search, Section::Context, Section::Mouse, Section::Audit];

    pub fn title(self) -> &'static str {
        match self {
            Section::ListPane => "List pane",
            Section::DetailPane => "Detail pane",
            Section::Actions => "Actions",
            Section::Search => "Search",
            Section::Context => "Context",
            Section::Mouse => "Mouse",
            Section::Audit => "@audit",
        }
    }
}

/// When a command only works on some selections: the check, and the
/// status-bar hint shown while it passes.
pub struct Gate {
    pub check: fn(&App) -> bool,
    /// `(key, label)` as the status bar prints it.
    pub hint: (&'static str, &'static str),
    /// Also hinted while the detail pane is focused. That bar is kept short
    /// (the pane's own footer carries the rest), so most hints are
    /// list-pane only.
    pub in_detail: bool,
}

/// The key the `:` picker presses for a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    Key(char),
    Ctrl(char),
}

impl Run {
    pub fn key_event(self) -> crossterm::event::KeyEvent {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        match self {
            // Terminals report an uppercase letter with SHIFT.
            Run::Key(c) if c.is_ascii_uppercase() => KeyEvent::new(KeyCode::Char(c), KeyModifiers::SHIFT),
            Run::Key(c) => KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            Run::Ctrl(c) => KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL),
        }
    }
}

pub struct Command {
    pub section: Section,
    pub key: &'static str,
    pub label: &'static str,
    pub gate: Option<Gate>,
    run: Option<Run>,
}

impl Command {
    /// Make a row runnable from the `:` picker.
    const fn runs(mut self, run: Run) -> Self {
        self.run = Some(run);
        self
    }

    /// The key the picker presses: the explicit one, else a gated row's
    /// hint key when it is one character.
    pub fn run(&self) -> Option<Run> {
        self.run.or_else(|| {
            let mut chars = self.gate.as_ref()?.hint.0.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Some(Run::Key(c)),
                _ => None,
            }
        })
    }

    /// Whether the picker offers this row now: it runs a key, the key means
    /// this in the focused pane, and its gate (if any) passes.
    pub fn runnable_in(&self, app: &App) -> bool {
        self.run().is_some()
            && match self.section {
                Section::ListPane => !app.details_focused,
                Section::DetailPane => app.details_focused,
                _ => true,
            }
            && self.gate.as_ref().is_none_or(|g| (g.check)(app))
    }
}

const fn cmd(section: Section, key: &'static str, label: &'static str) -> Command {
    Command { section, key, label, gate: None, run: None }
}

const fn gated(
    section: Section,
    key: &'static str,
    label: &'static str,
    check: fn(&App) -> bool,
    hint: (&'static str, &'static str),
    in_detail: bool,
) -> Command {
    Command { section, key, label, gate: Some(Gate { check, hint, in_detail }), run: None }
}

use Run::{Ctrl, Key};
use Section::*;

pub static COMMANDS: &[Command] = &[
    cmd(ListPane, "j / k ↑ / ↓", "move"),
    cmd(ListPane, "gg / G", "top / bottom"),
    cmd(ListPane, "^d / ^u", "half page"),
    cmd(ListPane, "l / → / ⏎", "open details"),
    cmd(ListPane, "h / ←", "back to the list"),
    cmd(ListPane, "⌫ / Ctrl-O", "history back").runs(Ctrl('o')),
    cmd(ListPane, "Ctrl-F", "history forward").runs(Ctrl('f')),
    cmd(ListPane, "`", "jump list (history)").runs(Key('`')),
    cmd(ListPane, "B", "bookmark this").runs(Key('B')),
    cmd(ListPane, "'", "bookmarks").runs(Key('\'')),
    cmd(ListPane, "Tab · 1–9", "sub-tabs"),
    cmd(ListPane, "H / L", "prev / next sub-tab"),
    cmd(ListPane, "y · X · ^X", "copy · export"),
    cmd(ListPane, "V · J / K · ^A", "select rows · extend · all"),
    cmd(ListPane, "  y·c / X / ^X", "md table / deep / list export"),
    cmd(ListPane, "a", "hide noisy rows").runs(Key('a')),
    gated(ListPane, "[ / ]", "@changes window", App::supports_changes_window, ("[/]", "window"), false),
    cmd(ListPane, "z", "cycle sort").runs(Key('z')),
    cmd(ListPane, "F", "cycle state filter").runs(Key('F')),
    cmd(ListPane, "r / F5", "refresh service").runs(Key('r')),
    cmd(DetailPane, "Tab · 1–9", "sections (flat: headers)"),
    cmd(DetailPane, "j / k · g / G", "line · top / bottom"),
    cmd(DetailPane, "V · J / K · ^A", "select · extend · all"),
    cmd(DetailPane, "\\", "flat view (all sections)").runs(Key('\\')),
    cmd(DetailPane, "/ · n / N", "filter · step matches (else N lens)"),
    cmd(DetailPane, "[[ / ]]", "prev / next group header"),
    cmd(DetailPane, "^W", "wrap long values").runs(Ctrl('w')),
    cmd(DetailPane, "H / L", "sub-tab (opens its first row)"),
    cmd(DetailPane, "⏎", "jump to the ARM id on the line"),
    cmd(DetailPane, "y", "copy line or selection"),
    cmd(DetailPane, "^L", "repaint the screen").runs(Ctrl('l')),
    cmd(DetailPane, "Z", "full-width pane").runs(Key('Z')),
    cmd(DetailPane, "r", "refresh this resource").runs(Key('r')),
    cmd(Actions, "O", "open in Azure portal").runs(Key('O')),
    cmd(Actions, "y", "copy resource id").runs(Key('y')),
    cmd(Actions, "e", "open in $EDITOR").runs(Key('e')),
    gated(Actions, "N", "network access (NSG rules)", App::supports_network_lens, ("N", "access"), false),
    gated(Actions, "i", "about this service (info card)", App::supports_info_card, ("i", "about"), false),
    gated(Actions, "m", "metrics (Azure Monitor)", App::supports_metrics, ("m", "metrics"), true),
    gated(
        Actions,
        "U",
        "referenced by (warm lists; L loads likely)",
        App::supports_refs_lens,
        ("U", "refs"),
        false,
    ),
    gated(Actions, "W", "change timeline (f · [ / ])", App::supports_timeline, ("W", "changes"), false),
    cmd(Actions, "m: c · W · w", "chart: changes · timeline · WAF"),
    gated(Actions, "C", "copy an az command (never run)", App::supports_cli_commands, ("C", "copy cmd"), false),
    cmd(Actions, "X", "export detail").runs(Key('X')),
    cmd(Actions, "^X", "export list").runs(Ctrl('x')),
    cmd(Actions, "M", "message history").runs(Key('M')),
    cmd(Actions, ",", "macros (⏎ run · n record)").runs(Key(',')),
    cmd(Actions, "b", "toggle banner").runs(Key('b')),
    cmd(Actions, ":", "command picker (run a key by name)"),
    cmd(Actions, "?", "help (type to filter)").runs(Key('?')),
    cmd(Actions, "q", "quit").runs(Key('q')),
    cmd(Search, "/", "fuzzy search").runs(Key('/')),
    cmd(Search, "@svc text", "switch service + search"),
    cmd(Search, "@rg @disk @nsg …", "switch to a sub-tab"),
    cmd(Search, "rg:name", "resource group filter"),
    cmd(Search, "tag:k=v", "exact tag filter"),
    cmd(Search, "@* …", "search every cached list"),
    cmd(Search, "Tab", "complete @prefix"),
    cmd(Search, "↑ / ↓", "earlier searches"),
    cmd(Search, "← → Home End", "edit the query (shell keys work too)"),
    cmd(Context, "S", "service").runs(Key('S')),
    cmd(Context, "R", "location").runs(Key('R')),
    cmd(Context, "P", "subscription").runs(Key('P')),
    cmd(Context, "@vm …", "switch via prefix"),
    cmd(Mouse, "click", "row · line · chip · hint"),
    cmd(Mouse, "double-click", "⏎ (open · jump)"),
    cmd(Mouse, "right-click", "⌫ back · close a popup"),
    cmd(Mouse, "drag", "select rows / lines"),
    cmd(Mouse, "wheel", "scroll the pane under it"),
    cmd(Mouse, "Shift-drag", "terminal text selection"),
    cmd(Audit, "⏎", "open the finding's resource"),
    cmd(Audit, "l / →", "evidence + remediation (text)"),
    cmd(Audit, "r", "load missing sources, re-audit"),
    cmd(Audit, "F · z", "filter · sort by severity"),
];

/// The rows listed under `section`, in table order.
pub fn in_section(section: Section) -> impl Iterator<Item = &'static Command> {
    COMMANDS.iter().filter(move |c| c.section == section)
}

/// The gated commands that work on the current selection, in table order:
/// the help's "Here" section.
pub fn available(app: &App) -> impl Iterator<Item = &'static Command> + '_ {
    COMMANDS.iter().filter(|c| c.gate.as_ref().is_some_and(|g| (g.check)(app)))
}

/// What the `:` picker lists for `query`: with no query, the rows that work
/// on the selection ("Here") first, then the rest in table order; with one,
/// best match first over key, label and section title (an exact key match
/// wins, so `:m` puts metrics on top).
pub fn picker_rows(app: &App, query: &str) -> Vec<&'static Command> {
    let rows: Vec<&'static Command> = COMMANDS.iter().filter(|c| c.runnable_in(app)).collect();
    if query.trim().is_empty() {
        let (here, rest): (Vec<_>, Vec<_>) = rows.into_iter().partition(|c| c.gate.is_some());
        return here.into_iter().chain(rest).collect();
    }
    crate::search::fuzzy::FuzzyMatcher::new()
        .filter_fields(query, &rows, |c| vec![c.key, c.label, c.section.title()])
        .into_iter()
        .map(|(i, _)| rows[i])
        .collect()
}

/// The status bar's conditional hints for the focused pane.
pub fn status_hints(app: &App, detail: bool) -> Vec<(&'static str, &'static str)> {
    available(app)
        .filter_map(|c| c.gate.as_ref())
        .filter(|g| !detail || g.in_detail)
        .map(|g| g.hint)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_is_in_a_column_and_has_rows() {
        for s in Section::LEFT.iter().chain(Section::RIGHT) {
            assert!(in_section(*s).next().is_some(), "{} is empty", s.title());
        }
        for c in COMMANDS {
            assert!(
                Section::LEFT.contains(&c.section) || Section::RIGHT.contains(&c.section),
                "{} is in no column",
                c.key
            );
        }
    }

    fn squash(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn a_hint_names_its_rows_key() {
        // A hint key is one of the row's keys (`[ / ]` hints as `[/]`).
        for c in COMMANDS {
            if let Some(g) = &c.gate {
                assert!(
                    c.key.split(" / ").any(|k| k == g.hint.0) || squash(c.key) == squash(g.hint.0),
                    "row {:?} hints {:?}",
                    c.key,
                    g.hint.0
                );
                assert!(!g.hint.1.is_empty(), "row {:?} has an empty hint label", c.key);
            }
        }
    }

    #[test]
    fn a_gated_row_runs_its_hint_key() {
        let m = COMMANDS.iter().find(|c| c.key == "m").unwrap();
        assert_eq!(m.run(), Some(Run::Key('m')));
        let window = COMMANDS.iter().find(|c| c.key == "[ / ]").unwrap();
        assert_eq!(window.run(), None, "`[/]` is not one key");
        let moves = COMMANDS.iter().find(|c| c.key == "j / k ↑ / ↓").unwrap();
        assert_eq!(moves.run(), None, "not one key: help only");
    }

    #[test]
    fn an_explicit_run_is_one_of_the_rows_keys() {
        // `⌫ / Ctrl-O` runs Ctrl-O; `r / F5` runs r; `^X` runs Ctrl-X.
        for c in COMMANDS.iter().filter(|c| c.run.is_some()) {
            let shown = match c.run.unwrap() {
                Run::Key(k) => k.to_string(),
                Run::Ctrl(k) => format!("Ctrl-{}", k.to_ascii_uppercase()),
            };
            let alt = shown.replace("Ctrl-", "^");
            let alt_lower = alt.to_ascii_lowercase();
            assert!(
                c.key.split([' ', '/']).any(|k| k == shown || k == alt || k == alt_lower)
                    || c.key.starts_with(&shown),
                "row {:?} runs {shown:?}",
                c.key
            );
        }
    }

    #[test]
    fn a_runnable_row_is_unique_per_pane_and_key() {
        // Two rows pressing the same key in the same pane would list twice.
        let mut seen = std::collections::HashSet::new();
        for c in COMMANDS {
            if let Some(run) = c.run() {
                let pane = match c.section {
                    ListPane => 1,
                    DetailPane => 2,
                    _ => 0,
                };
                assert!(seen.insert((pane, format!("{run:?}"))), "{:?} is listed twice", c.key);
            }
        }
    }

    /// The drift guard: a `supports_*` gate on `App` that isn't on a row
    /// here would be a working key with no help line and no hint.
    #[test]
    fn every_supports_gate_is_in_the_table() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![root.join("app.rs")];
        for e in std::fs::read_dir(root.join("app")).unwrap() {
            files.push(e.unwrap().path());
        }
        let mut gates: Vec<String> = Vec::new();
        for f in files.iter().filter(|f| f.extension().is_some_and(|e| e == "rs")) {
            let text = std::fs::read_to_string(f).unwrap();
            gates.extend(text.lines().filter_map(|l| {
                let rest = l.trim().strip_prefix("pub fn supports_")?;
                Some(rest.split('(').next()?.to_string())
            }));
        }
        assert!(gates.len() >= 5, "found {gates:?}");
        let table = include_str!("commands.rs");
        for g in gates {
            assert!(
                table.contains(&format!("App::supports_{g},")),
                "App::supports_{g} has no row in COMMANDS"
            );
        }
    }

    /// The pairing is structural (one row carries the help line and the
    /// hint); this holds the status bar to it: it draws no gate by hand.
    #[test]
    fn the_status_bar_draws_no_gate_by_hand() {
        let main = include_str!("main.rs");
        assert!(!main.contains("app.supports_"), "a status-bar hint bypasses the table");
    }
}
