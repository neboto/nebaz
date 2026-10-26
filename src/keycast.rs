// ported from neboto-tui src/keycast.rs @ b92e140 (the View diff, the fold
// and expiry; the overlay names and the fallback table are nebaz's keys)
//! Keycast (`--show-keys`, config `show_keys`): a small box in the corner
//! naming each key as it's pressed and what it did — `W  change timeline`,
//! `2  Related`, `⏎  follow link`. For screen recordings, screen shares and
//! demos, where the viewer can see the screen change but not the key.
//!
//! The label comes from what the key visibly *did*, not a keymap table:
//! `App::handle_key` snapshots a [`View`] before a key is dispatched and
//! `App::keycast_tick` snapshots again after (the same two-step the macro
//! recorder uses), and [`classify`] names the difference — a lens opened,
//! the service switched, the section changed. Only when nothing it can see
//! changed does a small fallback table label the key.
//!
//! The mouse shows too: every gesture replays a key through `handle_key`
//! (`src/app/mouse.rs`), so a click on a row's chip is cast as the key it
//! pressed. A gesture that replays two keys (select, then `⏎`) settles the
//! first against the view the second starts from, so both show.
//!
//! Typing is never echoed. While the search box, the detail filter, a
//! picker or the macro name prompt has the keyboard, only the keys that
//! finish the input (`⏎`, `Esc`) show, so a query never turns up in a
//! recording twice.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long an entry stays on screen.
pub const SHOW_FOR: Duration = Duration::from_millis(2500);
/// A repeat of the same key within this window folds into `j ×3`.
const FOLD_WITHIN: Duration = Duration::from_millis(1200);
/// Most entries on screen at once.
const MAX_ENTRIES: usize = 4;

/// The app state a key can visibly change. Built by `App::keycast_view`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    pub service: Option<String>,
    pub details_focused: bool,
    /// The detail pane's active section label (when a resource is selected).
    pub section: Option<String>,
    /// The list's sub-tab label.
    pub sub_tab: Option<String>,
    /// The lens or modal that owns the keyboard, by display name.
    pub overlay: Option<&'static str>,
    /// What is taking typed text, if anything.
    pub input: Option<Input>,
    /// The global search box's text, while it has the keyboard.
    pub search_query: String,
    /// `Z`: the list without the detail preview.
    pub list_only: bool,
    pub selected_id: Option<String>,
}

/// Something that takes typed text, which decides what `⏎` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// The global search box (`/`, `@`).
    Search,
    /// The detail pane's `/` filter.
    Filter,
    /// A type-to-filter picker (services, locations, subscriptions, `C`).
    Picker,
    /// The macro name prompt.
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub action: Option<String>,
    pub count: u32,
    pub at: Instant,
}

#[derive(Debug, Default)]
pub struct Keycast {
    pub entries: VecDeque<Entry>,
    /// The key being dispatched and the view before it.
    pending: Option<(KeyEvent, View)>,
}

impl Keycast {
    /// A key is about to be dispatched from `before`. A key still pending
    /// (a mouse gesture replays more than one per event) is settled first,
    /// against `before`, which is the view it left behind.
    pub fn note(&mut self, key: KeyEvent, before: View, now: Instant) {
        if self.pending.is_some() {
            self.settle(&before, now);
        }
        self.pending = Some((key, before));
    }

    /// Classify the pending key against the view after it ran.
    pub fn settle(&mut self, after: &View, now: Instant) {
        let Some((key, before)) = self.pending.take() else {
            return;
        };
        let Some((label, action)) = classify(key, &before, after) else {
            return;
        };
        if let Some(last) = self.entries.back_mut() {
            if last.key == label && last.action == action && now.duration_since(last.at) < FOLD_WITHIN {
                last.count += 1;
                last.at = now;
                return;
            }
        }
        self.entries.push_back(Entry {
            key: label,
            action,
            count: 1,
            at: now,
        });
        while self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
        }
    }

    /// Entries still on screen at `now`, oldest first.
    pub fn visible(&self, now: Instant) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(move |e| now.duration_since(e.at) < SHOW_FOR)
    }
}

/// The key's display label and what it did, or `None` to show nothing
/// (typing into a text input).
pub fn classify(key: KeyEvent, before: &View, after: &View) -> Option<(String, Option<String>)> {
    let label = key_label(key)?;

    // Text input: show only the keys that finish it.
    if let Some(input) = before.input {
        return match key.code {
            KeyCode::Enter => {
                let q = before.search_query.trim();
                if let (Input::Search, Some(svc)) = (input, q.strip_prefix('@')) {
                    // `@vm ⏎` reads better than a bare ⏎: the switch is the point.
                    if let Some(svc) = svc.split_whitespace().next() {
                        return Some((format!("@{svc} ⏎"), Some("switch service".into())));
                    }
                }
                let action = match input {
                    Input::Search => "search",
                    Input::Filter => "apply filter",
                    Input::Picker => "select",
                    Input::Name => "save macro",
                };
                Some((label, Some(action.into())))
            }
            KeyCode::Esc => Some((label, Some("cancel".into()))),
            _ => None,
        };
    }

    Some((label, action(key, before, after)))
}

/// What the key did, from the difference it made; the fallback table only
/// when nothing visible changed.
fn action(key: KeyEvent, before: &View, after: &View) -> Option<String> {
    let jumped = before.details_focused
        && matches!(key.code, KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right)
        && (after.service != before.service || after.selected_id != before.selected_id);
    if jumped {
        return Some("follow link".into());
    }
    if matches!(key.code, KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL)) {
        return Some("back".into());
    }
    if matches!(key.code, KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL)) {
        return Some("forward".into());
    }
    if after.overlay != before.overlay {
        return match (after.overlay, before.overlay) {
            (Some(opened), _) => Some(opened.to_string()),
            (None, Some(closed)) => Some(format!("close {closed}")),
            (None, None) => None,
        };
    }
    if let (Some(input), None) = (after.input, before.input) {
        return Some(match (input, key.code) {
            (Input::Search, KeyCode::Char('@')) => "switch service",
            (Input::Search, _) => "search",
            (Input::Filter, _) => "filter",
            (Input::Picker, _) => "pick",
            (Input::Name, _) => "name macro",
        }
        .into());
    }
    if after.service != before.service {
        return after.service.as_ref().map(|s| format!("go to {s}"));
    }
    if after.details_focused != before.details_focused {
        return Some(if after.details_focused { "open" } else { "back to list" }.into());
    }
    if after.list_only != before.list_only {
        return Some(if after.list_only { "list only" } else { "split view" }.into());
    }
    // Sub-tab before section: `H` / `L` from the detail pane change both,
    // and the tab is the point (the section just resets to the default).
    if after.sub_tab != before.sub_tab {
        return after.sub_tab.clone();
    }
    if after.details_focused && after.section != before.section {
        return after.section.clone();
    }
    // Cursor movement speaks for itself.
    if matches!(
        key.code,
        KeyCode::Char('j' | 'k' | 'g' | 'G') | KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
    ) && key.modifiers.difference(KeyModifiers::SHIFT).is_empty()
    {
        return None;
    }
    fallback(key, after).map(str::to_string)
}

/// Labels for keys whose effect the view can't see (a filter chip, a wrap
/// toggle, a copy). Kept small on purpose: anything visible is named above.
fn fallback(key: KeyEvent, after: &View) -> Option<&'static str> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('d') => Some("half page down"),
            KeyCode::Char('u') => Some("half page up"),
            KeyCode::Char('x' | 'X') => Some("export list"),
            KeyCode::Char('w') => Some("wrap lines"),
            KeyCode::Char('l') => Some("redraw"),
            KeyCode::Char('a') => Some("select all"),
            _ => None,
        };
    }
    let windowed = matches!(after.overlay, Some("change timeline" | "metrics"))
        || after.service.as_deref() == Some("Changes");
    match key.code {
        KeyCode::Char('t') if after.overlay == Some("network access") => Some("direction"),
        KeyCode::Char('[' | ']') if windowed => Some("time window"),
        KeyCode::Char('f') if after.overlay == Some("change timeline") => Some("sources"),
        KeyCode::Char('f') if after.overlay == Some("referenced by") => Some("service filter"),
        KeyCode::Char('L') if after.overlay == Some("referenced by") => Some("load likely"),
        KeyCode::Char('a') if after.overlay == Some("metrics") => Some("all metrics"),
        KeyCode::Char('F') => Some("state filter"),
        KeyCode::Char('y') => Some("copy"),
        KeyCode::Char('e') => Some("open in editor"),
        KeyCode::Char('r') | KeyCode::F(5) => Some("refresh"),
        KeyCode::Char('z') => Some("sort"),
        KeyCode::Char('a') => Some("hide noise"),
        KeyCode::Char('X') => Some("export"),
        KeyCode::Char('\\') => Some("flat view"),
        KeyCode::Char('w') => Some("watch mode"),
        KeyCode::Char('B') => Some("bookmark"),
        KeyCode::Char('b') => Some("banner"),
        KeyCode::Char('V') => Some("select lines"),
        _ => None,
    }
}

/// `⏎`, `Esc`, `Ctrl-O`, `⇥`; `None` for keys that never show (bare
/// modifiers, media keys).
pub fn key_label(key: KeyEvent) -> Option<String> {
    let base = match key.code {
        KeyCode::Char(' ') => "Space".to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "⏎".into(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Tab => "⇥".into(),
        KeyCode::BackTab => "⇤".into(),
        KeyCode::Backspace => "⌫".into(),
        KeyCode::Up => "↑".into(),
        KeyCode::Down => "↓".into(),
        KeyCode::Left => "←".into(),
        KeyCode::Right => "→".into(),
        KeyCode::PageUp => "PgUp".into(),
        KeyCode::PageDown => "PgDn".into(),
        KeyCode::Home => "Home".into(),
        KeyCode::End => "End".into(),
        KeyCode::Delete => "Del".into(),
        KeyCode::F(n) => format!("F{n}"),
        _ => return None,
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        Some(format!("Ctrl-{}", base.to_uppercase()))
    } else if key.modifiers.contains(KeyModifiers::ALT) {
        Some(format!("Alt-{base}"))
    } else {
        Some(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn code(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }
    fn list() -> View {
        View {
            service: Some("Virtual Machines".into()),
            sub_tab: Some("VMs".into()),
            ..View::default()
        }
    }

    #[test]
    fn names_what_the_key_did() {
        let before = list();
        let after = View { overlay: Some("change timeline"), ..list() };
        assert_eq!(classify(k('W'), &before, &after), Some(("W".into(), Some("change timeline".into()))));

        let after = View { details_focused: true, section: Some("Overview".into()), ..list() };
        assert_eq!(classify(code(KeyCode::Enter), &before, &after).unwrap().1.as_deref(), Some("open"));

        let before = View { details_focused: true, section: Some("Overview".into()), ..list() };
        let after = View { section: Some("Related".into()), ..before.clone() };
        assert_eq!(classify(k('5'), &before, &after).unwrap().1.as_deref(), Some("Related"));

        let after = View { service: Some("Virtual Network".into()), selected_id: Some("vnet".into()), ..before.clone() };
        assert_eq!(classify(code(KeyCode::Enter), &before, &after).unwrap().1.as_deref(), Some("follow link"));
    }

    #[test]
    fn never_echoes_typed_text() {
        let typing = View { input: Some(Input::Search), search_query: "secret-thing".into(), ..list() };
        assert_eq!(classify(k('s'), &typing, &typing), None);
        let (key, action) = classify(code(KeyCode::Enter), &typing, &list()).unwrap();
        assert_eq!((key.as_str(), action.as_deref()), ("⏎", Some("search")));

        // An @service switch is the exception: the service is the point.
        let at = View { input: Some(Input::Search), search_query: "@vm".into(), ..list() };
        assert_eq!(classify(code(KeyCode::Enter), &at, &list()).unwrap().0, "@vm ⏎");

        let picker = View { input: Some(Input::Picker), overlay: Some("locations"), ..list() };
        assert_eq!(classify(k('e'), &picker, &picker), None);
        assert_eq!(classify(code(KeyCode::Enter), &picker, &list()).unwrap().1.as_deref(), Some("select"));

        let naming = View { input: Some(Input::Name), overlay: Some("macros"), ..list() };
        assert_eq!(classify(k('x'), &naming, &naming), None);
    }

    #[test]
    fn cursor_keys_carry_no_label_and_repeats_fold() {
        let v = list();
        assert_eq!(classify(k('j'), &v, &v), Some(("j".into(), None)));
        let mut kc = Keycast::default();
        let t0 = Instant::now();
        for i in 0..3 {
            let at = t0 + Duration::from_millis(100 * i);
            kc.note(k('j'), v.clone(), at);
            kc.settle(&v, at);
        }
        assert_eq!(kc.entries.len(), 1);
        assert_eq!(kc.entries[0].count, 3);
    }

    #[test]
    fn a_second_key_in_one_event_settles_the_first() {
        let mut kc = Keycast::default();
        let t0 = Instant::now();
        kc.note(k('y'), list(), t0);
        kc.note(code(KeyCode::Enter), list(), t0);
        let after = View { details_focused: true, ..list() };
        kc.settle(&after, t0);
        let shown: Vec<_> = kc.entries.iter().map(|e| (e.key.as_str(), e.action.as_deref())).collect();
        assert_eq!(shown, vec![("y", Some("copy")), ("⏎", Some("open"))]);
    }

    #[test]
    fn entries_expire_and_cap() {
        let v = list();
        let mut kc = Keycast::default();
        let t0 = Instant::now();
        for (i, c) in "yeryeX".chars().enumerate() {
            let at = t0 + Duration::from_millis(10 * i as u64);
            kc.note(k(c), v.clone(), at);
            kc.settle(&v, at);
        }
        assert_eq!(kc.entries.len(), MAX_ENTRIES);
        assert_eq!(kc.visible(t0 + SHOW_FOR + Duration::from_secs(1)).count(), 0);
    }

    #[test]
    fn labels_modifiers() {
        let ctrl_o = KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL);
        assert_eq!(key_label(ctrl_o).as_deref(), Some("Ctrl-O"));
        assert_eq!(classify(ctrl_o, &list(), &list()).unwrap().1.as_deref(), Some("back"));
        let ctrl_f = KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL);
        assert_eq!(classify(ctrl_f, &list(), &list()).unwrap().1.as_deref(), Some("forward"));
    }
}
