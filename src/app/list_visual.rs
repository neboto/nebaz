// ported from neboto-tui src/app.rs @ 03760c0 (list_visual_anchor,
// list_visual_range, list_visual_step, the list-pane visual keymap,
// copy_list_selection, export_list_selection, export_selection_deep)
//! Linewise visual selection in the **list** pane (#39), the list-pane
//! twin of the detail pane's `V`. `V` toggles at the cursor, `J`/`K` and
//! Shift-↓/↑ start-and-extend, `Ctrl-A` selects every visible row, and
//! once active plain `j`/`k`/`g`/`G` extend (the anchor stays put); a
//! left-drag over rows selects too. `Esc` cancels.
//!
//! While a selection is active the copy and export verbs work on it: `y`
//! / `c` copy the rows as a Markdown table, `Ctrl-X` shallow-exports them,
//! `X` deep-exports them (every section, lazy ones waited for, as one
//! `nebaz-<label>-deep-<ts>` trio; see `app/export.rs`), capped at
//! [`MAX_DEEP_EXPORT`] rows.
//!
//! The range is positional over `filtered_resources`, so any rebuild
//! (`update_search`: a search edit, sort, state filter, noise toggle,
//! sub-tab switch, reload, a streamed page) and a drill-in cancel it.

use super::App;
use crate::azure::resource::Resource;
use crate::event::Event;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

/// The most rows one deep export fetches: a `Ctrl-A` + `X` on a large
/// list must not launch thousands of ARM calls in one keystroke.
pub(crate) const MAX_DEEP_EXPORT: usize = 50;

impl App {
    /// The inclusive `(start, end)` row range of the list selection, or
    /// `None` when there is none (or its rows are gone).
    pub fn list_visual_range(&self) -> Option<(usize, usize)> {
        let anchor = self.list_visual_anchor?;
        let n = self.filtered_resources.len();
        if n == 0 || anchor >= n {
            return None;
        }
        let cursor = self.selected_index?.min(n - 1);
        Some((anchor.min(cursor), anchor.max(cursor)))
    }

    /// Whether the list row at `pos` is in the visual selection (the list
    /// widget paints it like the cursor row).
    pub fn list_row_in_selection(&self, pos: usize) -> bool {
        self.list_visual_range().is_some_and(|(start, end)| pos >= start && pos <= end)
    }

    pub(crate) fn clear_list_visual(&mut self) {
        self.list_visual_anchor = None;
    }

    /// Start a selection at the cursor if none, then move one row.
    fn list_visual_step(&mut self, down: bool) {
        if self.filtered_resources.is_empty() {
            return;
        }
        if self.list_visual_anchor.is_none() {
            self.list_visual_anchor = Some(self.selected_index.unwrap_or(0));
        }
        self.move_selection(if down { 1 } else { -1 });
    }

    /// The selected rows, in list order.
    fn selected_list_resources(&self) -> Vec<&dyn Resource> {
        let Some((start, end)) = self.list_visual_range() else {
            return Vec::new();
        };
        (start..=end)
            .filter_map(|pos| self.filtered_resources.get(pos))
            .filter_map(|&i| self.resources.get(i))
            .map(|r| r.as_ref())
            .collect()
    }

    /// The list-pane visual keymap, before the list pane's own keys.
    /// Returns true when it consumed the key.
    pub(crate) fn handle_list_visual_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) -> bool {
        let active = self.list_visual_range().is_some();
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('V') => {
                if self.list_visual_anchor.is_some() {
                    self.clear_list_visual();
                } else if !self.filtered_resources.is_empty() {
                    self.list_visual_anchor = Some(self.selected_index.unwrap_or(0));
                }
            }
            // Before the noise toggle's `a` arm, which matches any modifier.
            KeyCode::Char('a') if ctrl => {
                let n = self.filtered_resources.len();
                if n > 0 {
                    self.list_visual_anchor = Some(0);
                    self.select(Some(n - 1));
                }
            }
            KeyCode::Char('J') => self.list_visual_step(true),
            KeyCode::Char('K') => self.list_visual_step(false),
            KeyCode::Down if key.modifiers.contains(KeyModifiers::SHIFT) => self.list_visual_step(true),
            KeyCode::Up if key.modifiers.contains(KeyModifiers::SHIFT) => self.list_visual_step(false),
            KeyCode::Esc if self.list_visual_anchor.is_some() => self.clear_list_visual(),
            KeyCode::Char('y') | KeyCode::Char('c') if active && !ctrl => self.copy_list_selection(),
            KeyCode::Char('x') | KeyCode::Char('X') if active && ctrl => self.export_list_selection(),
            KeyCode::Char('X') if active => self.export_selection_deep(event_tx),
            // A drill-in leaves the list: the selection goes with it.
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                self.clear_list_visual();
                return false;
            }
            _ => return false,
        }
        true
    }

    /// A left-drag over the list: the row the press landed on anchors the
    /// selection, the row under the pointer is the cursor.
    pub(crate) fn list_drag_to(&mut self, row: usize) {
        if row >= self.filtered_resources.len() {
            return;
        }
        if self.list_visual_anchor.is_none() {
            self.list_visual_anchor = Some(self.selected_index.unwrap_or(row));
        }
        self.select(Some(row));
    }

    /// `y` / `c` with a selection: the rows as a Markdown table (the list
    /// export's columns).
    fn copy_list_selection(&mut self) {
        let rows = self.selected_list_resources();
        let count = rows.len();
        let label = self.export_label(rows.iter().map(|r| r.resource_type()));
        let text = crate::export::list_markdown(&rows, &label);
        drop(rows);
        self.clear_list_visual();
        self.copy_to_clipboard(&text, &format!("{} rows as a Markdown table", count));
    }

    /// `Ctrl-X` with a selection: just those rows, list-level fields only.
    fn export_list_selection(&mut self) {
        let rows = self.selected_list_resources();
        let label = self.export_label(rows.iter().map(|r| r.resource_type()));
        let count = rows.len();
        let result = crate::export::export_list(&rows, &label, &self.export_options);
        drop(rows);
        self.clear_list_visual();
        self.report_list_export(count, &label, result);
    }

    /// `X` with a selection: arm a deep export of every selected row (held
    /// by id, so it outlives the positional selection). `X` again while
    /// it waits is a no-op.
    fn export_selection_deep(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.pending_export.is_some() {
            return;
        }
        let Some((start, end)) = self.list_visual_range() else {
            return;
        };
        let count = end - start + 1;
        if count > MAX_DEEP_EXPORT {
            self.error_message = Some(format!(
                "Deep export capped at {} resources ({} selected) — narrow the selection",
                MAX_DEEP_EXPORT, count
            ));
            return;
        }
        let ids: Vec<String> = self.selected_list_resources().iter().map(|r| r.id().to_string()).collect();
        self.arm_export(ids, false, event_tx);
    }

    /// What a list or selection export is called (file stem and status
    /// line): the rows' type when they share one, else `all` for an `@*`
    /// result, else the service.
    pub(crate) fn export_label<'a>(&self, mut types: impl Iterator<Item = &'a str>) -> String {
        let service = || {
            if self.all_search_mode {
                return "all".to_string();
            }
            self.current_service
                .map(|s| s.short_name().to_string())
                .unwrap_or_else(|| "resources".into())
        };
        match types.next() {
            Some(first) if types.all(|t| t == first) => first.to_string(),
            _ => service(),
        }
    }
}
