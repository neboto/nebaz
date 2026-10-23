// ported from neboto-tui src/app.rs @ 03760c0 (ClickAction, ClickRegion,
// PopupHits, handle_mouse, apply_click_action, note_left_click,
// handle_modal_mouse, select_modal_row, handle_pane_view_mouse,
// click_select_detail_row) and src/main.rs (hint_click_key,
// record_hint_regions); adapted to nebaz's synchronous handle_key, its
// modals and in-pane views, and one MouseState field
//! The mouse (#42). Everything the pointer can do replays a key through
//! `handle_key`, so the mouse can never do anything the keyboard can't.
//!
//! **How a click finds its target.** The read-only widgets record what
//! they drew as they draw it, so a hit target always matches the screen:
//! - `App::click_regions` — one-row targets that replay a key: service and
//!   sub-tab chips, the `‹`/`›` overflow markers, section chips, every key
//!   hint (status bar, detail footer, lens and metrics footers), the strip
//!   badges, the location chip, the search bar, the detail title bar.
//! - [`MouseState::popup`] — the open centered modal's outer rect (a click
//!   outside closes it) and its visible rows, by item index.
//! - [`MouseState::pane_rows`] — the rows of an in-pane view (the network
//!   lens, metrics) by item index.
//! - [`MouseState::detail_rows`] — the detail body's screen-row →
//!   `detail_body()` row map, so a click lands on the right logical row
//!   under `Ctrl-W` wrap and the `/` filter.
//!
//! [`MouseState::begin_frame`] empties them at the start of every frame.
//!
//! **Priority.** An open modal owns every mouse event (nothing falls
//! through to the panes beneath). Then a recorded click target. Then an
//! in-pane view, for events over the detail pane (outside it, a click or
//! a scroll closes the view and goes on, as before #42). Then the panes:
//! the wheel scrolls the pane under the pointer, a click puts the cursor
//! on a row or line, a second press on the same cell within
//! [`DOUBLE_CLICK_MS`] is `⏎`, a left-drag selects a range (the press
//! anchors it), and a right-click is `⌫` (back). Shift bypasses mouse
//! capture in most terminals, for native text selection.

use super::{point_in, App};
use crate::azure::service::ServiceType;
use crate::event::Event;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::text::Line;
use std::cell::{Cell, RefCell};
use std::time::Instant;
use tokio::sync::mpsc;

/// A second left press on the same cell within this many milliseconds is
/// a double-click.
pub const DOUBLE_CLICK_MS: u128 = 400;

/// What a click on a recorded region does. Each replays a key, so a click
/// reuses the exact logic the keyboard uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClickAction {
    Service(ServiceType),
    /// A list-level control (a sub-tab chip or marker, the search bar):
    /// focus the list, then press the key, so a digit switches the sub-tab
    /// rather than the detail section.
    List(KeyCode),
    /// A detail-pane control (a section chip or marker, the title bar):
    /// focus the detail pane (when a row is selected), then press the key.
    Detail(KeyCode),
    /// A key hint or a badge: press the key where focus already is, so the
    /// footer's `y` copies the body line and the status bar's `y` the id.
    Press(KeyCode),
}

/// A clickable region, recorded each frame by the (read-only) widgets.
#[derive(Debug, Clone, Copy)]
pub struct ClickRegion {
    pub rect: Rect,
    pub action: ClickAction,
}

/// Where a popup or an in-pane view drew itself this frame: its outer
/// rect and each visible row's rect with its item index.
#[derive(Debug, Default, Clone)]
pub struct PopupHits {
    pub area: Option<Rect>,
    pub rows: Vec<(usize, Rect)>,
}

impl PopupHits {
    /// A popup whose list draws one item per line in `list` (no borders),
    /// starting at item `offset`, out of `len` items.
    pub fn record_list(&mut self, popup: Rect, list: Rect, offset: usize, len: usize) {
        self.area = Some(popup);
        self.record_rows(list, offset, len);
    }

    /// Just the rows half of `record_list`.
    pub fn record_rows(&mut self, list: Rect, offset: usize, len: usize) {
        self.rows = (offset..len)
            .take(list.height as usize)
            .enumerate()
            .map(|(line, idx)| (idx, Rect { x: list.x, y: list.y + line as u16, width: list.width, height: 1 }))
            .collect();
    }

    /// A popup with no clickable rows (help, a prompt): only a click
    /// outside it means anything.
    pub fn record_area(&mut self, popup: Rect) {
        self.area = Some(popup);
        self.rows.clear();
    }

    fn row_at(&self, col: u16, row: u16) -> Option<usize> {
        self.rows.iter().find(|(_, r)| point_in(*r, col, row)).map(|(i, _)| *i)
    }

    fn contains(&self, col: u16, row: u16) -> bool {
        self.area.is_some_and(|a| point_in(a, col, row))
    }
}

/// The mouse's state: what the renderers recorded this frame (`Cell` /
/// `RefCell`, written through `&App`) and the gesture in progress.
#[derive(Debug, Default)]
pub struct MouseState {
    /// The open centered modal.
    pub popup: RefCell<PopupHits>,
    /// The in-pane view (lens, metrics) that owns the detail pane.
    pub pane_rows: RefCell<PopupHits>,
    /// The whole detail pane (border included), when drawn.
    pub detail_pane: Cell<Option<Rect>>,
    /// The detail body (inside the pane, above the filter bar).
    pub detail_body: Cell<Option<Rect>>,
    /// The `detail_body()` row each body screen row shows, top down.
    pub detail_rows: RefCell<Vec<usize>>,
    /// The first body row drawn last frame. The body keeps it while the
    /// cursor stays on screen, so a click never scrolls the line clicked.
    pub detail_top: Cell<usize>,
    /// Time and cell of the last left press, for double-clicks.
    last_left: Option<(Instant, u16, u16)>,
    /// The body row a left press landed on: a drag from it selects.
    detail_drag_anchor: Option<usize>,
}

impl MouseState {
    /// Forget last frame's hit targets (the renderers record this frame's).
    pub fn begin_frame(&self) {
        *self.popup.borrow_mut() = PopupHits::default();
        *self.pane_rows.borrow_mut() = PopupHits::default();
        self.detail_pane.set(None);
        self.detail_body.set(None);
        self.detail_rows.borrow_mut().clear();
    }

    /// Record a left press; whether it completes a double-click (a second
    /// press on the same cell within the window). A double resets the
    /// pair, so a third click starts fresh.
    fn note_left_click(&mut self, col: u16, row: u16) -> bool {
        let now = Instant::now();
        let double = self
            .last_left
            .is_some_and(|(t, c, r)| c == col && r == row && now.duration_since(t).as_millis() < DOUBLE_CLICK_MS);
        self.last_left = if double { None } else { Some((now, col, row)) };
        double
    }
}

/// The key a click on a hint chip presses, or `None` for a chip that is
/// not one key: `j/k`, `[/]` and `n/N` name pairs, `@service` and `type`
/// are typed. `q` is left out on purpose: a stray click must not quit.
pub fn hint_click_key(key: &str) -> Option<KeyCode> {
    match key {
        "⏎" => Some(KeyCode::Enter),
        "Esc" => Some(KeyCode::Esc),
        "Tab" | "⇥" => Some(KeyCode::Tab),
        "⌫" => Some(KeyCode::Backspace),
        "q" => None,
        k => {
            let mut chars = k.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if c.is_ascii_graphic() => Some(KeyCode::Char(c)),
                _ => None,
            }
        }
    }
}

/// Record a `Press` region over each key hint drawn from `line`, starting
/// at column `x` on row `y`, clipped at `right`. A hint is a key span then
/// a ` desc` span (`theme::hint`); the `  ·  ` separators `hint_line`
/// puts between hints, and the first `skip` spans (padding), are skipped.
pub fn record_hint_regions(app: &App, line: &Line, skip: usize, x: u16, y: u16, right: u16) {
    let mut x = x;
    let mut chip: Option<(u16, KeyCode)> = None;
    let mut key_next = true;
    for (i, span) in line.spans.iter().enumerate() {
        let w = span.width() as u16;
        if i >= skip && span.content != "  ·  " {
            if key_next {
                chip = hint_click_key(&span.content).map(|code| (x, code));
            } else if let Some((start, code)) = chip.take() {
                let end = x.saturating_add(w).min(right);
                if end > start {
                    app.push_click_region(Rect { x: start, y, width: end - start, height: 1 }, ClickAction::Press(code));
                }
            }
            key_next = !key_next;
        }
        x = x.saturating_add(w);
    }
}

/// The centered modals, in `handle_key`'s priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Modal {
    Help,
    Service,
    Location,
    Subscription,
    JumpList,
    Bookmarks,
    Messages,
    Macros,
    /// The `C` command picker (#47): its rows are recorded by
    /// `render_command_picker` (wrapped, between tier headings).
    Commands,
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

impl App {
    fn click_region_at(&self, col: u16, row: u16) -> Option<ClickAction> {
        self.click_regions
            .borrow()
            .iter()
            .find(|r| point_in(r.rect, col, row))
            .map(|r| r.action)
    }

    /// Route a mouse event (see the module doc for the order).
    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        if matches!(mouse.kind, MouseEventKind::Moved) {
            return;
        }
        if self.handle_modal_mouse(mouse, event_tx) {
            return;
        }
        let (col, row) = (mouse.column, mouse.row);
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            if let Some(action) = self.click_region_at(col, row) {
                self.apply_click_action(action, event_tx);
                return;
            }
        }
        if self.handle_pane_view_mouse(mouse, event_tx) {
            return;
        }

        let list = self.list_area.get();
        let in_list = self.current_service.is_some() && point_in(list, col, row);
        let in_detail = self.mouse.detail_body.get().is_some_and(|a| point_in(a, col, row));
        match mouse.kind {
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = matches!(mouse.kind, MouseEventKind::ScrollDown);
                if in_detail {
                    self.scroll_detail_by_mouse(down);
                } else if in_list {
                    if self.details_focused {
                        self.leave_detail_pane();
                    }
                    self.move_selection(if down { 1 } else { -1 });
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let double = self.mouse.note_left_click(col, row);
                if in_list {
                    if self.click_list_row(row) && double {
                        self.handle_key(press(KeyCode::Enter), event_tx);
                    }
                } else if in_detail && self.click_detail_row(row) {
                    // A plain click drops the selection but remembers the
                    // line, so a drag from here selects a range.
                    self.detail_visual_anchor = None;
                    self.mouse.detail_drag_anchor = Some(self.details_scroll);
                    if double {
                        self.handle_key(press(KeyCode::Enter), event_tx);
                    }
                }
            }
            // A left-drag selects a range: in the body from the line the
            // press anchored, in the list from the row it selected.
            MouseEventKind::Drag(MouseButton::Left) => {
                if in_detail {
                    if let Some(anchor) = self.mouse.detail_drag_anchor {
                        if self.click_detail_row(row) && self.details_scroll != anchor {
                            self.detail_visual_anchor = Some(anchor);
                        }
                    }
                } else if in_list && !self.details_focused && row > list.y {
                    let offset = self.resource_list_state.borrow().offset();
                    self.list_drag_to((row - list.y - 1) as usize + offset);
                }
            }
            // The selection stays (so `y` copies it); the drag ends.
            MouseEventKind::Up(MouseButton::Left) => self.mouse.detail_drag_anchor = None,
            MouseEventKind::Down(MouseButton::Right) => self.mouse_back(event_tx),
            _ => {}
        }
    }

    /// Right-click: `⌫`, the way back (#58): from the list, one place back
    /// in history; from the detail pane, back in history when there is
    /// any, else to the list. Nothing while typing a query, where `⌫`
    /// deletes a character.
    fn mouse_back(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.search_active || (self.details_focused && self.detail_search_active) {
            return;
        }
        self.handle_key(press(KeyCode::Backspace), event_tx);
    }

    fn apply_click_action(&mut self, action: ClickAction, event_tx: &mpsc::UnboundedSender<Event>) {
        // While typing, only a hint's own `⏎` / `Esc` apply: a letter
        // would be typed into the query.
        let typing = self.search_active || (self.details_focused && self.detail_search_active);
        // Anything but a hint leaves an in-pane view: it belongs to the
        // row it was opened on. (A hint drawn by the view is its own key.)
        if !matches!(action, ClickAction::Press(_)) {
            self.network_lens = None;
            self.metrics = None;
            self.timeline = None;
        }
        match action {
            ClickAction::Service(service) => {
                if self.current_service != Some(service) {
                    self.switch_service(service);
                }
            }
            ClickAction::List(code) => {
                if typing {
                    return;
                }
                if self.details_focused {
                    self.leave_detail_pane();
                }
                self.handle_key(press(code), event_tx);
            }
            ClickAction::Detail(code) => {
                if typing || self.get_selected_resource().is_none() {
                    return;
                }
                if !self.details_focused {
                    self.clear_list_visual();
                    self.details_focused = true;
                }
                self.handle_key(press(code), event_tx);
            }
            ClickAction::Press(code) => {
                if typing && matches!(code, KeyCode::Char(_)) {
                    return;
                }
                self.handle_key(press(code), event_tx);
            }
        }
    }

    /// Select the list row under a left press (and leave the detail
    /// pane). Whether a row was there.
    fn click_list_row(&mut self, row: u16) -> bool {
        let list = self.list_area.get();
        // Rows start below the top border.
        if row <= list.y {
            return false;
        }
        let offset = self.resource_list_state.borrow().offset();
        let idx = (row - list.y - 1) as usize + offset;
        if idx >= self.filtered_resources.len() {
            return false;
        }
        self.clear_list_visual();
        if self.selected_index != Some(idx) {
            self.select(Some(idx));
        }
        self.leave_detail_pane();
        true
    }

    /// Put the detail cursor on the body line under `row` (through the
    /// renderer's screen-row map: a wrapped line spans several rows),
    /// focusing the pane. Below the last line, the last line. Whether
    /// there was a body to click.
    fn click_detail_row(&mut self, row: u16) -> bool {
        let Some(area) = self.mouse.detail_body.get() else {
            return false;
        };
        if self.get_selected_resource().is_none() || row < area.y {
            return false;
        }
        if !self.details_focused {
            self.clear_list_visual();
            self.details_focused = true;
        }
        let count = self.detail_body().len();
        if count == 0 {
            return false;
        }
        let rows = self.mouse.detail_rows.borrow();
        let idx = match rows.get((row - area.y) as usize) {
            Some(&i) => i,
            None => rows.last().copied().unwrap_or(0),
        };
        drop(rows);
        self.details_scroll = idx.min(count - 1);
        true
    }

    /// The wheel over the detail body: three lines, focusing the pane.
    fn scroll_detail_by_mouse(&mut self, down: bool) {
        if self.get_selected_resource().is_none() {
            return;
        }
        if !self.details_focused {
            self.clear_list_visual();
            self.details_focused = true;
        }
        self.move_detail_cursor(if down { 3 } else { -3 });
    }

    /// The modal that owns the keyboard, in `handle_key`'s order.
    fn open_modal(&self) -> Option<Modal> {
        Some(if self.help_visible {
            Modal::Help
        } else if self.service_selector.visible {
            Modal::Service
        } else if self.location_selector.visible {
            Modal::Location
        } else if self.subscription_selector.visible {
            Modal::Subscription
        } else if self.jump_list_visible {
            Modal::JumpList
        } else if self.bookmarks_visible {
            Modal::Bookmarks
        } else if self.message_history_visible {
            Modal::Messages
        } else if self.macro_picker_visible {
            Modal::Macros
        } else if self.command_picker.is_some() {
            Modal::Commands
        } else {
            return None;
        })
    }

    /// Put the modal's highlight on item `idx`. Whether it was already
    /// there (a click on the highlighted row confirms it), or `None` when
    /// the row can't be selected (a category header, past the end).
    fn select_modal_row(&mut self, modal: Modal, idx: usize) -> Option<bool> {
        let (slot, len) = match modal {
            Modal::Service => {
                let already = self.service_selector.selected_index == idx;
                return self.service_selector.select_row(idx).then_some(already);
            }
            Modal::Location => {
                let len = self.location_selector.filtered().len();
                (&mut self.location_selector.selected_index, len)
            }
            Modal::Subscription => {
                let len = self.subscription_selector.filtered().len();
                (&mut self.subscription_selector.selected_index, len)
            }
            Modal::JumpList => (&mut self.jump_list_selected, self.nav_history.len()),
            Modal::Bookmarks => (&mut self.bookmarks_selected, self.bookmarks.len()),
            Modal::Messages => (&mut self.message_history_selected, self.message_history.len()),
            Modal::Macros => (&mut self.macro_picker_selected, self.macros.len()),
            Modal::Commands => {
                let p = self.command_picker.as_mut()?;
                let len = p.visible().len();
                (&mut p.selected, len)
            }
            Modal::Help => return None,
        };
        if idx >= len {
            return None;
        }
        let already = *slot == idx;
        *slot = idx;
        Some(already)
    }

    /// Mouse on a centered modal. The wheel moves the highlight (help:
    /// scrolls three lines), a click highlights a row, and a double-click
    /// or a click on the row already highlighted confirms it, as `⏎` does
    /// (`M`: a double-click copies the message, as `y` does). A click
    /// outside or a right-click closes, as `Esc` does. Whether a modal was
    /// open; when one is, it owns every mouse event.
    fn handle_modal_mouse(&mut self, mouse: MouseEvent, event_tx: &mpsc::UnboundedSender<Event>) -> bool {
        let Some(modal) = self.open_modal() else {
            return false;
        };
        // Naming a macro: `Esc` discards the recording, which a stray click
        // must never do. Only the keyboard finishes the prompt.
        if modal == Modal::Macros && self.macro_name_input.is_some() {
            return true;
        }
        match mouse.kind {
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let code = if matches!(mouse.kind, MouseEventKind::ScrollDown) { KeyCode::Down } else { KeyCode::Up };
                let notches = if modal == Modal::Help { 3 } else { 1 };
                for _ in 0..notches {
                    self.handle_key(press(code), event_tx);
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let (col, row) = (mouse.column, mouse.row);
                let (inside, hit) = {
                    let hits = self.mouse.popup.borrow();
                    (hits.contains(col, row), hits.row_at(col, row))
                };
                if !inside {
                    self.close_modal_by_mouse(modal, event_tx);
                    return true;
                }
                let Some(idx) = hit else { return true };
                let double = self.mouse.note_left_click(col, row);
                if let Some(already) = self.select_modal_row(modal, idx) {
                    if modal == Modal::Messages {
                        if double {
                            self.handle_key(press(KeyCode::Char('y')), event_tx);
                        }
                    } else if double || already {
                        self.handle_key(press(KeyCode::Enter), event_tx);
                    }
                }
            }
            MouseEventKind::Down(MouseButton::Right) => self.close_modal_by_mouse(modal, event_tx),
            _ => {}
        }
        true
    }

    /// A click outside a modal or a right-click: `Esc`, except the command
    /// picker closes outright (its first `Esc` only clears a filter).
    fn close_modal_by_mouse(&mut self, modal: Modal, event_tx: &mpsc::UnboundedSender<Event>) {
        if modal == Modal::Commands {
            self.command_picker = None;
        } else {
            self.handle_key(press(KeyCode::Esc), event_tx);
        }
    }

    /// Mouse on an in-pane view (the network lens, metrics). Over the
    /// pane, the wheel is `↓` / `↑`, a click puts the cursor on a row, a
    /// double-click is `⏎` (go to the line's NSG; chart the picked metric)
    /// and a right-click is `Esc`. Outside it, a click or a scroll closes
    /// the view and goes on to what is under the pointer. Whether the view
    /// took the event.
    fn handle_pane_view_mouse(&mut self, mouse: MouseEvent, event_tx: &mpsc::UnboundedSender<Event>) -> bool {
        if self.network_lens.is_none() && self.metrics.is_none() && self.timeline.is_none() {
            return false;
        }
        let (col, row) = (mouse.column, mouse.row);
        if !self.mouse.detail_pane.get().is_some_and(|a| point_in(a, col, row)) {
            if matches!(
                mouse.kind,
                MouseEventKind::Down(_) | MouseEventKind::ScrollDown | MouseEventKind::ScrollUp
            ) {
                self.network_lens = None;
                self.metrics = None;
                self.timeline = None;
            }
            return false;
        }
        match mouse.kind {
            MouseEventKind::ScrollDown => self.handle_key(press(KeyCode::Down), event_tx),
            MouseEventKind::ScrollUp => self.handle_key(press(KeyCode::Up), event_tx),
            MouseEventKind::Down(MouseButton::Left) => {
                let hit = self.mouse.pane_rows.borrow().row_at(col, row);
                let Some(idx) = hit else { return true };
                let double = self.mouse.note_left_click(col, row);
                if self.select_pane_view_row(idx) && double {
                    self.handle_key(press(KeyCode::Enter), event_tx);
                }
            }
            MouseEventKind::Down(MouseButton::Right) => self.handle_key(press(KeyCode::Esc), event_tx),
            _ => {}
        }
        true
    }

    /// Put the in-pane view's cursor on row `idx`, as `j`/`k` would.
    fn select_pane_view_row(&mut self, idx: usize) -> bool {
        if let Some(lens) = self.network_lens.as_mut() {
            if idx < lens.lines.len() {
                lens.selected = idx;
                return true;
            }
        } else if let Some(st) = self.timeline.as_mut() {
            if idx < st.rows.len() {
                st.selected = idx;
                return true;
            }
        } else if let Some(st) = self.metrics.as_mut() {
            match st.picker.as_mut() {
                Some(p) if idx < p.defs.len() => {
                    p.selected = idx;
                    return true;
                }
                None if idx < st.series.len() => {
                    st.selected = idx;
                    return true;
                }
                _ => {}
            }
        }
        false
    }
}
