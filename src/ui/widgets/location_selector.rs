// ported from neboto-tui src/ui/widgets/region_selector.rs @ d483900
use crate::azure::location::Location;
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        block::{Position, Title},
        Clear, List, ListItem, ListState, Paragraph,
    },
    Frame,
};

pub struct LocationSelectorState {
    pub visible: bool,
    pub selected_index: usize,
    pub query: String,
    locations: Vec<Location>,
    /// List-area height recorded at render time (`Cell`: render only sees
    /// `&self`), so `Ctrl-d`/`Ctrl-u` page jumps scale with the actual popup.
    viewport: std::cell::Cell<u16>,
}

fn matches(location: &Location, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    location.as_str().to_lowercase().contains(&q)
        || location.display_name().to_lowercase().contains(&q)
}

impl LocationSelectorState {
    pub fn new() -> Self {
        Self {
            visible: false,
            selected_index: 0,
            query: String::new(),
            locations: Location::all(),
            viewport: std::cell::Cell::new(0),
        }
    }

    pub fn show(&mut self, current_location: Location) {
        self.visible = true;
        self.query.clear();
        // Start on the current location (full list when query is empty).
        self.selected_index = self
            .locations
            .iter()
            .position(|r| *r == current_location)
            .unwrap_or(0);
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Locations matching the current search query.
    pub fn filtered(&self) -> Vec<Location> {
        self.locations
            .iter()
            .copied()
            .filter(|r| matches(r, &self.query))
            .collect()
    }

    pub fn next(&mut self) {
        let len = self.filtered().len();
        if len > 0 && self.selected_index + 1 < len {
            self.selected_index += 1;
        }
    }

    pub fn previous(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
        self.selected_index = 0;
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
        self.selected_index = 0;
    }

    pub fn selected_location(&self) -> Option<Location> {
        self.filtered().get(self.selected_index).copied()
    }

    fn page_stride(&self) -> usize {
        match self.viewport.get() {
            0 => 10,
            v => (v as usize / 2).max(1),
        }
    }

    pub fn page_down(&mut self) {
        let len = self.filtered().len();
        if len > 0 {
            self.selected_index = (self.selected_index + self.page_stride()).min(len - 1);
        }
    }

    pub fn page_up(&mut self) {
        self.selected_index = self.selected_index.saturating_sub(self.page_stride());
    }

    pub fn select_first(&mut self) {
        self.selected_index = 0;
    }

    pub fn select_last(&mut self) {
        self.selected_index = self.filtered().len().saturating_sub(1);
    }

    /// 1-based selection position and total — the `5/34` corner badge.
    pub fn position(&self) -> (usize, usize) {
        let len = self.filtered().len();
        ((self.selected_index + 1).min(len), len)
    }
}

pub fn render_location_selector(
    state: &LocationSelectorState,
    current_location: Location,
    frame: &mut Frame,
) {
    if !state.visible {
        return;
    }

    let area = centered_rect(60, 70, frame.size());
    frame.render_widget(Clear, area);

    let (pos, total) = state.position();
    let block = theme::popup_block("Filter by Location")
        .title(
            Title::from(theme::hint_line(&[
                ("type", "filter"),
                ("↑/↓", "move"),
                ("^d/^u", "page"),
                ("⏎", "select"),
                ("Esc", "close"),
            ]))
            .position(Position::Bottom)
            .alignment(Alignment::Center),
        )
        .title(
            Title::from(Span::styled(
                format!(" {}/{} ", pos, total),
                Style::default().fg(theme::text_dim()),
            ))
            .position(Position::Bottom)
            .alignment(Alignment::Right),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);

    render_search_line(&state.query, chunks[0], frame);
    state.viewport.set(chunks[1].height);

    let filtered = state.filtered();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|location| {
            let is_current = *location == current_location;
            let marker = if is_current {
                Span::styled("● ", Style::default().fg(theme::success()))
            } else {
                Span::raw("  ")
            };
            let code_style = if is_current {
                Style::default()
                    .fg(theme::success())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(crate::ui::theme::text_primary())
            };
            ListItem::new(Line::from(vec![
                marker,
                Span::styled(format!("{:<16}", location.as_str()), code_style),
                Span::styled(
                    location.display_name().to_string(),
                    Style::default().fg(crate::ui::theme::text_muted()),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .highlight_style(theme::selection_style(true))
        .highlight_symbol("▌ ");

    let mut list_state = ListState::default();
    if !filtered.is_empty() {
        list_state.select(Some(state.selected_index.min(filtered.len() - 1)));
    }

    frame.render_stateful_widget(list, chunks[1], &mut list_state);
}

/// Shared search-input row for the selector popups: `❯ <query>` (or a dim hint
/// when empty).
pub(crate) fn render_search_line(query: &str, area: Rect, frame: &mut Frame) {
    let line = if query.is_empty() {
        Line::from(vec![
            Span::styled(
                "❯ ",
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "type to filter…",
                Style::default()
                    .fg(theme::text_dim())
                    .add_modifier(Modifier::ITALIC),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "❯ ",
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(query.to_string(), Style::default().fg(crate::ui::theme::text_primary())),
        ])
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
