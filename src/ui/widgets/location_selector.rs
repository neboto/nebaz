// ported from neboto-tui src/ui/widgets/region_selector.rs @ d483900
//! The `R` picker. Unlike neboto's region picker it has no compiled table:
//! `App::location_rows` feeds it the subscription's locations endpoint
//! (once it has landed) merged with the distinct locations of the current
//! list and their row counts, so a location with zero rows in this service
//! is still pickable and one the endpoint doesn't know (a row's own
//! spelling) still shows.

use crate::azure::location::{Location, LocationRow};
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
    rows: Vec<LocationRow>,
    /// Whether the locations endpoint had landed when the picker opened —
    /// the footer says so while the list is only what the rows carry.
    endpoint_loaded: bool,
    /// List-area height recorded at render time (`Cell`: render only sees
    /// `&self`), so `Ctrl-d`/`Ctrl-u` page jumps scale with the actual popup.
    viewport: std::cell::Cell<u16>,
}

fn matches(row: &LocationRow, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    row.location.as_str().contains(&q) || row.display_name.to_lowercase().contains(&q)
}

impl LocationSelectorState {
    pub fn new() -> Self {
        Self {
            visible: false,
            selected_index: 0,
            query: String::new(),
            rows: Vec::new(),
            endpoint_loaded: false,
            viewport: std::cell::Cell::new(0),
        }
    }

    /// Show the modal over a fresh row set, selecting the current location.
    pub fn show(&mut self, current_location: &Location, rows: Vec<LocationRow>, endpoint_loaded: bool) {
        self.rows = rows;
        self.endpoint_loaded = endpoint_loaded;
        self.visible = true;
        self.query.clear();
        self.selected_index = self
            .rows
            .iter()
            .position(|r| r.location == *current_location)
            .unwrap_or(0);
    }

    /// Replace the rows while open (the endpoint list landed after `R`).
    pub fn refresh_rows(&mut self, rows: Vec<LocationRow>, endpoint_loaded: bool) {
        let keep = self.selected_location();
        self.rows = rows;
        self.endpoint_loaded = endpoint_loaded;
        if let Some(loc) = keep {
            if let Some(pos) = self.filtered().iter().position(|r| r.location == loc) {
                self.selected_index = pos;
            }
        }
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Rows matching the current search query.
    pub fn filtered(&self) -> Vec<&LocationRow> {
        self.rows.iter().filter(|r| matches(r, &self.query)).collect()
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
        self.filtered()
            .get(self.selected_index)
            .map(|r| r.location.clone())
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
    current_location: &Location,
    frame: &mut Frame,
) {
    if !state.visible {
        return;
    }

    let area = centered_rect(60, 70, frame.size());
    frame.render_widget(Clear, area);

    let (pos, total) = state.position();
    let hints: &[(&str, &str)] = if state.endpoint_loaded {
        &[
            ("type", "filter"),
            ("↑/↓", "move"),
            ("^d/^u", "page"),
            ("⏎", "select"),
            ("Esc", "close"),
        ]
    } else {
        &[
            ("type", "filter"),
            ("⏎", "select"),
            ("Esc", "close"),
            ("·", "location list loading — showing this view's locations"),
        ]
    };
    let block = theme::popup_block("Filter by Location")
        .title(
            Title::from(theme::hint_line(hints))
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
        .map(|row| {
            let is_current = row.location == *current_location;
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
            // Rows with nothing in this view are pickable but dim.
            let name_style = if row.count == 0 {
                Style::default().fg(theme::text_dim())
            } else {
                Style::default().fg(crate::ui::theme::text_muted())
            };
            let count = if row.count == 0 {
                "·".to_string()
            } else {
                row.count.to_string()
            };
            ListItem::new(Line::from(vec![
                marker,
                Span::styled(format!("{:<22}", row.location.as_str()), code_style),
                Span::styled(format!("{:<28}", row.display_name), name_style),
                Span::styled(format!("{:>6}", count), Style::default().fg(theme::text_dim())),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<LocationRow> {
        vec![
            LocationRow {
                location: Location::All,
                display_name: "All locations".into(),
                count: 3,
            },
            LocationRow {
                location: Location::parse("eastus"),
                display_name: "East US".into(),
                count: 2,
            },
            LocationRow {
                location: Location::parse("westeurope"),
                display_name: "West Europe".into(),
                count: 0,
            },
        ]
    }

    #[test]
    fn show_selects_the_current_location_and_filters_by_name_or_display() {
        let mut s = LocationSelectorState::new();
        s.show(&Location::parse("westeurope"), rows(), true);
        assert_eq!(s.selected_index, 2);
        s.push_char('e');
        s.push_char('a');
        s.push_char('s');
        s.push_char('t');
        assert_eq!(s.selected_location(), Some(Location::parse("eastus")));
        s.query = "west europe".into();
        assert_eq!(s.selected_location(), Some(Location::parse("westeurope")));
    }

    #[test]
    fn refresh_keeps_the_selection_by_location() {
        let mut s = LocationSelectorState::new();
        s.show(&Location::All, rows(), false);
        s.next();
        assert_eq!(s.selected_location(), Some(Location::parse("eastus")));
        let mut more = rows();
        more.insert(
            1,
            LocationRow {
                location: Location::parse("centralus"),
                display_name: "Central US".into(),
                count: 0,
            },
        );
        s.refresh_rows(more, true);
        assert_eq!(s.selected_location(), Some(Location::parse("eastus")));
    }
}
