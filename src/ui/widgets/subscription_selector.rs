// ported from neboto-tui src/ui/widgets/profile_selector.rs @ d483900
//! The `P` picker: every subscription `az account list` knows, all tenants,
//! with a tenant column instead of a tenant picker (ADR 0003). Disabled
//! subscriptions are listed but dimmed; the current one is marked. When
//! there is nothing to list the popup shows the auth line and its fix.

use crate::azure::auth::SubscriptionEntry;
use crate::ui::theme;
use crate::ui::widgets::location_selector::render_search_line;
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

pub struct SubscriptionSelectorState {
    pub visible: bool,
    pub selected_index: usize,
    pub query: String,
    subscriptions: Vec<SubscriptionEntry>,
    /// The auth line to show in place of an empty list.
    auth_message: Option<String>,
    /// List-area height recorded at render time (`Cell`: render only sees
    /// `&self`), so `Ctrl-d`/`Ctrl-u` page jumps scale with the actual popup.
    viewport: std::cell::Cell<u16>,
}

fn matches(entry: &SubscriptionEntry, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    entry.name.to_lowercase().contains(&q)
        || entry.id.to_lowercase().contains(&q)
        || entry.tenant_id.to_lowercase().contains(&q)
        || entry.state.to_lowercase().contains(&q)
}

impl SubscriptionSelectorState {
    pub fn new() -> Self {
        Self {
            visible: false,
            selected_index: 0,
            query: String::new(),
            subscriptions: Vec::new(),
            auth_message: None,
            viewport: std::cell::Cell::new(0),
        }
    }

    /// Show the modal over the given entries, selecting the active
    /// subscription if present.
    pub fn show(
        &mut self,
        subscriptions: Vec<SubscriptionEntry>,
        current_subscription: Option<&str>,
        auth_message: Option<String>,
    ) {
        self.subscriptions = subscriptions;
        self.auth_message = auth_message;
        self.visible = true;
        self.query.clear();
        self.selected_index = current_subscription
            .and_then(|target| self.subscriptions.iter().position(|p| p.id == target))
            .unwrap_or(0);
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Entries matching the current search query.
    pub fn filtered(&self) -> Vec<&SubscriptionEntry> {
        self.subscriptions
            .iter()
            .filter(|e| matches(e, &self.query))
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

    /// The selected subscription's id.
    pub fn selected_subscription(&self) -> Option<String> {
        self.filtered().get(self.selected_index).map(|e| e.id.clone())
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

    /// 1-based selection position and total — the `3/45` corner badge.
    pub fn position(&self) -> (usize, usize) {
        let len = self.filtered().len();
        ((self.selected_index + 1).min(len), len)
    }
}

pub fn render_subscription_selector(
    state: &SubscriptionSelectorState,
    current_subscription: Option<&str>,
    frame: &mut Frame,
) {
    if !state.visible {
        return;
    }

    let area = centered_rect(70, 60, frame.size());
    frame.render_widget(Clear, area);

    // Empty state: the auth line (not logged in, expired, …) or nothing found.
    if state.subscriptions.is_empty() {
        let block = theme::popup_block("Switch Subscription").title(
            Title::from(theme::hint_line(&[("R", "retry"), ("Esc", "close")]))
                .position(Position::Bottom)
                .alignment(Alignment::Center),
        );
        let text = state
            .auth_message
            .clone()
            .unwrap_or_else(|| "No subscriptions found — run `az login`, then press R".to_string());
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::styled(format!("  ✗ {}", text), Style::default().fg(theme::error())),
        ])
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: false });
        frame.render_widget(msg, area);
        return;
    }

    let (pos, total) = state.position();
    let block = theme::popup_block("Switch Subscription")
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
    let name_w = filtered
        .iter()
        .map(|e| e.name.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(8, 36);
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|entry| {
            let is_current = current_subscription == Some(entry.id.as_str());
            let enabled = entry.is_enabled();
            let marker = if is_current {
                Span::styled("⦿ ", Style::default().fg(theme::success()))
            } else {
                Span::raw("  ")
            };
            let name_style = if is_current {
                Style::default()
                    .fg(theme::success())
                    .add_modifier(Modifier::BOLD)
            } else if enabled {
                Style::default().fg(crate::ui::theme::text_primary())
            } else {
                Style::default().fg(theme::text_dim())
            };
            let dim = Style::default().fg(theme::text_dim());
            let state_style = if enabled {
                Style::default().fg(crate::ui::theme::text_muted())
            } else {
                Style::default().fg(theme::warning())
            };
            let mut name: String = entry.name.chars().take(name_w).collect();
            if entry.name.chars().count() > name_w {
                name.pop();
                name.push('…');
            }
            ListItem::new(Line::from(vec![
                marker,
                Span::styled(format!("{:<w$}", name, w = name_w), name_style),
                Span::styled(format!("  {}…", entry.short_id()), dim),
                Span::styled(format!("  {}…", entry.short_tenant()), dim),
                Span::styled(format!("  {}", entry.state.to_lowercase()), state_style),
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

    fn entry(id: &str, name: &str, tenant: &str, state: &str) -> SubscriptionEntry {
        SubscriptionEntry {
            id: id.into(),
            name: name.into(),
            tenant_id: tenant.into(),
            state: state.into(),
            is_default: false,
            cloud_name: None,
            user: None,
        }
    }

    #[test]
    fn show_marks_the_current_and_filters_on_name_id_tenant_or_state() {
        let mut s = SubscriptionSelectorState::new();
        s.show(
            vec![
                entry("1111", "Prod", "t-a", "Enabled"),
                entry("2222", "Dev", "t-b", "Enabled"),
                entry("3333", "Old", "t-b", "Disabled"),
            ],
            Some("2222"),
            None,
        );
        assert_eq!(s.selected_index, 1);
        s.query = "t-b".into();
        assert_eq!(s.filtered().len(), 2);
        s.query = "disabled".into();
        s.selected_index = 0;
        assert_eq!(s.selected_subscription().as_deref(), Some("3333"));
        s.query = "33".into();
        assert_eq!(s.selected_subscription().as_deref(), Some("3333"));
    }
}
