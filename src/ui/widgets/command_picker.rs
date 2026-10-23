// ported from neboto-tui src/ui/widgets/cli_picker.rs @ 343ef65 (adapted: a `/` fuzzy filter, nebaz's theme; state moved here from cli_actions)
//! `C` command picker (#47): the selected row's `az` commands grouped by
//! tier (Inspect / Connect / Change), and beneath them the **exact** text
//! `⏎` copies, so a command that changes Azure is read before it is pasted.
//! nebaz never runs any of them; the header says so. The catalogue is
//! `azure::cli_actions`; the keys are `App::handle_command_picker_key`.

use crate::app::PopupHits;
use crate::app::App;
use crate::azure::cli_actions::{CliAction, CliTier};
use crate::search::fuzzy::FuzzyMatcher;
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        block::{Position, Title},
        Clear, Paragraph, Wrap,
    },
    Frame,
};

/// The open `C` picker.
#[derive(Debug, Clone)]
pub struct CommandPickerState {
    /// What the commands target (`vm-1 · Virtual machine`).
    pub subject: String,
    pub actions: Vec<CliAction>,
    /// Index into [`Self::visible`], not into `actions`.
    pub selected: usize,
    pub query: String,
    /// `/` was pressed: printable keys type into `query`.
    pub filtering: bool,
    /// A caution shown in the header (a non-public cloud).
    pub caution: Option<String>,
}

impl CommandPickerState {
    pub fn new(subject: String, actions: Vec<CliAction>, caution: Option<String>) -> Self {
        CommandPickerState {
            subject,
            actions,
            selected: 0,
            query: String::new(),
            filtering: false,
            caution,
        }
    }

    /// Indices of the actions the filter keeps, in catalogue order (so the
    /// tier grouping holds): fuzzy over the label, the command and the
    /// tier name, the same scoring as every other picker.
    pub fn visible(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = FuzzyMatcher::new()
            .filter_fields(&self.query, &self.actions, |a| {
                vec![a.label.as_str(), a.command.as_str(), a.tier.heading()]
            })
            .into_iter()
            .map(|(i, _)| i)
            .collect();
        idx.sort_unstable();
        idx
    }

    pub fn selected_action(&self) -> Option<&CliAction> {
        self.visible().get(self.selected).map(|&i| &self.actions[i])
    }

    /// The `n`th visible action (the `1`–`9` keys).
    pub fn nth(&self, n: usize) -> Option<&CliAction> {
        self.visible().get(n).map(|&i| &self.actions[i])
    }

    pub fn next(&mut self) {
        let len = self.visible().len();
        if len > 0 {
            self.selected = (self.selected + 1).min(len - 1);
        }
    }

    pub fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn first(&mut self) {
        self.selected = 0;
    }

    pub fn last(&mut self) {
        self.selected = self.visible().len().saturating_sub(1);
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
        self.selected = 0;
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
        self.selected = 0;
    }

    pub fn clear_filter(&mut self) {
        self.query.clear();
        self.filtering = false;
        self.selected = 0;
    }
}

/// Draw the picker and record its rows for the mouse (`App::handle_mouse`:
/// a click highlights, a second click or a double-click copies).
pub fn render_command_picker(app: &App, frame: &mut Frame) {
    let Some(state) = &app.command_picker else {
        return;
    };
    let full = frame.size();
    let width = full.width.saturating_sub(4).clamp(20, 100).min(full.width);
    let inner_width = width.saturating_sub(2).max(1) as usize;

    let visible = state.visible();
    let mut lines = header_lines(state);
    let first_list_line = lines.len();
    let (list, list_items) = list_lines(state, &visible);
    lines.extend(list);
    lines.push(Line::styled(
        "─".repeat(inner_width),
        Style::default().fg(theme::text_dim()),
    ));
    lines.extend(preview_lines(state, inner_width));

    let rows: usize = lines
        .iter()
        .map(|l| l.width().max(1).div_ceil(inner_width))
        .sum();
    let height = ((rows + 2) as u16).min(full.height.saturating_sub(2)).max(8).min(full.height);
    let area = Rect {
        x: full.x + full.width.saturating_sub(width) / 2,
        y: full.y + full.height.saturating_sub(height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, area);
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };
    *app.mouse.popup.borrow_mut() = row_hits(area, inner, &lines, first_list_line, &list_items);

    let hints: &[(&str, &str)] = if state.filtering {
        &[("type", "filter"), ("↑/↓", "move"), ("⏎", "copy"), ("Esc", "clear")]
    } else {
        &[("j/k", "move"), ("⏎/y", "copy"), ("1-9", "pick"), ("/", "filter"), ("Esc", "close")]
    };
    let block = theme::popup_block(&format!("Copy az command · {}", state.subject)).title(
        Title::from(theme::hint_line(hints))
            .position(Position::Bottom)
            .alignment(Alignment::Center),
    );
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(block),
        area,
    );
}

fn header_lines(state: &CommandPickerState) -> Vec<Line<'static>> {
    let mut out = vec![Line::styled(
        " copies only: nebaz never runs these; you run them under your own az login",
        Style::default().fg(theme::text_dim()),
    )];
    if let Some(c) = &state.caution {
        out.push(Line::styled(format!(" ⚠ {}", c), Style::default().fg(theme::warning())));
    }
    if state.filtering || !state.query.is_empty() {
        let cursor = if state.filtering { "▏" } else { "" };
        out.push(Line::from(vec![
            Span::styled(" / ", Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{}{}", state.query, cursor), Style::default().fg(theme::text_primary())),
        ]));
    }
    out.push(Line::raw(""));
    out
}

/// The popup and each command row's screen rect, by position in
/// `visible()` (the index `select_modal_row` takes). The body wraps, so a
/// row's y is the sum of the wrapped heights above it, the arithmetic that
/// sizes the popup; rows past the bottom edge get no target.
fn row_hits(area: Rect, inner: Rect, lines: &[Line], first_list_line: usize, items: &[Option<usize>]) -> PopupHits {
    let w = (inner.width as usize).max(1);
    let mut hits = PopupHits { area: Some(area), rows: Vec::new() };
    let mut y = inner.y;
    for (i, line) in lines.iter().enumerate() {
        let h = line.width().max(1).div_ceil(w) as u16;
        let item = i.checked_sub(first_list_line).and_then(|j| items.get(j).copied().flatten());
        if let Some(pos) = item {
            if y + h <= inner.y + inner.height {
                hits.rows.push((pos, Rect { x: inner.x, y, width: inner.width, height: h }));
            }
        }
        y = y.saturating_add(h);
    }
    hits
}

/// Tier headings and numbered rows, and for each line the position in
/// `visible` it shows (`None` for a heading).
fn list_lines(state: &CommandPickerState, visible: &[usize]) -> (Vec<Line<'static>>, Vec<Option<usize>>) {
    if visible.is_empty() {
        return (
            vec![Line::styled("   no command matches the filter", Style::default().fg(theme::text_dim()))],
            vec![None],
        );
    }
    let mut out = Vec::new();
    let mut items = Vec::new();
    let mut tier: Option<CliTier> = None;
    for (pos, &i) in visible.iter().enumerate() {
        let a = &state.actions[i];
        if tier != Some(a.tier) {
            tier = Some(a.tier);
            let mut heading = vec![Span::styled(
                format!(" {}", a.tier.heading()),
                Style::default().fg(theme::heading()).add_modifier(Modifier::BOLD),
            )];
            if a.tier == CliTier::Change {
                heading.push(Span::styled(
                    "  ⚠ changes Azure",
                    Style::default().fg(theme::warning()),
                ));
            }
            out.push(Line::from(heading));
            items.push(None);
        }
        let selected = pos == state.selected;
        let marker = if selected {
            Span::styled(" ▸ ", Style::default().fg(theme::brand()))
        } else {
            Span::raw("   ")
        };
        let num = if pos < 9 { format!("{}  ", pos + 1) } else { "   ".to_string() };
        let mut style = if a.tier == CliTier::Change {
            Style::default().fg(theme::warning())
        } else {
            Style::default().fg(theme::text_primary())
        };
        if selected {
            style = style.add_modifier(Modifier::BOLD);
        }
        out.push(Line::from(vec![
            marker,
            Span::styled(num, Style::default().fg(theme::text_dim())),
            Span::styled(a.label.clone(), style),
        ]));
        items.push(Some(pos));
    }
    (out, items)
}

/// The selected command, exactly, then its note. Cut at the popup's width
/// by character (an ARM id has no spaces to wrap at), so the line count is
/// exact and the popup sizes to fit it.
fn preview_lines(state: &CommandPickerState, width: usize) -> Vec<Line<'static>> {
    let Some(a) = state.selected_action() else {
        return Vec::new();
    };
    let cmd = Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD);
    let mut out: Vec<Line<'static>> = chunks(&format!(" {}", a.command), width)
        .into_iter()
        .map(|c| Line::styled(c, cmd))
        .collect();
    if let Some(note) = &a.note {
        out.extend(
            chunks(&format!(" · {}", note), width)
                .into_iter()
                .map(|c| Line::styled(c, Style::default().fg(theme::text_dim()))),
        );
    }
    out
}

/// `text` in pieces of at most `width` characters.
fn chunks(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars.chunks(width.max(1)).map(|c| c.iter().collect()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(tier: CliTier, label: &str) -> CliAction {
        CliAction {
            tier,
            label: label.to_string(),
            command: label.to_string(),
            note: None,
        }
    }

    fn picker() -> CommandPickerState {
        CommandPickerState::new(
            "vm-1".into(),
            vec![
                action(CliTier::Inspect, "vm show"),
                action(CliTier::Inspect, "vm get-instance-view"),
                action(CliTier::Change, "vm restart"),
            ],
            None,
        )
    }

    #[test]
    fn the_filter_keeps_catalogue_order_and_resets_the_cursor() {
        let mut p = picker();
        p.next();
        p.next();
        assert_eq!(p.selected_action().unwrap().label, "vm restart");
        p.push_char('r');
        p.push_char('e');
        p.push_char('s');
        assert_eq!(p.selected, 0);
        assert_eq!(p.selected_action().unwrap().label, "vm restart");
        p.clear_filter();
        assert_eq!(p.visible(), vec![0, 1, 2]);
    }

    #[test]
    fn the_tier_name_is_searchable() {
        let mut p = picker();
        for c in "change".chars() {
            p.push_char(c);
        }
        assert_eq!(p.visible(), vec![2]);
    }

    #[test]
    fn movement_stays_in_bounds() {
        let mut p = picker();
        p.prev();
        assert_eq!(p.selected, 0);
        p.last();
        p.next();
        assert_eq!(p.selected, 2);
        assert_eq!(p.nth(1).unwrap().label, "vm get-instance-view");
        assert!(p.nth(9).is_none());
    }
}
