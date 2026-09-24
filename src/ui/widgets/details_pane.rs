//! The split detail pane — **header | rule | section tab bar | rule | body**
//! — written fresh for nebaz following neboto's conventions (its
//! `details_pane.rs` is 42K lines of per-type renderers; only the row-style
//! conventions and the `descriptor_tabs` shape are carried over, by hand).
//!
//! `style_detail_row` conventions for the `(key, value)` tuples every
//! `*_section_lines` returns:
//! - key + value → key-value row, key padded to the adaptive key column;
//! - empty key + value → plain content line (no colon);
//! - key + empty value, no leading space → group header;
//! - leading-space key + empty value → plain content line;
//! - both empty → blank spacer;
//! - a value starting `· ` → dim annotation row.

use crate::app::{App, ClickAction};
use crate::sections::{key_for, SectionDescriptor};
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        block::{Position, Title},
        Paragraph,
    },
    Frame,
};

const KEY_COL_MIN: usize = 16;
const KEY_COL_MAX: usize = 40;

pub fn render_details_pane(app: &App, area: Rect, frame: &mut Frame) {
    let focused = app.details_focused;
    let Some(resource) = app.get_selected_resource() else {
        let block = theme::pane_block("Details", focused);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let msg = if app.filtered_resources.is_empty() {
            "No resource selected"
        } else {
            "Select a resource"
        };
        frame.render_widget(
            Paragraph::new(Line::styled(msg, Style::default().fg(theme::text_dim())))
                .alignment(Alignment::Center),
            Rect {
                y: inner.y + inner.height / 2,
                height: 1,
                ..inner
            },
        );
        return;
    };

    let title = format!("{} · {}", resource.resource_type(), resource.name());
    let flat_hint = if app.detail_flat_mode { "tabs" } else { "flat" };
    let footer = if focused {
        theme::hint_line(&[
            ("Tab", if app.flat_active() { "header" } else { "section" }),
            ("j/k", "line"),
            ("V", "select"),
            ("⏎", "jump to id"),
            ("y", "copy"),
            ("\\", flat_hint),
            ("Esc", "back"),
        ])
    } else {
        theme::hint_line(&[("⏎", "focus"), ("e", "editor"), ("O", "portal"), ("\\", flat_hint)])
    };
    let block = theme::pane_block(&title, focused).title(
        Title::from(footer)
            .position(Position::Bottom)
            .alignment(Alignment::Right),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height < 3 {
        return;
    }

    let descriptor = resource.detail_sections();
    let mut constraints = vec![Constraint::Length(1), Constraint::Length(1)];
    if descriptor.is_some() {
        constraints.push(Constraint::Length(1)); // tab bar
        constraints.push(Constraint::Length(1)); // rule
    }
    constraints.push(Constraint::Min(0));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // Header: state dot + name, id dim on the right.
    let (dot, dot_color) = theme::state_indicator(&resource.state());
    let mut header = vec![
        Span::styled(format!(" {} ", dot), Style::default().fg(dot_color)),
        Span::styled(
            resource.name().to_string(),
            Style::default()
                .fg(theme::text_primary())
                .add_modifier(Modifier::BOLD),
        ),
    ];
    let label = resource.state_label();
    if !label.is_empty() {
        header.push(Span::styled(
            format!("  {}", label),
            Style::default().fg(dot_color),
        ));
    }
    if let Some(loc) = resource.location() {
        header.push(Span::styled(
            format!("  {}", loc),
            Style::default().fg(theme::text_dim()),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), rows[0]);
    frame.render_widget(rule(inner.width), rows[1]);

    let body_area = if let Some(desc) = descriptor {
        frame.render_widget(
            Paragraph::new(descriptor_tabs(app, desc, rows[2])),
            rows[2],
        );
        frame.render_widget(rule(inner.width), rows[3]);
        rows[4]
    } else {
        rows[2]
    };

    // Body: the cursor line (and the visual range) render on the selection
    // bar when the pane is focused; the view scrolls just enough to keep
    // the cursor on screen.
    let lines = app.get_detail_lines();
    let key_w = key_col_width(&lines, body_area.width as usize);
    let height = body_area.height as usize;
    let cursor = app.details_scroll.min(lines.len().saturating_sub(1));
    let offset = cursor.saturating_sub(height.saturating_sub(1));
    let styled: Vec<Line> = lines
        .iter()
        .enumerate()
        .skip(offset)
        .take(height)
        .map(|(idx, (k, v))| {
            let line = style_detail_row(k, v, key_w, app);
            if focused && app.detail_line_in_selection(idx) {
                let sel = theme::selection_style(true);
                let spans: Vec<Span> = line.spans.into_iter().map(|s| Span::styled(s.content, sel)).collect();
                Line::from(spans).style(sel)
            } else {
                line
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(styled), body_area);
}

fn rule(width: u16) -> Paragraph<'static> {
    Paragraph::new(Line::styled(
        "─".repeat(width as usize),
        Style::default().fg(theme::border_dim()),
    ))
}

/// The section tab bar for a descriptor: `1 Overview │ 2 Details │ …`, the
/// active chip highlighted, each chip recorded as a click region. Generic
/// over every split pane — no per-type tab widgets.
pub fn descriptor_tabs(app: &App, desc: &'static SectionDescriptor, area: Rect) -> Line<'static> {
    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    let mut x = area.x + 1;
    for (i, section) in desc.sections.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(theme::text_dim())));
            x += 3;
        }
        let key = key_for(i).unwrap_or(' ');
        let is_active = i == app.detail_section_idx;
        let w = section.label.chars().count() as u16 + 3;
        app.push_click_region(
            Rect {
                x,
                y: area.y,
                width: w,
                height: 1,
            },
            ClickAction::DetailSection(key),
        );
        x += w;
        if is_active {
            spans.push(Span::styled(
                key.to_string(),
                Style::default().fg(theme::brand()).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                format!(" {} ", section.label),
                Style::default()
                    .fg(Color::Black)
                    .bg(theme::brand())
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(key.to_string(), Style::default().fg(theme::accent())));
            spans.push(Span::styled(
                format!(" {} ", section.label),
                Style::default().fg(theme::text_muted()),
            ));
        }
    }
    Line::from(spans)
}

/// Adaptive key column: the widest key in the body, clamped to
/// `[KEY_COL_MIN, KEY_COL_MAX]` and to what the pane can spare.
fn key_col_width(lines: &[(String, String)], pane_width: usize) -> usize {
    let widest = lines
        .iter()
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    widest
        .clamp(KEY_COL_MIN, KEY_COL_MAX)
        .min(pane_width.saturating_sub(12).max(KEY_COL_MIN))
}

fn style_detail_row(key: &str, value: &str, key_w: usize, app: &App) -> Line<'static> {
    let key_blank = key.trim().is_empty();
    if key_blank && value.is_empty() {
        return Line::raw("");
    }
    // Plain content line: empty key + value, or leading-space key + no value.
    if key_blank || (key.starts_with(' ') && value.is_empty()) {
        let text = if key_blank { value } else { key }.trim_start();
        let style = if text.starts_with("· ") {
            Style::default().fg(theme::text_dim())
        } else if text.starts_with('⚠') || text.starts_with('✗') {
            Style::default().fg(theme::warning())
        } else {
            Style::default().fg(theme::text_primary())
        };
        return Line::from(Span::styled(format!("  {}", text), style));
    }
    // Flat-view section header (`━━ Name ━━━…`, inserted by the flat body
    // assembly): brand-bold so sections read apart from group headers.
    if value.is_empty() && crate::app::flat_header_name(key).is_some() {
        return Line::from(Span::styled(
            key.to_string(),
            Style::default().fg(theme::brand()).add_modifier(Modifier::BOLD),
        ));
    }
    // Group header: key, no value, no leading space.
    if value.is_empty() {
        return Line::from(Span::styled(
            key.to_string(),
            Style::default()
                .fg(theme::heading())
                .add_modifier(Modifier::BOLD),
        ));
    }
    // Key-value row.
    let mut k: String = key.chars().take(key_w).collect();
    if key.chars().count() > key_w {
        k.pop();
        k.push('…');
    }
    let pad = " ".repeat(key_w.saturating_sub(k.chars().count()));
    let value = spin_loading_row(value, app);
    let vstyle = if value.starts_with("· ") {
        Style::default().fg(theme::text_dim())
    } else if value.starts_with('✓') {
        Style::default().fg(theme::success())
    } else if value.starts_with('✗') || value.starts_with('⚠') {
        Style::default().fg(theme::warning())
    } else {
        Style::default().fg(theme::text_primary())
    };
    Line::from(vec![
        Span::styled(format!("  {}{}", k, pad), Style::default().fg(theme::accent())),
        Span::styled(": ", Style::default().fg(theme::text_dim())),
        Span::styled(value, vstyle),
    ])
}

/// The `Loading…` rewrite: an animated spinner when the pane is focused (a
/// fetch really is in flight), a static hint otherwise.
fn spin_loading_row(value: &str, app: &App) -> String {
    if value != "Loading…" {
        return value.to_string();
    }
    if app.details_focused {
        format!("{} Loading…", theme::spinner(app.tick_count))
    } else {
        "· not loaded — ⏎ to open".to_string()
    }
}
