//! The split detail pane — **header | rule | section tab bar | rule | body**
//! — written fresh for nebaz following neboto's conventions (its
//! `details_pane.rs` is 42K lines of per-type renderers; only the row-style
//! conventions and the `descriptor_tabs` shape are carried over, by hand;
//! the `Ctrl-W` wrap layout is ported, marked where it starts).
//!
//! The body is `App::detail_body` — the section (or flat) rows narrowed by
//! the `/` filter — with a one-row filter bar under it while filtering.
//!
//! `style_detail_row` conventions for the `(key, value)` tuples every
//! `*_section_lines` returns:
//! - key + value → key-value row, key padded to the adaptive key column;
//! - empty key + value → plain content line (no colon);
//! - key + empty value, no leading space → group header;
//! - leading-space key + empty value → plain content line;
//! - both empty → blank spacer;
//! - a value starting `· ` → dim annotation row.
//!
//! A line whose value is an ARM id of a browsed type ends in `→`: Enter
//! jumps to it (`app::detail_jump_view`).

use crate::app::{detail_jump_view, App, ClickAction};
use crate::sections::{key_for, SectionDescriptor};
use crate::ui::theme;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Paragraph,
    },
    Frame,
};

const KEY_COL_MIN: usize = 16;
const KEY_COL_MAX: usize = 40;
/// Appended to a line Enter jumps from (neboto's marker).
const JUMP_MARKER: &str = "  →";

/// The footer's hints, dropping the optional ones (least useful first)
/// until the line fits `width`: a block truncates an over-wide title,
/// which cut the `h list` and `⌫ back to …` hints first. Any other key
/// always stays (so does `Esc clear filter` while a filter is on).
fn fit_hints(mut hints: Vec<(&str, &str)>, width: usize) -> Line<'static> {
    const DROP_ORDER: [&str; 7] = ["/", "j/k", "\\", "V", "y", "⏎", "n/N"];
    let mut droppable = DROP_ORDER.iter();
    loop {
        let line = theme::hint_line(&hints);
        if line.width() <= width {
            return line;
        }
        match droppable.next() {
            Some(key) => hints.retain(|(k, _)| k != key),
            None => return line,
        }
    }
}

pub fn render_details_pane(app: &App, area: Rect, frame: &mut Frame) {
    app.mouse.detail_pane.set(Some(area));
    // The referenced-by lens (`U`) owns the pane while open.
    if app.refs_lens.is_some() {
        crate::ui::widgets::refs_lens::render_refs_lens(app, area, frame);
        return;
    }
    // So does the network access lens (`N`).
    if app.network_lens.is_some() {
        crate::ui::widgets::network_lens::render_network_lens(app, area, frame);
        return;
    }
    // So does the change timeline (`W`).
    if app.timeline.is_some() {
        crate::ui::widgets::timeline_lens::render_timeline_lens(app, area, frame);
        return;
    }
    // So does the metrics view (`m`).
    if app.metrics.is_some() {
        crate::ui::widgets::metrics_overlay::render_metrics_overlay(app, area, frame);
        return;
    }
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
        // `h` returns to the list; `⌫` walks history, and says where to
        // when there is somewhere (first, so a narrow pane keeps it).
        let back = app.nav_back_hint().map(|to| format!("back to {to}"));
        let filtered = !app.detail_search_query.is_empty();
        let mut hints: Vec<(&str, &str)> = Vec::new();
        if let Some(back) = back.as_deref() {
            hints.push(("⌫", back));
        }
        hints.extend([
            ("Tab", if app.flat_active() { "header" } else { "section" }),
            ("j/k", "line"),
            if filtered { ("n/N", "match") } else { ("/", "filter") },
            ("V", "select"),
            ("⏎", "jump to id"),
            ("y", "copy"),
            ("\\", flat_hint),
            ("h", "list"),
        ]);
        // While filtering, how to get the whole body back stays visible.
        if filtered {
            hints.push(("Esc", "clear filter"));
        }
        fit_hints(hints, area.width.saturating_sub(2) as usize)
    } else {
        theme::hint_line(&[("⏎", "focus"), ("e", "editor"), ("O", "portal"), ("\\", flat_hint)])
    };
    // The footer's hints are click targets. It is right-aligned inside
    // the bottom border's corners; a footer wider than that is cut by the
    // block, so it gets no regions rather than wrong ones.
    let inner_w = area.width.saturating_sub(2);
    let footer_w = footer.width() as u16;
    if area.height >= 2 && footer_w <= inner_w {
        let x = area.x + 1 + inner_w - footer_w;
        let y = area.y + area.height - 1;
        crate::app::record_hint_regions(app, &footer, 0, x, y, x + footer_w);
    }
    let mut block = theme::pane_block(&title, focused).title_bottom(footer.right_aligned());
    if let Some(ribbon) = ownership_ribbon_line(app, &title, area.width) {
        block = block.title_top(ribbon.right_aligned());
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);
    record_frame_regions(app, area);
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

    // The `/` filter bar takes the body's last row while filtering.
    let filtering = focused && (app.detail_search_active || !app.detail_search_query.is_empty());
    let (body_area, bar_area) = if filtering && body_area.height > 1 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(body_area);
        (split[0], Some(split[1]))
    } else {
        (body_area, None)
    };

    // Body: the cursor line (and the visual range) render on the selection
    // bar when the pane is focused; the view scrolls just enough to keep
    // the cursor on screen. `detail_body` is the filtered body every key
    // indexes, so what is drawn is what `y` copies and `⏎` follows.
    let lines = app.detail_body();
    let key_w = key_col_width(&lines, body_area.width as usize);
    let cursor = app.details_scroll.min(lines.len().saturating_sub(1));
    let query = app.detail_search_query.to_lowercase();
    let code = CodeBlocks::new(&lines, app.syntax_highlight);
    let style_row = |idx: usize| -> Line<'static> {
        let (k, v) = &lines[idx];
        let mut line = style_detail_row(k, v, key_w, app);
        // A selected row keeps the selection's colours.
        if !(focused && app.detail_line_in_selection(idx)) {
            if let Some(spans) = code.spans(&lines, idx) {
                line = recolour_code_row(line, spans);
            }
        }
        if !query.is_empty() {
            line = highlight_matches(line, &query);
        }
        if detail_jump_view(v).is_some() {
            line.spans.push(Span::styled(JUMP_MARKER, Style::default().fg(theme::brand())));
        }
        if focused && app.detail_line_in_selection(idx) {
            let sel = theme::selection_style(true);
            let spans: Vec<Span> = line.spans.into_iter().map(|s| Span::styled(s.content, sel)).collect();
            Line::from(spans).style(sel)
        } else {
            line
        }
    };
    let indent = |idx: usize| {
        let (k, v) = &lines[idx];
        wrap_indent(k, v, key_w)
    };
    let top = app.mouse.detail_top.get();
    let (styled, row_map) = layout_body(lines.len(), body_area, cursor, top, app.detail_wrap, style_row, indent);
    frame.render_widget(Paragraph::new(styled), body_area);
    app.mouse.detail_top.set(row_map.first().copied().unwrap_or(0));
    app.mouse.detail_body.set(Some(body_area));
    *app.mouse.detail_rows.borrow_mut() = row_map;

    if let Some(bar) = bar_area {
        frame.render_widget(Paragraph::new(filter_bar(app)), bar);
    }
}

/// The ownership ribbon (#48, `App::ownership_ribbon`): one dim line on
/// the top border, right of the title, cut to what is left of the border
/// (`None` when under 12 cells are). One central hook: every type gets it.
fn ownership_ribbon_line(app: &App, title: &str, width: u16) -> Option<Line<'static>> {
    let ribbon = app.ownership_ribbon()?;
    // Corners, the title's padding and a gap.
    let budget = (width as usize).saturating_sub(title.chars().count() + 8);
    if budget < 12 {
        return None;
    }
    let mut text = ribbon.text();
    if text.chars().count() > budget {
        text = text.chars().take(budget - 1).collect();
        text.push('…');
    }
    let color = if ribbon.warning { theme::warning() } else { theme::text_dim() };
    Some(Line::from(Span::styled(format!(" {} ", text), Style::default().fg(color))))
}

/// The pane's top border (its title bar) toggles full width, as `Z` does
/// from the pane: the mouse route to the one layout key with no visible
/// control.
fn record_frame_regions(app: &App, area: Rect) {
    if area.height > 0 {
        app.push_click_region(Rect { height: 1, ..area }, ClickAction::Detail(KeyCode::Char('Z')));
    }
}

/// The `/` filter bar: the query (with a caret while typing), the match
/// count, and the keys that leave it.
fn filter_bar(app: &App) -> Line<'static> {
    let n = app.detail_match_rows().len();
    let info = if app.detail_search_query.is_empty() {
        String::new()
    } else {
        format!(" ({} match{})", n, if n == 1 { "" } else { "es" })
    };
    let keys = if app.detail_search_active {
        "  ⏎ keep · Esc clear"
    } else {
        "  n/N next · / new · Esc clear"
    };
    let text = Style::default().fg(theme::text_primary());
    let mut spans = vec![Span::styled(" / ", Style::default().fg(theme::brand()).add_modifier(Modifier::BOLD))];
    if app.detail_search_active {
        // The caret sits on the char under the cursor, or after the text.
        let query = &app.detail_search_query;
        let at = crate::search::line_edit::cursor_index(query, app.detail_search_cursor_back);
        let mut chars = query.chars();
        let before: String = chars.by_ref().take(at).collect();
        let under = chars.next();
        let after: String = chars.collect();
        spans.push(Span::styled(before, text));
        match under {
            Some(c) => spans.push(Span::styled(
                c.to_string(),
                Style::default().fg(theme::brand()).add_modifier(Modifier::REVERSED),
            )),
            None => spans.push(Span::styled("█", Style::default().fg(theme::brand()))),
        }
        spans.push(Span::styled(after, text));
    } else {
        spans.push(Span::styled(app.detail_search_query.clone(), text));
    }
    spans.push(Span::styled(info, Style::default().fg(theme::text_dim())));
    spans.push(Span::styled(keys, Style::default().fg(theme::text_dim())));
    Line::from(spans)
}

/// Reverse-video every case-insensitive occurrence of `query` (already
/// lowercased) inside each span, keeping the span's own style. A span
/// whose lowercase form changes byte length is left as is rather than
/// sliced at a wrong boundary.
fn highlight_matches(line: Line<'static>, query: &str) -> Line<'static> {
    // Matched over the whole line, not span by span: a syntax-coloured code
    // row splits `"effect": "Deny"` into several spans, and a query across
    // them must still mark.
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    let lower = text.to_lowercase();
    if query.is_empty() || lower.len() != text.len() || !lower.contains(query) {
        return line;
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0;
    while let Some(found) = lower[pos..].find(query) {
        let start = pos + found;
        ranges.push((start, start + query.len()));
        pos = start + query.len();
    }
    // Lowercasing kept the length, but not necessarily every char's: don't
    // cut a char in half.
    if ranges.iter().any(|&(a, b)| !text.is_char_boundary(a) || !text.is_char_boundary(b)) {
        return line;
    }
    let style = line.style;
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut offset = 0;
    for span in line.spans {
        let content = span.content.to_string();
        let (start, end) = (offset, offset + content.len());
        offset = end;
        let mut cur = start;
        for &(a, b) in &ranges {
            let (a, b) = (a.max(cur), b.min(end));
            if a >= b {
                continue;
            }
            if a > cur {
                out.push(Span::styled(content[cur - start..a - start].to_string(), span.style));
            }
            out.push(Span::styled(
                content[a - start..b - start].to_string(),
                span.style.add_modifier(Modifier::REVERSED),
            ));
            cur = b;
        }
        if cur < end {
            out.push(Span::styled(content[cur - start..].to_string(), span.style));
        }
    }
    Line::from(out).style(style)
}

/// The runs of plain content rows in a body that read as code, coloured at
/// render time by `ui::syntax` (ported from neboto #304). Detected from the
/// rows themselves each frame, so no pane declares anything and the rows
/// stay plain text for copy, export, `nebaz get` and `/`. A run is
/// highlighted whole (YAML block scalars carry state from line to line),
/// and only once something in it is drawn.
struct CodeBlocks {
    /// Each row's run, as an index into `runs`.
    run_of: Vec<Option<usize>>,
    /// `(first row, end row, language)`.
    runs: Vec<(usize, usize, crate::ui::syntax::Lang)>,
    lit: std::cell::RefCell<std::collections::HashMap<usize, Vec<Vec<Span<'static>>>>>,
}

impl CodeBlocks {
    fn new(rows: &[(String, String)], enabled: bool) -> Self {
        let mut blocks = CodeBlocks { run_of: Vec::new(), runs: Vec::new(), lit: Default::default() };
        if !enabled {
            return blocks;
        }
        blocks.run_of = vec![None; rows.len()];
        let mut i = 0;
        while i < rows.len() {
            if code_text(&rows[i]).is_none() {
                i += 1;
                continue;
            }
            let start = i;
            while i < rows.len() && code_text(&rows[i]).is_some() {
                i += 1;
            }
            let lines: Vec<&str> = rows[start..i].iter().filter_map(code_text).collect();
            if let Some(lang) = crate::ui::syntax::detect(&lines) {
                let run = blocks.runs.len();
                blocks.runs.push((start, i, lang));
                blocks.run_of[start..i].fill(Some(run));
            }
        }
        blocks
    }

    /// The row's coloured spans, as drawn (a value-only row keeps its
    /// two-space content indent, and the code's own indentation after it).
    fn spans(&self, rows: &[(String, String)], idx: usize) -> Option<Vec<Span<'static>>> {
        let run = (*self.run_of.get(idx)?)?;
        let (start, end, lang) = self.runs[run];
        let mut lit = self.lit.borrow_mut();
        let lines = lit.entry(run).or_insert_with(|| {
            let text: Vec<&str> = rows[start..end].iter().filter_map(code_text).collect();
            crate::ui::syntax::highlight(lang, &text)
        });
        let mut spans = lines.get(idx - start).cloned()?;
        if rows[idx].0.trim().is_empty() {
            spans.insert(0, Span::raw("  "));
        }
        Some(spans)
    }
}

/// The text of a plain content row (`style_detail_row`'s leading-space key
/// with no value, or a blank key with only a value) that isn't one of its
/// styled variants: a warning, an error, a `· ` annotation or a tab-split
/// note. `None` for anything else.
fn code_text(row: &(String, String)) -> Option<&str> {
    let (key, value) = (row.0.as_str(), row.1.as_str());
    let text = if key.trim().is_empty() {
        value
    } else if key.starts_with(' ') && value.is_empty() {
        key
    } else {
        return None;
    };
    let t = text.trim_start();
    (!t.is_empty() && !text.contains('\t') && !t.starts_with('⚠') && !t.starts_with('✗') && !t.starts_with("· "))
        .then_some(text)
}

/// Swap a plain content row's text for its coloured spans, keeping
/// anything the renderer appended after it (the `→` jump hint).
fn recolour_code_row(mut line: Line<'static>, spans: Vec<Span<'static>>) -> Line<'static> {
    if line.spans.is_empty() {
        return line;
    }
    let tail = line.spans.split_off(1);
    line.spans = spans;
    line.spans.extend(tail);
    line
}

/// Columns a wrapped body keeps free at the right edge for a row's `  →`
/// jump marker, so it lands on the row's last screen line.
const WRAP_ARROW_RESERVE: usize = 3;
/// Narrowest text column a continuation row is ever given.
const WRAP_MIN_COLS: usize = 12;

/// Hanging indent for a wrapped row's continuation lines: the value
/// column for a `key: value` row (`"  " + key column + ": "`), the
/// two-space content indent for anything else.
fn wrap_indent(key: &str, value: &str, key_w: usize) -> usize {
    if !key.trim().is_empty() && !value.is_empty() {
        key_w + 4
    } else {
        2
    }
}

// ported from neboto-tui src/ui/widgets/details_pane/mod.rs @ 7330ba4
// (layout_detail_body, wrap_styled_line, first_visible_row; the screen-row
// map came with the mouse, #42, and the scroll keeps last frame's top)
/// Lay out the body into exactly the screen lines that fit `area`, keeping
/// the logical `cursor` row fully on screen, and say which logical row
/// each screen line shows (the mouse maps a click through it).
/// `style_row(idx)` renders one logical row. The view keeps `top`, last
/// frame's first row, while the cursor stays fully on screen, so neither
/// `k` nor a click scrolls a line out from under the pointer. Clip mode
/// is one screen line per row. With `wrap` on, a long row continues on
/// hanging-indent lines (`indent(idx)` columns), and a scroll is computed
/// in screen rows, bottom-up from the cursor, so a wrapped cursor row is
/// never cut off (`Paragraph::wrap` would anchor to the top and clip).
/// Everything that indexes the body stays on logical rows; only the
/// screen shape changes.
fn layout_body(
    count: usize,
    area: Rect,
    cursor: usize,
    top: usize,
    wrap: bool,
    style_row: impl Fn(usize) -> Line<'static>,
    indent: impl Fn(usize) -> usize,
) -> (Vec<Line<'static>>, Vec<usize>) {
    let height = area.height as usize;
    if count == 0 || height == 0 {
        return (Vec::new(), Vec::new());
    }
    let cursor = cursor.min(count - 1);
    if !wrap {
        let offset = if cursor < top {
            cursor
        } else if cursor >= top + height {
            cursor + 1 - height
        } else {
            // No blank tail while there are rows above to show.
            top.min(count.saturating_sub(height))
        };
        let rows: Vec<usize> = (offset..count.min(offset + height)).collect();
        return (rows.iter().map(|&i| style_row(i)).collect(), rows);
    }
    let avail = (area.width as usize).saturating_sub(WRAP_ARROW_RESERVE).max(1);
    let wrapped = |idx: usize| -> Vec<Line<'static>> {
        let mut line = style_row(idx);
        let arrow = if line.spans.last().is_some_and(|s| s.content == JUMP_MARKER) {
            line.spans.pop()
        } else {
            None
        };
        let hang = indent(idx).min(avail.saturating_sub(WRAP_MIN_COLS));
        let mut rows = wrap_styled_line(line, avail, hang);
        if let (Some(a), Some(last)) = (arrow, rows.last_mut()) {
            last.spans.push(a);
        }
        rows
    };
    // Keep `top` when every row from it through the cursor fits.
    let fits_from_top = cursor >= top && (top..=cursor).map(|idx| wrapped(idx).len()).sum::<usize>() <= height;
    let first = if fits_from_top { top } else { first_visible_row(cursor, height, |idx| wrapped(idx).len()) };
    let mut out: Vec<Line<'static>> = Vec::with_capacity(height);
    let mut rows: Vec<usize> = Vec::with_capacity(height);
    for idx in first..count {
        for line in wrapped(idx) {
            if out.len() >= height {
                return (out, rows);
            }
            out.push(line);
            rows.push(idx);
        }
    }
    (out, rows)
}

/// First logical row to draw so the cursor row ends up fully visible:
/// walk back from the cursor adding row heights while they still fit. A
/// cursor row taller than the pane starts at its own top.
fn first_visible_row(cursor: usize, visible_height: usize, height: impl Fn(usize) -> usize) -> usize {
    let mut used = height(cursor);
    let mut first = cursor;
    while first > 0 {
        let h = height(first - 1);
        if used + h > visible_height {
            break;
        }
        used += h;
        first -= 1;
    }
    first
}

/// Split one styled line into screen rows of at most `avail` display
/// columns: the first row as is, every following row prefixed with
/// `indent` spaces. Splits by display width, never bytes or chars, so a
/// wide glyph is never cut in half; span styles and the line's own style
/// carry over to every row.
fn wrap_styled_line(line: Line<'static>, avail: usize, indent: usize) -> Vec<Line<'static>> {
    use unicode_width::UnicodeWidthChar;
    let avail = avail.max(1);
    if line.width() <= avail {
        return vec![line];
    }
    let line_style = line.style;
    let mut out: Vec<Line<'static>> = Vec::new();
    let mut cur: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    let mut cap = avail;
    for span in line.spans {
        let mut buf = String::new();
        for ch in span.content.chars() {
            let cw = ch.width().unwrap_or(0);
            if used + cw > cap && used > 0 {
                if !buf.is_empty() {
                    cur.push(Span::styled(std::mem::take(&mut buf), span.style));
                }
                out.push(Line::from(std::mem::take(&mut cur)).style(line_style));
                cur.push(Span::raw(" ".repeat(indent)));
                used = 0;
                cap = avail.saturating_sub(indent).max(1);
                if ch == ' ' {
                    continue; // a continuation never starts with the break space
                }
            }
            buf.push(ch);
            used += cw;
        }
        if !buf.is_empty() {
            cur.push(Span::styled(buf, span.style));
        }
    }
    if !cur.is_empty() {
        out.push(Line::from(cur).style(line_style));
    }
    out
}

fn rule(width: u16) -> Paragraph<'static> {
    Paragraph::new(Line::styled(
        "─".repeat(width as usize),
        Style::default().fg(theme::border_dim()),
    ))
}

/// The section tab bar for a descriptor: `1 Overview │ 2 Details │ …`, the
/// active chip highlighted, each chip recorded as a click region. Generic
/// over every split pane — no per-type tab widgets. It scrolls around the
/// active section with `‹`/`›` when the pane is too narrow, as the sub-tab
/// bar does.
pub fn descriptor_tabs(app: &App, desc: &'static SectionDescriptor, area: Rect) -> Line<'static> {
    let tabs: Vec<(char, &str, bool)> = desc
        .sections
        .iter()
        .enumerate()
        .map(|(i, s)| (key_for(i).unwrap_or(' '), s.label, i == app.detail_section_idx))
        .collect();
    // `‹` / `›` step one section (or header, in the flat view), as Tab does.
    Line::from(crate::ui::widgets::subtab_bar::chip_spans(
        app,
        area,
        &tabs,
        ClickAction::Detail,
        (KeyCode::BackTab, KeyCode::Tab),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn a_long_line_wraps_under_its_hanging_indent() {
        let line = Line::from(vec![Span::raw("  Key : "), Span::raw("abcdefghijklmnop")]);
        let rows: Vec<String> = wrap_styled_line(line, 12, 8).iter().map(text).collect();
        assert_eq!(rows, ["  Key : abcd", "        efgh", "        ijkl", "        mnop"]);
        // A line that fits is untouched.
        assert_eq!(wrap_styled_line(Line::raw("short"), 12, 8).len(), 1);
    }

    #[test]
    fn a_narrow_footer_drops_the_filter_hints_but_keeps_esc_clear_filter() {
        let hints = vec![("Tab", "section"), ("n/N", "match"), ("V", "select"), ("h", "list"), ("Esc", "clear filter")];
        let line = text(&fit_hints(hints, 45));
        assert!(!line.contains("n/N") && line.contains("Esc") && line.contains("clear filter"), "{line}");
        let line = text(&fit_hints(vec![("Tab", "section"), ("/", "filter"), ("h", "list")], 20));
        assert!(!line.contains("filter"), "{line}");
    }

    #[test]
    fn a_wide_glyph_is_never_split() {
        let rows: Vec<String> = wrap_styled_line(Line::raw("ab漢字"), 5, 0).iter().map(text).collect();
        assert_eq!(rows, ["ab漢", "字"]);
    }

    #[test]
    fn the_cursor_row_is_fully_visible() {
        // Rows of heights 1, 3, 1, 4 in a 5-row pane.
        let heights = [1, 3, 1, 4];
        let h = |i: usize| heights[i];
        assert_eq!(first_visible_row(3, 5, h), 2);
        assert_eq!(first_visible_row(1, 5, h), 0);
        // Taller than the pane: it starts at its own top.
        assert_eq!(first_visible_row(3, 3, h), 3);
    }

    #[test]
    fn matches_are_marked_case_insensitively_in_place() {
        let line = highlight_matches(Line::from(vec![Span::raw("NIC vm-1-Nic")]), "nic");
        let marked: Vec<&str> = line
            .spans
            .iter()
            .filter(|s| s.style.add_modifier.contains(Modifier::REVERSED))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(marked, ["NIC", "Nic"]);
        assert_eq!(text(&line), "NIC vm-1-Nic");
    }
}

#[cfg(test)]
mod code_block_tests {
    use super::*;

    fn rows(spec: &[(&str, &str)]) -> Vec<(String, String)> {
        spec.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn only_runs_that_read_as_code_are_coloured() {
        let body = rows(&[
            ("Rule", ""),
            ("", "{"),
            ("", "  \"effect\": \"deny\""),
            ("", "}"),
            ("", ""),
            ("Prefixes", ""),
            ("", "10.0.0.0/16"),
            ("", "10.1.0.0/16"),
            ("Name", "web"),
            ("  ⚠ 403 Forbidden", ""),
        ]);
        let code = CodeBlocks::new(&body, true);
        let coloured: Vec<usize> = (0..body.len()).filter(|&i| code.spans(&body, i).is_some()).collect();
        assert_eq!(coloured, vec![1, 2, 3]);
        // The spans are the row as drawn: the content indent, then the line.
        let spans = code.spans(&body, 2).unwrap();
        assert_eq!(spans.iter().map(|s| s.content.as_ref()).collect::<String>(), "    \"effect\": \"deny\"");
        // Off means off.
        assert!(CodeBlocks::new(&body, false).spans(&body, 2).is_none());
    }

    #[test]
    fn key_style_content_rows_are_code_too() {
        let body = rows(&[("  {", ""), ("    \"a\": 1", ""), ("  }", "")]);
        let code = CodeBlocks::new(&body, true);
        let spans = code.spans(&body, 1).unwrap();
        assert_eq!(spans.iter().map(|s| s.content.as_ref()).collect::<String>(), body[1].0);
    }

    #[test]
    fn recolour_keeps_the_jump_arrow() {
        let line = Line::from(vec![Span::raw("  \"id\": \"x\""), Span::raw("  →")]);
        let spans = vec![Span::raw("  \"id\""), Span::raw(": \"x\"")];
        let out = recolour_code_row(line, spans);
        assert_eq!(out.spans.len(), 3);
        assert_eq!(out.spans[2].content, "  →");
    }

    #[test]
    fn search_marks_a_match_across_spans() {
        let line = Line::from(vec![Span::raw("\"effect\""), Span::raw(": "), Span::raw("\"deny\"")]);
        let out = highlight_matches(line, "t\": \"de");
        let marked: String = out
            .spans
            .iter()
            .filter(|s| s.style.add_modifier.contains(Modifier::REVERSED))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(marked, "t\": \"de");
        let all: String = out.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(all, "\"effect\": \"deny\"");
    }
}
