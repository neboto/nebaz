// ported from neboto-tui src/ui/widgets/help_overlay.rs @ 6e0163d (type-to-filter, #150; the layout is nebaz's own)
use crate::app::App;
use crate::search::fuzzy::FuzzyMatcher;
use crate::ui::theme;
use unicode_width::UnicodeWidthStr;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        block::{Position, Title},
        Clear, Paragraph,
    },
    Frame,
};

struct Section {
    title: &'static str,
    entries: &'static [(&'static str, &'static str)],
}

// Help entries are one line each — short labels, never sentences. There is no
// word wrap: anything that can't fit the column is truncated with `…`, so
// keep descriptions tight and put detail in the feature itself.
const LEFT_SECTIONS: &[Section] = &[
    Section {
        title: "List pane",
        entries: &[
            ("j / k ↑ / ↓", "move"),
            ("gg / G", "top / bottom"),
            ("^d / ^u", "half page"),
            ("l / → / ⏎", "open details"),
            ("h / ←", "back to the list"),
            ("⌫ / Ctrl-O", "history back"),
            ("Ctrl-F", "history forward"),
            ("`", "jump list (history)"),
            ("B / '", "bookmark / bookmarks"),
            ("Tab · 1–9", "sub-tabs"),
            ("H / L", "prev / next sub-tab"),
            ("y · X · ^X", "copy · export"),
            ("V · J / K · ^A", "select rows · extend · all"),
            ("  y·c / X / ^X", "md table / deep / list export"),
            ("a", "hide noisy rows"),
            ("[ / ]", "@changes window"),
            ("z", "cycle sort"),
            ("F", "cycle state filter"),
            ("r / F5", "refresh service"),
        ],
    },
    Section {
        title: "Detail pane",
        entries: &[
            ("Tab · 1–9", "sections (flat: headers)"),
            ("j / k · g / G", "line · top / bottom"),
            ("V · J / K · ^A", "select · extend · all"),
            ("\\", "flat view (all sections)"),
            ("/ · n / N", "filter · step matches (else N lens)"),
            ("[[ / ]]", "prev / next group header"),
            ("^W", "wrap long values"),
            ("H / L", "sub-tab (opens its first row)"),
            ("⏎", "jump to the ARM id on the line"),
            ("y", "copy line or selection"),
            ("^L", "repaint the screen"),
            ("Z", "full-width pane"),
            ("r", "refresh this resource"),
        ],
    },
];

const RIGHT_SECTIONS: &[Section] = &[
    Section {
        title: "Actions",
        entries: &[
            ("O", "open in Azure portal"),
            ("y", "copy resource id"),
            ("C", "copy an az command (never run)"),
            ("e", "open in $EDITOR"),
            ("N", "network access (NSG rules)"),
            ("U", "referenced by (warm lists; L loads likely)"),
            ("m", "metrics (Azure Monitor)"),
            ("W", "change timeline (f · [ / ])"),
            ("X / ^X", "export detail / list"),
            ("M", "message history"),
            (",", "macros (⏎ run · n record)"),
            ("b", "toggle banner"),
            ("? / q", "help (type to filter) / quit"),
        ],
    },
    Section {
        title: "Search",
        entries: &[
            ("/", "fuzzy search"),
            ("@svc text", "switch service + search"),
            ("@rg @disk @nsg …", "switch to a sub-tab"),
            ("rg:name", "resource group filter"),
            ("tag:k=v", "exact tag filter"),
            ("@* …", "search every cached list"),
            ("Tab", "complete @prefix"),
            ("↑ / ↓", "earlier searches"),
        ],
    },
    Section {
        title: "Context",
        entries: &[
            ("S / R / P", "service / location / subscription"),
            ("@vm …", "switch via prefix"),
        ],
    },
    Section {
        title: "Mouse",
        entries: &[
            ("click", "row · line · chip · hint"),
            ("double-click", "⏎ (open · jump)"),
            ("right-click", "⌫ back · close a popup"),
            ("drag", "select rows / lines"),
            ("wheel", "scroll the pane under it"),
            ("Shift-drag", "terminal text selection"),
        ],
    },
    Section {
        title: "@audit",
        entries: &[
            ("⏎", "open the finding's resource"),
            ("l / →", "evidence + remediation (text)"),
            ("r", "load missing sources, re-audit"),
            ("F · z", "filter · sort by severity"),
        ],
    },
];

/// Columns between the two help columns, so a truncated left entry never
/// runs into a right-column title.
const GUTTER: u16 = 3;

/// One section as drawn: the full table, or the entries left by a filter.
struct Group {
    title: &'static str,
    entries: Vec<(&'static str, &'static str)>,
}

fn groups(sections: &'static [Section]) -> Vec<Group> {
    sections
        .iter()
        .map(|s| Group { title: s.title, entries: s.entries.to_vec() })
        .collect()
}

/// The entries `query` matches, both columns in reading order (left, then
/// right), each kept under its section title. An entry matches on its key,
/// its description or its section's title, so `mouse` lists the whole Mouse
/// section. Order is the table's, not the score's: the result still reads
/// as the help, just shorter.
fn filter_groups(query: &str) -> Vec<Group> {
    let all: Vec<(&'static str, &'static str, &'static str)> = LEFT_SECTIONS
        .iter()
        .chain(RIGHT_SECTIONS)
        .flat_map(|s| s.entries.iter().map(move |(k, d)| (s.title, *k, *d)))
        .collect();
    let mut hits: Vec<usize> = FuzzyMatcher::new()
        .filter_fields(query, &all, |(title, key, desc)| vec![*key, *desc, *title])
        .into_iter()
        .map(|(i, _)| i)
        .collect();
    hits.sort_unstable();
    let mut out: Vec<Group> = Vec::new();
    for i in hits {
        let (title, key, desc) = all[i];
        match out.last_mut() {
            Some(g) if g.title == title => g.entries.push((key, desc)),
            _ => out.push(Group { title, entries: vec![(key, desc)] }),
        }
    }
    out
}

/// Render the help overlay: a filter row over two aligned key/description
/// columns, sized to the content (capped by the terminal), scrollable when it
/// doesn't fit. Typing filters it to one full-width column, so a matched
/// entry has room for its whole description.
pub fn render_help_overlay(app: &App, frame: &mut Frame) {
    let size = frame.size();

    // Width: what the content needs, so nothing is truncated while the
    // terminal has room. A narrower terminal shares the space in proportion
    // to each column's need; only then do descriptions get a `…`.
    let (left, right) = (groups(LEFT_SECTIONS), groups(RIGHT_SECTIONS));
    let (left_need, right_need) = (natural_width(&left), natural_width(&right));
    let chrome = 2 + 4 + GUTTER; // borders + margins + gutter
    let width = (left_need + right_need + chrome).min(size.width.saturating_sub(4)).max(40);
    let avail = width.saturating_sub(chrome);
    let (left_w, right_w) = if left_need + right_need <= avail {
        (left_need, avail - left_need)
    } else {
        let left = (avail as u32 * left_need as u32 / (left_need + right_need) as u32) as u16;
        (left, avail - left)
    };

    let left_lines = section_lines(&left, left_w as usize);
    let right_lines = section_lines(&right, right_w as usize);
    let full_h = left_lines.len().max(right_lines.len()) as u16;

    let query = app.help_query.as_str();
    let filtered = (!query.trim().is_empty()).then(|| {
        let matches = filter_groups(query);
        if matches.is_empty() {
            vec![
                Line::raw(""),
                Line::from(Span::styled(
                    format!("  No keys match \"{}\"", query.trim()),
                    Style::default().fg(theme::text_dim()),
                )),
            ]
        } else {
            section_lines(&matches, width.saturating_sub(2 + 4) as usize)
        }
    });
    let content_h = filtered.as_ref().map_or(full_h, |l| l.len() as u16);

    // Height: fit the unfiltered content plus the filter row, so the popup
    // holds still while you type; cap at 80% of the terminal and scroll.
    let max_h = (size.height * 80 / 100).max(10);
    let height = (full_h + 1 + 2).min(max_h);
    let area = centered_rect(width, height, size);
    let viewport = height.saturating_sub(2 + 1);
    let max_scroll = content_h.saturating_sub(viewport);
    app.help_max_scroll.set(max_scroll);
    let offset = app.help_scroll.min(max_scroll);

    frame.render_widget(Clear, area);
    app.mouse.popup.borrow_mut().record_area(area);

    let mut block = theme::popup_block("Help").title(
        Title::from(Span::styled(
            if max_scroll > 0 {
                " type to filter · ↑/↓ scroll · Esc close "
            } else {
                " type to filter · Esc close "
            },
            Style::default().fg(theme::text_dim()),
        ))
        .position(Position::Bottom)
        .alignment(Alignment::Center),
    );
    if max_scroll > 0 {
        // Overflow indicator: which slice of the content is on screen.
        block = block.title(
            Title::from(Span::styled(
                format!(" {}–{}/{} ", offset + 1, (offset + viewport).min(content_h), content_h),
                Style::default().fg(theme::text_dim()),
            ))
            .position(Position::Bottom)
            .alignment(Alignment::Right),
        );
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);
    frame.render_widget(Paragraph::new(filter_line(query)), rows[0]);

    if let Some(lines) = filtered {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .horizontal_margin(2)
            .constraints([Constraint::Min(0)])
            .split(rows[1]);
        frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), body[0]);
        return;
    }

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(left_w),
            Constraint::Length(GUTTER),
            Constraint::Min(0),
        ])
        .horizontal_margin(2)
        .split(rows[1]);

    frame.render_widget(
        Paragraph::new(left_lines).scroll((offset, 0)),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(right_lines).scroll((offset, 0)),
        columns[2],
    );
}

/// The filter row: the query with a cursor, or a dim placeholder.
fn filter_line(query: &str) -> Line<'static> {
    let prompt = Span::styled("  / ", Style::default().fg(theme::accent()));
    if query.is_empty() {
        Line::from(vec![
            prompt,
            Span::styled("type to filter keys", Style::default().fg(theme::text_dim())),
        ])
    } else {
        Line::from(vec![
            prompt,
            Span::styled(query.to_string(), Style::default().fg(theme::text_primary())),
            Span::styled("▏", Style::default().fg(theme::accent())),
        ])
    }
}

/// Key column width shared by a column's entries.
fn key_width(sections: &[Group]) -> usize {
    sections
        .iter()
        .flat_map(|s| s.entries.iter())
        .map(|(key, _)| key.width())
        .max()
        .unwrap_or(0)
}

/// The width a column needs to show every entry untruncated.
fn natural_width(sections: &[Group]) -> u16 {
    let desc = sections
        .iter()
        .flat_map(|s| s.entries.iter())
        .map(|(_, desc)| desc.width())
        .max()
        .unwrap_or(0);
    let titles = sections.iter().map(|s| s.title.width()).max().unwrap_or(0);
    (2 + key_width(sections) + 2 + desc).max(titles) as u16
}

/// Build one column's lines: section titles + `key  description` rows with
/// the keys right-padded to a shared column. No wrapping — a description
/// that can't fit is truncated with `…`.
fn section_lines(sections: &[Group], col_width: usize) -> Vec<Line<'static>> {
    let key_width = key_width(sections);
    let desc_budget = col_width.saturating_sub(2 + key_width + 2);

    let mut lines = vec![Line::raw("")];
    for section in sections {
        lines.push(Line::from(Span::styled(
            section.title,
            Style::default()
                .fg(theme::warning())
                .add_modifier(Modifier::BOLD),
        )));
        for (key, desc) in &section.entries {
            let pad = " ".repeat(key_width.saturating_sub(key.width()) + 2);
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    *key,
                    Style::default()
                        .fg(theme::accent())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(pad),
                Span::styled(truncate(desc, desc_budget), Style::default().fg(crate::ui::theme::text_muted())),
            ]));
        }
        lines.push(Line::raw(""));
    }
    // Drop the trailing blank so content height is exact.
    lines.pop();
    lines
}

/// Truncate to `max` display characters, ellipsized.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let mut s: String = text.chars().take(max - 1).collect();
        s.push('…');
        s
    }
}

/// Centered rectangle with a fixed size (not percentage-based — the popup is
/// sized to its content by the caller).
fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let width = width.min(r.width);
    let height = height.min(r.height);
    Rect {
        x: r.x + (r.width - width) / 2,
        y: r.y + (r.height - height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_line_exceeds_the_column_budget() {
        // The whole point of the redesign: nothing wraps. Every built line
        // must fit the column it was built for, at a typical column width.
        for col_width in [30usize, 40, 52] {
            for sections in [LEFT_SECTIONS, RIGHT_SECTIONS] {
                for line in section_lines(&groups(sections), col_width) {
                    assert!(
                        line.width() <= col_width,
                        "line {:?} is {} wide, budget {}",
                        line,
                        line.width(),
                        col_width
                    );
                }
            }
        }
    }

    fn keys(groups: &[Group]) -> Vec<&'static str> {
        groups.iter().flat_map(|g| g.entries.iter().map(|(k, _)| *k)).collect()
    }

    #[test]
    fn filter_matches_descriptions_and_keeps_section_titles() {
        let hits = filter_groups("azure portal");
        assert_eq!(keys(&hits), vec!["O"], "{:?}", keys(&hits));
        assert_eq!(hits[0].title, "Actions");
    }

    #[test]
    fn filter_on_a_section_title_lists_the_section() {
        let hits = filter_groups("mouse");
        let mouse = RIGHT_SECTIONS.iter().find(|s| s.title == "Mouse").unwrap();
        let section = hits.iter().find(|g| g.title == "Mouse").unwrap();
        assert_eq!(section.entries.len(), mouse.entries.len());
    }

    #[test]
    fn filter_keeps_table_order_across_both_columns() {
        let order: Vec<&str> = LEFT_SECTIONS.iter().chain(RIGHT_SECTIONS).map(|s| s.title).collect();
        let hits = filter_groups("refresh");
        let pos: Vec<usize> =
            hits.iter().map(|g| order.iter().position(|t| *t == g.title).unwrap()).collect();
        assert!(pos.len() >= 2 && pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
        assert_eq!(&order[pos[0]], &"List pane");
        assert!(filter_groups("zzqqxx").is_empty());
    }

    #[test]
    fn truncate_ellipsizes() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly-10", 10), "exactly-10");
        assert_eq!(truncate("longer than that", 10), "longer th…");
    }

    #[test]
    fn natural_width_shows_every_description_whole() {
        // The overlay is sized to this width when the terminal allows, so
        // nothing should be ellipsized on a wide screen.
        for sections in [LEFT_SECTIONS, RIGHT_SECTIONS] {
            let text: String = section_lines(&groups(sections), natural_width(&groups(sections)) as usize)
                .iter()
                .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>() + "\n")
                .collect();
            for (_, desc) in sections.iter().flat_map(|s| s.entries.iter()) {
                assert!(text.contains(desc), "{desc:?} is truncated at natural width");
            }
        }
    }
}
