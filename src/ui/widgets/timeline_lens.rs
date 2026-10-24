// ported from neboto-tui src/ui/widgets/trail_lens.rs @ ee8eb89 (adapted:
// four Azure sources, the window keys, the lens's own palette accessors)
//! Change timeline (`W`, #52): "what changed around this resource?",
//! rendered **in the detail pane** (`Z` full width) like the network lens
//! and metrics. Four sources merge into one newest-first list, each row
//! wearing a badge (`azure::timeline` has the row model):
//!
//! - `ACT`  — the Activity Log for the row (the Activity section's query,
//!   over the lens window): changes only, `a` shows every operation.
//! - `HLTH` — Resource Health transitions (resources only).
//! - `ALRT` — alerts that fired on the row, and when they resolved.
//! - `DEP`  — ARM deployments in the row's group that deployed it.
//!
//! Sources land independently under one generation guard (a reopen, a
//! window change or `r` supersedes them). The Activity Log is the primary
//! source: its failure takes the header's error slot; any other source
//! failing is a dim note on the counts row. `f` cycles a source filter,
//! `[` / `]` widen the window 7d / 30d / 90d (the Activity Log's
//! retention), `⏎` / `v` open the row's named fields in `$EDITOR` (`e` the
//! whole timeline), `y` copies the row. Off the `LazyStore`: every open
//! refetches.

use crate::azure::timeline::{merge, slot, LensWindow, TimelineRow, TimelineSource};
use crate::ui::theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct TimelineLensState {
    pub title: String,
    /// The row the lens is about (its ARM id).
    pub resource_id: String,
    /// The Activity Log answer, kept raw so `a` re-derives without a call.
    pub activity_events: Vec<Value>,
    /// The Activity Log stopped at its event cap.
    pub activity_capped: bool,
    /// Per-source rows (indexed by `timeline::slot`), replaced whole when a
    /// source lands.
    pub lists: [Vec<TimelineRow>; 4],
    /// The merged, filtered view the body draws.
    pub rows: Vec<TimelineRow>,
    pub selected: usize,
    pub window: LensWindow,
    /// The window's start (Unix seconds), fixed when the fetch began.
    pub since: i64,
    /// `a`: every Activity Log operation, not only the changes.
    pub include_all: bool,
    /// Sources with a fetch in flight.
    pub pending: Vec<TimelineSource>,
    /// `f`: one source only.
    pub source_filter: Option<TimelineSource>,
    /// The Activity Log's failure: the headline slot.
    pub error: Option<String>,
    /// Dim per-source notes: another source failed, or does not apply.
    pub notes: Vec<String>,
    /// Set by `⏎` / `v`: the editor opens the selected row, not the view.
    pub editor_row: bool,
}

impl TimelineLensState {
    pub fn open(title: String, resource_id: String, window: LensWindow, include_all: bool) -> Self {
        Self { title, resource_id, window, include_all, ..Default::default() }
    }

    /// Start (or restart) a fetch pass over `sources` from `since`. Rows
    /// already shown stay until their replacement lands.
    pub fn begin(&mut self, sources: Vec<TimelineSource>, since: i64) {
        self.pending = sources;
        self.since = since;
        self.error = None;
        self.notes.clear();
    }

    pub fn is_loading(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The Activity Log landed: keep the events, derive the rows.
    pub fn set_activity(&mut self, events: Vec<Value>, capped: bool) {
        self.activity_events = events;
        self.activity_capped = capped;
        let rows = crate::azure::timeline::activity_rows(&self.activity_events, self.since, self.include_all);
        self.set_rows(TimelineSource::Activity, rows);
    }

    pub fn set_rows(&mut self, source: TimelineSource, rows: Vec<TimelineRow>) {
        self.lists[slot(source)] = rows;
        self.pending.retain(|s| *s != source);
        self.rebuild();
    }

    /// A source failed: the Activity Log takes the error slot, any other
    /// is a note (its absence must not read as the lens breaking).
    pub fn set_source_error(&mut self, source: TimelineSource, err: String) {
        self.pending.retain(|s| *s != source);
        self.lists[slot(source)].clear();
        match source {
            TimelineSource::Activity => self.error = Some(err),
            s => self.notes.push(format!("{}: {}", s.label(), err)),
        }
        self.rebuild();
    }

    /// A source that does not apply to this row, or a coverage limit.
    pub fn note(&mut self, text: String) {
        if !self.notes.contains(&text) {
            self.notes.push(text);
        }
    }

    pub fn rebuild(&mut self) {
        self.rows = merge(&self.lists, self.source_filter);
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
    }

    /// `f`: all → ACT → HLTH → ALRT → DEP → all.
    pub fn cycle_source_filter(&mut self) {
        let all = TimelineSource::ALL;
        self.source_filter = match self.source_filter {
            None => Some(all[0]),
            Some(cur) => all.iter().position(|s| *s == cur).and_then(|i| all.get(i + 1)).copied(),
        };
        self.selected = 0;
        self.rebuild();
    }

    /// `a`: every Activity Log operation, or the changes only.
    pub fn toggle_include_all(&mut self) {
        self.include_all = !self.include_all;
        // In flight, the answer is derived under the new mode when it lands.
        if !self.pending.contains(&TimelineSource::Activity) {
            let events = std::mem::take(&mut self.activity_events);
            self.set_activity(events, self.activity_capped);
        }
    }

    pub fn selected_row(&self) -> Option<&TimelineRow> {
        self.rows.get(self.selected)
    }

    pub fn move_by(&mut self, delta: isize) {
        let max = self.rows.len().saturating_sub(1) as isize;
        self.selected = (self.selected as isize + delta).clamp(0, max.max(0)) as usize;
    }

    pub fn goto_top(&mut self) {
        self.selected = 0;
    }

    pub fn goto_bottom(&mut self) {
        self.selected = self.rows.len().saturating_sub(1);
    }

    /// The editor's text: the selected row's named fields after `⏎` / `v`,
    /// else the whole timeline.
    pub fn editor_text(&self) -> String {
        if self.editor_row {
            if let Some(row) = self.selected_row() {
                return row.as_text();
            }
        }
        self.as_text()
    }

    /// The whole timeline as text (the `e` editor view).
    pub fn as_text(&self) -> String {
        let mut out = format!("Timeline — {}\nlast {} · {}\n", self.title, self.window.label(), self.mode_label());
        for note in self.notes.iter().chain(self.error.iter()) {
            out.push_str(&format!("! {}\n", note));
        }
        out.push('\n');
        for r in &self.rows {
            out.push_str(&r.summary_line());
            out.push('\n');
        }
        out
    }

    fn mode_label(&self) -> &'static str {
        if self.include_all {
            "every operation"
        } else {
            "changes only"
        }
    }
}

fn source_color(source: TimelineSource) -> Color {
    match source {
        TimelineSource::Activity => theme::accent(),
        TimelineSource::Health => theme::warning(),
        TimelineSource::Alert => theme::error(),
        TimelineSource::Deployment => theme::success(),
    }
}

pub fn render_timeline_lens(app: &crate::app::App, area: Rect, frame: &mut Frame) {
    let Some(st) = &app.timeline else {
        return;
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::border_focused()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // per-source counts · notes
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(inner);

    // ── Header: badge · title · count · window · mode · filter ──
    let mut header = vec![
        Span::styled(" ⏱ TIMELINE ", Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)),
        Span::styled(st.title.clone(), Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  {} row{}", st.rows.len(), if st.rows.len() == 1 { "" } else { "s" }),
            Style::default().fg(theme::text_dim()),
        ),
        Span::styled(format!("  · last {}", st.window.label()), Style::default().fg(theme::accent())),
        Span::styled(format!("  · {}", st.mode_label()), Style::default().fg(theme::text_dim())),
    ];
    if let Some(f) = st.source_filter {
        header.push(Span::styled(format!("  · {} only", f.label()), Style::default().fg(source_color(f))));
    }
    if st.is_loading() {
        header.push(Span::styled(
            format!("  {} reading…", theme::spinner(app.tick_count)),
            Style::default().fg(theme::warning()),
        ));
    }
    if let Some(e) = &st.error {
        header.push(Span::styled(format!("   ⚠ Activity Log: {}", e), Style::default().fg(theme::error())));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), chunks[0]);

    // ── Counts row: per-source totals, then the notes ──
    let mut counts: Vec<Span> = vec![Span::raw(" ")];
    for source in TimelineSource::ALL {
        let in_flight = st.pending.contains(&source);
        let n = st.lists[slot(source)].len();
        counts.push(Span::styled(format!("{} ", source.badge().trim()), Style::default().fg(source_color(source))));
        counts.push(Span::styled(
            if in_flight { "…  ".to_string() } else { format!("{}  ", n) },
            Style::default().fg(theme::text_dim()),
        ));
    }
    if st.activity_capped {
        counts.push(Span::styled(
            format!("  · Activity Log: the newest {} events", crate::azure::timeline::TIMELINE_MAX_EVENTS),
            Style::default().fg(theme::warning()),
        ));
    }
    // Who owns it (#48's ribbon), when the lens is on the selected row.
    if app.get_selected_resource().is_some_and(|r| r.id().eq_ignore_ascii_case(&st.resource_id)) {
        if let Some(ribbon) = app.ownership_ribbon() {
            counts.push(Span::styled(format!("  {}", ribbon.text()), Style::default().fg(theme::text_dim())));
        }
    }
    for note in &st.notes {
        counts.push(Span::styled(format!("  · {}", note), Style::default().fg(theme::text_dim())));
    }
    frame.render_widget(Paragraph::new(Line::from(counts)), chunks[1]);

    // ── Body: one row per entry, selectable ──
    let viewport = chunks[2].height as usize;
    let top = if viewport > 0 && st.selected >= viewport { st.selected + 1 - viewport } else { 0 };
    let mut body: Vec<Line> = Vec::with_capacity(viewport);
    if st.rows.is_empty() {
        let empty = if st.is_loading() {
            "  Reading the Activity Log, Resource Health, alerts and deployments…"
        } else if st.error.is_some() {
            "  The Activity Log could not be read (see the header)"
        } else if st.source_filter.is_some() {
            "  Nothing from this source in the window: f cycles sources, ] widens"
        } else {
            "  No changes in the window: ] widens, a shows every operation"
        };
        body.push(Line::styled(empty, Style::default().fg(theme::text_dim())));
    }
    // The subject column only when rows are about different resources (a
    // group's or subscription's timeline): on a resource it is the title.
    let subjects =
        st.rows.iter().any(|r| r.target.as_deref().is_some_and(|t| !t.eq_ignore_ascii_case(&st.resource_id)));
    for (i, row) in st.rows.iter().enumerate().skip(top).take(viewport) {
        body.push(timeline_line(row, i == st.selected, subjects));
    }
    frame.render_widget(Paragraph::new(body), chunks[2]);
    // A click puts the cursor on a row, a double-click opens it.
    app.mouse.pane_rows.borrow_mut().record_rows(chunks[2], top, st.rows.len());

    // ── Footer ──
    let mut footer = theme::hint_line(&[
        ("j/k", "select"),
        ("⏎", "open"),
        ("l", "go to"),
        ("f", "sources"),
        ("[/]", "window"),
        ("a", if st.include_all { "changes only" } else { "all operations" }),
        ("y", "copy"),
        ("r", "refetch"),
        ("Esc", "close"),
    ]);
    footer.spans.insert(0, Span::raw(" "));
    let c = chunks[3];
    crate::app::record_hint_regions(app, &footer, 1, c.x, c.y, c.x + c.width);
    frame.render_widget(Paragraph::new(footer), c);
}

fn timeline_line(row: &TimelineRow, selected: bool, subject: bool) -> Line<'static> {
    let base = if selected {
        Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::text_primary())
    };
    let what = if row.failed { base.fg(theme::error()) } else { base };
    let mut spans = vec![
        Span::styled(if selected { "▸ " } else { "  " }, Style::default().fg(theme::accent())),
        Span::styled(format!("{:16} ", trim(&row.time, 16)), base.fg(theme::text_dim())),
        Span::styled(format!("{} ", row.source().badge()), Style::default().fg(source_color(row.source()))),
        Span::styled(format!("{:40} ", trim(&row.what, 40)), what),
    ];
    if subject {
        spans.push(Span::styled(format!("{:18} ", trim(&row.subject, 18)), base));
    }
    spans.push(Span::styled(format!("{:22} ", trim(&row.who, 22)), base.fg(theme::accent())));
    spans.push(Span::styled(trim(&row.detail, 100), base.fg(theme::text_dim())));
    Line::from(spans)
}

/// Truncate to `width` characters, `…` when clipped.
fn trim(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::timeline::tests::{alert, event, health, VM};
    use crate::azure::timeline::{alert_rows, health_rows};

    #[test]
    fn sources_land_independently_and_merge_newest_first() {
        let mut st = TimelineLensState::open("VM · vm1".into(), VM.into(), LensWindow::Week, false);
        st.begin(TimelineSource::ALL.to_vec(), 0);
        assert!(st.is_loading());
        st.set_rows(TimelineSource::Alert, alert_rows(&[alert("2026-10-20T08:00:00Z", None)], 0));
        st.set_activity(
            vec![
                event("2026-10-20T10:00:00Z", "c1", "x/write", "Succeeded", "a@x.com"),
                event("2026-10-20T11:00:00Z", "c2", "x/read", "Succeeded", "a@x.com"),
            ],
            false,
        );
        st.set_source_error(TimelineSource::Deployment, "403".into());
        assert!(st.is_loading(), "health is still in flight");
        st.set_rows(TimelineSource::Health, health_rows(&[health("2026-10-20T09:00:00Z", "Degraded", false)], 0));
        assert!(!st.is_loading());
        assert!(st.error.is_none(), "an auxiliary failure is a note");
        assert_eq!(st.notes, ["Deployments: 403"]);
        let order: Vec<TimelineSource> = st.rows.iter().map(|r| r.source()).collect();
        assert_eq!(order, [TimelineSource::Activity, TimelineSource::Health, TimelineSource::Alert]);

        // `a` re-derives the Activity rows: the read appears, newest.
        st.toggle_include_all();
        assert_eq!(st.rows.len(), 4);
        assert_eq!(st.rows[0].what, "x/read");

        // `f` cycles one source at a time, then back to all.
        st.cycle_source_filter();
        assert!(st.rows.iter().all(|r| r.source() == TimelineSource::Activity));
        for _ in 0..4 {
            st.cycle_source_filter();
        }
        assert_eq!(st.source_filter, None);

        st.goto_bottom();
        st.editor_row = true;
        assert!(st.editor_text().starts_with("Alert"));
        st.editor_row = false;
        assert!(st.editor_text().starts_with("Timeline — VM · vm1\nlast 7d · every operation"));

        st.set_source_error(TimelineSource::Activity, "denied".into());
        assert_eq!(st.error.as_deref(), Some("denied"), "the primary source takes the error slot");
    }
}
