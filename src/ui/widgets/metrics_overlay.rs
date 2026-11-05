// ported from neboto-tui src/ui/widgets/metrics_overlay.rs @ 03760c0 (adapted: one generic renderer over Azure Monitor series, not one per CloudWatch kind; the range chrome, `spark_line` and the braille value chart)
//! Azure Monitor metrics (`m`, #51), rendered **in the detail pane** (`Z`
//! full width): one line per metric (label, sparkline, last / min / max /
//! avg in the metric's unit) and a braille chart of the selected one.
//! The default set is curated per ARM type (`azure::metrics`); `a` lists
//! every metric the resource has (its metric definitions) to chart one.
//!
//! `[` / `]` or `1`–`5` pick the window (1h, 6h, 24h, 7d, 30d) and refetch;
//! `r` refetches; a metric that fails is a warning on its line, never an
//! error for the view.
//!
//! Change markers (#152, neboto-tui#259 / #284 / #289): the `W` timeline's
//! events for the resource (Activity Log, Resource Health, fired alerts,
//! deployments) drawn as vertical lines on the selected metric's chart, a
//! failed one in the error colour, with a legend on the chart's bottom
//! border (each change named once with a count). `c` hides them, `W` opens
//! the timeline and `Esc` there returns here with the range kept. The rows
//! come from `App::chart_timeline`, fetched through the same sources as
//! `W` (`app/timeline.rs`), over the week or month the range needs.

use crate::azure::timeline::TimelineRow;
use crate::azure::metrics::{fmt_value, MetricDefinition, MetricQuery, MetricSeries, MetricWindow};
use crate::ui::theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph};
use ratatui::Frame;

/// The `a` picker: the resource's metric definitions.
#[derive(Debug, Clone, Default)]
pub struct MetricPicker {
    pub defs: Vec<MetricDefinition>,
    pub loading: bool,
    pub error: Option<String>,
    pub selected: usize,
}

#[derive(Debug, Clone, Default)]
pub struct MetricsState {
    pub resource_id: String,
    pub title: String,
    pub window: MetricWindow,
    /// What is charted: the curated set, or one picked metric.
    pub queries: Vec<MetricQuery>,
    /// `queries` is the type's curated set (`d` returns to it).
    pub curated: bool,
    pub series: Vec<MetricSeries>,
    pub loading: bool,
    /// The fetch could not start (no pipeline for the tenant).
    pub error: Option<String>,
    pub selected: usize,
    /// The window's end, epoch seconds (the chart's `now`).
    pub end: i64,
    pub picker: Option<MetricPicker>,
    /// The WAF view (#153) of this resource, when it has one; `waf_on`
    /// says it is what the pane shows (`d` shows the default set instead,
    /// `w` comes back).
    pub waf: Option<super::metrics_waf::WafState>,
    pub waf_on: bool,
}

impl MetricsState {
    pub fn open(resource_id: String, title: String, queries: Vec<MetricQuery>, window: MetricWindow) -> Self {
        Self {
            resource_id,
            title,
            window,
            curated: !queries.is_empty(),
            loading: !queries.is_empty(),
            queries,
            ..Default::default()
        }
    }

    pub fn set_series(&mut self, end: i64, series: Vec<MetricSeries>) {
        self.loading = false;
        self.end = end;
        self.series = series;
        self.selected = self.selected.min(self.series.len().saturating_sub(1));
    }

    pub fn set_waf(&mut self, data: crate::azure::waf_metrics::WafData) {
        self.loading = false;
        self.end = data.end;
        if let Some(w) = self.waf.as_mut() {
            w.set_data(data);
        }
    }

    /// The WAF view is what the pane shows.
    pub fn waf_view(&self) -> bool {
        self.waf_on && self.waf.is_some() && self.picker.is_none()
    }

    pub fn selected_series(&self) -> Option<&MetricSeries> {
        self.series.get(self.selected)
    }

    pub fn move_by(&mut self, delta: isize) {
        if let Some(p) = self.picker.as_mut() {
            let max = p.defs.len().saturating_sub(1) as isize;
            p.selected = (p.selected as isize + delta).clamp(0, max.max(0)) as usize;
            return;
        }
        if self.waf_view() {
            if let Some(w) = self.waf.as_mut() {
                w.move_row(delta);
            }
            return;
        }
        let max = self.series.len().saturating_sub(1) as isize;
        self.selected = (self.selected as isize + delta).clamp(0, max.max(0)) as usize;
    }

    pub fn goto(&mut self, bottom: bool) {
        self.move_by(if bottom { isize::MAX / 2 } else { isize::MIN / 2 });
    }

    /// Every line, as text (the `e` editor view).
    pub fn as_text(&self) -> String {
        let mut out = format!("Metrics — {} — last {}\n\n", self.title, self.window.label());
        if self.waf_view() {
            out.push_str(&self.waf.as_ref().map(|w| w.as_text()).unwrap_or_default());
            return out;
        }
        for s in &self.series {
            out.push_str(&s.summary());
            out.push('\n');
        }
        out
    }
}

/// One character per column, the column's mean on an eight-step scale.
pub(crate) fn spark_line(points: &[(i64, f64)], width: usize) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let n = points.len();
    if n == 0 || width == 0 {
        return String::new();
    }
    let lo = points.iter().map(|(_, y)| *y).fold(f64::MAX, f64::min);
    let hi = points.iter().map(|(_, y)| *y).fold(f64::MIN, f64::max);
    let span = (hi - lo).max(f64::EPSILON);
    let width = width.min(n);
    (0..width)
        .map(|i| {
            let start = i * n / width;
            let end = (((i + 1) * n) / width).max(start + 1).min(n);
            let mean = points[start..end].iter().map(|(_, y)| *y).sum::<f64>() / (end - start) as f64;
            BARS[(((mean - lo) / span) * 7.0).round().clamp(0.0, 7.0) as usize]
        })
        .collect()
}

pub fn render_metrics_overlay(app: &crate::app::App, area: Rect, frame: &mut Frame) {
    let Some(st) = &app.metrics else {
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
            Constraint::Length(1), // range
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(inner);

    // ── Header ──
    let mut header = vec![
        Span::styled(" ∿ METRICS ", Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)),
        Span::styled(st.title.clone(), Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD)),
        Span::styled(
            if st.picker.is_some() {
                "  · all metrics".to_string()
            } else if st.waf_view() {
                waf_header(st)
            } else if st.curated {
                "  · default set".to_string()
            } else {
                "  · picked".to_string()
            },
            Style::default().fg(theme::text_dim()),
        ),
    ];
    let failed = st.series.iter().filter(|s| s.error.is_some()).count();
    if failed > 0 {
        header.push(Span::styled(format!("  · {} unread", failed), Style::default().fg(theme::warning())));
    }
    let loading = st.loading || st.picker.as_ref().is_some_and(|p| p.loading);
    if loading {
        header.push(Span::styled(
            format!("  {} reading Azure Monitor…", theme::spinner(app.tick_count)),
            Style::default().fg(theme::warning()),
        ));
    }
    if let Some(e) = &st.error {
        header.push(Span::styled(format!("   ⚠ {}", e), Style::default().fg(theme::error())));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), chunks[0]);

    // ── Range ──
    let mut range = vec![
        Span::styled(" Range ", Style::default().fg(theme::text_dim())),
        Span::styled("[ ", Style::default().fg(theme::warning())),
    ];
    // Each window chip presses its digit.
    let mut x = chunks[1].x + Line::from(range.clone()).width() as u16;
    for (i, w) in MetricWindow::ALL.iter().enumerate() {
        let chip = format!(" {} {} ", i + 1, w.label());
        let width = Line::raw(chip.as_str()).width() as u16;
        let right = (chunks[1].x + chunks[1].width).min(x + width);
        if right > x {
            app.push_click_region(
                Rect { x, y: chunks[1].y, width: right - x, height: 1 },
                crate::app::ClickAction::Press(crossterm::event::KeyCode::Char(char::from(b'1' + i as u8))),
            );
        }
        x += width;
        let style = if *w == st.window {
            Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(theme::text_dim())
        };
        range.push(Span::styled(chip, style));
    }
    range.push(Span::styled(" ]", Style::default().fg(theme::warning())));
    range.push(Span::styled(format!("   grain {}", st.window.interval()), Style::default().fg(theme::text_dim())));
    frame.render_widget(Paragraph::new(Line::from(range)), chunks[1]);

    // ── Body ──
    let mut rows = app.mouse.pane_rows.borrow_mut();
    if let Some(p) = &st.picker {
        render_picker(p, chunks[2], &mut rows, frame);
    } else if let (true, Some(w)) = (st.waf_view(), st.waf.as_ref()) {
        super::metrics_waf::render_waf(st, w, app.marker_source(), chunks[2], frame);
    } else {
        render_series(st, app.marker_source(), chunks[2], &mut rows, frame);
    }
    drop(rows);

    // ── Footer ──
    let hints: &[(&str, &str)] = if st.picker.is_some() {
        &[("j/k", "select"), ("⏎", "chart it"), ("Esc", "back")]
    } else if st.waf_view() {
        let w = st.waf.as_ref();
        if w.is_some_and(|w| w.targets.len() > 1) {
            &[("j/k", "rule"), ("Tab", "table"), ("⏎", "chart rule"), ("n", "next"), ("d", "back"), ("[/]", "range"), ("c", "changes"), ("y", "copy"), ("r", "refetch"), ("Esc", "close")]
        } else {
            &[("j/k", "rule"), ("Tab", "table"), ("⏎", "chart rule"), ("d", "back"), ("[/]", "range"), ("c", "changes"), ("W", "timeline"), ("y", "copy"), ("r", "refetch"), ("Esc", "close")]
        }
    } else if st.waf.is_some() {
        &[
            ("j/k", "select"),
            ("[/]", "range"),
            ("w", "WAF view"),
            ("a", "all metrics"),
            ("c", "changes"),
            ("W", "timeline"),
            ("y", "copy"),
            ("r", "refetch"),
            ("Esc", "close"),
        ]
    } else {
        &[
            ("j/k", "select"),
            ("[/]", "range"),
            ("a", "all metrics"),
            ("d", "default set"),
            ("c", "changes"),
            ("W", "timeline"),
            ("y", "copy"),
            ("r", "refetch"),
            ("Z", "width"),
            ("Esc", "close"),
        ]
    };
    let mut footer = theme::hint_line(hints);
    footer.spans.insert(0, Span::raw(" "));
    let c = chunks[3];
    crate::app::record_hint_regions(app, &footer, 1, c.x, c.y, c.x + c.width);
    frame.render_widget(Paragraph::new(footer), c);
}

/// `· WAF view · policy wafp-1 · 2 of 3 attached (n next)`.
fn waf_header(st: &MetricsState) -> String {
    let mut s = String::from("  · WAF view");
    if let Some(w) = &st.waf {
        if let Some(p) = &w.policy {
            s.push_str(&format!(" · policy {p}"));
        }
        if w.targets.len() > 1 {
            s.push_str(&format!(" · {} of {} attached (n next)", w.target + 1, w.targets.len()));
        }
        if !w.skipped.is_empty() {
            s.push_str(&format!(" · {} attachment(s) without a WAF view", w.skipped.len()));
        }
    }
    s
}

fn render_picker(p: &MetricPicker, area: Rect, hits: &mut crate::app::PopupHits, frame: &mut Frame) {
    let viewport = area.height as usize;
    let mut lines: Vec<Line> = Vec::new();
    if let Some(e) = &p.error {
        lines.push(Line::styled(format!("  ! {}", e), Style::default().fg(theme::warning())));
    } else if p.defs.is_empty() {
        let msg = if p.loading { "  Reading metric definitions…" } else { "  This resource publishes no platform metrics" };
        lines.push(Line::styled(msg, Style::default().fg(theme::text_dim())));
    }
    let room = viewport.saturating_sub(lines.len());
    let top = if room > 0 && p.selected >= room { p.selected + 1 - room } else { 0 };
    let skip = lines.len() as u16;
    hits.record_rows(Rect { y: area.y + skip, height: area.height.saturating_sub(skip), ..area }, top, p.defs.len());
    for (i, d) in p.defs.iter().enumerate().skip(top).take(room) {
        let sel = i == p.selected;
        let bold = |s: Style| if sel { s.add_modifier(Modifier::BOLD) } else { s };
        let mut spans = vec![
            Span::styled(if sel { "▸ " } else { "  " }, Style::default().fg(theme::accent())),
            Span::styled(d.label.clone(), bold(Style::default().fg(theme::text_primary()))),
            Span::styled(
                format!("  {} · {} · {}", d.name, d.unit, d.aggregation.short()),
                Style::default().fg(theme::text_dim()),
            ),
        ];
        if !d.dimensions.is_empty() {
            spans.push(Span::styled(
                format!("  by {}", d.dimensions.join(", ")),
                Style::default().fg(theme::text_dim()).add_modifier(Modifier::ITALIC),
            ));
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The series palette, cycled: theme accessors only.
fn series_color(i: usize) -> Color {
    [theme::accent(), theme::success(), theme::warning(), theme::heading(), theme::brand(), theme::border_focused()][i % 6]
}

fn render_series(st: &MetricsState, markers: Option<MarkerSource>, area: Rect, hits: &mut crate::app::PopupHits, frame: &mut Frame) {
    if st.series.is_empty() {
        let msg = if st.loading {
            "  Reading…"
        } else if st.queries.is_empty() {
            "  No default metrics for this type: a lists what it has"
        } else {
            "  Nothing to show (see header)"
        };
        frame.render_widget(Paragraph::new(Line::styled(msg, Style::default().fg(theme::text_dim()))), area);
        return;
    }
    // The list on top; the selected metric's chart below when there is
    // room for it (the list and a blank line first).
    let list_h = st.series.len() as u16;
    let (list_area, chart_area) = if area.height >= list_h + 8 {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(list_h + 1), Constraint::Min(0)])
            .split(area);
        (parts[0], Some(parts[1]))
    } else {
        (area, None)
    };

    let label_w = st.series.iter().map(|s| s.label.chars().count()).max().unwrap_or(0).min(24);
    let width = list_area.width as usize;
    let mut lines = Vec::new();
    for (i, s) in st.series.iter().enumerate() {
        let sel = i == st.selected;
        let bold = |s: Style| if sel { s.add_modifier(Modifier::BOLD) } else { s };
        let mut spans = vec![
            Span::styled(if sel { "▸ " } else { "  " }, Style::default().fg(theme::accent())),
            Span::styled(
                format!("{:<w$} ", s.label.chars().take(label_w).collect::<String>(), w = label_w),
                bold(Style::default().fg(theme::text_primary())),
            ),
        ];
        let used = 2 + label_w + 1;
        match (&s.error, s.stats()) {
            (Some(e), _) => spans.push(Span::styled(format!("! {}", e), Style::default().fg(theme::warning()))),
            (None, None) => spans.push(Span::styled("no data in the window", Style::default().fg(theme::text_dim()))),
            (None, Some(stats)) => {
                let f = |v| fmt_value(v, &s.unit);
                // The aggregation, when it is not the average (`sum`, `max`).
                let agg = match s.aggregation {
                    crate::azure::metrics::Aggregation::Average => String::new(),
                    a => format!("  ({})", a.short()),
                };
                let tail = format!(
                    " last {}  min {}  max {}  avg {}{}",
                    f(stats.last),
                    f(stats.min),
                    f(stats.max),
                    f(stats.avg),
                    agg
                );
                let spark_w = width.saturating_sub(used + tail.chars().count()).min(48);
                spans.push(Span::styled(spark_line(&s.points, spark_w), Style::default().fg(series_color(i))));
                spans.push(Span::styled(tail, bold(Style::default().fg(theme::text_muted()))));
            }
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), list_area);
    hits.record_rows(list_area, 0, st.series.len());

    if let (Some(chart_area), Some(s)) = (chart_area, st.selected_series()) {
        render_value_chart(s, st, markers.as_ref(), series_color(st.selected), chart_area, frame);
    }
}

/// What the chart draws markers from: the timeline's rows (newest first)
/// and whether its fetch is still running.
pub struct MarkerSource<'a> {
    pub rows: &'a [TimelineRow],
    pub loading: bool,
}

/// One marker on the time axis: the row it is, its x (seconds from the
/// window's start) and whether the event failed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Marker {
    pub row: usize,
    pub x: f64,
    pub failed: bool,
}

/// The rows that fall inside a chart whose window is `window_secs` long
/// and ends at `end` (epoch secs), as x positions. An event outside the
/// window (or without a time) is dropped; nothing is drawn before the
/// series has landed (`end == 0`).
pub fn marker_positions(rows: &[TimelineRow], end: i64, window_secs: i64) -> Vec<Marker> {
    if end <= 0 {
        return Vec::new();
    }
    let start = end - window_secs;
    rows.iter()
        .enumerate()
        .filter(|(_, r)| r.ts_secs > 0)
        .map(|(row, r)| Marker { row, x: (r.ts_secs - start) as f64, failed: r.failed })
        .filter(|m| (0.0..=window_secs as f64).contains(&m.x))
        .collect()
}

/// An operation name short enough for a legend: the last two segments of
/// an ARM operation (`Microsoft.Network/networkSecurityGroups/securityRules/write`
/// is `securityRules/write`); anything else as it is.
fn short_what(what: &str) -> String {
    if what.contains('/') {
        let parts: Vec<&str> = what.split('/').collect();
        if parts.len() > 2 {
            return parts[parts.len() - 2..].join("/");
        }
    }
    what.to_string()
}

/// The legend: each drawn change named once with a count (`Delete ×3`),
/// newest first, as many as fit, then how many did not and the keys.
fn marker_legend(rows: &[TimelineRow], drawn: &[Marker], loading: bool, width: u16) -> Line<'static> {
    let dim = Style::default().fg(theme::text_dim());
    let key = Style::default().fg(theme::warning());
    let tail = [Span::styled("  c", key), Span::styled(" hide · ", dim), Span::styled("W", key), Span::styled(" timeline", dim)];
    let tail_w: usize = tail.iter().map(|s| s.width()).sum();
    let mut spans = vec![Span::styled(" ┊ ", dim)];
    if drawn.is_empty() {
        let msg = if loading {
            "loading changes…".to_string()
        } else {
            format!("no changes in this window ({} in the timeline)", rows.len())
        };
        spans.push(Span::styled(msg, dim));
        spans.extend(tail);
        return Line::from(spans);
    }
    // (label, count, any failed) per distinct change, newest first.
    let mut groups: Vec<(String, usize, bool)> = Vec::new();
    for m in drawn {
        let r = &rows[m.row];
        let label = format!("{} {}", r.source().badge().trim(), short_what(&r.what));
        match groups.iter_mut().find(|g| g.0 == label) {
            Some(g) => {
                g.1 += 1;
                g.2 |= m.failed;
            }
            None => groups.push((label, 1, m.failed)),
        }
    }
    let budget = (width as usize).saturating_sub(3 + tail_w + 12);
    let (mut used, mut shown) = (0, 0);
    for (label, n, failed) in &groups {
        let mut text: String = if label.chars().count() > 40 {
            label.chars().take(39).chain(['…']).collect()
        } else {
            label.clone()
        };
        if *n > 1 {
            text.push_str(&format!(" ×{n}"));
        }
        let w = text.chars().count() + 3;
        if shown > 0 && used + w > budget {
            break;
        }
        if shown > 0 {
            spans.push(Span::styled(" · ", dim));
        }
        let color = if *failed { theme::error() } else { theme::text_primary() };
        spans.push(Span::styled(text, Style::default().fg(color)));
        used += w;
        shown += 1;
    }
    if shown < groups.len() {
        spans.push(Span::styled(format!("  +{} more", groups.len() - shown), dim));
    }
    if loading {
        spans.push(Span::styled("  loading…", dim));
    }
    spans.extend(tail);
    Line::from(spans)
}

/// One line of a chart: its name (the legend), colour and points.
pub struct ChartLine<'a> {
    pub name: &'a str,
    pub color: Color,
    pub points: &'a [(i64, f64)],
}

/// The selected metric as a braille line chart over the window, with the
/// change markers behind the line when there are any.
fn render_value_chart(
    s: &MetricSeries,
    st: &MetricsState,
    markers: Option<&MarkerSource>,
    color: Color,
    area: Rect,
    frame: &mut Frame,
) {
    let title = format!(" {} · {} ({}) ", s.label, s.name, s.aggregation.short());
    let title = vec![Span::styled(title, Style::default().fg(color).add_modifier(Modifier::BOLD))];
    let line = ChartLine { name: &s.label, color, points: &s.points };
    render_lines_chart(title, &s.unit, &[line], st, markers, area, frame);
}

/// Any number of lines over the window on one axis (the WAF view draws
/// its actions this way), with the change markers behind them. The
/// markers' x origin is the window's start, `st.end - st.window.secs()`.
pub fn render_lines_chart(
    title: Vec<Span<'static>>,
    unit: &str,
    lines: &[ChartLine],
    st: &MetricsState,
    markers: Option<&MarkerSource>,
    area: Rect,
    frame: &mut Frame,
) {
    let x_max = st.window.secs() as f64;
    let start = st.end - st.window.secs();
    let series: Vec<Vec<(f64, f64)>> =
        lines.iter().map(|l| l.points.iter().map(|&(t, v)| ((t - start) as f64, v)).collect()).collect();
    let ys = || series.iter().flatten().map(|(_, y)| *y);
    let lo = ys().fold(0.0_f64, f64::min);
    let peak = ys().fold(f64::MIN, f64::max);
    let hi = if peak > lo { peak + (peak - lo) * 0.1 } else { lo + 1.0 };
    let label = |v: f64| Span::styled(fmt_value(v, unit), Style::default().fg(theme::text_dim()));
    let drawn = markers.map(|m| marker_positions(m.rows, st.end, st.window.secs())).unwrap_or_default();
    // Unnamed datasets, before the series so the data draws on top.
    let marks: Vec<([(f64, f64); 2], bool)> = drawn.iter().map(|m| ([(m.x, lo), (m.x, hi)], m.failed)).collect();
    let mut datasets: Vec<Dataset> = marks
        .iter()
        .map(|(pts, failed)| {
            Dataset::default()
                .data(pts)
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(if *failed { theme::error() } else { theme::text_dim() }))
        })
        .collect();
    for (data, l) in series.iter().zip(lines) {
        datasets.push(
            Dataset::default()
                .data(data)
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(l.color)),
        );
    }
    let mut block = Block::default()
        .title(Line::from(title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::border_dim()));
    if let Some(m) = markers.filter(|m| m.loading || !m.rows.is_empty()) {
        block = block.title_bottom(marker_legend(m.rows, &drawn, m.loading, area.width.saturating_sub(2)));
    }
    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(Axis::default().bounds([0.0, x_max]).labels(vec![
            Span::styled(st.window.start_label(), Style::default().fg(theme::text_dim())),
            Span::styled("now", Style::default().fg(theme::text_dim())),
        ]))
        .y_axis(Axis::default().bounds([lo, hi]).labels(vec![label(lo), label((lo + hi) / 2.0), label(hi)]));
    frame.render_widget(chart, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::metrics::Aggregation;

    #[test]
    fn spark_line_buckets_and_scales() {
        let pts: Vec<(i64, f64)> = (0..8).map(|i| (i, i as f64)).collect();
        assert_eq!(spark_line(&pts, 8), "▁▂▃▄▅▆▇█");
        assert_eq!(spark_line(&pts, 4).chars().count(), 4);
        // Never wider than the points.
        assert_eq!(spark_line(&pts[..2], 10).chars().count(), 2);
        assert_eq!(spark_line(&[], 10), "");
    }

    fn row(ts: i64, what: &str, failed: bool) -> TimelineRow {
        TimelineRow {
            ts_secs: ts,
            what: what.to_string(),
            failed,
            source: Some(crate::azure::timeline::TimelineSource::Activity),
            ..Default::default()
        }
    }

    const END: i64 = 1_800_000_000;

    #[test]
    fn markers_sit_at_their_time_on_the_axis_and_outside_events_are_dropped() {
        let rows = vec![
            row(END - 600, "a", true),       // 10 min ago
            row(END - 1800, "b", false),     // half way back
            row(END - 3600, "c", false),     // exactly the window's start
            row(END - 7200, "d", false),     // before the window
            row(END + 60, "e", false),       // after the window's end
            row(0, "f", false),              // no time
        ];
        let m = marker_positions(&rows, END, 3600);
        assert_eq!(
            m,
            vec![
                Marker { row: 0, x: 3000.0, failed: true },
                Marker { row: 1, x: 1800.0, failed: false },
                Marker { row: 2, x: 0.0, failed: false },
            ]
        );
        // The same events on a 24h axis: x scales with the window start.
        let day = marker_positions(&rows, END, 86_400);
        assert_eq!(day.len(), 4);
        assert_eq!(day[0].x, 86_400.0 - 600.0);
        // Nothing before the series has landed (no window end).
        assert!(marker_positions(&rows, 0, 3600).is_empty());
    }

    fn chart_buffer(markers: Option<&MarkerSource>) -> ratatui::buffer::Buffer {
        let pts: Vec<(i64, f64)> = (0..=60).map(|m| (END - 3600 + m * 60, 10.0 + (m % 7) as f64)).collect();
        let s = MetricSeries {
            name: "Percentage CPU".into(),
            label: "CPU".into(),
            unit: "Percent".into(),
            aggregation: crate::azure::metrics::Aggregation::Average,
            points: pts,
            error: None,
        };
        let mut st = MetricsState::open("/x".into(), "VM · x".into(), vec![], MetricWindow::OneHour);
        st.end = END;
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 16)).unwrap();
        terminal.draw(|f| render_value_chart(&s, &st, markers, Color::Green, f.size(), f)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn a_marker_draws_a_vertical_line_and_no_event_in_the_window_leaves_the_chart_alone() {
        let plain = chart_buffer(None);
        let rows = vec![row(END - 600, "UpdateApp", true), row(END - 2400, "UpdateApp", false)];
        let marked = chart_buffer(Some(&MarkerSource { rows: &rows, loading: false }));
        assert_ne!(plain, marked);
        // The failed one is error-coloured inside the plot (not the legend row).
        let w = marked.area.width as usize;
        let h = marked.area.height as usize;
        let plot = &marked.content()[w..w * (h - 1)];
        assert!(plot.iter().any(|c| c.fg == theme::error()), "a failed change is error-coloured");
        assert!(plot.iter().any(|c| c.fg == theme::text_dim() && c.symbol() != " "), "an ordinary change is dim");

        // Only older events: the plot is untouched (the legend says so).
        let old = vec![row(END - 7200, "Old", false)];
        let outside = chart_buffer(Some(&MarkerSource { rows: &old, loading: false }));
        let plot = |b: &ratatui::buffer::Buffer| b.content()[w..w * (h - 1)].to_vec();
        assert_eq!(plot(&plain), plot(&outside));
    }

    #[test]
    fn the_legend_names_each_change_once_with_a_count_and_counts_what_does_not_fit() {
        let text = |l: Line| l.spans.iter().map(|s| s.content.to_string()).collect::<String>();
        let rows = vec![
            row(END - 100, "Delete", false),
            row(END - 200, "Delete", false),
            row(END - 300, "Delete", true),
            row(END - 400, "Restart", false),
            row(END - 500, "A fairly long operation name", false),
        ];
        let drawn = marker_positions(&rows, END, 3600);
        let wide = text(marker_legend(&rows, &drawn, false, 200));
        assert!(wide.contains("ACT Delete ×3 · ACT Restart"), "{wide}");
        assert_eq!(short_what("Microsoft.Network/networkSecurityGroups/securityRules/write"), "securityRules/write");
        assert_eq!(short_what("Microsoft.Compute/virtualMachines/deallocate/action"), "deallocate/action");
        assert_eq!(short_what("Alert fired · Sev3"), "Alert fired · Sev3");
        assert!(wide.contains("c hide") && wide.contains("W timeline"), "{wide}");
        let narrow = text(marker_legend(&rows, &drawn, false, 60));
        assert!(narrow.contains("+") && narrow.contains("more"), "{narrow}");

        let none = text(marker_legend(&rows, &[], false, 120));
        assert!(none.contains("no changes in this window (5 in the timeline)"), "{none}");
        assert!(text(marker_legend(&rows, &[], true, 120)).contains("loading changes…"));
    }

    #[test]
    fn selection_clamps_and_the_picker_moves_its_own_cursor() {
        let q = MetricQuery { name: "a".into(), label: "A".into(), aggregation: Aggregation::Average };
        let mut st = MetricsState::open("/x".into(), "VM · x".into(), vec![q.clone()], MetricWindow::OneHour);
        assert!(st.loading && st.curated);
        let series = |n: &str| MetricSeries {
            name: n.into(),
            label: n.into(),
            unit: "Count".into(),
            aggregation: Aggregation::Total,
            points: vec![(0, 1.0)],
            error: None,
        };
        st.set_series(60, vec![series("a"), series("b")]);
        st.goto(true);
        assert_eq!(st.selected, 1);
        st.picker = Some(MetricPicker { defs: vec![], ..Default::default() });
        st.move_by(3);
        assert_eq!(st.selected, 1, "the picker owns j/k");
        assert!(st.as_text().contains("b (sum b)  last 1"));
        // A type with no default set opens empty and not loading.
        let st = MetricsState::open("/x".into(), "t".into(), vec![], MetricWindow::OneHour);
        assert!(!st.loading && !st.curated);
    }
}
