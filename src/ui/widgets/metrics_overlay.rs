// ported from neboto-tui src/ui/widgets/metrics_overlay.rs @ 03760c0 (adapted: one generic renderer over Azure Monitor series, not one per CloudWatch kind; the range chrome, `spark_line` and the braille value chart)
//! Azure Monitor metrics (`m`, #51), rendered **in the detail pane** (`Z`
//! full width): one line per metric (label, sparkline, last / min / max /
//! avg in the metric's unit) and a braille chart of the selected one.
//! The default set is curated per ARM type (`azure::metrics`); `a` lists
//! every metric the resource has (its metric definitions) to chart one.
//!
//! `[` / `]` or `1`–`4` pick the window (1h, 6h, 24h, 7d) and refetch;
//! `r` refetches; a metric that fails is a warning on its line, never an
//! error for the view.

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

    pub fn selected_series(&self) -> Option<&MetricSeries> {
        self.series.get(self.selected)
    }

    pub fn move_by(&mut self, delta: isize) {
        if let Some(p) = self.picker.as_mut() {
            let max = p.defs.len().saturating_sub(1) as isize;
            p.selected = (p.selected as isize + delta).clamp(0, max.max(0)) as usize;
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
        for s in &self.series {
            out.push_str(&s.summary());
            out.push('\n');
        }
        out
    }
}

/// One character per column, the column's mean on an eight-step scale.
fn spark_line(points: &[(i64, f64)], width: usize) -> String {
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
    } else {
        render_series(st, chunks[2], &mut rows, frame);
    }
    drop(rows);

    // ── Footer ──
    let hints: &[(&str, &str)] = if st.picker.is_some() {
        &[("j/k", "select"), ("⏎", "chart it"), ("Esc", "back")]
    } else {
        &[
            ("j/k", "select"),
            ("[/]", "range"),
            ("a", "all metrics"),
            ("d", "default set"),
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

fn render_series(st: &MetricsState, area: Rect, hits: &mut crate::app::PopupHits, frame: &mut Frame) {
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
        render_value_chart(s, st, series_color(st.selected), chart_area, frame);
    }
}

/// The selected metric as a braille line chart over the window.
fn render_value_chart(s: &MetricSeries, st: &MetricsState, color: Color, area: Rect, frame: &mut Frame) {
    let x_max = st.window.secs() as f64;
    let start = st.end - st.window.secs();
    let data: Vec<(f64, f64)> = s.points.iter().map(|&(t, v)| ((t - start) as f64, v)).collect();
    let lo = data.iter().map(|(_, y)| *y).fold(0.0_f64, f64::min);
    let peak = data.iter().map(|(_, y)| *y).fold(f64::MIN, f64::max);
    let hi = if peak > lo { peak + (peak - lo) * 0.1 } else { lo + 1.0 };
    let label = |v: f64| Span::styled(fmt_value(v, &s.unit), Style::default().fg(theme::text_dim()));
    let dataset = Dataset::default()
        .data(&data)
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(color));
    let title = format!(" {} · {} ({}) ", s.label, s.name, s.aggregation.short());
    let chart = Chart::new(vec![dataset])
        .block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(color).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::border_dim())),
        )
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
