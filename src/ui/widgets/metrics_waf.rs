// ported in spirit from neboto-tui src/ui/widgets/metrics_overlay.rs @ 4b45a5a / 90bad9b (the WAF view: actions on one chart, a block-rate row, rule tables beside the chart or under it when narrow, ⏎ on a rule charts it, colours that mean something); the data is Azure Monitor dimension splits, not CloudWatch metric math
//! The WAF view inside the metrics view (#153): `m` on an Application
//! Gateway with WAF, a Front Door Standard / Premium profile, or a WAF
//! policy attached to one. The data and the rules are
//! `azure::waf_metrics`; the keys and the fetch are `app::metrics`.
//!
//! Top to bottom: one line per action (allow green, block red, log amber)
//! and the block rate; then the chart of the actions with the rule tables
//! beside it (under it below [`WIDE`] columns). `Tab` moves between the
//! tables, `j`/`k` along one, `⏎` charts the rule's actions over time,
//! `d` goes back. Change markers (#152) draw on this chart like any other.

use super::metrics_overlay::{render_lines_chart, spark_line, ChartLine, MarkerSource, MetricsState};
use crate::azure::metrics::fmt_value;
use crate::azure::waf_metrics::{ActionKind, ActionLine, RuleRow, RuleTable, WafData, WafProduct};
use crate::ui::theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// At or above this many columns the tables sit beside the chart.
pub const WIDE: u16 = 110;

/// The WAF view's state, on `MetricsState::waf` for a resource that has
/// one (present even while `d` shows the default set, so `w` returns).
#[derive(Debug, Clone)]
pub struct WafState {
    pub product: WafProduct,
    /// Opened from a policy: its `PolicyName`, pinned in every call.
    pub policy: Option<String>,
    /// The resources the policy is attached to (the view is `target`'s);
    /// just the one for a gateway or profile.
    pub targets: Vec<String>,
    pub target: usize,
    /// Attachments with no WAF view, as the policy writes them.
    pub skipped: Vec<String>,
    pub data: Option<WafData>,
    /// The focused table and row.
    pub table: usize,
    pub row: usize,
    /// The rule being charted (`⏎`), as (table, row).
    pub charted: Option<(usize, usize)>,
}

impl WafState {
    pub fn new(product: WafProduct, policy: Option<String>, targets: Vec<String>, skipped: Vec<String>) -> Self {
        Self { product, policy, targets, target: 0, skipped, data: None, table: 0, row: 0, charted: None }
    }

    pub fn set_data(&mut self, data: WafData) {
        self.data = Some(data);
        self.table = self.table.min(self.data.as_ref().map_or(0, |d| d.tables.len().saturating_sub(1)));
        self.move_row(0);
        if self.charted_rule().is_none() {
            self.charted = None;
        }
    }

    fn tables(&self) -> &[RuleTable] {
        self.data.as_ref().map_or(&[], |d| d.tables.as_slice())
    }

    /// The row under the cursor.
    pub fn selected_rule(&self) -> Option<&RuleRow> {
        self.tables().get(self.table)?.rows.get(self.row)
    }

    /// The charted rule's row.
    pub fn charted_rule(&self) -> Option<&RuleRow> {
        let (t, r) = self.charted?;
        self.tables().get(t)?.rows.get(r)
    }

    pub fn move_row(&mut self, delta: isize) {
        let n = self.tables().get(self.table).map_or(0, |t| t.rows.len());
        self.row = (self.row as isize + delta).clamp(0, n.saturating_sub(1) as isize) as usize;
    }

    pub fn goto(&mut self, bottom: bool) {
        self.row = 0;
        if bottom {
            self.move_row(isize::MAX / 2);
        }
    }

    /// `Tab`: the next table that has rows.
    pub fn next_table(&mut self) {
        let n = self.tables().len();
        for step in 1..=n {
            let i = (self.table + step) % n;
            if !self.tables()[i].rows.is_empty() {
                self.table = i;
                self.row = 0;
                return;
            }
        }
    }

    /// `⏎`: chart the rule under the cursor.
    pub fn chart_selected(&mut self) -> bool {
        if self.selected_rule().is_some() {
            self.charted = Some((self.table, self.row));
            true
        } else {
            false
        }
    }

    /// The rule's identity as one line (`y`, the chart title).
    pub fn rule_label(r: &RuleRow) -> String {
        [&r.set, &r.group, &r.rule].iter().filter(|s| !s.is_empty()).map(|s| s.as_str()).collect::<Vec<_>>().join(" / ")
    }

    pub fn as_text(&self) -> String {
        self.data.as_ref().map(WafData::as_text).unwrap_or_default()
    }
}

/// An action's colour by what it means, whatever the palette: allow
/// green, block red, log amber; other actions cycle the neutral ones.
fn action_color(kind: ActionKind, nth_other: usize) -> Color {
    match kind {
        ActionKind::Allow => theme::success(),
        ActionKind::Block => theme::error(),
        ActionKind::Log => theme::warning(),
        ActionKind::Other => [theme::accent(), theme::heading(), theme::brand()][nth_other % 3],
    }
}

/// Each action's colour, in order.
fn colors(lines: &[ActionLine]) -> Vec<Color> {
    let mut other = 0;
    lines
        .iter()
        .map(|l| {
            let c = action_color(l.kind, other);
            if l.kind == ActionKind::Other {
                other += 1;
            }
            c
        })
        .collect()
}

fn clip(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        s.to_string()
    } else {
        s.chars().take(w.saturating_sub(1)).chain(['…']).collect()
    }
}

pub fn render_waf(
    st: &MetricsState,
    waf: &WafState,
    markers: Option<MarkerSource>,
    area: Rect,
    frame: &mut Frame,
) {
    let dim = Style::default().fg(theme::text_dim());
    let Some(data) = &waf.data else {
        let msg = if st.loading { "  Reading…" } else { "  Nothing to show (see header)" };
        frame.render_widget(Paragraph::new(Line::styled(msg, dim)), area);
        return;
    };

    // ── The action lines and the block rate ──
    let cols = colors(&data.actions);
    let rate_pts = crate::azure::waf_metrics::block_rate_points(&data.actions);
    let name_w = data.actions.iter().map(|a| a.action.chars().count()).max().unwrap_or(0).max("Block rate".len()).min(20);
    let mut list: Vec<Line> = Vec::new();
    if let Some(e) = &data.actions_error {
        list.push(Line::styled(format!("  ! requests by action: {e}"), Style::default().fg(theme::warning())));
    } else if data.actions.is_empty() {
        list.push(Line::styled("  No requests evaluated by the WAF in this window", dim));
    }
    for (a, c) in data.actions.iter().zip(&cols) {
        let tail = format!(" {} in the window", fmt_value(a.total, "Count"));
        let spark_w = (area.width as usize).saturating_sub(4 + name_w + 1 + tail.chars().count()).min(48);
        list.push(Line::from(vec![
            Span::styled("  ■ ", Style::default().fg(*c)),
            Span::styled(format!("{:<w$} ", clip(&a.action, name_w), w = name_w), Style::default().fg(theme::text_primary())),
            Span::styled(spark_line(&a.points, spark_w), Style::default().fg(*c)),
            Span::styled(tail, Style::default().fg(theme::text_muted())),
        ]));
    }
    if data.actions_error.is_none() {
        let peak = rate_pts.iter().map(|p| p.1).fold(0.0_f64, f64::max);
        let tail = format!(" {:.1}% of what ended  peak {:.1}%", data.block_rate(), peak);
        let spark_w = (area.width as usize).saturating_sub(4 + name_w + 1 + tail.chars().count()).min(48);
        list.push(Line::from(vec![
            Span::styled("  ▲ ", Style::default().fg(theme::error())),
            Span::styled(
                format!("{:<w$} ", "Block rate", w = name_w),
                Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD),
            ),
            Span::styled(spark_line(&rate_pts, spark_w), Style::default().fg(theme::error())),
            Span::styled(tail, Style::default().fg(theme::text_muted())),
        ]));
    }
    let list_h = (list.len() as u16 + 1).min(area.height);
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(list_h), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(list), parts[0]);
    let rest = parts[1];
    if rest.height == 0 {
        return;
    }

    // ── The chart and the tables ──
    let has_tables = !data.tables.is_empty();
    let (chart_area, tables_area) = if !has_tables {
        (Some(rest), None)
    } else if rest.width >= WIDE {
        let tw = (rest.width * 2 / 5).clamp(48, 76);
        let p = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(30), Constraint::Length(tw)])
            .split(rest);
        (Some(p[0]), Some(p[1]))
    } else if rest.height >= 18 {
        let ch = (rest.height * 2 / 5).max(8);
        let p = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(ch), Constraint::Min(0)])
            .split(rest);
        (Some(p[0]), Some(p[1]))
    } else {
        (None, Some(rest))
    };

    if let Some(area) = chart_area.filter(|a| a.height >= 6) {
        match waf.charted_rule() {
            Some(rule) => {
                let c = colors(&rule.actions);
                let lines: Vec<ChartLine> =
                    rule.actions.iter().zip(&c).map(|(a, c)| ChartLine { name: &a.action, color: *c, points: &a.points }).collect();
                let mut title = vec![Span::styled(
                    format!(" {} ", clip(&WafState::rule_label(rule), (area.width as usize).saturating_sub(24).max(12))),
                    Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD),
                )];
                title.extend(legend(&lines));
                title.push(Span::styled("· d back ", Style::default().fg(theme::text_dim())));
                render_lines_chart(title, "Count", &lines, st, markers.as_ref(), area, frame);
            }
            None => {
                let lines: Vec<ChartLine> =
                    data.actions.iter().zip(&cols).map(|(a, c)| ChartLine { name: &a.action, color: *c, points: &a.points }).collect();
                let mut title = vec![Span::styled(
                    format!(" {} by action ", waf.product.label()),
                    Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD),
                )];
                title.extend(legend(&lines));
                render_lines_chart(title, "Count", &lines, st, markers.as_ref(), area, frame);
            }
        }
    }
    if let Some(area) = tables_area {
        render_tables(waf, data, area, chart_area.is_some() && rest.width >= WIDE, frame);
    }
}

/// `■ Allowed ■ Blocked` on the chart's title.
fn legend(lines: &[ChartLine]) -> Vec<Span<'static>> {
    lines
        .iter()
        .flat_map(|l| {
            [
                Span::styled("■ ", Style::default().fg(l.color)),
                Span::styled(format!("{} ", l.name), Style::default().fg(theme::text_dim())),
            ]
        })
        .collect()
}

/// A table's column header and rows as text lines; the row index of the
/// selected row within the returned lines when this table is focused.
fn table_lines(t: &RuleTable, focused: Option<usize>, width: usize) -> (Vec<Line<'static>>, Option<usize>) {
    let dim = Style::default().fg(theme::text_dim());
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" {} ", t.title), Style::default().fg(theme::heading()).add_modifier(Modifier::BOLD)),
        Span::styled(format!("({})", if t.rows.len() == 1 { "1 rule".to_string() } else { format!("{} rules", t.rows.len()) }), dim),
    ])];
    if let Some(e) = &t.error {
        lines.push(Line::styled(format!("  ! {e}"), Style::default().fg(theme::warning())));
        return (lines, None);
    }
    let (show_group, show_set, show_policy, show_blocked) = (t.has_group(), t.has_set(), t.has_policy(), t.has_blocked());
    let col = |f: &dyn Fn(&RuleRow) -> &str, cap: usize| t.rows.iter().map(|r| f(r).chars().count()).max().unwrap_or(0).min(cap);
    let (set_w, group_w, policy_w) = (
        if show_set { col(&|r| &r.set, 14) } else { 0 },
        if show_group { col(&|r| &r.group, 24) } else { 0 },
        if show_policy { col(&|r| &r.policy, 16) } else { 0 },
    );
    let num_w = 8;
    let fixed = 2
        + [set_w, group_w, policy_w].iter().filter(|w| **w > 0).map(|w| w + 1).sum::<usize>()
        + num_w
        + if show_blocked { num_w + 1 } else { 0 };
    let rule_w = width.saturating_sub(fixed + 1).clamp(6, 40);
    let mut head = String::from("  ");
    let mut push = |s: &str, w: usize| head.push_str(&format!("{:<w$} ", clip(s, w), w = w));
    push("Rule", rule_w);
    if show_set {
        push("Set", set_w);
    }
    if show_group {
        push("Group", group_w);
    }
    if show_policy {
        push("Policy", policy_w);
    }
    head.push_str(&format!("{:>w$}", "Matches", w = num_w));
    if show_blocked {
        head.push_str(&format!(" {:>w$}", "Blocked", w = num_w));
    }
    lines.push(Line::styled(head, dim));
    let mut sel_line = None;
    for (i, r) in t.rows.iter().enumerate() {
        let sel = focused == Some(i);
        if sel {
            sel_line = Some(lines.len());
        }
        let bold = |s: Style| if sel { s.add_modifier(Modifier::BOLD | Modifier::REVERSED) } else { s };
        let text = Style::default().fg(theme::text_primary());
        let mut spans = vec![
            Span::styled(if sel { "▸ " } else { "  " }, Style::default().fg(theme::accent())),
            Span::styled(format!("{:<w$} ", clip(&r.rule, rule_w), w = rule_w), bold(text)),
        ];
        let mut cell = |s: &str, w: usize| spans.push(Span::styled(format!("{:<w$} ", clip(s, w), w = w), bold(dim)));
        if show_set {
            cell(&r.set, set_w);
        }
        if show_group {
            cell(&r.group, group_w);
        }
        if show_policy {
            cell(&r.policy, policy_w);
        }
        spans.push(Span::styled(format!("{:>w$}", fmt_value(r.total, "Count"), w = num_w), bold(Style::default().fg(theme::text_muted()))));
        if show_blocked {
            let c = if r.blocked > 0.0 { theme::error() } else { theme::text_dim() };
            spans.push(Span::styled(format!(" {:>w$}", fmt_value(r.blocked, "Count"), w = num_w), bold(Style::default().fg(c))));
        }
        lines.push(Line::from(spans));
    }
    if let Some(n) = t.cap_note() {
        lines.push(Line::styled(format!("  … {n}"), dim));
    }
    (lines, sel_line)
}

fn render_tables(waf: &WafState, data: &WafData, area: Rect, beside: bool, frame: &mut Frame) {
    let borders = if beside { Borders::LEFT } else { Borders::TOP };
    let block = Block::default().borders(borders).border_style(Style::default().fg(theme::border_dim()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines: Vec<Line> = Vec::new();
    let mut sel_line = 0;
    for (i, t) in data.tables.iter().enumerate() {
        if i > 0 {
            lines.push(Line::raw(""));
        }
        let focused = (waf.table == i).then_some(waf.row);
        let (mut l, sel) = table_lines(t, focused, inner.width as usize);
        if let Some(s) = sel {
            sel_line = lines.len() + s;
        }
        lines.append(&mut l);
    }
    if data.tables.is_empty() {
        lines.push(Line::styled("  No rule matches in this window", Style::default().fg(theme::text_dim())));
    }
    let h = inner.height as usize;
    let scroll = if sel_line >= h { sel_line + 1 - h } else { 0 };
    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::waf_metrics::{ActionKind, Role};

    fn row(rule: &str, total: f64, blocked: f64) -> RuleRow {
        RuleRow {
            rule: rule.into(),
            group: String::new(),
            set: String::new(),
            policy: String::new(),
            total,
            blocked,
            actions: vec![ActionLine {
                action: "Blocked".into(),
                kind: ActionKind::Block,
                points: vec![(60, blocked)],
                total: blocked,
            }],
        }
    }

    fn table(rows: Vec<RuleRow>) -> RuleTable {
        RuleTable { role: Role::Managed, title: "Managed rules", rows, series: 1, top: 60, error: None }
    }

    fn state() -> WafState {
        let mut w = WafState::new(WafProduct::AppGateway, None, vec!["/x".into()], vec![]);
        w.set_data(WafData {
            tables: vec![table(vec![row("942100", 6.0, 5.0), row("941100", 3.0, 0.0)]), table(vec![]), table(vec![row("bot", 1.0, 0.0)])],
            ..Default::default()
        });
        w
    }

    #[test]
    fn the_cursor_moves_in_a_table_tab_skips_empty_ones_and_enter_charts_the_row() {
        let mut w = state();
        assert_eq!(w.selected_rule().unwrap().rule, "942100");
        w.move_row(5);
        assert_eq!(w.selected_rule().unwrap().rule, "941100", "clamped");
        w.goto(false);
        assert!(w.chart_selected());
        assert_eq!(w.charted_rule().unwrap().rule, "942100");
        w.next_table();
        assert_eq!((w.table, w.row), (2, 0), "the empty table is skipped");
        w.next_table();
        assert_eq!(w.table, 0, "and it wraps");
        // New data that no longer has the charted rule drops the chart.
        w.set_data(WafData::default());
        assert!(w.charted.is_none() && w.selected_rule().is_none());
        assert!(!w.chart_selected());
    }

    #[test]
    fn action_colours_mean_something() {
        assert_eq!(action_color(ActionKind::Allow, 0), theme::success());
        assert_eq!(action_color(ActionKind::Block, 0), theme::error());
        assert_eq!(action_color(ActionKind::Log, 0), theme::warning());
        assert_ne!(action_color(ActionKind::Other, 0), action_color(ActionKind::Other, 1));
    }

    #[test]
    fn a_table_hides_empty_columns_and_marks_the_selection() {
        let t = table(vec![row("942100", 6.0, 5.0), row("941100", 3.0, 0.0)]);
        let text = |l: &Line| l.spans.iter().map(|s| s.content.to_string()).collect::<String>();
        let (lines, sel) = table_lines(&t, Some(1), 60);
        assert_eq!(sel, Some(3));
        assert!(text(&lines[1]).contains("Rule") && text(&lines[1]).contains("Matches") && text(&lines[1]).contains("Blocked"));
        assert!(!text(&lines[1]).contains("Group") && !text(&lines[1]).contains("Set") && !text(&lines[1]).contains("Policy"));
        assert!(text(&lines[3]).starts_with("▸ 941100"));
        // Nothing blocked: no Blocked column.
        let (lines, _) = table_lines(&table(vec![row("a", 2.0, 0.0)]), None, 60);
        assert!(!text(&lines[1]).contains("Blocked"));
        // The cap is said.
        let capped = RuleTable { series: 60, ..table(vec![row("a", 2.0, 0.0)]) };
        let (lines, _) = table_lines(&capped, None, 60);
        assert!(text(lines.last().unwrap()).contains("top 60 series"));
    }
}
