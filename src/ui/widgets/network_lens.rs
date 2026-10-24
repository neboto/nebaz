// ported from neboto-tui src/ui/widgets/access_lens.rs @ 456eb70 (adapted: NSG layers, not merged SGs + NACLs)
//! Network access lens (`N`, #50): the NSG rules that apply to the
//! selected resource, rendered **in the detail pane** (`Z` full width), in
//! the order Azure evaluates them. The evaluation is `azure::nsg_eval`;
//! this is the state and the drawing.
//!
//! Entry points: a NIC; a VM (or anything whose Related lists NICs, such
//! as a private endpoint) through its NICs; a subnet (or anything whose
//! Related lists subnets) for what applies to anything placed in it; an
//! NSG for its own rules and what it guards.
//!
//! Rows come from the warm list caches when present, else one GET each
//! (NIC, the subnet's VNet, NSG), in one task off the `LazyStore` like
//! neboto's lenses; `r` refetches everything, ignoring the caches. A
//! missing piece is a warning line, never an error.
//!
//! `t` cycles inbound + outbound → inbound → outbound; an inbound allow
//! from anywhere reads in the warning colour, a shadowed rule dim; `⏎`
//! jumps to the line's NSG (or subnet / NIC); `e` opens the whole view in
//! `$EDITOR`; `y` copies a line.

use crate::azure::nsg_eval::{build_lines, Cross, Dir, LensLine, LineKind, Resolved, Seed};
use crate::ui::theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Says what this is on every screen: the lens is not Azure's view.
pub const COMPUTED_NOTE: &str =
    "computed from NSG rules (GETs only), not Azure's effective view: ignores Azure Firewall, UDRs and AVNM admin rules";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LensDirection {
    #[default]
    Both,
    Inbound,
    Outbound,
}

impl LensDirection {
    pub fn next(self) -> Self {
        match self {
            Self::Both => Self::Inbound,
            Self::Inbound => Self::Outbound,
            Self::Outbound => Self::Both,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Both => "inbound + outbound",
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }

    fn dirs(self) -> &'static [Dir] {
        match self {
            Self::Both => &[Dir::Inbound, Dir::Outbound],
            Self::Inbound => &[Dir::Inbound],
            Self::Outbound => &[Dir::Outbound],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkLensState {
    pub title: String,
    pub seed: Seed,
    pub resolved: Option<Resolved>,
    /// `resolved` as lines for `direction`.
    pub lines: Vec<LensLine>,
    pub direction: LensDirection,
    pub loading: bool,
    /// The fetch could not start (no pipeline for the tenant).
    pub error: Option<String>,
    pub selected: usize,
}

impl NetworkLensState {
    pub fn open(title: String, seed: Seed, direction: LensDirection) -> Self {
        Self {
            title,
            seed,
            direction,
            loading: true,
            ..Default::default()
        }
    }

    pub fn set_resolved(&mut self, resolved: Resolved) {
        self.loading = false;
        self.resolved = Some(resolved);
        self.rebuild();
    }

    pub fn rebuild(&mut self) {
        self.lines = self
            .resolved
            .as_ref()
            .map(|r| build_lines(r, self.direction.dirs()))
            .unwrap_or_default();
        self.selected = self.selected.min(self.lines.len().saturating_sub(1));
    }

    pub fn cycle_direction(&mut self) {
        self.direction = self.direction.next();
        self.rebuild();
    }

    pub fn selected_line(&self) -> Option<&LensLine> {
        self.lines.get(self.selected)
    }

    /// Whole view as text (the `e` editor view).
    pub fn as_text(&self) -> String {
        let mut out = format!("Network access — {}\n{}\n\n", self.title, COMPUTED_NOTE);
        for l in &self.lines {
            match &l.rule {
                Some(r) => out.push_str(&format!("      {}", r.text())),
                None => out.push_str(&l.text),
            }
            out.push('\n');
        }
        out
    }

    pub fn move_by(&mut self, delta: isize) {
        let max = self.lines.len().saturating_sub(1) as isize;
        self.selected = (self.selected as isize + delta).clamp(0, max.max(0)) as usize;
    }

    pub fn goto_top(&mut self) {
        self.selected = 0;
    }

    pub fn goto_bottom(&mut self) {
        self.selected = self.lines.len().saturating_sub(1);
    }
}

pub fn render_network_lens(app: &crate::app::App, area: Rect, frame: &mut Frame) {
    let Some(st) = &app.network_lens else {
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
            Constraint::Length(1), // the computed-view note
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(inner);

    // ── Header ──
    let rules: Vec<_> = st.lines.iter().filter_map(|l| l.rule.as_ref()).collect();
    let open = rules.iter().filter(|r| r.open_to_internet && r.shadowed_by.is_none()).count();
    let shadowed = rules.iter().filter(|r| r.shadowed_by.is_some()).count();
    let blocked = rules.iter().filter(|r| matches!(r.cross, Some(Cross::Blocked(_)))).count();
    let warnings = st.lines.iter().filter(|l| l.kind == LineKind::Warning).count();
    let mut header = vec![
        Span::styled(
            " ⇄ NETWORK ACCESS ",
            Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            st.title.clone(),
            Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {} rule{}", rules.len(), if rules.len() == 1 { "" } else { "s" }),
            Style::default().fg(theme::text_dim()),
        ),
        Span::styled(format!("  · {}", st.direction.label()), Style::default().fg(theme::accent())),
    ];
    let mut flag = |n: usize, what: &str| {
        if n > 0 {
            header.push(Span::styled(format!("  · {} {}", n, what), Style::default().fg(theme::warning())));
        }
    };
    flag(open, "open to the internet");
    flag(blocked, "blocked by the other layer");
    flag(warnings, "unread");
    if shadowed > 0 {
        header.push(Span::styled(format!("  · {} shadowed", shadowed), Style::default().fg(theme::text_dim())));
    }
    if st.loading {
        header.push(Span::styled(
            format!("  {} reading NICs, subnets, NSGs…", theme::spinner(app.tick_count)),
            Style::default().fg(theme::warning()),
        ));
    }
    if let Some(e) = &st.error {
        header.push(Span::styled(format!("   ⚠ {}", e), Style::default().fg(theme::error())));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::styled(
            format!(" {}", COMPUTED_NOTE),
            Style::default().fg(theme::text_dim()).add_modifier(Modifier::ITALIC),
        )),
        chunks[1],
    );

    // ── Body ──
    let viewport = chunks[2].height as usize;
    let top = if viewport > 0 && st.selected >= viewport { st.selected + 1 - viewport } else { 0 };
    let mut body: Vec<Line> = Vec::with_capacity(viewport);
    if st.lines.is_empty() {
        let empty = if st.loading { "  Reading…" } else { "  Nothing to show (see header)" };
        body.push(Line::styled(empty, Style::default().fg(theme::text_dim())));
    }
    for (i, l) in st.lines.iter().enumerate().skip(top).take(viewport) {
        body.push(lens_line(l, i == st.selected));
    }
    frame.render_widget(Paragraph::new(body), chunks[2]);
    // A click puts the cursor on a line, a double-click follows it.
    app.mouse.pane_rows.borrow_mut().record_rows(chunks[2], top, st.lines.len());

    // ── Footer ──
    let mut spans = vec![Span::raw(" ")];
    for (k, d) in [
        ("j/k", "select"),
        ("⏎", "go to NSG"),
        ("t", "direction"),
        ("e", "open all"),
        ("y", "copy"),
        ("r", "refetch"),
        ("Z", "width"),
        ("Esc", "close"),
    ] {
        spans.extend(theme::hint(k, d));
    }
    let footer = Line::from(spans);
    let c = chunks[3];
    crate::app::record_hint_regions(app, &footer, 1, c.x, c.y, c.x + c.width);
    frame.render_widget(Paragraph::new(footer), c);
}

fn lens_line(l: &LensLine, selected: bool) -> Line<'static> {
    let marker = Span::styled(if selected { "▸ " } else { "  " }, Style::default().fg(theme::accent()));
    let bold = |s: Style| if selected { s.add_modifier(Modifier::BOLD) } else { s };
    let Some(r) = &l.rule else {
        let style = match l.kind {
            LineKind::Section => Style::default().fg(theme::heading()).add_modifier(Modifier::BOLD),
            LineKind::Layer => Style::default().fg(theme::accent()),
            LineKind::Warning => Style::default().fg(theme::warning()),
            LineKind::Note | LineKind::Blank => Style::default().fg(theme::text_dim()),
            LineKind::Rule => Style::default().fg(theme::text_primary()),
        };
        return Line::from(vec![marker, Span::styled(l.text.clone(), bold(style))]);
    };

    let live = r.shadowed_by.is_none();
    let base = bold(Style::default().fg(if live { theme::text_primary() } else { theme::text_dim() }));
    let verdict = if !live {
        base
    } else if r.allow {
        base.fg(theme::success())
    } else {
        base.fg(theme::warning())
    };
    let flow = if r.open_to_internet && live { base.fg(theme::warning()) } else { base };
    let mut spans = vec![
        marker,
        Span::raw("    "),
        Span::styled(format!("{:>5} ", r.priority), base),
        Span::styled(format!("{:<5} ", if r.allow { "allow" } else { "deny" }), verdict),
        Span::styled(format!("{:<4} ", r.protocol), base),
        Span::styled(format!("{}  ", r.flow), flow),
        Span::styled(r.name.clone(), base.fg(theme::text_dim())),
    ];
    if r.is_default {
        spans.push(Span::styled(" (default)", base.fg(theme::text_dim()).add_modifier(Modifier::ITALIC)));
    }
    if let Some(a) = r.annotation() {
        let style = match &r.cross {
            _ if !live => base.fg(theme::text_dim()),
            Some(Cross::Blocked(_)) => base.fg(theme::warning()),
            Some(Cross::Allowed(_)) => base.fg(theme::success()),
            _ => base.fg(theme::text_dim()),
        };
        spans.push(Span::styled(format!("  {}", a), style));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::nsg_eval::Note;

    fn resolved() -> Resolved {
        Resolved {
            notes: vec![Note { text: "a note".into(), id: None }],
            warnings: vec!["NSG x: 403".into()],
            ..Default::default()
        }
    }

    #[test]
    fn direction_cycles_and_selection_clamps() {
        let mut st = NetworkLensState::open("VM · vm-1".into(), Seed::default(), LensDirection::default());
        assert!(st.loading);
        st.set_resolved(resolved());
        assert!(!st.loading);
        assert_eq!(st.lines.len(), 2);
        st.goto_bottom();
        assert_eq!(st.selected_line().unwrap().copy_text(), "· a note");
        st.move_by(10);
        assert_eq!(st.selected, 1);
        st.move_by(-10);
        assert_eq!(st.selected, 0);
        st.cycle_direction();
        assert_eq!(st.direction, LensDirection::Inbound);
        st.cycle_direction();
        st.cycle_direction();
        assert_eq!(st.direction, LensDirection::Both);
        let text = st.as_text();
        assert!(text.starts_with("Network access — VM · vm-1\ncomputed from NSG rules"));
        assert!(text.contains("! NSG x: 403"));
    }
}
