// copy-adapted from neboto-tui src/ui/widgets/refs_lens.rs @ 03760c0 (the
// state, the `f` filter cycle, the header / coverage / body / footer layout)
//! "Referenced by" lens (`U`, #49), rendered **in the detail pane** (`Z`
//! full width): every row of the warm list caches whose links point at the
//! selected resource, grouped by the sub-tab it came from, with the link
//! that carried it. The index is `azure::references`; the cache walk and
//! the keys are `app/refs_lens.rs`.
//!
//! Coverage is stated, never implied: the second line counts the lists
//! searched and names the ones not loaded, the likely ones first; `L`
//! loads those in the background and the lens rescans as each lands.

use crate::app::all_search_label;
use crate::azure::references::RefRow;
use crate::azure::resource::Resource;
use crate::azure::service::{JumpView, ServiceType};
use crate::ui::theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// What the last scan read: the lists searched, and the ones not loaded
/// (`likely`: those whose rows usually point at this type).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RefsCoverage {
    pub searched: usize,
    pub total: usize,
    pub likely_cold: Vec<JumpView>,
    pub other_cold: usize,
}

#[derive(Debug, Clone)]
pub struct RefsLensState {
    pub title: String,
    /// The resource the lens is about (a directory row matches by alias).
    pub target: Box<dyn Resource>,
    /// Every match, in sub-tab order then by name.
    pub all_rows: Vec<RefRow>,
    /// `all_rows` narrowed by `service_filter`.
    pub rows: Vec<RefRow>,
    pub service_filter: Option<ServiceType>,
    pub coverage: RefsCoverage,
    /// Lists `L` is loading in the background.
    pub warming: Vec<JumpView>,
    /// A background load that failed: shown, never fatal.
    pub warnings: Vec<String>,
    pub selected: usize,
    pub message: Option<String>,
}

/// A view's place in the tab strip, for sorting groups.
fn view_order(view: JumpView) -> (usize, usize) {
    let services = ServiceType::all();
    let s = view.service();
    let si = services.iter().position(|x| *x == s).unwrap_or(usize::MAX);
    let vi = s.views().iter().position(|v| *v == view).unwrap_or(usize::MAX);
    (si, vi)
}

impl RefsLensState {
    pub fn open(title: String, target: Box<dyn Resource>) -> Self {
        Self {
            title,
            target,
            all_rows: Vec::new(),
            rows: Vec::new(),
            service_filter: None,
            coverage: RefsCoverage::default(),
            warming: Vec::new(),
            warnings: Vec::new(),
            selected: 0,
            message: None,
        }
    }

    pub fn set_rows(&mut self, mut rows: Vec<RefRow>, coverage: RefsCoverage) {
        rows.sort_by(|a, b| {
            view_order(a.view)
                .cmp(&view_order(b.view))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        self.all_rows = rows;
        self.coverage = coverage;
        if self.service_filter.is_some_and(|f| !self.all_rows.iter().any(|r| r.view.service() == f)) {
            self.service_filter = None;
        }
        self.rebuild();
    }

    /// Services present in the results, in display order: the `f` cycle.
    pub fn services_present(&self) -> Vec<ServiceType> {
        let mut out: Vec<ServiceType> = Vec::new();
        for r in &self.all_rows {
            if !out.contains(&r.view.service()) {
                out.push(r.view.service());
            }
        }
        out
    }

    fn rebuild(&mut self) {
        self.rows = self
            .all_rows
            .iter()
            .filter(|r| self.service_filter.is_none_or(|f| f == r.view.service()))
            .cloned()
            .collect();
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
    }

    pub fn cycle_service_filter(&mut self) {
        let present = self.services_present();
        self.service_filter = match self.service_filter {
            None => present.first().copied(),
            Some(cur) => present.iter().position(|s| *s == cur).and_then(|i| present.get(i + 1).copied()),
        };
        self.rebuild();
    }

    pub fn selected_row(&self) -> Option<&RefRow> {
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

    /// The likely lists not loaded and not loading: what `L` would load.
    pub fn loadable(&self) -> Vec<JumpView> {
        self.coverage.likely_cold.iter().copied().filter(|v| !self.warming.contains(v)).collect()
    }

    /// The coverage line: lists searched, then what was not.
    pub fn coverage_text(&self) -> String {
        let c = &self.coverage;
        let mut out = format!("searched {} of {} lists (zero calls)", c.searched, c.total);
        if !c.likely_cold.is_empty() {
            let names: Vec<String> = c.likely_cold.iter().map(|v| all_search_label(*v)).collect();
            out.push_str(&format!(" · not checked — load {}", names.join(", ")));
        }
        if c.other_cold > 0 {
            out.push_str(&format!(" · {} other list{} not loaded", c.other_cold, if c.other_cold == 1 { "" } else { "s" }));
        }
        out
    }

    /// Whole view as text (the `e` editor view).
    pub fn as_text(&self) -> String {
        let mut out = format!("Referenced by — {}\n{}\n\n", self.title, self.coverage_text());
        for r in &self.rows {
            out.push_str(&format!("{}\t{}\t{}\tvia {}\n", all_search_label(r.view), r.name, r.id, r.via));
        }
        for w in &self.warnings {
            out.push_str(&format!("! {}\n", w));
        }
        out
    }
}

pub fn render_refs_lens(app: &crate::app::App, area: Rect, frame: &mut Frame) {
    let Some(st) = &app.refs_lens else {
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
            Constraint::Length(1), // coverage
            Constraint::Length(st.warnings.len().min(3) as u16), // failed loads
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(inner);

    // ── Header ──
    let n = st.rows.len();
    let mut header = vec![
        Span::styled(" ⇠ REFERENCED BY ", Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)),
        Span::styled(st.title.clone(), Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {} ref{}", n, if n == 1 { "" } else { "s" }), Style::default().fg(theme::text_dim())),
    ];
    if let Some(f) = st.service_filter {
        header.push(Span::styled(format!("  · {} only", f.short_name()), Style::default().fg(theme::accent())));
    }
    if !st.warming.is_empty() {
        let names: Vec<String> = st.warming.iter().map(|v| all_search_label(*v)).collect();
        header.push(Span::styled(
            format!("  {} loading {}…", theme::spinner(app.tick_count), names.join(", ")),
            Style::default().fg(theme::warning()),
        ));
    }
    if let Some(m) = &st.message {
        header.push(Span::styled(format!("   {}", m), Style::default().fg(theme::success())));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::styled(format!(" {}", st.coverage_text()), Style::default().fg(theme::text_dim()))),
        chunks[1],
    );
    let warnings: Vec<Line> = st
        .warnings
        .iter()
        .map(|w| Line::styled(format!(" ⚠ {}", w), Style::default().fg(theme::warning())))
        .collect();
    frame.render_widget(Paragraph::new(warnings), chunks[2]);

    // ── Body: one row per referrer, the group label on its first row ──
    let viewport = chunks[3].height as usize;
    let top = if viewport > 0 && st.selected >= viewport { st.selected + 1 - viewport } else { 0 };
    let mut body: Vec<Line> = Vec::with_capacity(viewport);
    if st.rows.is_empty() {
        let empty = if st.coverage.searched == 0 {
            "  Nothing loaded yet: open the lists that might point here (or L), then r"
        } else if st.service_filter.is_some() {
            "  No references from this service: f cycles"
        } else {
            "  No loaded resource points at this one (only loaded lists were searched)"
        };
        body.push(Line::styled(empty, Style::default().fg(theme::text_dim())));
    }
    let group_w = 22usize;
    let name_w = 30usize;
    for (i, row) in st.rows.iter().enumerate().skip(top).take(viewport) {
        let selected = i == st.selected;
        let first_of_group = i == top || st.rows[i - 1].view != row.view;
        let base = if selected {
            Style::default().fg(theme::text_primary()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::text_primary())
        };
        let group = if first_of_group { all_search_label(row.view) } else { String::new() };
        body.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, Style::default().fg(theme::accent())),
            Span::styled(format!("{:<w$} ", trim(&group, group_w), w = group_w), Style::default().fg(theme::heading())),
            Span::styled(format!("{:<w$} ", trim(&row.name, name_w), w = name_w), base),
            Span::styled(format!("via {}", row.via), base.fg(theme::text_dim())),
        ]));
    }
    frame.render_widget(Paragraph::new(body), chunks[3]);
    // A click puts the cursor on a row, a double-click follows it.
    app.mouse.pane_rows.borrow_mut().record_rows(chunks[3], top, st.rows.len());

    // ── Footer ──
    let mut hints = vec![("j/k", "select"), ("⏎", "go to"), ("f", "service"), ("r", "rescan")];
    if !st.loadable().is_empty() {
        hints.push(("L", "load likely"));
    }
    hints.extend([("y", "copy id"), ("e", "open all"), ("Z", "width"), ("Esc", "close")]);
    let mut footer = theme::hint_line(&hints);
    footer.spans.insert(0, Span::raw(" "));
    let c = chunks[4];
    crate::app::record_hint_regions(app, &footer, 1, c.x, c.y, c.x + c.width);
    frame.render_widget(Paragraph::new(footer), c);
}

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

    fn row(view: JumpView, name: &str) -> RefRow {
        RefRow { view, resource_type: "T".into(), name: name.into(), id: format!("/x/{name}"), via: "v".into() }
    }

    #[test]
    fn rows_sort_by_tab_order_and_f_cycles_the_services_present() {
        let target = crate::app::harness_tests::mocks::nic("nic-1", "westeurope");
        let mut st = RefsLensState::open("NIC · nic-1".into(), target);
        st.set_rows(
            vec![row(JumpView::PrivateEndpoints, "pe-1"), row(JumpView::VirtualMachines, "vm-b"), row(JumpView::VirtualMachines, "vm-a")],
            RefsCoverage { searched: 2, total: 40, likely_cold: vec![JumpView::LoadBalancers], other_cold: 3 },
        );
        let names: Vec<&str> = st.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["vm-a", "vm-b", "pe-1"]);
        st.cycle_service_filter();
        assert_eq!(st.service_filter, Some(ServiceType::VirtualMachines));
        assert_eq!(st.rows.len(), 2);
        st.cycle_service_filter();
        assert_eq!(st.rows.len(), 1);
        st.cycle_service_filter();
        assert_eq!((st.service_filter, st.rows.len()), (None, 3));
        st.goto_bottom();
        st.move_by(5);
        assert_eq!(st.selected_row().unwrap().name, "pe-1");
        assert_eq!(
            st.coverage_text(),
            "searched 2 of 40 lists (zero calls) · not checked — load VNet/LBs · 3 other lists not loaded"
        );
        assert_eq!(st.loadable(), vec![JumpView::LoadBalancers]);
        st.warming.push(JumpView::LoadBalancers);
        assert!(st.loadable().is_empty());
    }
}
