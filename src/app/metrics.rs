//! The metrics view (`m`, #51) on `App`: opening it on the selected row,
//! the fetch tasks (series and the `a` picker's definitions) and its keys.
//! The calls and parsing are `azure::metrics`; the drawing is
//! `ui::widgets::metrics_overlay`.

use super::{App, LayoutMode, PAGE_STEP};
use crate::azure::metrics::{
    curated_queries, definitions_path, fetch_series, is_arm_resource, metrics_path, now_minute, parse_definitions,
    short_error, supports_metrics, METRICS_API_VERSION,
};
use crate::azure::resource::Resource;
use crate::azure::services::edge::{AppGatewayRow, FrontDoorProfileRow, WafPolicyRow};
use crate::azure::waf_metrics::{fetch_waf, policy_name, policy_targets, WafProduct};
use crate::ui::widgets::metrics_waf::WafState;
use crate::event::Event;
use crate::lazy::LazyApply;
use crate::app::timeline::TimelineTarget;
use crate::ui::widgets::metrics_overlay::{MarkerSource, MetricPicker, MetricsState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

impl App {
    /// Whether `m` opens on a default chart set for the selected row (the
    /// status-bar hint). Any other ARM resource still opens, on the picker.
    pub fn supports_metrics(&self) -> bool {
        self.get_selected_resource()
            .is_some_and(|r| supports_metrics(r.id()) || r.as_any().downcast_ref::<WafPolicyRow>().is_some())
    }

    pub(super) fn open_metrics(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(r) = self.get_selected_resource() else {
            self.error_message = Some("No resource selected".into());
            return;
        };
        let id = r.id().to_string();
        if !is_arm_resource(&id) {
            self.error_message = Some(format!("No Azure Monitor metrics for a {}", r.resource_type()));
            return;
        }
        let mut title = format!("{} · {}", r.resource_type(), r.name());
        let (id, waf) = match waf_view_for(r) {
            Ok(Some(w)) => {
                // A policy charts the resource it is attached to.
                let target = w.targets[0].clone();
                if target != id {
                    title = waf_title(w.product, &target);
                }
                (target, Some(w))
            }
            Ok(None) => (id, None),
            Err(e) => {
                self.error_message = Some(e);
                return;
            }
        };
        // The window is sticky across opens.
        let window = self.metrics_window;
        let queries = curated_queries(&id);
        let curated = !queries.is_empty() || waf.is_some();
        self.network_lens = None;
        self.refs_lens = None;
        self.chart_timeline = None;
        self.metrics_parked = None;
        let mut st = MetricsState::open(id, title, queries, window);
        st.waf_on = waf.is_some();
        st.waf = waf;
        self.metrics = Some(st);
        // From the list: the pane behind the view is the default section,
        // with its on-enter hook fired, so closing never leaves a spinner.
        if !self.details_focused {
            self.details_focused = true;
            self.reset_detail_section_to_default(event_tx);
        }
        if curated {
            self.fetch_metrics(event_tx);
        } else {
            self.open_metric_picker(event_tx);
        }
        self.seed_chart_markers(event_tx);
    }

    /// The change markers the open chart draws: the `W` timeline rows
    /// behind it, unless `c` hid them.
    pub fn marker_source(&self) -> Option<MarkerSource<'_>> {
        let tl = self.chart_timeline.as_ref().filter(|_| self.chart_markers)?;
        Some(MarkerSource { rows: &tl.rows, loading: tl.is_loading() })
    }

    /// One task: every series of the view's window, delivered through the
    /// apply-closure event, stamped with the lazy epoch (a subscription
    /// switch drops it) and the metrics generation (a reopen, a window
    /// change or `r` supersedes it).
    fn fetch_metrics(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.metrics.as_ref().is_some_and(|st| st.waf_on && st.waf.is_some()) {
            return self.fetch_waf_view(event_tx);
        }
        self.metrics_generation += 1;
        let generation = self.metrics_generation;
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        st.error = None;
        self.metrics_window = st.window;
        if st.queries.is_empty() {
            st.loading = false;
            return;
        }
        st.loading = true;
        let arm = match self.azure_clients.arm_for_path(&st.resource_id) {
            Ok(arm) => arm,
            Err(e) => {
                st.loading = false;
                st.error = Some(e);
                return;
            }
        };
        let (path, queries, window) = (metrics_path(&st.resource_id), st.queries.clone(), st.window);
        let end = now_minute();
        let epoch = self.lazy.epoch();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let fetch = |query: Vec<(&'static str, String)>| {
                let (arm, path) = (arm.clone(), path.clone());
                async move {
                    let pairs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
                    arm.get_query(&path, METRICS_API_VERSION, &pairs).await.map_err(|e| e.to_string())
                }
            };
            let series = fetch_series(&queries, window, end, fetch).await;
            let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
                if app.metrics_generation != generation {
                    return;
                }
                if let Some(st) = app.metrics.as_mut() {
                    st.set_series(end, series);
                }
            });
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    /// The WAF view's one task: the action split and the rule tables of
    /// the view's resource, delivered like the series (same epoch and
    /// generation guards).
    fn fetch_waf_view(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        self.metrics_generation += 1;
        let generation = self.metrics_generation;
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        let Some(waf) = st.waf.as_ref() else {
            return;
        };
        st.error = None;
        self.metrics_window = st.window;
        st.loading = true;
        let (product, policy) = (waf.product, waf.policy.clone());
        let arm = match self.azure_clients.arm_for_path(&st.resource_id) {
            Ok(arm) => arm,
            Err(e) => {
                st.loading = false;
                st.error = Some(e);
                return;
            }
        };
        let (id, path, window) = (st.resource_id.clone(), metrics_path(&st.resource_id), st.window);
        let end = now_minute();
        let epoch = self.lazy.epoch();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let fetch = |query: Vec<(&'static str, String)>| {
                let (arm, path) = (arm.clone(), path.clone());
                async move {
                    let pairs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
                    arm.get_query(&path, METRICS_API_VERSION, &pairs).await.map_err(|e| e.to_string())
                }
            };
            let data = fetch_waf(product, policy.as_deref(), window, end, fetch).await;
            let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
                if app.metrics_generation != generation {
                    return;
                }
                if let Some(st) = app.metrics.as_mut().filter(|st| st.resource_id == id) {
                    st.set_waf(data);
                }
            });
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    /// `n` on a policy attached to several resources: the next one.
    fn waf_next_target(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        let Some(w) = st.waf.as_mut().filter(|w| w.targets.len() > 1) else {
            return;
        };
        w.target = (w.target + 1) % w.targets.len();
        let id = w.targets[w.target].clone();
        w.data = None;
        w.charted = None;
        (w.table, w.row) = (0, 0);
        st.title = waf_title(w.product, &id);
        st.queries = curated_queries(&id);
        st.resource_id = id;
        st.series.clear();
        // The markers are the new resource's.
        self.chart_timeline = None;
        self.fetch_metrics(event_tx);
        self.seed_chart_markers(event_tx);
    }

    /// `d` in the WAF view: back from a charted rule, else to the
    /// resource's default metric set.
    fn waf_back(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        if st.waf.as_ref().is_some_and(|w| w.charted.is_some()) {
            if let Some(w) = st.waf.as_mut() {
                w.charted = None;
            }
            return;
        }
        let queries = curated_queries(&st.resource_id);
        if queries.is_empty() {
            self.toast("No default metrics for this type");
            return;
        }
        st.waf_on = false;
        st.queries = queries;
        st.curated = true;
        st.series.clear();
        st.selected = 0;
        self.fetch_metrics(event_tx);
    }

    /// `a`: the resource's metric definitions, to chart any one.
    fn open_metric_picker(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        st.picker = Some(MetricPicker { loading: true, ..Default::default() });
        let id = st.resource_id.clone();
        let arm = match self.azure_clients.arm_for_path(&id) {
            Ok(arm) => arm,
            Err(e) => {
                st.picker = Some(MetricPicker { error: Some(e), ..Default::default() });
                return;
            }
        };
        let epoch = self.lazy.epoch();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let result = arm.get(&definitions_path(&id), METRICS_API_VERSION).await.map_err(|e| e.to_string());
            let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
                let Some(st) = app.metrics.as_mut().filter(|st| st.resource_id == id) else {
                    return;
                };
                let Some(p) = st.picker.as_mut() else {
                    return;
                };
                p.loading = false;
                match result {
                    Ok(body) => p.defs = parse_definitions(&body),
                    Err(e) => p.error = Some(short_error(&e)),
                }
            });
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    fn close_metrics(&mut self) {
        self.metrics = None;
        self.chart_timeline = None;
        if self.layout_mode == LayoutMode::DetailsOnly {
            self.layout_mode = LayoutMode::Split;
        }
    }

    /// Keys while the metrics view owns the detail pane.
    pub(super) fn handle_metrics_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // The WAF view's own keys, before the common ones.
        if st.waf_view() && !ctrl {
            match key.code {
                KeyCode::Tab | KeyCode::BackTab => {
                    if let Some(w) = st.waf.as_mut() {
                        w.next_table();
                    }
                    return;
                }
                KeyCode::Enter => {
                    let charted = st.waf.as_mut().is_some_and(|w| w.chart_selected());
                    if !charted {
                        self.toast("No rule selected");
                    }
                    return;
                }
                KeyCode::Char('n') => {
                    self.waf_next_target(event_tx);
                    return;
                }
                KeyCode::Char('d') => {
                    self.waf_back(event_tx);
                    return;
                }
                KeyCode::Esc if st.waf.as_ref().is_some_and(|w| w.charted.is_some()) => {
                    if let Some(w) = st.waf.as_mut() {
                        w.charted = None;
                    }
                    return;
                }
                KeyCode::Char('y') => {
                    let text = match st.waf.as_ref().and_then(|w| w.selected_rule()) {
                        Some(r) => WafState::rule_label(r),
                        None => st.waf.as_ref().map(|w| w.as_text()).unwrap_or_default(),
                    };
                    self.copy_to_clipboard(&text, "WAF rule");
                    return;
                }
                _ => {}
            }
        }
        if st.picker.is_none() && !st.waf_on && st.waf.is_some() && key.code == KeyCode::Char('w') && !ctrl {
            st.waf_on = true;
            self.fetch_metrics(event_tx);
            return;
        }
        match key.code {
            KeyCode::Char('l') if ctrl => self.redraw_requested = true,
            KeyCode::Char('d') if ctrl => st.move_by(PAGE_STEP as isize),
            KeyCode::Char('u') if ctrl => st.move_by(-(PAGE_STEP as isize)),
            KeyCode::Char('j') | KeyCode::Down => st.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => st.move_by(-1),
            KeyCode::PageDown => st.move_by(2 * PAGE_STEP as isize),
            KeyCode::PageUp => st.move_by(-2 * (PAGE_STEP as isize)),
            KeyCode::Char('g') | KeyCode::Home => st.goto(false),
            KeyCode::Char('G') | KeyCode::End => st.goto(true),
            // The picker: ⏎ charts the metric, Esc (or `a`) goes back.
            KeyCode::Enter if st.picker.is_some() => {
                let picked = st.picker.as_ref().and_then(|p| p.defs.get(p.selected)).map(|d| d.query());
                if let Some(q) = picked {
                    st.picker = None;
                    st.waf_on = false;
                    st.queries = vec![q];
                    st.curated = false;
                    st.series.clear();
                    st.selected = 0;
                    self.fetch_metrics(event_tx);
                }
            }
            KeyCode::Esc | KeyCode::Char('a') | KeyCode::Char('h') | KeyCode::Left if st.picker.is_some() => {
                st.picker = None;
            }
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('m') | KeyCode::Char('h') | KeyCode::Left => {
                self.close_metrics()
            }
            KeyCode::Char(']') => {
                st.window = st.window.next();
                self.fetch_metrics(event_tx);
                self.widen_chart_markers(event_tx);
            }
            KeyCode::Char('[') => {
                // From 1h this wraps to 30d, and the changes widen with it.
                st.window = st.window.prev();
                self.fetch_metrics(event_tx);
                self.widen_chart_markers(event_tx);
            }
            KeyCode::Char(c @ '1'..='5') => {
                if let Some(w) = crate::azure::metrics::MetricWindow::from_digit(c) {
                    st.window = w;
                    self.fetch_metrics(event_tx);
                    self.widen_chart_markers(event_tx);
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                self.fetch_metrics(event_tx);
                // The changes since the last read, too.
                if self.chart_timeline.is_some() {
                    self.fetch_timeline(event_tx, TimelineTarget::Markers);
                }
            }
            // Change markers: hide / show; the first show fetches them.
            KeyCode::Char('c') if st.picker.is_none() => {
                self.chart_markers = !self.chart_markers;
                if self.chart_markers {
                    self.seed_chart_markers(event_tx);
                }
            }
            KeyCode::Char('W') if st.picker.is_none() => self.metrics_to_timeline(event_tx),
            KeyCode::Char('a') => self.open_metric_picker(event_tx),
            KeyCode::Char('d') => {
                let queries = curated_queries(&st.resource_id);
                if queries.is_empty() {
                    self.toast("No default metrics for this type");
                } else if !st.curated {
                    st.queries = queries;
                    st.curated = true;
                    st.series.clear();
                    st.selected = 0;
                    self.fetch_metrics(event_tx);
                }
            }
            KeyCode::Char('e') => self.editor_requested = true,
            KeyCode::Char('y') => {
                if let Some(text) = st.selected_series().map(|s| s.summary()) {
                    self.copy_to_clipboard(&text, "metric");
                }
            }
            KeyCode::Char('Z') => {
                self.layout_mode = match self.layout_mode {
                    LayoutMode::DetailsOnly => LayoutMode::Split,
                    _ => LayoutMode::DetailsOnly,
                }
            }
            _ => {}
        }
    }
}

/// `Application Gateway · agw-1`: the title of a WAF view opened from a
/// policy (the policy's resource, not the policy).
fn waf_title(product: WafProduct, id: &str) -> String {
    format!("{} · {}", product.label(), policy_name(id))
}

/// The WAF view a row opens, if it has one: a gateway with a WAF, a Front
/// Door profile, or a WAF policy (its first attached resource, with the
/// policy pinned as the `PolicyName` filter; `n` steps through the rest).
/// `Err` is a policy attached to nothing there is a view for.
fn waf_view_for(r: &dyn Resource) -> Result<Option<WafState>, String> {
    let any = r.as_any();
    if let Some(p) = any.downcast_ref::<WafPolicyRow>() {
        let t = policy_targets(&p.associations);
        let Some(first) = t.targets.first() else {
            return Err(if t.skipped.is_empty() {
                format!("{} is attached to nothing: no WAF traffic to chart", p.base.name)
            } else {
                format!("{} is attached only to a classic Front Door or Gateway for Containers: no WAF metrics view", p.base.name)
            });
        };
        let product = WafProduct::from_id(first).expect("policy_targets keeps only WAF products");
        return Ok(Some(WafState::new(product, Some(policy_name(&p.base.id)), t.targets.clone(), t.skipped)));
    }
    if any.downcast_ref::<AppGatewayRow>().is_some_and(AppGatewayRow::has_waf) || any.downcast_ref::<FrontDoorProfileRow>().is_some() {
        let product = WafProduct::from_id(r.id());
        return Ok(product.map(|p| WafState::new(p, None, vec![r.id().to_string()], Vec::new())));
    }
    Ok(None)
}
