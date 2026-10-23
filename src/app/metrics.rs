//! The metrics view (`m`, #51) on `App`: opening it on the selected row,
//! the fetch tasks (series and the `a` picker's definitions) and its keys.
//! The calls and parsing are `azure::metrics`; the drawing is
//! `ui::widgets::metrics_overlay`.

use super::{App, LayoutMode, PAGE_STEP};
use crate::azure::metrics::{
    curated_queries, definitions_path, fetch_series, is_arm_resource, metrics_path, now_minute, parse_definitions,
    short_error, supports_metrics, METRICS_API_VERSION,
};
use crate::event::Event;
use crate::lazy::LazyApply;
use crate::ui::widgets::metrics_overlay::{MetricPicker, MetricsState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

impl App {
    /// Whether `m` opens on a default chart set for the selected row (the
    /// status-bar hint). Any other ARM resource still opens, on the picker.
    pub fn supports_metrics(&self) -> bool {
        self.get_selected_resource().is_some_and(|r| supports_metrics(r.id()))
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
        let title = format!("{} · {}", r.resource_type(), r.name());
        // The window is sticky across opens.
        let window = self.metrics_window;
        let queries = curated_queries(&id);
        let curated = !queries.is_empty();
        self.network_lens = None;
        self.metrics = Some(MetricsState::open(id, title, queries, window));
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
    }

    /// One task: every series of the view's window, delivered through the
    /// apply-closure event, stamped with the lazy epoch (a subscription
    /// switch drops it) and the metrics generation (a reopen, a window
    /// change or `r` supersedes it).
    fn fetch_metrics(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
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
            }
            KeyCode::Char('[') => {
                st.window = st.window.prev();
                self.fetch_metrics(event_tx);
            }
            KeyCode::Char(c @ '1'..='4') => {
                if let Some(w) = crate::azure::metrics::MetricWindow::from_digit(c) {
                    st.window = w;
                    self.fetch_metrics(event_tx);
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => self.fetch_metrics(event_tx),
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
