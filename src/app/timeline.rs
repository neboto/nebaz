// ported from neboto-tui src/app.rs @ ee8eb89 (the `W` block: seed_trail_lens
// and the lens keys; adapted to one apply-closure task per source)
//! The change timeline (`W`, #52) on `App`: what it opens on, one fetch
//! task per source, and its keys. The row model and the paths are
//! `azure::timeline`; the state and the drawing `ui::widgets::timeline_lens`.

use super::{App, LayoutMode, PAGE_STEP};
use crate::azure::resource::{name_of_id, Resource};
use crate::azure::services::activity::{activity_path, activity_query_since, ACTIVITY_API_VERSION};
use crate::azure::timeline::{
    alert_rows, alerts_request, deployment_rows, deployments_path, health_path, health_rows, now_secs,
    LensWindow, TimelineSource, ALERTS_API_VERSION, DEPLOYMENTS_API_VERSION, HEALTH_API_VERSION,
    TIMELINE_MAX_EVENTS, TIMELINE_MAX_ITEMS,
};
use crate::event::Event;
use crate::lazy::LazyApply;
use crate::ui::widgets::timeline_lens::TimelineLensState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::Value;
use std::future::Future;
use tokio::sync::mpsc;

type SourceResult = std::result::Result<Vec<Value>, String>;

/// The ARM id the timeline of `r` is about: the row's own id when it is an
/// ARM id (a directory row has none).
pub fn timeline_target(r: &dyn Resource) -> Option<String> {
    r.id().starts_with("/subscriptions/").then(|| r.id().to_string())
}

impl App {
    /// Whether `W` has a timeline for the selected row (the status-bar hint).
    pub fn supports_timeline(&self) -> bool {
        self.get_selected_resource().is_some_and(|r| timeline_target(r).is_some())
    }

    pub(super) fn open_timeline(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(r) = self.get_selected_resource() else {
            self.error_message = Some("No resource selected".into());
            return;
        };
        let Some(id) = timeline_target(r) else {
            self.error_message = Some(format!("No Activity Log for a {}", r.resource_type()));
            return;
        };
        let title = if id == r.id() {
            format!("{} · {}", r.resource_type(), r.name())
        } else {
            name_of_id(&id).to_string()
        };
        self.network_lens = None;
        self.metrics = None;
        self.refs_lens = None;
        self.timeline = Some(TimelineLensState::open(title, id, self.timeline_window, self.timeline_include_all));
        // From the list: the pane behind the lens is the default section,
        // with its hook fired, so closing never leaves a spinner.
        if !self.details_focused {
            self.details_focused = true;
            self.reset_detail_section_to_default(event_tx);
        }
        self.fetch_timeline(event_tx);
    }

    /// One task per source, each delivered through the apply-closure event
    /// under the lazy epoch (a subscription switch drops it) and the
    /// timeline generation (a reopen, a window change or `r` supersedes it).
    fn fetch_timeline(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        self.timeline_generation += 1;
        let generation = self.timeline_generation;
        let Some(st) = self.timeline.as_ref() else {
            return;
        };
        let (id, window) = (st.resource_id.clone(), st.window);
        self.timeline_window = window;
        let since = now_secs() - window.days() * 86_400;
        let is_resource = health_path(&id).is_some();

        let mut sources = vec![TimelineSource::Activity, TimelineSource::Alert];
        let health = health_path(&id);
        if health.is_some() {
            sources.push(TimelineSource::Health);
        }
        let deployments = deployments_path(&id);
        if deployments.is_some() {
            sources.push(TimelineSource::Deployment);
        }
        if let Some(st) = self.timeline.as_mut() {
            st.begin(sources, since);
            if health.is_none() {
                st.note("Resource Health: resources only".into());
            }
            if window == LensWindow::Quarter {
                st.note("alerts: the last 30 days (their retention)".into());
            }
        }

        let c = &self.azure_clients;
        let activity = c.list_fetch_query_capped(
            &activity_path(&id).unwrap_or_default(),
            ACTIVITY_API_VERSION,
            activity_query_since(&id, since),
            TIMELINE_MAX_EVENTS,
        );
        self.spawn_timeline_source(event_tx, generation, activity, |st, result| match result {
            Ok(events) => {
                let capped = events.len() >= TIMELINE_MAX_EVENTS;
                st.set_activity(events, capped);
            }
            Err(e) => st.set_source_error(TimelineSource::Activity, short(&e)),
        });

        if let Some((path, query)) = alerts_request(&id, window) {
            let fetch = c.list_fetch_query_capped(&path, ALERTS_API_VERSION, query, TIMELINE_MAX_ITEMS);
            self.spawn_timeline_source(event_tx, generation, fetch, move |st, result| match result {
                Ok(items) => st.set_rows(TimelineSource::Alert, alert_rows(&items, since)),
                Err(e) => st.set_source_error(TimelineSource::Alert, short(&e)),
            });
        }

        if let Some(path) = health {
            let fetch = self.azure_clients.list_fetch_query_capped(&path, HEALTH_API_VERSION, vec![], TIMELINE_MAX_ITEMS);
            self.spawn_timeline_source(event_tx, generation, fetch, move |st, result| match result {
                Ok(items) => st.set_rows(TimelineSource::Health, health_rows(&items, since)),
                Err(e) => st.set_source_error(TimelineSource::Health, short(&e)),
            });
        }

        if let Some(path) = deployments {
            let fetch =
                self.azure_clients.list_fetch_query_capped(&path, DEPLOYMENTS_API_VERSION, vec![], TIMELINE_MAX_ITEMS);
            let touching = is_resource.then(|| id.clone());
            self.spawn_timeline_source(event_tx, generation, fetch, move |st, result| match result {
                Ok(items) => {
                    st.set_rows(TimelineSource::Deployment, deployment_rows(&items, since, touching.as_deref()))
                }
                Err(e) => st.set_source_error(TimelineSource::Deployment, short(&e)),
            });
        }
    }

    fn spawn_timeline_source<F>(
        &self,
        event_tx: &mpsc::UnboundedSender<Event>,
        generation: u64,
        fetch: F,
        land: impl FnOnce(&mut TimelineLensState, SourceResult) + Send + 'static,
    ) where
        F: Future<Output = SourceResult> + Send + 'static,
    {
        let epoch = self.lazy.epoch();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let result = fetch.await;
            let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
                if app.timeline_generation != generation {
                    return;
                }
                if let Some(st) = app.timeline.as_mut() {
                    land(st, result);
                }
            });
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    fn close_timeline(&mut self) {
        self.timeline = None;
        if self.layout_mode == LayoutMode::DetailsOnly {
            self.layout_mode = LayoutMode::Split;
        }
    }

    /// Keys while the timeline owns the detail pane.
    pub(super) fn handle_timeline_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.timeline.as_mut() else {
            return;
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('l') if ctrl => self.redraw_requested = true,
            KeyCode::Char('d') if ctrl => st.move_by(PAGE_STEP as isize),
            KeyCode::Char('u') if ctrl => st.move_by(-(PAGE_STEP as isize)),
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('W') | KeyCode::Char('h') | KeyCode::Left => {
                self.close_timeline()
            }
            KeyCode::Char('j') | KeyCode::Down => st.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => st.move_by(-1),
            KeyCode::PageDown => st.move_by(2 * PAGE_STEP as isize),
            KeyCode::PageUp => st.move_by(-2 * (PAGE_STEP as isize)),
            KeyCode::Char('g') | KeyCode::Home => st.goto_top(),
            KeyCode::Char('G') | KeyCode::End => st.goto_bottom(),
            KeyCode::Char('f') => st.cycle_source_filter(),
            KeyCode::Char('a') => {
                st.toggle_include_all();
                self.timeline_include_all = st.include_all;
            }
            KeyCode::Char(']') => {
                let next = st.window.next();
                if next != st.window {
                    st.window = next;
                    self.fetch_timeline(event_tx);
                }
            }
            KeyCode::Char('[') => {
                let prev = st.window.prev();
                if prev != st.window {
                    st.window = prev;
                    self.fetch_timeline(event_tx);
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => self.fetch_timeline(event_tx),
            // The row's named fields in `$EDITOR`; `e` the whole timeline.
            KeyCode::Enter | KeyCode::Char('v') => {
                if st.selected_row().is_some() {
                    st.editor_row = true;
                    self.editor_requested = true;
                }
            }
            KeyCode::Char('e') => {
                st.editor_row = false;
                self.editor_requested = true;
            }
            // Go to what the row is about; Ctrl-O comes back.
            KeyCode::Char('l') | KeyCode::Right => {
                let target = st.selected_row().and_then(|r| r.target.clone());
                if let Some(id) = target.filter(|t| !t.eq_ignore_ascii_case(&st.resource_id)) {
                    self.close_timeline();
                    self.jump_to_arm_id(&id, event_tx);
                }
            }
            KeyCode::Char('y') => {
                if let Some(text) = st.selected_row().map(|r| r.as_text()) {
                    self.copy_to_clipboard(&text, "change");
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

/// A source's error, one line; a 403 names what Reader grants.
fn short(e: &str) -> String {
    if e.contains("403") || e.contains("AuthorizationFailed") || e.contains("Forbidden") {
        return "no access".into();
    }
    let first = e.lines().next().unwrap_or(e);
    if first.chars().count() > 120 {
        format!("{}…", first.chars().take(120).collect::<String>())
    } else {
        first.to_string()
    }
}
