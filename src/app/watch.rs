//! Watch mode on `App` (`w`, `-w`, config `watch`; #228, neboto's loop and
//! neboto-tui#329): every `Tick` asks whether a refresh is due.
//!
//! - **The list**: a due pass re-runs the current sub-tab's streaming load
//!   with its pages diverted into `watch_staging`, so the rows on screen
//!   stay until the whole set lands and swaps in, the selection kept by id
//!   (the stream handlers in `app.rs`). A failed pass keeps the rows and
//!   says so once (`WatchState::report`).
//! - **The charts** (`m`): while they own the pane, watch refetches them
//!   instead of the list behind them, at the watch interval but never under
//!   a minute (Azure Monitor's finest grain is `PT1M`, so a faster refetch
//!   reads the same points), keeping the window; a failed pass keeps the
//!   series it had.
//!
//! The interval presets floor at 15 s for ARM throttling (`WATCH_INTERVALS`);
//! #63 is a per-service floor for Storage.

use super::App;
use crate::event::Event;
use std::time::Duration;
use tokio::sync::mpsc;

/// Azure Monitor's finest grain: the charts never refetch faster.
pub const CHART_FLOOR: Duration = Duration::from_secs(60);

impl App {
    /// Called on every `Tick` (250 ms): start a refresh when one is due.
    pub(super) fn watch_tick(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if !self.watch.enabled {
            return;
        }
        if self.metrics.is_some() {
            return self.watch_tick_charts(event_tx);
        }
        let blocked = self.watch_list_blocked();
        if self.watch.due(blocked) {
            self.watch.mark_refreshed();
            self.start_watch_refresh();
        }
    }

    /// What holds a list pass over: no stream to re-run (`@audit` is
    /// computed, `@*` owns the rows), a load already in flight, typing in
    /// the search bar, a modal, a visual selection (a swap would move it),
    /// an export waiting on its sections, a lens over the pane (it is
    /// about the row, not the list), or no login (the app-wide line says
    /// so; a pass would only repeat it).
    fn watch_list_blocked(&self) -> bool {
        self.current_service.is_none_or(|s| s.is_virtual())
            || self.all_search_mode
            || self.loading
            || self.search_active
            || self.any_modal_open()
            || self.list_visual_anchor.is_some()
            || self.pending_export.is_some()
            || self.network_lens.is_some()
            || self.refs_lens.is_some()
            || self.timeline.is_some()
            || self.auth_error.is_some()
    }

    /// A list pass: the normal streaming load (the main loop spawns it from
    /// `should_load_resources`), its pages diverted into `watch_staging`.
    /// The list never blanks, and no loading indicator shows: the status
    /// bar's watch chip spins instead.
    fn start_watch_refresh(&mut self) {
        self.supersede_loads();
        self.loading = true;
        self.loading_started = false;
        self.loading_complete = false;
        self.loading_progress = None;
        self.load_warnings.clear();
        self.watch_staging = Some(Vec::new());
    }

    /// How often watch refetches the open charts: the watch interval, never
    /// under a minute. `None` with no charts open.
    pub fn chart_watch_interval(&self) -> Option<Duration> {
        self.metrics.as_ref().map(|_| self.watch.interval.max(CHART_FLOOR))
    }

    /// The charts' pass: due an interval after the last chart fetch (open,
    /// `r`, a window key or the last pass all stamp `last_refresh`), never
    /// while one is in flight, in the `a` picker, or under a modal.
    fn watch_tick_charts(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(every) = self.chart_watch_interval() else {
            return;
        };
        let busy = self.metrics.as_ref().is_none_or(|st| st.loading || st.picker.is_some());
        if busy || self.any_modal_open() || self.auth_error.is_some() {
            return;
        }
        if self.watch.last_refresh.is_some_and(|t| t.elapsed() < every) {
            return;
        }
        self.refetch_metrics_watched(event_tx);
    }

    /// The chip's spinner: a list pass streaming into staging, or a chart
    /// fetch in flight under watch.
    pub fn watch_spinning(&self) -> bool {
        self.watch_refresh_active() || self.metrics.as_ref().is_some_and(|st| st.loading)
    }

    /// The cadence the chip shows: the charts' while they are open.
    pub fn watch_cadence(&self) -> Duration {
        self.chart_watch_interval().unwrap_or(self.watch.interval)
    }

    /// `w`: on fires the first pass on the next tick, so it feels
    /// immediate; the toast says what is refreshed, and how often.
    pub(super) fn toggle_watch(&mut self) {
        self.watch.enabled = !self.watch.enabled;
        if !self.watch.enabled {
            self.watch_staging = None;
            return self.toast("Watch off");
        }
        self.watch.last_refresh = None;
        self.watch.failed = None;
        let what = if self.metrics.is_some() { "the charts" } else { "the list" };
        self.toast(format!("Watch on: refreshing {what} every {}s (w off, +/- interval)", self.watch_cadence().as_secs()));
    }

    /// `+` / `-`: the next preset, said in a toast (the charts' floor too).
    pub(super) fn step_watch_interval(&mut self, longer: bool) {
        if longer {
            self.watch.lengthen();
        } else {
            self.watch.shorten();
        }
        let floor = match self.chart_watch_interval() {
            Some(every) if every > self.watch.interval => format!(" (the charts: {}s, Azure Monitor's minute)", every.as_secs()),
            _ => String::new(),
        };
        self.toast(format!("Watch every {}s{floor}", self.watch.interval.as_secs()));
    }

    /// A failed pass: the rows (or series) on screen stay, and the failure
    /// is said once until a pass succeeds or a different one fails.
    pub(super) fn watch_failed(&mut self, error: String) {
        if self.watch.report(&error) {
            self.error_message = Some(format!("Watch: {error} (the last read stays on screen)"));
        }
    }
}
