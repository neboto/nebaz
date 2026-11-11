//! `|` (split out, from neboto #326 / #328) on `App`: build the place and
//! the command, run the launchers `crate::split` picks, and, in the new
//! process, restore `--at` once the startup load is under way.

use super::App;
use crate::event::Event;
use crate::split::{Place, Session};
use tokio::sync::mpsc;

/// What a restored place still has to do once its row lands: the section
/// it was on (a pending jump otherwise opens the default one), the charts'
/// window when they were open, and what `nebaz open` asked for.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PendingPlace {
    /// The row's id; a name while `by_name` (`resolve_pending_jump` swaps
    /// in the id once the list has loaded).
    pub id: String,
    /// A section label, matched in any case. A `|` place's is exact and
    /// skipped quietly when the type has none by that name; `open`'s
    /// (`strict`) says so.
    pub section: Option<String>,
    pub chart_window: Option<crate::azure::metrics::MetricWindow>,
    /// Open the charts even without a window (`open --metric`).
    pub charts: bool,
    /// The chart row to put the cursor on (`open --metric`).
    pub metric: Option<String>,
    /// The pane takes the whole width (`open --full`).
    pub full: bool,
    pub by_name: bool,
    /// From `open`: a section that isn't there is reported.
    pub strict: bool,
}

impl App {
    /// `|`: open another nebaz in a pane beside this one, at this place.
    /// With no host that can split, the command is copied instead, so it
    /// can be pasted into a pane opened by hand.
    pub(super) fn split_out(&mut self) {
        // Charts reopen at their window; the other in-pane views give the
        // pane behind them.
        let chart_window = self.metrics.as_ref().map(|st| st.window);
        let place = self
            .current_nav_location()
            .map(|loc| crate::split::encode_place(&Place { loc, chart_window }));
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "nebaz".to_string());
        let session = Session {
            service: self.current_service.as_ref().map(|s| s.prefix()),
            subscription: self.subscription_id.as_deref(),
            location: self.current_location.as_str(),
            endpoint: self.azure_clients.current_endpoint(),
            demo: self.azure_clients.is_demo(),
            watch: self.watch.enabled,
        };
        let nebaz = crate::split::nebaz_command(&exe, &session, place.as_deref());

        let host = crate::split::current_host();
        if host.is_none() && self.split_command.is_none() {
            self.copy_to_clipboard(&nebaz, "the nebaz command (no terminal here to split; see split_command)");
            return;
        }
        let shell_cmd =
            crate::split::hold_shell_on_error(&crate::split::with_forwarded_env(&nebaz, |k| std::env::var(k).ok()));
        // Config `split_command` wins over detection: it's how a terminal
        // nebaz doesn't know (or a window manager rule) gets a pane.
        let launches = match (&self.split_command, host) {
            (Some(template), _) => vec![crate::split::custom_launch(template, &shell_cmd)],
            (None, Some(host)) => {
                crate::split::launches(host, &shell_cmd, |k| std::env::var(k).ok(), cfg!(target_os = "macos"))
            }
            (None, None) => Vec::new(),
        };
        // Best first; the first error is the one worth reading (the kitty
        // split's "remote control is disabled", not the window's).
        let mut first_err = None;
        for launch in &launches {
            match crate::split::run(launch) {
                Ok(()) => {
                    let mut msg = launch.describe(host);
                    if let Some(e) = first_err {
                        msg.push_str(&format!(" (no split: {e})"));
                    }
                    self.toast(msg);
                    return;
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        // Nothing opened: say why, and copy the command to run by hand. The
        // copy's own toast would replace the reason, so it goes quietly.
        let _ = self.clipboard.copy(&nebaz);
        self.error_message = Some(format!(
            "Can't split: {}; the nebaz command is copied",
            first_err.unwrap_or_else(|| "no launcher".to_string())
        ));
    }

    /// `--at`, `open`, `--bookmark`: go to the place this process was
    /// started at. Called once the startup load is under way, so the
    /// restore resolves as the rows land.
    pub fn restore_startup_location(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(Place { loc, chart_window }) = self.startup_place.take() else {
            return;
        };
        let open = self.startup_open.take();
        let Some(id) = loc.selected_id.clone() else {
            return self.restore_nav_location(loc, event_tx);
        };
        let strict = open.is_some();
        let open = open.unwrap_or_default();
        // Set ahead of the restore: its pending jump reads `by_name`, and
        // lands the place itself when the row is already there.
        self.pending_place = Some(PendingPlace {
            id: id.clone(),
            section: open.section.or_else(|| loc.detail_section.clone()),
            chart_window,
            charts: open.charts || chart_window.is_some(),
            metric: open.metric,
            full: open.full,
            by_name: open.by_name,
            strict,
        });
        self.restore_nav_location(loc, event_tx);
        // Still loading: `resolve_pending_jump` finishes when the row lands.
        if self.pending_jump.is_none() {
            if self.get_selected_resource().is_some_and(|r| r.matches_id(&id)) {
                self.land_pending_place(&id, event_tx);
            } else {
                self.pending_place = None;
            }
        }
    }

    /// The rest of a restored place, once its row `id` is selected in the
    /// detail pane.
    pub(super) fn land_pending_place(&mut self, id: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(p) = self.pending_place.take_if(|p| p.id == id) else {
            return;
        };
        if let Some(name) = p.section.as_deref() {
            let labels: Vec<&str> =
                self.selected_descriptor().map(|d| d.sections.iter().map(|s| s.label).collect()).unwrap_or_default();
            match crate::open::match_section(&labels, name) {
                Ok(idx) => self.set_detail_section(idx, event_tx),
                Err(e) if p.strict => self.error_message = Some(e),
                Err(_) => {}
            }
        }
        if p.full {
            self.layout_mode = super::LayoutMode::DetailsOnly;
        }
        if !p.charts || self.selected_index.is_none() {
            return;
        }
        if let Some(window) = p.chart_window {
            self.metrics_window = window;
        }
        self.open_metrics(event_tx);
        let Some(wanted) = p.metric.as_deref() else {
            return;
        };
        // `open_metrics` said why when it opened nothing.
        let Some(st) = self.metrics.as_mut() else {
            return;
        };
        if st.queries.is_empty() {
            self.error_message = Some(format!(
                "open: no default charts for this type to find {wanted:?} in; pick a metric from the list"
            ));
            return;
        }
        match crate::open::match_metric(&st.queries, wanted) {
            Ok(i) => st.selected = i,
            Err(e) => self.error_message = Some(e),
        }
    }

    /// An in-pane view (`N`, `U`, `m`, `W`) has the keys; `|` is checked
    /// ahead of them. None of them takes typed text today: one that does
    /// must keep `|` a character while it is.
    pub(super) fn in_pane_view_open(&self) -> bool {
        self.network_lens.is_some() || self.refs_lens.is_some() || self.metrics.is_some() || self.timeline.is_some()
    }
}
