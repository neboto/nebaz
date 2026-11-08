//! `|` (split out, from neboto #326 / #328) on `App`: build the place and
//! the command, run the launchers `crate::split` picks, and, in the new
//! process, restore `--at` once the startup load is under way.

use super::App;
use crate::event::Event;
use crate::split::{Place, Session};
use tokio::sync::mpsc;

/// What a restored place still has to do once its row lands: the section
/// it was on (a pending jump otherwise opens the default one) and the
/// charts' window when they were open.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingPlace {
    pub id: String,
    pub section: Option<String>,
    pub chart_window: Option<crate::azure::metrics::MetricWindow>,
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

    /// `--at`: go to the place this pane was split out at. Called once the
    /// startup load is under way, so the restore resolves as the rows land.
    pub fn restore_startup_location(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(Place { loc, chart_window }) = self.startup_place.take() else {
            return;
        };
        let (id, section) = (loc.selected_id.clone(), loc.detail_section.clone());
        self.restore_nav_location(loc, event_tx);
        match (self.pending_jump.as_ref(), id) {
            // Still loading: finish when the row lands (`land_pending_place`).
            (Some((pending, _)), Some(id)) if *pending == id => {
                self.pending_place = Some(PendingPlace { id, section, chart_window });
            }
            _ => self.reopen_charts(chart_window, event_tx),
        }
    }

    /// The rest of a restored place, once its pending jump has landed on
    /// `id` in the detail pane.
    pub(super) fn land_pending_place(&mut self, id: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(p) = self.pending_place.take_if(|p| p.id == id) else {
            return;
        };
        if let Some(idx) = p.section.as_deref().and_then(|name| {
            self.selected_descriptor()
                .and_then(|d| d.sections.iter().position(|s| s.label == name))
        }) {
            self.set_detail_section(idx, event_tx);
        }
        self.reopen_charts(p.chart_window, event_tx);
    }

    fn reopen_charts(
        &mut self,
        window: Option<crate::azure::metrics::MetricWindow>,
        event_tx: &mpsc::UnboundedSender<Event>,
    ) {
        if let (Some(window), true) = (window, self.selected_index.is_some()) {
            self.metrics_window = window;
            self.open_metrics(event_tx);
        }
    }

    /// An in-pane view (`N`, `U`, `m`, `W`) has the keys; `|` is checked
    /// ahead of them. None of them takes typed text today: one that does
    /// must keep `|` a character while it is.
    pub(super) fn in_pane_view_open(&self) -> bool {
        self.network_lens.is_some() || self.refs_lens.is_some() || self.metrics.is_some() || self.timeline.is_some()
    }
}
