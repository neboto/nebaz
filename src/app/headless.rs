// ported from neboto-tui src/app.rs @ 08fcd0c (the `headless (neboto get)`
// block: new_headless, find, select, section labels, capture)
//! The terminal-less `App` behind `nebaz ls` and `nebaz get` (#44). The
//! headless driver (`src/headless.rs`) opens a sub-tab, pumps events until
//! the list lands, selects a row the way a jump does and fires every
//! section's on-enter hook, so a list and a pane come from exactly the code
//! the TUI runs: no per-service code here or there. Nothing in this block
//! draws, reads keys, or touches the terminal.

use super::App;
use crate::azure::client::AzureClients;
use crate::azure::location::Location;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::config::Config;
use crate::event::Event;
use tokio::sync::mpsc;

/// What `ls` narrows a list by: the TUI's filters, as flags.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListShaping {
    /// The search box's text: fuzzy text plus `rg:` / `tag:` terms.
    pub query: String,
    pub location: Location,
    /// The state column's text, matched in any case.
    pub state: Option<String>,
    pub hide_noise: bool,
}

impl App {
    /// The TUI's `App` over an already-resolved config and client set, with
    /// nothing hidden: no location filter, noise shown, no config warning
    /// on the (absent) status bar.
    pub(crate) fn new_headless(config: Config, clients: AzureClients) -> Self {
        let mut app = Self::from_parts(config, clients, None);
        app.current_location = Location::All;
        app.hide_noise = false;
        app.error_message = None;
        app
    }

    /// Point the app at `view` and arm its list load (served from the list
    /// cache when it was loaded before in this run). The caller pumps
    /// `load_resources_async` and `handle_event` as the main loop does.
    pub(crate) fn headless_open(&mut self, view: JumpView) {
        self.switch_view(view);
        if self.resources.is_empty() && !self.loading && !self.loading_complete {
            self.load_service_resources();
        }
    }

    /// Point the app at another subscription for `ls --subscriptions`
    /// (#62): the TUI's switch without its locations fetch (`ls` validates
    /// the location once, up front) and with the last subscription's load
    /// error and warnings dropped, so they can't be read as this one's. The
    /// caller re-opens the sub-tab: a cache hit once the fan-out filled it.
    pub(crate) fn headless_switch_subscription(&mut self, id: &str) -> Result<(), String> {
        if self.subscription_id.as_deref() != Some(id) {
            self.azure_clients.set_subscription(id).map_err(|e| e.to_string())?;
            self.apply_subscription_identity();
            self.lazy = crate::lazy::LazyStore::new(self.lazy.epoch() + 1);
            self.load_service_resources();
        }
        self.error_message = None;
        self.load_warnings.clear();
        Ok(())
    }

    /// Why the list did not load, if it did not: the auth condition (the
    /// one app-wide line) or the load's error. `(is_auth, message)`.
    pub(crate) fn headless_load_failure(&self) -> Option<(bool, String)> {
        if let Some(a) = &self.auth_error {
            return Some((true, a.status_line()));
        }
        // A load whose second phase failed is partial, not failed: its
        // warnings go to stderr and the rows (maybe none) still print.
        if self.resources.is_empty() && self.load_warnings.is_empty() {
            return self.error_message.clone().map(|e| (false, e));
        }
        None
    }

    /// The warnings the list load sent (a failed second phase).
    pub(crate) fn headless_load_warnings(&self) -> &[String] {
        &self.load_warnings
    }

    /// The list as the TUI would show it under `shaping`: the same
    /// `update_search` (location, query, `rg:` / `tag:`, state, noise).
    pub(crate) fn headless_rows(&mut self, shaping: &ListShaping) -> Vec<&dyn Resource> {
        self.search_query = shaping.query.clone();
        self.current_location = shaping.location.clone();
        self.hide_noise = shaping.hide_noise;
        // The state filter compares the label exactly; take the list's own
        // spelling of what was asked for.
        self.list_state_filter = shaping.state.as_deref().map(|want| {
            self.resources
                .iter()
                .map(|r| r.state_label())
                .find(|l| l.eq_ignore_ascii_case(want))
                .unwrap_or_else(|| want.to_string())
        });
        self.update_search();
        self.filtered_resources
            .iter()
            .map(|&i| self.resources[i].as_ref())
            .collect()
    }

    /// Ids of the loaded rows that `query` names: the row with that id
    /// (case-insensitively, the jump rule), else every row with that exact
    /// name.
    pub(crate) fn headless_find(&self, query: &str) -> Vec<String> {
        if let Some(r) = self.resources.iter().find(|r| r.matches_id(query)) {
            return vec![r.id().to_string()];
        }
        self.resources
            .iter()
            .filter(|r| r.name() == query)
            .map(|r| r.id().to_string())
            .collect()
    }

    /// Select the row with `id` in `view` the way a jump lands: open the
    /// sub-tab (a cache hit once loaded), clear every filter, put the
    /// cursor on it. False when the row is not in the list.
    pub(crate) fn headless_select(&mut self, view: JumpView, id: &str) -> bool {
        self.headless_open(view);
        self.headless_rows(&ListShaping::default());
        if !self.restore_selection_by_id(id) {
            return false;
        }
        self.details_focused = true;
        true
    }

    /// The selected row's section labels in pane order (`["Details"]` for
    /// a type without a descriptor): what `get --section` matches.
    pub(crate) fn headless_section_labels(&self) -> Vec<String> {
        match self.selected_descriptor() {
            Some(desc) => desc.sections.iter().map(|s| s.label.to_string()).collect(),
            None => vec!["Details".to_string()],
        }
    }

    /// One pass over the selected row: fire the on-enter hook of every
    /// wanted section (all of them when `only` is `None`; idempotent, the
    /// LazyMap contains-guard), the follow-up fetches a landed section
    /// starts (principal names), then snapshot those sections with the
    /// same `section_lines_for` the pane draws. The caller pumps events and
    /// repeats until nothing reads as loading. A section outside `only` is
    /// never entered, so its fetch never happens.
    pub(crate) fn headless_capture(
        &mut self,
        only: Option<&[usize]>,
        event_tx: &mpsc::UnboundedSender<Event>,
    ) -> Vec<(String, Vec<(String, String)>)> {
        let count = self.selected_descriptor().map(|d| d.len()).unwrap_or(0);
        let wanted: Vec<usize> = match only {
            Some(idx) => idx.to_vec(),
            None => (0..count.max(1)).collect(),
        };
        for &i in &wanted {
            self.set_detail_section(i, event_tx);
        }
        self.trigger_principal_names(event_tx);
        self.trigger_directory_followups(event_tx);
        self.detail_sections_snapshot()
            .into_iter()
            .enumerate()
            .filter(|(i, _)| wanted.contains(i))
            .map(|(_, s)| s)
            .collect()
    }
}
