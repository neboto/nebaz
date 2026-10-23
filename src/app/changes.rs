//! `@changes` (#61, ADR 0006) on `App`: the window keys and the window
//! the list (and its cache entry) belongs to. The sub-tab filter and the
//! newest-first sort run inside `update_search`; the provider is
//! `azure::services::changes`.

use super::App;
use crate::azure::services::changes::ChangesWindow;

pub(super) use crate::azure::services::changes::{time_of, view_admits};

impl App {
    /// `[` / `]` on the list: a narrower or wider window, served from the
    /// cache when that window was loaded before, else loaded.
    pub(super) fn step_changes_window(&mut self, wider: bool) {
        let next = if wider { self.changes_window.wider() } else { self.changes_window.narrower() };
        if next == self.changes_window {
            self.toast(format!("@changes: {} is the {} window", next.label(), if wider { "widest" } else { "narrowest" }));
            return;
        }
        self.set_changes_window(next);
        self.toast(format!("@changes: the last {}", next.label()));
    }

    /// Point `@changes` at `window` (headless `changes --since` too).
    pub(crate) fn set_changes_window(&mut self, window: ChangesWindow) {
        self.changes_window = window;
        if self.current_service == Some(crate::azure::service::ServiceType::Changes) {
            self.load_service_resources();
        }
    }
}
