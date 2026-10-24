// ported from neboto-tui src/app.rs @ b92e140 (`keycast_view`,
// `keycast_tick`), the overlay list rewritten for nebaz's modals and lenses
//! Keycast (`--show-keys`, #43) on `App`: the [`View`] a key can visibly
//! change, snapshotted before dispatch (`handle_key`) and after
//! (`keycast_tick`, from the main loop), for `crate::keycast` to diff.

use super::{App, LayoutMode};
use crate::keycast::{Input, View};

impl App {
    /// What a key can visibly change. The overlay names are what the box
    /// prints when the key opens one.
    pub(super) fn keycast_view(&self) -> View {
        let overlay = if self.help_visible {
            Some("help")
        } else if self.service_selector.visible {
            Some("services")
        } else if self.location_selector.visible {
            Some("locations")
        } else if self.subscription_selector.visible {
            Some("subscriptions")
        } else if self.jump_list_visible {
            Some("jump list")
        } else if self.bookmarks_visible {
            Some("bookmarks")
        } else if self.message_history_visible {
            Some("messages")
        } else if self.macro_picker_visible {
            Some("macros")
        } else if self.command_picker.is_some() {
            Some("CLI commands")
        } else if self.network_lens.is_some() {
            Some("network access")
        } else if self.refs_lens.is_some() {
            Some("referenced by")
        } else if self.metrics.is_some() {
            Some("metrics")
        } else if self.timeline.is_some() {
            Some("change timeline")
        } else {
            None
        };
        let input = if self.search_active {
            Some(Input::Search)
        } else if self.details_focused && self.detail_search_active {
            Some(Input::Filter)
        } else if self.macro_picker_visible && self.macro_name_input.is_some() {
            Some(Input::Name)
        } else if self.service_selector.visible
            || self.location_selector.visible
            || self.subscription_selector.visible
            || self.command_picker.as_ref().is_some_and(|p| p.filtering)
        {
            Some(Input::Picker)
        } else {
            None
        };
        View {
            service: self.current_service.map(|s| s.name().to_string()),
            details_focused: self.details_focused,
            section: self
                .selected_descriptor()
                .and_then(|d| d.sections.get(self.detail_section_idx))
                .map(|s| s.label.to_string()),
            sub_tab: self.current_service.map(|_| self.current_view.label().to_string()),
            overlay,
            input,
            search_query: if self.search_active { self.search_query.clone() } else { String::new() },
            list_only: self.layout_mode == LayoutMode::ListOnly,
            selected_id: self.get_selected_resource_id(),
        }
    }

    /// Name the key `handle_key` just ran (main loop, after dispatch).
    pub fn keycast_tick(&mut self) {
        if self.keycast.is_none() {
            return;
        }
        let after = self.keycast_view();
        if let Some(kc) = self.keycast.as_mut() {
            kc.settle(&after, std::time::Instant::now());
        }
    }
}
