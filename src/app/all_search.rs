// copy-adapted from neboto-tui src/app.rs @ 03760c0 (`rebuild_all_search_resources`,
// `jump_to_all_result`, the @all stream guards; ADR 0004 there)
//! `@* <text>` (#38): one fuzzy search over every **warm** list cache entry
//! of the current subscription. It never fetches (neboto's ADR 0004: a
//! fan-out load would be slow, throttled and permission-noisy), so its
//! coverage is shown instead: the list title counts the warm lists, and the
//! status line names the services not checked.
//!
//! While the mode holds, `resources` is the flattened cached rows with a
//! parallel `all_search_sources` (the sub-tab each came from). Entering it
//! supersedes the current list load, so no stream can land on (or cache)
//! the foreign rows; leaving it re-serves the current sub-tab from its
//! cache or a fresh load. `⏎` opens a row in its typed tab through the jump
//! path; `l` peeks at it in place.

use super::{App, NavLocation};
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::all_resources::GenericResourceRow;
use crate::event::Event;
use crate::search::query_parser::parse_all_query;
use std::collections::HashSet;
use tokio::sync::mpsc;

/// What the last `@*` pass searched: how many of the subscription's lists
/// had a warm cache entry, and the services with none (not checked).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AllSearchCoverage {
    pub warm: usize,
    pub total: usize,
    pub unchecked: Vec<ServiceType>,
}

/// What `update_search` does after syncing the mode with the query.
pub(super) enum AllSearchStep {
    /// Not an `@*` query: the ordinary per-list search.
    Off,
    /// An `@*` query: `resources` holds the cached rows; search this text.
    On(String),
    /// The query just stopped being `@*`: the current list was re-served
    /// (and re-filtered, on a cache hit), so there is nothing left to do.
    Left,
}

impl App {
    /// Enter, refresh or leave `@*` mode to match the query. Called first
    /// thing by `update_search`, so typing the prefix live switches modes
    /// and a background load finishing elsewhere shows on the next key.
    pub(super) fn sync_all_search(&mut self) -> AllSearchStep {
        match parse_all_query(&self.search_query).map(str::to_string) {
            Some(text) => {
                if !self.all_search_mode {
                    // Retire the current load: its rows would land on (and
                    // be cached from) the foreign list. Leaving reloads it.
                    self.supersede_loads();
                    self.loading = false;
                    self.loading_progress = None;
                    self.pending_jump = None;
                    self.all_search_mode = true;
                }
                self.rebuild_all_search_resources();
                AllSearchStep::On(text)
            }
            None if self.all_search_mode => {
                self.leave_all_search();
                self.load_service_resources();
                AllSearchStep::Left
            }
            None => AllSearchStep::Off,
        }
    }

    /// Drop the mode and its rows. The caller re-serves the current list
    /// (`load_service_resources`) or switches to another one.
    pub(super) fn leave_all_search(&mut self) {
        self.all_search_mode = false;
        self.all_search_sources.clear();
        self.all_search_coverage = AllSearchCoverage::default();
        self.resources.clear();
        self.filtered_resources.clear();
        self.select(None);
    }

    /// Flatten every warm cache entry of the current subscription (the
    /// cache maps a tenant-scoped list to its tenant entry itself) into
    /// `resources`, in service and sub-tab order. All resources rows come
    /// last and only for ids no typed list already supplied, so a VM is one
    /// typed row, while a type nebaz does not browse still matches.
    fn rebuild_all_search_resources(&mut self) {
        let sub = self.subscription_key();
        let mut resources: Vec<Box<dyn crate::azure::resource::Resource>> = Vec::new();
        let mut sources: Vec<JumpView> = Vec::new();
        let mut coverage = AllSearchCoverage::default();
        let mut generic: Option<&[Box<dyn crate::azure::resource::Resource>]> = None;
        // `@changes` rows are events, not resources (ADR 0006): never searched.
        for service in ServiceType::all().into_iter().filter(|s| *s != ServiceType::Changes) {
            let mut any_warm = false;
            for view in service.views() {
                coverage.total += 1;
                let Some(list) = self.cache.get_ref(&service, &sub, Some(view.as_str())) else {
                    continue;
                };
                coverage.warm += 1;
                any_warm = true;
                if *view == JumpView::AllResources {
                    generic = Some(list);
                    continue;
                }
                sources.extend(std::iter::repeat_n(*view, list.len()));
                resources.extend(list.iter().cloned());
            }
            if !any_warm {
                coverage.unchecked.push(service);
            }
        }
        if let Some(list) = generic {
            let typed: HashSet<String> = resources.iter().map(|r| r.id().to_lowercase()).collect();
            for r in list.iter().filter(|r| !typed.contains(&r.id().to_lowercase())) {
                sources.push(JumpView::AllResources);
                resources.push(r.clone());
            }
        }
        self.resources = resources;
        self.all_search_sources = sources;
        self.all_search_coverage = coverage;
    }

    /// The badge an `@*` row leads with: its service, and its sub-tab when
    /// the service has several (`VNet/Subnets`, `Storage`).
    pub fn all_search_badge(&self, idx: usize) -> String {
        match self.all_search_sources.get(idx) {
            Some(view) => all_search_label(*view),
            None => String::new(),
        }
    }

    /// `⏎` on an `@*` row: record the result list (Ctrl-O returns to it),
    /// leave the mode and land on the row in its typed tab, pane focused.
    /// An All resources row of a browsed type opens in that type's tab.
    pub(super) fn open_all_search_result(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(idx) = self.selected_index.and_then(|p| self.filtered_resources.get(p).copied()) else {
            return;
        };
        let (Some(source), Some(row)) = (self.all_search_sources.get(idx).copied(), self.resources.get(idx)) else {
            return;
        };
        let view = match source {
            JumpView::AllResources => row
                .as_any()
                .downcast_ref::<GenericResourceRow>()
                .and_then(|g| g.view)
                .unwrap_or(JumpView::AllResources),
            v => v,
        };
        let loc = NavLocation {
            service: view.service(),
            view: Some(view),
            subscription: self.subscription_id.clone(),
            query: String::new(),
            selected_id: Some(row.id().to_string()),
            label: format!("{} · {}", view.label(), row.name()),
            details_focused: true,
            detail_section: None,
        };
        // The results (query included) are what back returns to; the
        // restore's own switches record nothing.
        self.push_nav_location();
        self.leave_all_search();
        self.search_query.clear();
        // The result may be in the sub-tab already open, which the switch
        // below leaves alone: put its own list back first.
        self.load_service_resources();
        self.restore_nav_location(loc, event_tx);
    }

    /// The "not checked" hint: the services with no warm list, by short
    /// name, the first few then a count (the status line drops a hint that
    /// does not fit whole).
    pub fn all_search_unchecked_hint(&self) -> String {
        const SHOWN: usize = 4;
        let unchecked = &self.all_search_coverage.unchecked;
        let mut hint = unchecked
            .iter()
            .take(SHOWN)
            .map(|s| s.short_name())
            .collect::<Vec<_>>()
            .join(" · ");
        if unchecked.len() > SHOWN {
            hint.push_str(&format!(" +{} more", unchecked.len() - SHOWN));
        }
        hint
    }
}

/// `Service/Sub-tab` for a multi-tab service, else the service.
pub fn all_search_label(view: JumpView) -> String {
    let service = view.service();
    if service.views().len() > 1 {
        format!("{}/{}", service.short_name(), view.label())
    } else {
        service.short_name().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_name_the_sub_tab_only_when_the_service_has_several() {
        assert_eq!(all_search_label(JumpView::Subnets), "VNet/Subnets");
        assert_eq!(all_search_label(JumpView::StorageAccounts), "Storage");
        assert_eq!(all_search_label(JumpView::AllResources), "Subs/All resources");
    }
}
