// ported from neboto-tui src/app.rs @ a6de34a (`count_sub_tab_matches`,
// `follow_matches_to_sub_tab`, the Esc return; neboto-tui#301)
//! A `/` search on a service with sub-tabs follows its matches (#154).
//!
//! Matches are counted per sub-tab for the current query. While the bar is
//! open the list follows them: the tab the search started on wins while it
//! has matches, else the first tab that does. `Esc` returns to the starting
//! tab, `⏎` keeps the tab it found, and the tabs with no matches are dimmed
//! (`ui/widgets/subtab_bar.rs`).
//!
//! **Different from neboto.** A neboto sub-tab filters one loaded list; a
//! nebaz sub-tab is its own subscription-wide list with its own cache slot,
//! and a tab never opened has no rows. So only **warm** tabs are counted
//! (the current tab once its load is complete, the others from the list
//! cache, as `@*` reads it), nothing is ever fetched, and a cold tab is
//! neither followed nor dimmed (`None` in the counts). Following is a view
//! change onto a cached list: no navigation entry, no query reset.
//!
//! A tab picked by hand is never overridden: picking one clears the query
//! (`reset_list_shaping`), and with it the counts and the starting tab.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::{JumpView, ServiceType};
use crate::search::query_parser::{parse_query, rg_filter_admits, TagFilter};

/// The sub-tab to show: `home` (where the search started) while it has
/// matches, else the first tab that does. A `home` that is not warm
/// (`None`: still loading, or its cache expired) keeps the tab we are on
/// (`cur`), since going back would start a load. With matches nowhere,
/// `home`. `counts` are in sub-tab order; `None` is a cold tab.
pub(super) fn follow_target(home: usize, cur: usize, counts: &[Option<usize>]) -> usize {
    match counts.get(home).copied().flatten() {
        None => cur,
        Some(n) if n > 0 => home,
        Some(_) => counts.iter().position(|n| n.is_some_and(|n| n > 0)).unwrap_or(home),
    }
}

impl App {
    /// Matches per sub-tab of the current service, in sub-tab order, for the
    /// query already split into `text`, `tags` and `rgs`; `None` for a tab
    /// that is not warm. Empty with no query, outside a tabbed service, in
    /// `@*` mode or in a virtual service. Respects the location filter and
    /// the noise toggle, not the `F` state filter (that is a choice about
    /// one tab).
    pub(super) fn count_sub_tab_matches(&self, text: &str, tags: &[TagFilter], rgs: &[String]) -> Vec<Option<usize>> {
        let Some(service) = self.current_service else {
            return Vec::new();
        };
        let views = service.views();
        if views.len() < 2 || service.is_virtual() || self.all_search_mode {
            return Vec::new();
        }
        if text.is_empty() && tags.is_empty() && rgs.is_empty() {
            return Vec::new();
        }
        let sub = self.subscription_key();
        views
            .iter()
            .map(|&view| {
                let rows: &[Box<dyn Resource>] = if service == ServiceType::Changes || view == self.current_view {
                    // `@changes` is one list its sub-tabs filter; the
                    // current tab's rows are live, so wait for the load.
                    if !self.loading_complete {
                        return None;
                    }
                    &self.resources
                } else {
                    self.cache.get_ref(&service, &sub, Some(view.as_str()))?
                };
                let n = self
                    .fuzzy
                    .filter_resources(text, rows)
                    .into_iter()
                    .map(|(i, _)| rows[i].as_ref())
                    .filter(|r| self.current_location.admits(r.filter_location()))
                    .filter(|r| tags.iter().all(|f| f.matches(r.tags())))
                    .filter(|r| rg_filter_admits(rgs, r.resource_group()))
                    .filter(|r| super::changes::view_admits(view, *r))
                    .filter(|r| !(self.hide_noise && r.is_noise()))
                    .count();
                Some(n)
            })
            .collect()
    }

    /// While the bar is open: move to the tab the matches are on. Returns
    /// whether the view changed (the list was re-served, so the caller has
    /// nothing left to filter). Not while an `F` state filter holds the
    /// tab, a jump is landing, or the query names another service (`@vm …`).
    pub(super) fn follow_matches_to_sub_tab(&mut self) -> bool {
        let Some(service) = self.current_service else {
            return false;
        };
        if !self.search_active
            || self.all_search_mode
            || self.sub_tab_match_counts.is_empty()
            || self.pending_jump.is_some()
            || parse_query(&self.search_query).is_service_switch
        {
            return false;
        }
        let views = service.views();
        let Some(cur) = views.iter().position(|v| *v == self.current_view) else {
            return false;
        };
        let home = match self.search_home_view {
            Some(v) if v.service() == service => v,
            // First pass of this search.
            _ => {
                self.search_home_view = Some(self.current_view);
                self.current_view
            }
        };
        if self.list_state_filter.is_some() {
            return false;
        }
        let Some(home_idx) = views.iter().position(|v| *v == home) else {
            return false;
        };
        let target = follow_target(home_idx, cur, &self.sub_tab_match_counts);
        if target == cur {
            return false;
        }
        self.follow_to(views[target]);
        true
    }

    /// `Esc` in the bar: back to the tab the search started on.
    pub(super) fn return_to_search_home(&mut self) {
        self.sub_tab_match_counts.clear();
        let Some(home) = self.search_home_view.take() else {
            return;
        };
        if home != self.current_view && Some(home.service()) == self.current_service && !self.all_search_mode {
            self.follow_to(home);
        }
    }

    /// Show `view` of the current service without navigating: the query and
    /// shaping stay, no history entry is pushed, and the list is served from
    /// its cache (or loaded, as opening the tab would).
    fn follow_to(&mut self, view: JumpView) {
        self.current_view = view;
        self.leave_detail_pane();
        self.pending_detail_focus = false;
        self.detail_section_idx = 0;
        self.filtered_resources.clear();
        self.select(None);
        self.load_service_resources();
    }
}

#[cfg(test)]
mod tests {
    use super::follow_target;

    #[test]
    fn home_wins_while_it_has_matches() {
        assert_eq!(follow_target(0, 2, &[Some(1), Some(5), Some(2)]), 0);
        assert_eq!(follow_target(2, 0, &[Some(1), Some(5), Some(2)]), 2);
    }

    #[test]
    fn without_matches_at_home_the_first_tab_with_some() {
        assert_eq!(follow_target(0, 0, &[Some(0), Some(0), Some(3), Some(1)]), 2);
        assert_eq!(follow_target(2, 2, &[Some(0), Some(4), Some(0)]), 1);
    }

    #[test]
    fn a_cold_tab_is_never_followed() {
        assert_eq!(follow_target(0, 0, &[Some(0), None, Some(2)]), 2);
        assert_eq!(follow_target(0, 0, &[Some(0), None, None]), 0);
    }

    #[test]
    fn a_cold_home_keeps_the_current_tab() {
        assert_eq!(follow_target(0, 2, &[None, Some(0), Some(1)]), 2);
    }

    #[test]
    fn matches_nowhere_goes_home() {
        assert_eq!(follow_target(1, 2, &[Some(0), Some(0), Some(0)]), 1);
    }
}
