// copy-adapted from neboto-tui src/app.rs @ 03760c0 (`open_refs_lens`,
// `scan_refs_lens`, `handle_refs_lens_key`); the background load of the
// likely lists is new in nebaz
//! The "referenced by" lens (`U`, #49) on `App`: the warm-cache walk that
//! builds the reverse index, the lens's keys, and `L`, which loads the
//! lists likely to point at the target in the background.
//!
//! **The index** (`azure::references::ReverseIndex`) is built from every
//! warm list cache entry of the current subscription, walked in the same
//! order as `@*` (typed lists by tab, All resources last), plus the
//! on-screen list when its own cache entry has lapsed. It is kept on `App`
//! and reused by the next `U` while its stamp holds: the cache's write
//! generation, the subscription, how many lists are warm (a TTL expiry
//! changes that) and the on-screen list's length. Anything else rebuilds
//! it, so it is never stale and never rebuilt per keypress. Zero calls.
//!
//! **`L`** streams each likely list not yet warm through its provider's
//! ordinary list load, off the current list's stream (no generation of the
//! visible load is touched), and delivers the rows through the lazy apply
//! event: into the list cache, under the subscription it was started for
//! (a switch bumps the lazy epoch and drops it), then a rescan of the lens
//! when it is still open. A failure is a `⚠` in the lens header.

use super::{App, LayoutMode, NavLocation, PAGE_STEP};
use crate::azure::references::{likely_referrers, ReverseIndex};
use crate::azure::resource::Resource;
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::edge::{derived_links, BackendTargets, TargetLists};
use crate::event::Event;
use crate::lazy::LazyApply;
use crate::ui::widgets::refs_lens::{RefsCoverage, RefsLensState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

/// The reverse index with what it was built from.
pub struct RefsIndex {
    stamp: Stamp,
    index: ReverseIndex,
    /// The lists it read, and the ones with no warm entry.
    warm: Vec<JumpView>,
    cold: Vec<JumpView>,
}

/// The lists one index reads (each with its sub-tab), then the warm and
/// the cold sub-tabs.
type RefsLists<'a> = (Vec<(JumpView, &'a [Box<dyn Resource>])>, Vec<JumpView>, Vec<JumpView>);

#[derive(Debug, Clone, PartialEq)]
struct Stamp {
    cache_generation: u64,
    subscription: String,
    warm: usize,
    on_screen: Option<(JumpView, usize)>,
    /// Front Door topologies loaded: each adds origin links.
    topologies: usize,
}

impl App {
    /// The lists the index reads, as `(view, rows)`, typed lists first and
    /// All resources last (as `@*` walks them), plus the warm / cold split.
    fn refs_lists(&self) -> RefsLists<'_> {
        let sub = self.subscription_key();
        let (mut lists, mut warm, mut cold) = (Vec::new(), Vec::new(), Vec::new());
        let mut generic = None;
        for service in ServiceType::all() {
            for view in service.views() {
                match self.cache.get_ref(&service, &sub, Some(view.as_str())) {
                    Some(list) if *view == JumpView::AllResources => {
                        warm.push(*view);
                        generic = Some(list);
                    }
                    Some(list) => {
                        warm.push(*view);
                        lists.push((*view, list));
                    }
                    // The list on screen stands in for its lapsed entry.
                    None if self.refs_on_screen() == Some(*view) => {
                        warm.push(*view);
                        lists.push((*view, self.resources.as_slice()));
                    }
                    None => cold.push(*view),
                }
            }
        }
        if let Some(list) = generic {
            lists.push((JumpView::AllResources, list));
        }
        (lists, warm, cold)
    }

    /// The on-screen list, when it counts as a source of its own: loaded
    /// (or loading) rows of a sub-tab whose cache entry is gone. Not under
    /// `@*`, whose rows are the caches themselves.
    fn refs_on_screen(&self) -> Option<JumpView> {
        let sub = self.subscription_key();
        let service = self.current_service?;
        (!self.all_search_mode
            && !self.resources.is_empty()
            && self.cache.get_ref(&service, &sub, Some(self.current_view.as_str())).is_none())
        .then_some(self.current_view)
    }

    fn refs_stamp(&self, warm: usize) -> Stamp {
        Stamp {
            cache_generation: self.cache.generation(),
            subscription: self.subscription_key(),
            warm,
            on_screen: self.refs_on_screen().map(|v| (v, self.resources.len())),
            topologies: self.lazy.afd_topology.iter().filter(|(_, v)| matches!(v, crate::lazy::Lazy::Loaded(_))).count(),
        }
    }

    /// Build the index unless the one on `App` still holds.
    fn ensure_refs_index(&mut self) {
        let (lists, warm, cold) = self.refs_lists();
        let stamp = self.refs_stamp(warm.len());
        if self.refs_index.as_ref().is_some_and(|i| i.stamp == stamp) {
            return;
        }
        // A gateway backend or a Front Door origin matched to a warm row
        // (a Container App, an environment, a site, a private endpoint)
        // is a reference too: the same matching the Backends section does.
        let find = |view: JumpView| lists.iter().find(|(v, _)| *v == view).map(|(_, l)| *l);
        let targets = BackendTargets::from_lists(TargetLists {
            container_apps: find(JumpView::ContainerApps),
            environments: find(JumpView::ContainerAppEnvironments),
            sites: find(JumpView::WebApps),
            private_endpoints: find(JumpView::PrivateEndpoints),
            public_ips: find(JumpView::PublicIps),
        });
        let topologies = &self.lazy.afd_topology;
        let index = ReverseIndex::build_with(lists, |r| derived_links(r, &targets, topologies));
        self.refs_index = Some(RefsIndex { stamp, index, warm, cold });
    }

    /// Answer the lens's target from the (fresh) index.
    fn scan_refs_lens(&mut self) {
        self.ensure_refs_index();
        let (Some(st), Some(ix)) = (self.refs_lens.as_mut(), self.refs_index.as_ref()) else {
            return;
        };
        let rows = ix.index.referrers(st.target.as_ref());
        let target_view = JumpView::landing_for_arm_id(st.target.id());
        let likely = target_view.map(likely_referrers).unwrap_or(&[]);
        let likely_cold: Vec<JumpView> = likely.iter().copied().filter(|v| ix.cold.contains(v)).collect();
        let coverage = RefsCoverage {
            searched: ix.warm.len(),
            total: ix.warm.len() + ix.cold.len(),
            other_cold: ix.cold.len() - likely_cold.len(),
            likely_cold,
        };
        st.set_rows(rows, coverage);
    }

    /// `U`: open the lens on the selected row.
    pub(super) fn open_refs_lens(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(r) = self.get_selected_resource() else {
            self.error_message = Some("No resource selected".into());
            return;
        };
        let title = format!("{} · {}", r.resource_type(), r.name());
        let target = r.clone_box();
        self.network_lens = None;
        self.metrics = None;
        self.refs_lens = Some(RefsLensState::open(title, target));
        // From the list: the pane behind the view is the default section,
        // with its on-enter hook fired, so closing never leaves a spinner.
        if !self.details_focused {
            self.details_focused = true;
            self.reset_detail_section_to_default(event_tx);
        }
        self.scan_refs_lens();
    }

    fn close_refs_lens(&mut self) {
        self.refs_lens = None;
        if self.layout_mode == LayoutMode::DetailsOnly {
            self.layout_mode = LayoutMode::Split;
        }
    }

    /// `L`: load the likely lists that are not warm, in the background.
    fn load_likely_referrers(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(views) = self.refs_lens.as_ref().map(|st| st.loadable()) else {
            return;
        };
        if views.is_empty() {
            if let Some(st) = self.refs_lens.as_mut() {
                st.message = Some("nothing likely left to load".into());
            }
            return;
        }
        let epoch = self.lazy.epoch();
        let sub = self.subscription_key();
        for view in views {
            let service = view.service();
            let provider = self.azure_clients.service(service);
            let tx = event_tx.clone();
            let sub = sub.clone();
            tokio::spawn(async move {
                let (inner_tx, mut inner_rx) = mpsc::unbounded_channel::<Event>();
                let _ = provider.list_resources_streaming(view, inner_tx, service).await;
                let mut rows: Vec<Box<dyn Resource>> = Vec::new();
                let mut error = None;
                while let Ok(ev) = inner_rx.try_recv() {
                    match ev {
                        Event::ResourcesLoaded { resources, .. } => rows = resources,
                        Event::ResourcesPartiallyLoaded { resources, .. } => rows.extend(resources),
                        Event::ResourceLoadError { error: e, .. } => error = Some(e),
                        _ => {}
                    }
                }
                let result = match error {
                    Some(e) => Err(e),
                    None => Ok(rows),
                };
                let apply: Box<dyn FnOnce(&mut App) + Send> =
                    Box::new(move |app: &mut App| app.refs_list_landed(view, &sub, result));
                let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
            });
            if let Some(st) = self.refs_lens.as_mut() {
                st.warming.push(view);
            }
        }
    }

    /// A background list load from `L` finished: cache it (for the
    /// subscription it was started for) and rescan an open lens.
    pub(crate) fn refs_list_landed(
        &mut self,
        view: JumpView,
        subscription: &str,
        result: Result<Vec<Box<dyn Resource>>, String>,
    ) {
        let failed = match result {
            Ok(rows) => {
                self.cache.insert(view.service(), subscription, Some(view.as_str().to_string()), rows);
                None
            }
            Err(e) => Some(format!("{}: {}", crate::app::all_search_label(view), e)),
        };
        if let Some(st) = self.refs_lens.as_mut() {
            st.warming.retain(|v| *v != view);
            st.warnings.extend(failed);
        }
        if self.refs_lens.is_some() {
            self.scan_refs_lens();
        }
    }

    /// `⏎` on a referrer: land on it in its tab through the jump path
    /// (`Ctrl-O` returns). Under `@*` the result list is left first, as
    /// `⏎` on an `@*` row does.
    fn follow_refs_row(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(row) = self.refs_lens.as_ref().and_then(|st| st.selected_row()).cloned() else {
            return;
        };
        self.close_refs_lens();
        if self.all_search_mode {
            self.push_nav_location();
            self.leave_all_search();
            self.search_query.clear();
            self.load_service_resources();
            let view = match row.view {
                JumpView::AllResources => JumpView::landing_for_arm_id(&row.id).unwrap_or(JumpView::AllResources),
                v => v,
            };
            let loc = NavLocation {
                service: view.service(),
                view: Some(view),
                subscription: self.subscription_id.clone(),
                query: String::new(),
                selected_id: Some(row.id.clone()),
                label: format!("{} · {}", view.label(), row.name),
                details_focused: true,
                detail_section: None,
            };
            self.restore_nav_location(loc, event_tx);
            return;
        }
        self.jump_to_arm_id(&row.id, event_tx);
    }

    /// Keys while the lens owns the detail pane.
    pub(super) fn handle_refs_lens_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.refs_lens.as_mut() else {
            return;
        };
        st.message = None;
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('U') | KeyCode::Char('h') | KeyCode::Left => {
                self.close_refs_lens()
            }
            KeyCode::Char('j') | KeyCode::Down => st.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => st.move_by(-1),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => st.move_by(PAGE_STEP as isize),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => st.move_by(-(PAGE_STEP as isize)),
            KeyCode::PageDown => st.move_by(2 * PAGE_STEP as isize),
            KeyCode::PageUp => st.move_by(-2 * (PAGE_STEP as isize)),
            KeyCode::Char('g') | KeyCode::Home => st.goto_top(),
            KeyCode::Char('G') | KeyCode::End => st.goto_bottom(),
            KeyCode::Char('f') => st.cycle_service_filter(),
            // Re-walk the caches: after loading another list, say.
            KeyCode::Char('r') => {
                self.scan_refs_lens();
                if let Some(st) = self.refs_lens.as_mut() {
                    st.message = Some("rescanned".into());
                }
            }
            KeyCode::Char('L') => self.load_likely_referrers(event_tx),
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => self.redraw_requested = true,
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => self.follow_refs_row(event_tx),
            KeyCode::Char('e') => self.editor_requested = true,
            KeyCode::Char('y') => {
                if let Some(id) = st.selected_row().map(|r| r.id.clone()) {
                    self.copy_to_clipboard(&id, "resource id");
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
