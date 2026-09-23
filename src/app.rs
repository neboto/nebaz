//! Application state and the event/key handlers. Written fresh for nebaz
//! following neboto's conventions (`src/app.rs` there is 30K lines and
//! 75-service-specific; nothing was copied): all state lives here, is
//! mutated only in `handle_event` / `handle_key`, and every widget renders
//! from `&App`.

use crate::azure::cache::ResourceCache;
use crate::azure::client::AzureClients;
use crate::azure::location::Location;
use crate::azure::resource::{Resource, ResourceState};
use crate::azure::service::ServiceType;
use crate::azure::services::stub::{stub_section_lines, StubDetailSection, StubResource};
use crate::config::Config;
use crate::error::Result;
use crate::event::{Event, LoadProgress};
use crate::lazy::{LazyApply, LazyMap, LazyStore};
use crate::macros::{Macro, MacroPlayer, MacroRecorder, MacroStep, PendingKey};
use crate::search::fuzzy::FuzzyMatcher;
use crate::search::query_parser::{parse_query, split_tag_filters};
use crate::ui::widgets::location_selector::LocationSelectorState;
use crate::ui::widgets::service_selector::ServiceSelectorState;
use crate::ui::widgets::subscription_selector::SubscriptionSelectorState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// ── Supporting types (ported by hand from neboto's app.rs) ──────────────

/// Whether a screen cell (`col`, `row`) falls inside `area`.
fn point_in(area: Rect, col: u16, row: u16) -> bool {
    col >= area.x
        && col < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

/// What a click on a recorded tab-bar region should do. `Service` switches the
/// active service; `Key` replays a keypress through `handle_key` so a sub-tab
/// click reuses the exact per-service view/toggle logic the keyboard uses.
#[derive(Debug, Clone, Copy)]
pub enum ClickAction {
    Service(ServiceType),
    Key(char),
    /// A detail-pane section tab: focus the detail pane (if needed) and replay
    /// the section's number key, so the click reuses the keyboard section logic.
    DetailSection(char),
}

/// A clickable region in the service/sub-tab bars, recorded each frame by the
/// (read-only) tab widgets so `handle_mouse` can map a click to an action.
#[derive(Debug, Clone, Copy)]
pub struct ClickRegion {
    pub rect: Rect,
    pub action: ClickAction,
}

/// Controls how the main content area is split between list and details.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayoutMode {
    Split,       // default: 40 list / 60 details
    ListOnly,    // list fills the full width
    DetailsOnly, // details fills the full width
}

/// List ordering (`z` cycles). `Default` is the service's own order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListSort {
    #[default]
    Default,
    NameAsc,
    NameDesc,
    State,
}

impl ListSort {
    pub fn next(self) -> Self {
        match self {
            ListSort::Default => ListSort::NameAsc,
            ListSort::NameAsc => ListSort::NameDesc,
            ListSort::NameDesc => ListSort::State,
            ListSort::State => ListSort::Default,
        }
    }

    /// Corner-chip label; `None` when inactive (default order).
    pub fn label(self) -> Option<&'static str> {
        match self {
            ListSort::Default => None,
            ListSort::NameAsc => Some("name ↑"),
            ListSort::NameDesc => Some("name ↓"),
            ListSort::State => Some("state"),
        }
    }
}

/// Severity rank for `ListSort::State` — problem states surface first.
fn state_sort_rank(state: &ResourceState) -> u8 {
    use ResourceState::*;
    match state {
        Unavailable => 0,
        Terminated => 1,
        Stopped => 2,
        Deleting => 3,
        Pending => 4,
        Creating => 5,
        Unknown(_) => 6,
        Running => 7,
        Available => 8,
    }
}

/// Destination sub-tab for a "go to resource" jump. neboto carries one
/// variant per service view enum; nebaz's per-service views are added as
/// each catalog ticket lands, so only the single-view case exists yet.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum JumpView {
    None,
}

/// A captured navigation location for the "go back" / jump-list history and
/// for bookmarks: service + sub-tab, the search query, the selected id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NavLocation {
    pub service: ServiceType,
    pub view: JumpView,
    pub query: String,
    pub selected_id: Option<String>,
    /// Precomputed one-line label for the jump-list picker.
    pub label: String,
    /// Captured while the detail pane was focused — restoring re-enters the
    /// detail pane once the row resolves.
    #[serde(default)]
    pub details_focused: bool,
    /// The active split-pane section name at capture time — restored by
    /// name so stale bookmarks survive a pane reshuffle.
    #[serde(default)]
    pub detail_section: Option<String>,
}

/// Cap on the navigation timeline length (oldest entries drop off the front).
const NAV_HISTORY_MAX: usize = 25;

/// Severity of a recorded status message (drives the icon/colour in the
/// `M` message-history viewer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageLevel {
    Success,
    Error,
}

/// One entry in the reviewable message history (`M`).
#[derive(Debug, Clone)]
pub struct MessageEntry {
    pub level: MessageLevel,
    pub text: String,
    pub at: Instant,
}

/// Cap on the message history length (oldest entries drop off the back).
const MESSAGE_HISTORY_MAX: usize = 100;

/// Watch-mode (auto-refresh) state. Kept even though watch mode is fog for
/// the first release: the status bar and the `w` toggle key on it, and the
/// ARM-throttling question is about the *interval floor*, not the shape.
#[derive(Debug, Clone)]
pub struct WatchState {
    pub enabled: bool,
    pub interval: Duration,
    pub last_refresh: Option<Instant>,
}

/// `+`/`-` step through these interval presets (seconds). The floor is
/// deliberately higher than neboto's 5s: the Storage RP allows 100 list
/// calls per 5 minutes per subscription/region.
const WATCH_INTERVALS: &[u64] = &[15, 30, 60, 120, 300];

impl WatchState {
    pub const DEFAULT_SECS: u64 = 30;

    pub fn new(enabled: bool, interval_secs: Option<u64>) -> Self {
        let secs = interval_secs
            .unwrap_or(Self::DEFAULT_SECS)
            .clamp(WATCH_INTERVALS[0], *WATCH_INTERVALS.last().unwrap());
        Self {
            enabled,
            interval: Duration::from_secs(secs),
            last_refresh: None,
        }
    }

    pub fn due(&self, blocked: bool) -> bool {
        if !self.enabled || blocked {
            return false;
        }
        match self.last_refresh {
            None => true,
            Some(t) => t.elapsed() >= self.interval,
        }
    }

    pub fn mark_refreshed(&mut self) {
        self.last_refresh = Some(Instant::now());
    }

    pub fn lengthen(&mut self) {
        let cur = self.interval.as_secs();
        if let Some(&next) = WATCH_INTERVALS.iter().find(|&&s| s > cur) {
            self.interval = Duration::from_secs(next);
        }
    }

    pub fn shorten(&mut self) {
        let cur = self.interval.as_secs();
        if let Some(&prev) = WATCH_INTERVALS.iter().rev().find(|&&s| s < cur) {
            self.interval = Duration::from_secs(prev);
        }
    }
}

/// Half-page step for `Ctrl-d` / `Ctrl-u`.
const PAGE_STEP: usize = 10;
/// How long a success toast stays before the hint line returns.
const SUCCESS_TOAST: Duration = Duration::from_secs(3);
/// Macro playback settle window (see `MacroPlayer::last_step_at`).
const MACRO_SETTLE: Duration = Duration::from_millis(150);

// ── App ─────────────────────────────────────────────────────────────────

pub struct App {
    pub running: bool,
    pub config: Config,
    pub azure_clients: AzureClients,

    // Context: the three slots.
    pub current_service: Option<ServiceType>,
    pub current_location: Location,
    pub subscription_id: Option<String>,
    pub subscription_name: Option<String>,
    pub tenant_id: Option<String>,
    pub visited_services: HashSet<ServiceType>,
    /// Set while a subscription switch awaits its client rebuild.
    pub switching_subscription: Option<String>,

    // Resources for the current service.
    pub resources: Vec<Box<dyn Resource>>,
    /// Indices into `resources`, in display order.
    pub filtered_resources: Vec<usize>,
    /// Position in `filtered_resources`.
    pub selected_index: Option<usize>,
    pub resource_list_state: RefCell<ListState>,
    pub cache: ResourceCache,
    pub lazy: LazyStore,
    /// Bumped on every list load and every context switch; stream events
    /// carrying an older generation are dropped.
    pub load_generation: u64,

    // Loading state.
    pub loading: bool,
    pub loading_started: bool,
    pub loading_complete: bool,
    pub loading_progress: Option<LoadProgress>,
    load_warnings: Vec<String>,
    pub tick_count: u64,

    // Search and list shaping.
    pub search_active: bool,
    pub search_query: String,
    pending_search: bool,
    fuzzy: FuzzyMatcher,
    pub all_search_mode: bool,
    pub all_search_sources: Vec<ServiceType>,
    pub list_sort: ListSort,
    pub list_state_filter: Option<String>,
    pub hide_noise: bool,
    pub hidden_noise_count: usize,
    pub noise_in_view: bool,
    /// Rows dropped by the location filter on the last `update_search`.
    pub location_hidden_count: usize,

    // Detail pane.
    pub details_focused: bool,
    pub details_selected_index: Option<usize>,
    /// The single cursor into the selected resource's section descriptor.
    pub detail_section_idx: usize,
    pub details_scroll: usize,
    pub layout_mode: LayoutMode,

    // Status messages.
    pub error_message: Option<String>,
    pub success_message: Option<String>,
    success_message_at: Option<Instant>,
    pub message_history: Vec<MessageEntry>,
    pub message_history_selected: usize,
    pub message_history_visible: bool,
    last_recorded_message: Option<(MessageLevel, String)>,

    // Overlays.
    pub help_visible: bool,
    pub help_scroll: u16,
    pub help_max_scroll: Cell<u16>,
    pub service_selector: ServiceSelectorState,
    pub location_selector: LocationSelectorState,
    pub subscription_selector: SubscriptionSelectorState,
    pub banner_visible: bool,

    // Navigation history and bookmarks.
    pub nav_history: Vec<NavLocation>,
    pub nav_cursor: Option<usize>,
    pub jump_list_visible: bool,
    pub jump_list_selected: usize,
    pub bookmarks: Vec<NavLocation>,
    pub bookmarks_visible: bool,
    pub bookmarks_selected: usize,

    // Macros.
    pub macros: Vec<Macro>,
    pub macro_recorder: Option<MacroRecorder>,
    pub macro_player: Option<MacroPlayer>,
    pub macro_picker_visible: bool,
    pub macro_picker_selected: usize,
    pub macro_name_input: Option<String>,
    startup_macro: Option<String>,

    // Watch mode / export.
    pub watch: WatchState,
    pub watch_staging: Option<Vec<Box<dyn Resource>>>,
    pub deep_export_progress: Option<String>,

    // `$EDITOR`.
    pub editor_requested: bool,

    // Mouse hit-testing, recorded by the read-only widgets each frame.
    click_regions: RefCell<Vec<ClickRegion>>,
    list_area: Cell<Rect>,
}

impl App {
    pub async fn new(cli: crate::cli::Cli) -> Result<Self> {
        let mut config = Config::load();
        cli.apply_to(&mut config);

        // Theme first: everything drawn after this reads the palette.
        let (palette, theme_warnings) = crate::ui::theme::Palette::from_config(
            config.theme.as_deref(),
            config.theme_colors.as_ref(),
        );
        crate::ui::theme::init_palette(palette);

        let azure_clients =
            AzureClients::new(config.default_subscription.clone(), config.endpoint_url.clone())
                .await?;
        let subscription_id = azure_clients.current_subscription().map(str::to_string);

        let cache_ttl = Duration::from_secs(config.cache_ttl.unwrap_or(300));
        let cache = ResourceCache::new(cache_ttl, config.cache_ttl_overrides());
        let current_service = config.default_service_type();
        let current_location = config.default_location_typed().unwrap_or_default();

        let mut app = Self {
            running: true,
            azure_clients,
            current_service,
            current_location,
            subscription_id,
            subscription_name: None,
            tenant_id: None,
            visited_services: HashSet::new(),
            switching_subscription: None,
            resources: Vec::new(),
            filtered_resources: Vec::new(),
            selected_index: None,
            resource_list_state: RefCell::new(ListState::default()),
            cache,
            lazy: LazyStore::new(0),
            load_generation: 0,
            loading: false,
            loading_started: false,
            loading_complete: false,
            loading_progress: None,
            load_warnings: Vec::new(),
            tick_count: 0,
            search_active: false,
            search_query: String::new(),
            pending_search: false,
            fuzzy: FuzzyMatcher::new(),
            all_search_mode: false,
            all_search_sources: Vec::new(),
            list_sort: ListSort::Default,
            list_state_filter: None,
            hide_noise: true,
            hidden_noise_count: 0,
            noise_in_view: false,
            location_hidden_count: 0,
            details_focused: false,
            details_selected_index: None,
            detail_section_idx: 0,
            details_scroll: 0,
            layout_mode: LayoutMode::Split,
            error_message: None,
            success_message: None,
            success_message_at: None,
            message_history: Vec::new(),
            message_history_selected: 0,
            message_history_visible: false,
            last_recorded_message: None,
            help_visible: false,
            help_scroll: 0,
            help_max_scroll: Cell::new(0),
            service_selector: ServiceSelectorState::new(),
            location_selector: LocationSelectorState::new(),
            subscription_selector: SubscriptionSelectorState::new(),
            banner_visible: config.show_banner.unwrap_or(true),
            nav_history: Vec::new(),
            nav_cursor: None,
            jump_list_visible: false,
            jump_list_selected: 0,
            bookmarks: crate::bookmarks::load(),
            bookmarks_visible: false,
            bookmarks_selected: 0,
            macros: crate::macros::load(),
            macro_recorder: None,
            macro_player: None,
            macro_picker_visible: false,
            macro_picker_selected: 0,
            macro_name_input: None,
            startup_macro: cli.macro_name.clone(),
            watch: WatchState::new(config.watch.unwrap_or(false), config.watch_interval),
            watch_staging: None,
            deep_export_progress: None,
            editor_requested: false,
            click_regions: RefCell::new(Vec::new()),
            list_area: Cell::new(Rect::default()),
            config,
        };
        if let Some(w) = app.config.load_warning.take() {
            app.error_message = Some(w);
        }
        if !theme_warnings.is_empty() {
            app.error_message = Some(format!("theme: {}", theme_warnings.join("; ")));
        }
        if let Some(s) = current_service {
            app.visited_services.insert(s);
        }
        Ok(app)
    }

    // ── Startup / main-loop hooks ───────────────────────────────────────

    /// A `--macro` whose first step switches service supersedes the
    /// default-service load (the list would be fetched and discarded).
    pub fn macro_supersedes_startup_load(&self) -> bool {
        let Some(name) = &self.startup_macro else {
            return false;
        };
        self.macros
            .iter()
            .find(|m| &m.name == name)
            .and_then(|m| m.steps.first())
            .is_some_and(|s| {
                matches!(s, MacroStep::SwitchService(_))
                    || matches!(s, MacroStep::Search(q) if q.starts_with('@'))
            })
    }

    /// Arm the `--macro` for playback (called once by `main` after `new`).
    pub fn arm_startup_macro(&mut self) {
        if let Some(name) = self.startup_macro.take() {
            match self.macros.iter().find(|m| m.name == name).cloned() {
                Some(m) => self.start_macro(m),
                None => self.error_message = Some(format!("No macro named “{}”", name)),
            }
        }
    }

    /// Serve the current service from cache, or mark a load as needed.
    pub fn load_service_resources(&mut self) {
        let Some(service) = self.current_service else {
            return;
        };
        let sub = self.subscription_key();
        if let Some(cached) = self.cache.get(&service, &sub, None) {
            self.resources = cached;
            self.loading = false;
            self.loading_started = true;
            self.loading_complete = true;
            self.update_search();
        } else {
            self.resources.clear();
            self.filtered_resources.clear();
            self.selected_index = None;
            self.loading = true;
            self.loading_started = false;
            self.loading_complete = false;
        }
    }

    pub fn should_load_resources(&self) -> bool {
        self.loading && !self.loading_started && self.current_service.is_some()
    }

    /// Spawn the streaming list load for the current service. Every event
    /// the provider emits is wrapped in `LoadStream { generation }` so a
    /// superseded load can't land on a newer list.
    pub fn load_resources_async(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(service) = self.current_service else {
            return;
        };
        self.loading_started = true;
        self.loading_progress = None;
        self.load_warnings.clear();
        self.load_generation += 1;
        let generation = self.load_generation;
        let provider = self.azure_clients.service(service);
        let outer = event_tx.clone();

        // Forwarder: tag each stream event with this load's generation.
        let (inner_tx, mut inner_rx) = mpsc::unbounded_channel::<Event>();
        let fwd = outer.clone();
        tokio::spawn(async move {
            while let Some(ev) = inner_rx.recv().await {
                if fwd
                    .send(Event::LoadStream {
                        generation,
                        event: Box::new(ev),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let _ = provider.list_resources_streaming(inner_tx, service).await;
        });
    }

    /// Background identity fetch for the service-tab badge. The stub reports
    /// the configured subscription only; ticket 05 replaces the body with
    /// `GET /subscriptions/{id}`.
    pub fn spawn_subscription_info_fetch(&self, event_tx: &mpsc::UnboundedSender<Event>) {
        let id = self.subscription_id.clone();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::SubscriptionInfoLoaded {
                subscription_id: id,
                display_name: None,
                tenant_id: None,
            });
        });
    }

    fn subscription_key(&self) -> String {
        self.subscription_id.clone().unwrap_or_default()
    }

    // ── Read-only accessors for widgets and the status bar ──────────────

    pub fn show_loading_indicator(&self) -> bool {
        self.loading && !self.watch_refresh_active()
    }

    pub fn watch_refresh_active(&self) -> bool {
        self.watch_staging.is_some()
    }

    pub fn current_data_age(&self) -> Option<Duration> {
        let service = self.current_service?;
        self.cache
            .age(&service, &self.subscription_key(), None)
            .filter(|a| a.as_secs() >= 60)
    }

    /// Rows in the current view before the search/state/noise filters.
    pub fn current_view_total(&self) -> usize {
        self.resources.len() - self.location_hidden_count
    }

    /// List visual selection is not ported yet; no row is ever "in" one.
    pub fn list_row_in_selection(&self, _pos: usize) -> bool {
        false
    }

    pub fn record_list_geometry(&self, area: Rect) {
        self.list_area.set(area);
    }

    pub fn clear_click_regions(&self) {
        self.click_regions.borrow_mut().clear();
    }

    pub fn push_click_region(&self, rect: Rect, action: ClickAction) {
        self.click_regions.borrow_mut().push(ClickRegion { rect, action });
    }

    pub fn get_selected_resource(&self) -> Option<&dyn Resource> {
        let pos = self.selected_index?;
        let idx = *self.filtered_resources.get(pos)?;
        self.resources.get(idx).map(|r| r.as_ref())
    }

    pub fn get_selected_resource_id(&self) -> Option<String> {
        self.get_selected_resource().map(|r| r.id().to_string())
    }

    pub fn restore_selection_by_id(&mut self, id: &str) {
        if let Some(pos) = self
            .filtered_resources
            .iter()
            .position(|&i| self.resources[i].id() == id)
        {
            self.select(Some(pos));
        }
    }

    fn select(&mut self, pos: Option<usize>) {
        self.selected_index = pos;
        self.resource_list_state.borrow_mut().select(pos);
        self.details_scroll = 0;
    }

    // ── Search ──────────────────────────────────────────────────────────

    /// Rebuild `filtered_resources` from the query, the location filter,
    /// the state filter, the noise toggle and the sort.
    pub fn update_search(&mut self) {
        let keep_id = self.get_selected_resource_id();
        let parsed = parse_query(&self.search_query);
        let (tag_filters, text) = split_tag_filters(&parsed.search_text);

        // Location filter first — it decides the "of N" denominator.
        let admitted: Vec<usize> = (0..self.resources.len())
            .filter(|&i| self.current_location.admits(self.resources[i].location()))
            .collect();
        self.location_hidden_count = self.resources.len() - admitted.len();

        let admitted_set: HashSet<usize> = admitted.iter().copied().collect();
        let mut matches: Vec<(usize, i64)> = self
            .fuzzy
            .filter_resources(&text, &self.resources)
            .into_iter()
            .filter(|(i, _)| admitted_set.contains(i))
            .filter(|(i, _)| tag_filters.iter().all(|f| f.matches(self.resources[*i].tags())))
            .filter(|(i, _)| {
                self.list_state_filter
                    .as_deref()
                    .is_none_or(|s| self.resources[*i].state_label() == s)
            })
            .collect();

        let noise_total = matches
            .iter()
            .filter(|(i, _)| self.resources[*i].is_noise())
            .count();
        self.noise_in_view = noise_total > 0;
        if self.hide_noise {
            matches.retain(|(i, _)| !self.resources[*i].is_noise());
            self.hidden_noise_count = noise_total;
        } else {
            self.hidden_noise_count = 0;
        }

        // Match score wins while searching; otherwise the chosen sort.
        if text.is_empty() {
            match self.list_sort {
                ListSort::Default => {}
                ListSort::NameAsc => matches.sort_by(|a, b| {
                    self.resources[a.0]
                        .name()
                        .to_lowercase()
                        .cmp(&self.resources[b.0].name().to_lowercase())
                }),
                ListSort::NameDesc => matches.sort_by(|a, b| {
                    self.resources[b.0]
                        .name()
                        .to_lowercase()
                        .cmp(&self.resources[a.0].name().to_lowercase())
                }),
                ListSort::State => matches.sort_by_key(|(i, _)| {
                    state_sort_rank(&self.resources[*i].state())
                }),
            }
        }

        self.filtered_resources = matches.into_iter().map(|(i, _)| i).collect();
        match keep_id {
            Some(id) => {
                let pos = self
                    .filtered_resources
                    .iter()
                    .position(|&i| self.resources[i].id() == id);
                self.select(pos.or(if self.filtered_resources.is_empty() {
                    None
                } else {
                    Some(0)
                }));
            }
            None if !self.filtered_resources.is_empty() => self.select(Some(0)),
            None => self.select(None),
        }
    }

    /// Deferred to after the draw so the typed character shows before the
    /// (possibly expensive) filter runs.
    pub fn process_pending_search(&mut self) {
        if self.pending_search {
            self.pending_search = false;
            self.update_search();
        }
    }

    /// Apply a search query: a `@service` prefix switches service first.
    fn apply_query(&mut self, query: String) {
        self.search_query = query;
        let parsed = parse_query(&self.search_query);
        if parsed.is_service_switch {
            match parsed.service {
                Some(s) if Some(s) != self.current_service => {
                    self.switch_service(s);
                    self.search_query = parsed.search_text;
                }
                Some(_) => self.search_query = parsed.search_text,
                None => {
                    if self.search_query.trim().len() > 1 {
                        self.error_message =
                            Some(format!("Unknown service prefix “{}”", self.search_query.trim()));
                    }
                    return;
                }
            }
        }
        self.pending_search = true;
    }

    // ── Context switches ────────────────────────────────────────────────

    pub fn switch_service(&mut self, service: ServiceType) {
        if self.current_service == Some(service) {
            return;
        }
        self.push_nav_location();
        self.current_service = Some(service);
        self.visited_services.insert(service);
        self.details_focused = false;
        self.detail_section_idx = 0;
        self.list_sort = ListSort::Default;
        self.list_state_filter = None;
        self.search_query.clear();
        self.load_service_resources();
    }

    fn switch_location(&mut self, location: Location) {
        // Client-side: nothing to fetch, just re-filter.
        self.current_location = location;
        self.update_search();
    }

    async fn switch_subscription(&mut self, subscription_id: String) -> Result<()> {
        self.switching_subscription = Some(subscription_id.clone());
        self.azure_clients =
            AzureClients::new(Some(subscription_id.clone()), self.config.endpoint_url.clone())
                .await?;
        self.subscription_id = Some(subscription_id);
        self.subscription_name = None;
        // Everything subscription-scoped resets by construction.
        self.lazy = LazyStore::new(self.lazy.epoch() + 1);
        self.load_generation += 1;
        self.switching_subscription = None;
        self.load_service_resources();
        Ok(())
    }

    // ── Lazy sections ───────────────────────────────────────────────────

    /// The one lazy-fetch entry point: mark `key` loading in the map `lens`
    /// selects, spawn `fut`, and deliver the outcome through `Event::Lazy`
    /// stamped with the current epoch.
    pub fn trigger_lazy<T, F, Fut>(
        &mut self,
        lens: fn(&mut LazyStore) -> &mut LazyMap<T>,
        key: String,
        event_tx: &mpsc::UnboundedSender<Event>,
        fut: F,
    ) where
        T: Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<T, String>> + Send + 'static,
    {
        let map = lens(&mut self.lazy);
        if map.contains(&key) {
            return;
        }
        map.insert_loading(key.clone());
        let epoch = self.lazy.epoch();
        let tx = event_tx.clone();
        let fut = fut();
        tokio::spawn(async move {
            let result = fut.await;
            let apply: Box<dyn FnOnce(&mut App) + Send> =
                Box::new(move |app: &mut App| lens(&mut app.lazy).apply(key, result));
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    /// On-enter hook for the stub pane's Details section.
    pub fn trigger_stub_details(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(id) = app.get_selected_resource_id() else {
            return;
        };
        let fetched_id = id.clone();
        app.trigger_lazy(
            |s| &mut s.stub_details,
            id,
            event_tx,
            move || async move {
                tokio::time::sleep(Duration::from_millis(600)).await;
                Ok(format!("lazily fetched detail for {}", fetched_id))
            },
        );
    }

    // ── Detail sections ─────────────────────────────────────────────────

    fn selected_descriptor(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        self.get_selected_resource().and_then(|r| r.detail_sections())
    }

    /// Move the section cursor and fire the section's on-enter hook.
    pub fn set_detail_section(&mut self, idx: usize, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(desc) = self.selected_descriptor() else {
            return;
        };
        let idx = idx.min(desc.len().saturating_sub(1));
        self.detail_section_idx = idx;
        self.details_scroll = 0;
        desc.enter(idx, self, event_tx);
    }

    pub fn reset_detail_section_to_default(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        self.set_detail_section(0, event_tx);
    }

    pub fn cycle_detail_section(&mut self, forward: bool, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(desc) = self.selected_descriptor() else {
            return;
        };
        let n = desc.len();
        let next = if forward {
            (self.detail_section_idx + 1) % n
        } else {
            (self.detail_section_idx + n - 1) % n
        };
        self.set_detail_section(next, event_tx);
    }

    /// The single source of truth for the detail body — downcasts the
    /// selected resource and dispatches to its `*_section_lines`. Falls back
    /// to the flat `details()` view for types without a descriptor.
    pub fn get_detail_lines(&self) -> Vec<(String, String)> {
        let Some(resource) = self.get_selected_resource() else {
            return Vec::new();
        };
        if let Some(stub) = resource.as_any().downcast_ref::<StubResource>() {
            return stub_section_lines(
                stub,
                StubDetailSection::from_index(self.detail_section_idx),
                self.lazy.stub_details.get(stub.id()),
            );
        }
        let mut lines = resource.details();
        if !resource.tags().is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Tags".into(), String::new()));
            let mut tags: Vec<_> = resource.tags().iter().collect();
            tags.sort();
            for (k, v) in tags {
                lines.push((format!("  {}", k), v.clone()));
            }
        }
        lines
    }

    // ── Messages ────────────────────────────────────────────────────────

    /// Diff-record any new status message into the reviewable history.
    pub fn record_message_history(&mut self) {
        let current = if let Some(e) = &self.error_message {
            Some((MessageLevel::Error, e.clone()))
        } else {
            self.success_message
                .as_ref()
                .map(|s| (MessageLevel::Success, s.clone()))
        };
        if current.is_some() && current != self.last_recorded_message {
            let (level, text) = current.clone().unwrap();
            self.message_history.insert(
                0,
                MessageEntry {
                    level,
                    text,
                    at: Instant::now(),
                },
            );
            self.message_history.truncate(MESSAGE_HISTORY_MAX);
        }
        self.last_recorded_message = current;
    }

    pub fn clear_expired_success_message(&mut self) {
        if let Some(at) = self.success_message_at {
            if at.elapsed() >= SUCCESS_TOAST {
                self.success_message = None;
                self.success_message_at = None;
            }
        }
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.success_message = Some(msg.into());
        self.success_message_at = Some(Instant::now());
        self.error_message = None;
    }

    fn copy_to_clipboard(&mut self, text: &str, what: &str) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())) {
            Ok(()) => self.toast(format!("Copied {}", what)),
            Err(e) => self.error_message = Some(format!("Clipboard: {}", e)),
        }
    }

    // ── `$EDITOR` ───────────────────────────────────────────────────────

    /// Called by `main` after the TUI is torn down: open the selected
    /// resource's raw content or its detail snapshot as JSON.
    pub fn open_in_editor(&mut self) -> Result<()> {
        let Some(resource) = self.get_selected_resource() else {
            return Ok(());
        };
        if let Some(raw) = resource.raw_content() {
            return crate::editor::spawn_editor_with_content(&raw, ".json");
        }
        let sections = self.detail_sections_snapshot();
        let json = crate::export::detail_json(resource, &sections);
        let text = serde_json::to_string_pretty(&json)?;
        crate::editor::spawn_editor_with_content(&text, ".json")
    }

    /// Every section's lines, in descriptor order — the shape export,
    /// `$EDITOR` and (later) the flat view consume.
    pub fn detail_sections_snapshot(&self) -> Vec<(String, Vec<(String, String)>)> {
        let Some(resource) = self.get_selected_resource() else {
            return Vec::new();
        };
        let Some(desc) = resource.detail_sections() else {
            return vec![("Details".to_string(), self.get_detail_lines())];
        };
        let Some(stub) = resource.as_any().downcast_ref::<StubResource>() else {
            return Vec::new();
        };
        desc.sections
            .iter()
            .enumerate()
            .map(|(i, s)| {
                (
                    s.label.to_string(),
                    stub_section_lines(
                        stub,
                        StubDetailSection::from_index(i),
                        self.lazy.stub_details.get(stub.id()),
                    ),
                )
            })
            .collect()
    }

    // ── Navigation history / bookmarks ──────────────────────────────────

    fn current_nav_location(&self) -> Option<NavLocation> {
        let service = self.current_service?;
        let selected = self.get_selected_resource();
        let label = match selected {
            Some(r) => format!("{} · {}", service.short_name(), r.name()),
            None => service.name().to_string(),
        };
        let detail_section = self
            .selected_descriptor()
            .and_then(|d| d.sections.get(self.detail_section_idx))
            .map(|s| s.label.to_string());
        Some(NavLocation {
            service,
            view: JumpView::None,
            query: self.search_query.clone(),
            selected_id: selected.map(|r| r.id().to_string()),
            label,
            details_focused: self.details_focused,
            detail_section,
        })
    }

    fn push_nav_location(&mut self) {
        if let Some(loc) = self.current_nav_location() {
            if let Some(cursor) = self.nav_cursor.take() {
                self.nav_history.truncate(cursor + 1);
            }
            self.nav_history.push(loc);
            if self.nav_history.len() > NAV_HISTORY_MAX {
                self.nav_history.remove(0);
            }
        }
    }

    fn restore_nav_location(&mut self, loc: NavLocation, event_tx: &mpsc::UnboundedSender<Event>) {
        self.switch_service(loc.service);
        self.search_query = loc.query;
        self.update_search();
        if let Some(id) = &loc.selected_id {
            self.restore_selection_by_id(id);
        }
        if loc.details_focused && self.selected_index.is_some() {
            self.details_focused = true;
            let idx = loc
                .detail_section
                .as_deref()
                .and_then(|name| {
                    self.selected_descriptor()
                        .and_then(|d| d.sections.iter().position(|s| s.label == name))
                })
                .unwrap_or(0);
            self.set_detail_section(idx, event_tx);
        }
    }

    // ── Macros ──────────────────────────────────────────────────────────

    fn start_macro(&mut self, m: Macro) {
        self.macro_player = Some(MacroPlayer {
            name: m.name,
            steps: m.steps,
            index: 0,
            last_step_at: None,
        });
    }

    /// Nothing loading, no switch in flight — the player may inject.
    fn macro_ready(&self) -> bool {
        !self.loading && self.switching_subscription.is_none()
    }

    fn any_modal_open(&self) -> bool {
        self.help_visible
            || self.service_selector.visible
            || self.location_selector.visible
            || self.subscription_selector.visible
            || self.jump_list_visible
            || self.bookmarks_visible
            || self.message_history_visible
            || self.macro_picker_visible
    }

    /// Recording (classify the key just dispatched by diffing state) and
    /// playback (inject the next step once quiescent). Runs pre-draw.
    pub fn macro_tick(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        // ── Recording: checkpoints by diffing state ──
        let loc_now = self.current_location.as_str().to_string();
        let sub_now = self.subscription_id.clone();
        let service_now = self.current_service;
        let picker_open = self.service_selector.visible;
        let pending = self.macro_recorder.as_mut().and_then(|r| r.pending.take());
        // Classify the pending key against *current* state (post-dispatch).
        let key_step = pending.and_then(|pending| {
            let code = pending.key.code;
            if pending.was_search_active {
                match code {
                    KeyCode::Enter => Some(MacroStep::Search(pending.query)),
                    _ => None, // typed characters collapse into the Search step
                }
            } else if pending.was_modal {
                None // picker keys are filter text; the outcome is checkpointed
            } else if matches!(
                code,
                KeyCode::Char('j') | KeyCode::Char('k') | KeyCode::Up | KeyCode::Down
            ) {
                self.get_selected_resource().map(|r| MacroStep::SelectId {
                    id: r.id().to_string(),
                    label: r.name().to_string(),
                })
            } else if let KeyCode::Char(c) = code {
                match crate::sections::index_for_key(c) {
                    Some(_) if self.details_focused => self
                        .selected_descriptor()
                        .and_then(|d| d.sections.get(self.detail_section_idx))
                        .map(|s| MacroStep::DetailSection(s.label.to_string())),
                    _ => MacroStep::from_key(pending.key),
                }
            } else {
                MacroStep::from_key(pending.key)
            }
        });
        if let Some(rec) = self.macro_recorder.as_mut() {
            let loc = loc_now;
            if rec.last_location != loc {
                rec.last_location = loc.clone();
                rec.steps.push(MacroStep::SwitchLocation(loc));
            }
            if rec.last_subscription != sub_now {
                rec.last_subscription = sub_now.clone();
                if let Some(s) = &sub_now {
                    rec.steps.push(MacroStep::SwitchSubscription(s.clone()));
                }
            }
            if rec.last_service != service_now {
                if rec.service_selector_was_open && !picker_open {
                    if let Some(s) = service_now {
                        rec.steps.push(MacroStep::SwitchService(s));
                    }
                }
                rec.last_service = service_now;
            }
            rec.service_selector_was_open = picker_open;

            if let Some(step) = key_step {
                // Collapsing: a run of SelectId keeps only the last.
                if matches!(step, MacroStep::SelectId { .. })
                    && matches!(rec.steps.last(), Some(MacroStep::SelectId { .. }))
                {
                    rec.steps.pop();
                }
                rec.steps.push(step);
            }
        }

        // ── Playback ──
        let ready = self.macro_ready();
        let Some(player) = self.macro_player.as_mut() else {
            return;
        };
        if player.index >= player.steps.len() {
            let name = player.name.clone();
            self.macro_player = None;
            self.toast(format!("Macro “{}” done", name));
            return;
        }
        if let Some(at) = player.last_step_at {
            if at.elapsed() < MACRO_SETTLE {
                return;
            }
        }
        if !ready {
            return;
        }
        let step = player.steps[player.index].clone();
        player.index += 1;
        player.last_step_at = Some(Instant::now());
        match step {
            MacroStep::Search(q) => {
                self.search_active = false;
                self.apply_query(q);
                self.process_pending_search();
            }
            MacroStep::SelectId { id, .. } => self.restore_selection_by_id(&id),
            MacroStep::DetailSection(name) => {
                if self.selected_index.is_some() {
                    self.details_focused = true;
                    if let Some(idx) = self
                        .selected_descriptor()
                        .and_then(|d| d.sections.iter().position(|s| s.label == name))
                    {
                        self.set_detail_section(idx, event_tx);
                    }
                }
            }
            MacroStep::SwitchLocation(l) => {
                if let Some(loc) = Location::from_str(&l) {
                    self.switch_location(loc);
                }
            }
            MacroStep::SwitchSubscription(s) => {
                let _ = event_tx.send(Event::SubscriptionSwitchRequested { subscription_id: s });
            }
            MacroStep::SwitchService(s) => self.switch_service(s),
            MacroStep::Key { .. } => {
                if let Some(key) = step.to_key() {
                    let _ = event_tx.send(Event::Key(key));
                }
            }
        }
    }

    // ── Events ──────────────────────────────────────────────────────────

    pub async fn handle_event(
        &mut self,
        event: Event,
        event_tx: &mpsc::UnboundedSender<Event>,
    ) -> Result<()> {
        match event {
            Event::Key(key) => self.handle_key(key, event_tx),
            Event::Mouse(mouse) => self.handle_mouse(mouse, event_tx),
            Event::Resize => {}
            Event::Tick => self.tick_count = self.tick_count.wrapping_add(1),

            Event::LoadStream { generation, event } => {
                if generation != self.load_generation {
                    return Ok(()); // superseded stream
                }
                self.handle_stream_event(*event);
            }
            // Untagged stream events (a provider sending directly) are
            // treated as current.
            e @ (Event::ResourcesLoaded { .. }
            | Event::ResourcesPartiallyLoaded { .. }
            | Event::ResourcesFullyLoaded { .. }
            | Event::ResourceLoadError { .. }
            | Event::ResourceLoadWarning { .. }) => self.handle_stream_event(e),

            Event::ResourceRefreshed {
                id,
                resource,
                quiet,
            } => {
                if let Some(slot) = self.resources.iter_mut().find(|r| r.id() == id) {
                    *slot = resource;
                }
                self.update_search();
                if !quiet {
                    self.toast("Refreshed");
                }
            }
            Event::ResourceRefreshFailed { error } => self.error_message = Some(error),

            Event::LocationSwitchRequested { location } => self.switch_location(location),
            Event::SubscriptionSwitchRequested { subscription_id } => {
                if let Err(e) = self.switch_subscription(subscription_id).await {
                    self.switching_subscription = None;
                    self.error_message = Some(format!("Subscription switch failed: {}", e));
                }
            }
            Event::SubscriptionInfoLoaded {
                subscription_id,
                display_name,
                tenant_id,
            } => {
                if subscription_id.is_some() {
                    self.subscription_id = subscription_id;
                }
                self.subscription_name = display_name;
                self.tenant_id = tenant_id;
            }
            Event::Lazy(apply) => {
                if apply.epoch == self.lazy.epoch() {
                    (apply.apply)(self);
                }
            }
        }
        Ok(())
    }

    fn handle_stream_event(&mut self, event: Event) {
        match event {
            Event::ResourcesLoaded { service, resources } => {
                if Some(service) != self.current_service {
                    return;
                }
                self.resources = resources;
                self.finish_load(service);
            }
            Event::ResourcesPartiallyLoaded {
                service,
                resources,
                progress,
            } => {
                if Some(service) != self.current_service || !self.loading {
                    return;
                }
                self.resources.extend(resources);
                self.loading_progress = Some(progress);
                self.update_search();
            }
            Event::ResourcesFullyLoaded { service, .. } => {
                if Some(service) == self.current_service {
                    self.finish_load(service);
                }
            }
            Event::ResourceLoadError { service, error } => {
                if Some(service) == self.current_service {
                    self.loading = false;
                    self.loading_complete = true;
                    self.loading_progress = None;
                    self.error_message = Some(error);
                }
            }
            Event::ResourceLoadWarning { service, warning }
                if Some(service) == self.current_service =>
            {
                self.load_warnings.push(warning);
            }
            _ => {}
        }
    }

    fn finish_load(&mut self, service: ServiceType) {
        self.loading = false;
        self.loading_complete = true;
        self.loading_progress = None;
        let sub = self.subscription_key();
        self.cache.insert(service, &sub, None, self.resources.clone());
        if !self.load_warnings.is_empty() {
            self.error_message = Some(format!(
                "{} phase(s) failed: {}",
                self.load_warnings.len(),
                self.load_warnings.join(" · ")
            ));
        }
        self.update_search();
    }

    fn handle_mouse(&mut self, mouse: MouseEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        match mouse.kind {
            MouseEventKind::Down(_) => {
                let hit = self
                    .click_regions
                    .borrow()
                    .iter()
                    .find(|r| point_in(r.rect, mouse.column, mouse.row))
                    .map(|r| r.action);
                match hit {
                    Some(ClickAction::Service(s)) => self.switch_service(s),
                    Some(ClickAction::Key(c)) => {
                        self.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE), event_tx)
                    }
                    Some(ClickAction::DetailSection(c)) => {
                        if self.selected_index.is_some() {
                            self.details_focused = true;
                            if let Some(idx) = crate::sections::index_for_key(c) {
                                self.set_detail_section(idx, event_tx);
                            }
                        }
                    }
                    None => {
                        let list = self.list_area.get();
                        if point_in(list, mouse.column, mouse.row) {
                            let offset = self.resource_list_state.borrow().offset();
                            let row = (mouse.row - list.y).saturating_sub(1) as usize + offset;
                            if row < self.filtered_resources.len() {
                                self.select(Some(row));
                                self.details_focused = false;
                            }
                        }
                    }
                }
            }
            MouseEventKind::ScrollDown => self.move_selection(1),
            MouseEventKind::ScrollUp => self.move_selection(-1),
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.filtered_resources.is_empty() {
            return;
        }
        let cur = self.selected_index.unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, self.filtered_resources.len() as isize - 1) as usize;
        self.select(Some(next));
        self.detail_section_idx = 0;
    }

    // ── Keys ────────────────────────────────────────────────────────────

    pub fn handle_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        // Macro recording snapshot (pre-dispatch, see `macro_tick`).
        let was_modal = self.any_modal_open();
        let was_search_active = self.search_active;
        let query = self.search_query.clone();
        if let Some(rec) = self.macro_recorder.as_mut() {
            if !crate::macros::is_unrecordable(key.code) && !matches!(key.code, KeyCode::Char(',')) {
                rec.pending = Some(PendingKey {
                    key,
                    was_search_active,
                    was_modal,
                    query,
                });
            }
        }

        // Modals first — each owns the keyboard while open.
        if self.help_visible {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => self.help_visible = false,
                KeyCode::Char('j') | KeyCode::Down => {
                    self.help_scroll = (self.help_scroll + 1).min(self.help_max_scroll.get())
                }
                KeyCode::Char('k') | KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
                _ => {}
            }
            return;
        }
        if self.service_selector.visible {
            self.handle_service_selector_key(key);
            return;
        }
        if self.location_selector.visible {
            self.handle_location_selector_key(key, event_tx);
            return;
        }
        if self.subscription_selector.visible {
            self.handle_subscription_selector_key(key, event_tx);
            return;
        }
        if self.jump_list_visible || self.bookmarks_visible {
            self.handle_list_picker_key(key, event_tx);
            return;
        }
        if self.message_history_visible {
            match key.code {
                KeyCode::Esc | KeyCode::Char('M') | KeyCode::Char('q') => {
                    self.message_history_visible = false
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    self.message_history_selected = (self.message_history_selected + 1)
                        .min(self.message_history.len().saturating_sub(1))
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.message_history_selected = self.message_history_selected.saturating_sub(1)
                }
                KeyCode::Char('y') => {
                    if let Some(e) = self.message_history.get(self.message_history_selected) {
                        let text = e.text.clone();
                        self.copy_to_clipboard(&text, "message");
                    }
                }
                _ => {}
            }
            return;
        }
        if self.macro_picker_visible {
            self.handle_macro_picker_key(key);
            return;
        }

        // Search input.
        if self.search_active {
            match key.code {
                KeyCode::Esc => {
                    self.search_active = false;
                    self.search_query.clear();
                    self.pending_search = true;
                }
                KeyCode::Enter => {
                    self.search_active = false;
                    let q = self.search_query.clone();
                    self.apply_query(q);
                }
                KeyCode::Tab => {
                    // Complete a partial `@prefix` to the first match.
                    if let Some(partial) = self.search_query.strip_prefix('@') {
                        if !partial.contains(' ') {
                            let p = partial.to_lowercase();
                            if let Some(s) = ServiceType::all()
                                .into_iter()
                                .find(|s| s.prefix()[1..].starts_with(&p))
                            {
                                self.search_query = format!("{} ", s.prefix());
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.pending_search = true;
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.pending_search = true;
                }
                _ => {}
            }
            return;
        }

        // Detail pane focused.
        if self.details_focused {
            match key.code {
                KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => {
                    self.details_focused = false;
                }
                KeyCode::Char('j') | KeyCode::Down => self.details_scroll += 1,
                KeyCode::Char('k') | KeyCode::Up => {
                    self.details_scroll = self.details_scroll.saturating_sub(1)
                }
                KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.details_scroll += PAGE_STEP
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.details_scroll = self.details_scroll.saturating_sub(PAGE_STEP)
                }
                KeyCode::Tab => self.cycle_detail_section(true, event_tx),
                KeyCode::BackTab => self.cycle_detail_section(false, event_tx),
                KeyCode::Char(c) if crate::sections::index_for_key(c).is_some() => {
                    self.set_detail_section(crate::sections::index_for_key(c).unwrap(), event_tx)
                }
                KeyCode::Char('y') => {
                    let lines = self.get_detail_lines();
                    if let Some((_, v)) = lines.get(self.details_scroll) {
                        let text = v.clone();
                        self.copy_to_clipboard(&text, "row");
                    }
                }
                KeyCode::Char('Z') => {
                    self.layout_mode = match self.layout_mode {
                        LayoutMode::DetailsOnly => LayoutMode::Split,
                        _ => LayoutMode::DetailsOnly,
                    }
                }
                KeyCode::Char('r') => self.refresh_selected(event_tx),
                _ => self.handle_global_key(key, event_tx),
            }
            return;
        }

        // List pane.
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.move_selection(PAGE_STEP as isize)
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.move_selection(-(PAGE_STEP as isize))
            }
            KeyCode::Char('G') | KeyCode::End => {
                let n = self.filtered_resources.len();
                if n > 0 {
                    self.select(Some(n - 1));
                }
            }
            KeyCode::Char('g') | KeyCode::Home => {
                if !self.filtered_resources.is_empty() {
                    self.select(Some(0));
                }
            }
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if self.selected_index.is_some() {
                    self.details_focused = true;
                    self.reset_detail_section_to_default(event_tx);
                }
            }
            KeyCode::Char('/') => {
                self.search_active = true;
            }
            KeyCode::Char('z') => {
                self.list_sort = self.list_sort.next();
                self.update_search();
            }
            KeyCode::Char('F') => self.cycle_state_filter(),
            KeyCode::Char('a') => {
                self.hide_noise = !self.hide_noise;
                self.update_search();
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                if let Some(service) = self.current_service {
                    let sub = self.subscription_key();
                    self.cache.invalidate(&service, &sub, None);
                    self.load_service_resources();
                }
            }
            KeyCode::Char('w') => {
                self.watch.enabled = !self.watch.enabled;
                self.toast(if self.watch.enabled {
                    "Watch mode on (not yet wired to a refresh loop)"
                } else {
                    "Watch mode off"
                });
            }
            KeyCode::Char('+') => self.watch.lengthen(),
            KeyCode::Char('-') => self.watch.shorten(),
            KeyCode::Char('Z') => {
                self.layout_mode = match self.layout_mode {
                    LayoutMode::ListOnly => LayoutMode::Split,
                    _ => LayoutMode::ListOnly,
                }
            }
            KeyCode::Char('B') => {
                if let Some(loc) = self.current_nav_location() {
                    self.bookmarks.push(loc);
                    crate::bookmarks::save(&self.bookmarks);
                    self.toast("Bookmarked");
                }
            }
            KeyCode::Char('X') if key.modifiers.contains(KeyModifiers::CONTROL) => self.export_list(),
            KeyCode::Char('X') => self.export_detail(),
            _ => self.handle_global_key(key, event_tx),
        }
    }

    /// Keys that work from either pane.
    fn handle_global_key(&mut self, key: KeyEvent, _event_tx: &mpsc::UnboundedSender<Event>) {
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('?') => {
                self.help_visible = true;
                self.help_scroll = 0;
            }
            KeyCode::Char('S') => self.service_selector.show(self.current_service),
            KeyCode::Char('R') => self.location_selector.show(self.current_location),
            KeyCode::Char('P') => self
                .subscription_selector
                .show(self.azure_clients.current_subscription()),
            KeyCode::Char('b') => self.banner_visible = !self.banner_visible,
            KeyCode::Char('e') => {
                if self.selected_index.is_some() {
                    self.editor_requested = true;
                }
            }
            KeyCode::Char('y') => {
                if let Some(id) = self.get_selected_resource_id() {
                    self.copy_to_clipboard(&id, "resource id");
                }
            }
            KeyCode::Char('C') => {
                let cmd = self.get_selected_resource().and_then(|r| r.cli_command());
                match cmd {
                    Some(mut cmd) => {
                        if let Some(sub) = self.azure_clients.current_subscription() {
                            cmd.push_str(&format!(" --subscription {}", sub));
                        }
                        self.copy_to_clipboard(&cmd, "az command");
                    }
                    None => self.error_message = Some("No CLI command for this resource".into()),
                }
            }
            KeyCode::Char('O') => {
                let url = self.get_selected_resource().and_then(|r| r.portal_url());
                match url {
                    Some(url) => self.copy_to_clipboard(&url, "portal URL"),
                    None => self.error_message = Some("No portal page for this resource".into()),
                }
            }
            KeyCode::Char('`') => {
                self.jump_list_visible = true;
                self.jump_list_selected = 0;
            }
            KeyCode::Char('\'') => {
                self.bookmarks_visible = true;
                self.bookmarks_selected = 0;
            }
            KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.nav_back(_event_tx)
            }
            KeyCode::Char('M') => {
                self.message_history_visible = true;
                self.message_history_selected = 0;
            }
            KeyCode::Char(',') => {
                if let Some(rec) = self.macro_recorder.take() {
                    // Stop recording → name prompt.
                    self.macro_recorder = Some(rec);
                    self.macro_name_input = Some(String::new());
                    self.macro_picker_visible = true;
                } else {
                    self.macro_picker_visible = true;
                    self.macro_picker_selected = 0;
                }
            }
            _ => {}
        }
    }

    fn nav_back(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.nav_history.is_empty() {
            return;
        }
        let cursor = match self.nav_cursor {
            None => {
                self.push_nav_location();
                self.nav_history.len().saturating_sub(2)
            }
            Some(c) => c.saturating_sub(1),
        };
        self.nav_cursor = Some(cursor);
        if let Some(loc) = self.nav_history.get(cursor).cloned() {
            self.restore_nav_location(loc, event_tx);
        }
    }

    fn cycle_state_filter(&mut self) {
        let mut labels: Vec<String> = self
            .resources
            .iter()
            .map(|r| r.state_label())
            .filter(|l| !l.is_empty())
            .collect();
        labels.sort();
        labels.dedup();
        self.list_state_filter = match &self.list_state_filter {
            None => labels.first().cloned(),
            Some(cur) => labels
                .iter()
                .position(|l| l == cur)
                .and_then(|i| labels.get(i + 1).cloned()),
        };
        self.update_search();
    }

    fn refresh_selected(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let (Some(service), Some(id)) = (self.current_service, self.get_selected_resource_id())
        else {
            return;
        };
        let provider = self.azure_clients.service(service);
        let tx = event_tx.clone();
        tokio::spawn(async move {
            match provider.get_resource_details(&id).await {
                Ok(resource) => {
                    let _ = tx.send(Event::ResourceRefreshed {
                        id,
                        resource,
                        quiet: false,
                    });
                }
                Err(e) => {
                    let _ = tx.send(Event::ResourceRefreshFailed {
                        error: e.to_string(),
                    });
                }
            }
        });
    }

    fn export_list(&mut self) {
        let rows: Vec<&dyn Resource> = self
            .filtered_resources
            .iter()
            .map(|&i| self.resources[i].as_ref())
            .collect();
        let label = self
            .current_service
            .map(|s| s.short_name().to_string())
            .unwrap_or_else(|| "resources".into());
        match crate::export::export_list(&rows, &label) {
            Ok(paths) => self.toast(format!("Exported {} file(s)", paths.len())),
            Err(e) => self.error_message = Some(format!("Export failed: {}", e)),
        }
    }

    fn export_detail(&mut self) {
        let Some(resource) = self.get_selected_resource() else {
            return;
        };
        let sections = self.detail_sections_snapshot();
        if crate::export::any_section_unloaded(&sections) {
            self.error_message = Some("Some sections not loaded yet — open them, then X again".into());
            return;
        }
        let label = resource.name().to_string();
        match crate::export::export_detail(resource, &sections, &label) {
            Ok(paths) => self.toast(format!("Exported {} file(s)", paths.len())),
            Err(e) => self.error_message = Some(format!("Export failed: {}", e)),
        }
    }

    // ── Picker keys ─────────────────────────────────────────────────────

    fn handle_service_selector_key(&mut self, key: KeyEvent) {
        let sel = &mut self.service_selector;
        match key.code {
            KeyCode::Esc => sel.hide(),
            KeyCode::Enter => {
                if let Some(s) = sel.selected_service() {
                    sel.hide();
                    self.switch_service(s);
                }
            }
            KeyCode::Down | KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.next(),
            KeyCode::Down => sel.next(),
            KeyCode::Up => sel.previous(),
            KeyCode::Left => sel.prev_category(),
            KeyCode::Right => sel.next_category(),
            KeyCode::Home => sel.select_first(),
            KeyCode::End => sel.select_last(),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.page_down(),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.page_up(),
            KeyCode::Backspace => sel.pop_char(),
            KeyCode::Char(c) => sel.push_char(c),
            _ => {}
        }
    }

    fn handle_location_selector_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let sel = &mut self.location_selector;
        match key.code {
            KeyCode::Esc => sel.hide(),
            KeyCode::Enter => {
                if let Some(l) = sel.selected_location() {
                    sel.hide();
                    let _ = event_tx.send(Event::LocationSwitchRequested { location: l });
                }
            }
            KeyCode::Down => sel.next(),
            KeyCode::Up => sel.previous(),
            KeyCode::Home => sel.select_first(),
            KeyCode::End => sel.select_last(),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.page_down(),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.page_up(),
            KeyCode::Backspace => sel.pop_char(),
            KeyCode::Char(c) => sel.push_char(c),
            _ => {}
        }
    }

    fn handle_subscription_selector_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let sel = &mut self.subscription_selector;
        match key.code {
            KeyCode::Esc => sel.hide(),
            KeyCode::Enter => {
                if let Some(s) = sel.selected_subscription() {
                    sel.hide();
                    let _ = event_tx.send(Event::SubscriptionSwitchRequested { subscription_id: s });
                }
            }
            KeyCode::Down => sel.next(),
            KeyCode::Up => sel.previous(),
            KeyCode::Home => sel.select_first(),
            KeyCode::End => sel.select_last(),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.page_down(),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => sel.page_up(),
            KeyCode::Backspace => sel.pop_char(),
            KeyCode::Char(c) => sel.push_char(c),
            _ => {}
        }
    }

    /// Jump list and bookmarks share one key handler.
    fn handle_list_picker_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let is_bookmarks = self.bookmarks_visible;
        let len = if is_bookmarks {
            self.bookmarks.len()
        } else {
            self.nav_history.len()
        };
        let selected = if is_bookmarks {
            &mut self.bookmarks_selected
        } else {
            &mut self.jump_list_selected
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('`') | KeyCode::Char('\'') | KeyCode::Char('q') => {
                self.jump_list_visible = false;
                self.bookmarks_visible = false;
            }
            KeyCode::Char('j') | KeyCode::Down => *selected = (*selected + 1).min(len.saturating_sub(1)),
            KeyCode::Char('k') | KeyCode::Up => *selected = selected.saturating_sub(1),
            KeyCode::Char('d') if is_bookmarks => {
                if *selected < len {
                    let i = *selected;
                    self.bookmarks.remove(i);
                    crate::bookmarks::save(&self.bookmarks);
                    self.bookmarks_selected = self.bookmarks_selected.min(self.bookmarks.len().saturating_sub(1));
                }
            }
            KeyCode::Enter => {
                let loc = if is_bookmarks {
                    self.bookmarks.get(*selected).cloned()
                } else {
                    // Displayed most-recent first.
                    let idx = len.checked_sub(1 + *selected);
                    idx.and_then(|i| self.nav_history.get(i).cloned())
                };
                self.jump_list_visible = false;
                self.bookmarks_visible = false;
                if let Some(loc) = loc {
                    self.push_nav_location();
                    self.restore_nav_location(loc, event_tx);
                }
            }
            _ => {}
        }
    }

    fn handle_macro_picker_key(&mut self, key: KeyEvent) {
        // Naming a fresh recording.
        if let Some(name) = self.macro_name_input.as_mut() {
            match key.code {
                KeyCode::Esc => {
                    self.macro_name_input = None;
                    self.macro_recorder = None;
                    self.macro_picker_visible = false;
                }
                KeyCode::Enter => {
                    let name = name.trim().to_string();
                    if let Some(rec) = self.macro_recorder.take() {
                        if !name.is_empty() && !rec.steps.is_empty() {
                            self.macros.retain(|m| m.name != name);
                            self.macros.push(Macro {
                                name: name.clone(),
                                steps: rec.steps,
                            });
                            crate::macros::save(&self.macros);
                            self.toast(format!("Saved macro “{}”", name));
                        }
                    }
                    self.macro_name_input = None;
                    self.macro_picker_visible = false;
                }
                KeyCode::Backspace => {
                    name.pop();
                }
                KeyCode::Char(c) => name.push(c),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char(',') | KeyCode::Char('q') => self.macro_picker_visible = false,
            KeyCode::Char('j') | KeyCode::Down => {
                self.macro_picker_selected =
                    (self.macro_picker_selected + 1).min(self.macros.len().saturating_sub(1))
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.macro_picker_selected = self.macro_picker_selected.saturating_sub(1)
            }
            KeyCode::Char('n') => {
                self.macro_picker_visible = false;
                self.macro_recorder = Some(MacroRecorder {
                    last_location: self.current_location.as_str().to_string(),
                    last_subscription: self.subscription_id.clone(),
                    last_service: self.current_service,
                    ..Default::default()
                });
                self.toast("Recording — press , to stop");
            }
            KeyCode::Char('d') => {
                if self.macro_picker_selected < self.macros.len() {
                    self.macros.remove(self.macro_picker_selected);
                    crate::macros::save(&self.macros);
                    self.macro_picker_selected = self
                        .macro_picker_selected
                        .min(self.macros.len().saturating_sub(1));
                }
            }
            KeyCode::Enter => {
                if let Some(m) = self.macros.get(self.macro_picker_selected).cloned() {
                    self.macro_picker_visible = false;
                    self.start_macro(m);
                }
            }
            _ => {}
        }
    }
}
