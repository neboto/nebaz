//! Application state and the event/key handlers. Written fresh for nebaz
//! following neboto's conventions (`src/app.rs` there is 30K lines and
//! 75-service-specific; nothing was copied): all state lives here, is
//! mutated only in `handle_event` / `handle_key`, and every widget renders
//! from `&App`.

use crate::azure::auth::AuthError;
use crate::azure::cache::ResourceCache;
use crate::azure::client::AzureClients;
use crate::azure::location::{Location, LocationRow, ALL_DISPLAY};
use crate::azure::resource::{Resource, ResourceState};
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::resource::{name_of_id, subscription_of};
use crate::azure::services::aks::{
    cluster_section_lines, node_pool_section_lines, ClusterDetailSection, ClusterRow, NodePoolDetailSection,
    NodePoolRow,
};
use crate::azure::services::compute::{
    disk_section_lines, instance_view_path, nic_section_lines, vm_section_lines, DiskDetailSection, DiskRow,
    NicDetailSection, NicRow, VmDetailSection, VmRow, VM_API_VERSION,
};
use crate::azure::services::keyvault::{
    names_path, vault_section_lines, VaultDetailSection, VaultRow, VAULT_NAMES_API_VERSION,
};
use crate::azure::services::network::{
    nsg_section_lines, subnet_section_lines, vnet_section_lines, NsgDetailSection, NsgRow, SubnetDetailSection,
    SubnetRow, VnetDetailSection, VnetRow,
};
use crate::azure::services::storage::{
    containers_path, storage_account_section_lines, StorageAccountDetailSection, StorageAccountRow,
    STORAGE_API_VERSION,
};
use crate::azure::services::subscriptions::{
    resource_group_section_lines, subscription_section_lines, ResourceGroupDetailSection,
    ResourceGroupRow, SubscriptionDetailSection, SubscriptionRow,
};
use crate::config::Config;
use crate::error::Result;
use crate::event::{Event, LoadProgress};
use crate::lazy::{LazyApply, LazyMap, LazyStore};
use crate::macros::{Macro, MacroPlayer, MacroRecorder, MacroStep, PendingKey};
use crate::search::fuzzy::FuzzyMatcher;
use crate::search::query_parser::{parse_query, rg_filter_admits, split_rg_filters, split_tag_filters};
use crate::ui::widgets::location_selector::{EndpointState, LocationSelectorState};
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

/// A captured navigation location for the "go back" / jump-list history and
/// for bookmarks: subscription + service + sub-tab, the search query, the
/// selected id. A jump into another subscription switches it first
/// (ADR 0002); one whose subscription is not in the picker's list fails
/// with a message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NavLocation {
    pub service: ServiceType,
    /// The sub-tab; `None` (older bookmarks) lands on the service's first.
    #[serde(default)]
    pub view: Option<JumpView>,
    /// The subscription the location was captured in.
    #[serde(default)]
    pub subscription: Option<String>,
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

    // Context: the three slots, plus the sub-tab within the service.
    pub current_service: Option<ServiceType>,
    /// The active sub-tab; always one of `current_service.views()`.
    pub current_view: JumpView,
    pub current_location: Location,
    pub subscription_id: Option<String>,
    pub subscription_name: Option<String>,
    pub tenant_id: Option<String>,
    /// The one app-wide auth condition (ADR 0003): one status-bar line
    /// with the fix, suppressing per-service load errors while it holds;
    /// cleared by the next successful token.
    pub auth_error: Option<AuthError>,
    pub visited_services: HashSet<ServiceType>,

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
    /// A jump (Related section, bookmark, history) whose target row has
    /// not landed yet: `(ARM id, focus the pane once it does)`. Resolved
    /// as pages stream in; cleared with a message if the load ends
    /// without it.
    pub pending_jump: Option<(String, bool)>,
    /// `Ctrl-L`: the main loop clears the terminal before the next draw,
    /// so a screen garbled by the terminal (or something printing over
    /// it) is one key from clean.
    pub redraw_requested: bool,
    /// One long-lived clipboard handle (see `clipboard.rs` for why).
    clipboard: crate::clipboard::Clipboard,
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

        let azure_clients = AzureClients::new(&config).await?;
        let subscription_id = azure_clients.current_subscription().map(str::to_string);
        let subscription_name = azure_clients.current_subscription_name().map(str::to_string);
        let tenant_id = azure_clients.current_tenant().map(str::to_string);
        let auth_error = azure_clients.auth_error().cloned();

        let cache_ttl = Duration::from_secs(config.cache_ttl.unwrap_or(300));
        let cache = ResourceCache::new(cache_ttl, config.cache_ttl_overrides());
        // `default_service = "rg"` is a routing prefix: it names the sub-tab too.
        let (current_service, current_view) = match config
            .default_service
            .as_deref()
            .and_then(ServiceType::from_prefix)
        {
            Some((service, view)) => (Some(service), view.unwrap_or(service.default_view())),
            None => (None, JumpView::Subscriptions),
        };
        let current_location = config.default_location_typed().unwrap_or_default();

        let mut app = Self {
            running: true,
            azure_clients,
            current_service,
            current_view,
            current_location,
            subscription_id,
            subscription_name,
            tenant_id,
            auth_error,
            visited_services: HashSet::new(),
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
            pending_jump: None,
            redraw_requested: false,
            clipboard: crate::clipboard::Clipboard::new(),
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
        // No subscription resolved: open the picker with the auth line.
        if app.subscription_id.is_none() {
            app.open_subscription_picker();
        }
        Ok(app)
    }

    /// `P`: the picker over every subscription the CLI knows, or the auth
    /// line when there are none.
    fn open_subscription_picker(&mut self) {
        let entries = self.azure_clients.subscriptions().to_vec();
        let current = self.azure_clients.current_subscription().map(str::to_string);
        let message = self.auth_error.as_ref().map(|a| a.status_line());
        self.subscription_selector
            .show(entries, current.as_deref(), message);
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

    /// The list cache variant for the active sub-tab.
    fn cache_variant(&self) -> &'static str {
        self.current_view.as_str()
    }

    /// Serve the current sub-tab from cache, or mark a load as needed.
    pub fn load_service_resources(&mut self) {
        let Some(service) = self.current_service else {
            return;
        };
        let sub = self.subscription_key();
        if let Some(cached) = self.cache.get(&service, &sub, Some(self.cache_variant())) {
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
        let view = self.current_view;
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
            let _ = provider.list_resources_streaming(view, inner_tx, service).await;
        });
    }

    /// Identity for the service-tab badge. Filled from the `az account
    /// list` entry — no ARM call — and delivered through the same event a
    /// fetched identity would use.
    pub fn spawn_subscription_info_fetch(&self, event_tx: &mpsc::UnboundedSender<Event>) {
        let entry = self.azure_clients.current_entry().cloned();
        let _ = event_tx.send(Event::SubscriptionInfoLoaded {
            subscription_id: entry.as_ref().map(|e| e.id.clone()),
            display_name: entry.as_ref().map(|e| e.name.clone()),
            tenant_id: entry.map(|e| e.tenant_id),
        });
    }

    /// `R` on the auth line: re-read the account list, then reload the
    /// current view under a fresh LazyStore.
    async fn retry_auth(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        match self.azure_clients.retry_auth().await {
            Ok(_) => {
                self.auth_error = self.azure_clients.auth_error().cloned();
            }
            Err(e) => {
                self.auth_error = e.auth_error().or_else(|| Some(AuthError::Other(e.to_string())));
            }
        }
        if self.subscription_selector.visible {
            self.open_subscription_picker();
        }
        if self.auth_error.is_some() {
            return;
        }
        self.apply_subscription_identity();
        self.spawn_subscription_info_fetch(event_tx);
        self.lazy = LazyStore::new(self.lazy.epoch() + 1);
        self.load_generation += 1;
        if let Some(service) = self.current_service {
            let sub = self.subscription_key();
            self.cache.invalidate(&service, &sub, Some(self.cache_variant()));
        }
        self.load_service_resources();
        App::trigger_locations(self, event_tx);
        self.toast("Retrying with the Azure CLI");
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
            .age(&service, &self.subscription_key(), Some(self.cache_variant()))
            .filter(|a| a.as_secs() >= 60)
    }

    /// The sub-tab chips for the current service: `(digit, label, active)`.
    /// Empty for a single-sub-tab service (the bar is hidden).
    pub fn sub_tab_chips(&self) -> Vec<(char, &'static str, bool)> {
        let Some(service) = self.current_service else {
            return Vec::new();
        };
        let views = service.views();
        if views.len() < 2 {
            return Vec::new();
        }
        views
            .iter()
            .enumerate()
            .map(|(i, v)| {
                (
                    crate::sections::key_for(i).unwrap_or(' '),
                    v.label(),
                    *v == self.current_view,
                )
            })
            .collect()
    }

    /// The `R` picker's rows: `All` first, then the subscription's locations
    /// (once the endpoint list has landed) merged with the distinct
    /// locations of the current list and their row counts, sorted by
    /// count then name. A location the endpoint doesn't know but a row
    /// carries still appears; one with zero rows is still pickable.
    pub fn location_rows(&self) -> Vec<LocationRow> {
        let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for r in &self.resources {
            if let Some(l) = r.location() {
                *counts.entry(l.to_lowercase()).or_default() += 1;
            }
        }
        let mut names: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        if let Some(crate::lazy::Lazy::Loaded(infos)) = self.subscription_locations() {
            for info in infos {
                names.insert(info.name.to_lowercase(), info.display_name.clone());
            }
        }
        let mut rows: Vec<LocationRow> = names
            .keys()
            .chain(counts.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|name| LocationRow {
                location: Location::Named(name.clone()),
                display_name: names.get(name).cloned().unwrap_or_else(|| name.clone()),
                count: counts.get(name).copied().unwrap_or(0),
            })
            .collect();
        rows.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.location.as_str().cmp(b.location.as_str()))
        });
        rows.insert(
            0,
            LocationRow {
                location: Location::All,
                display_name: ALL_DISPLAY.to_string(),
                count: self.resources.len(),
            },
        );
        rows
    }

    /// The current subscription's locations list, as far as it has landed.
    fn subscription_locations(&self) -> Option<&crate::lazy::Lazy<Vec<crate::azure::location::LocationInfo>>> {
        self.lazy.locations.get(&self.subscription_key())
    }

    /// What the status bar shows for the `R` slot: the endpoint's display
    /// name when known, else the short name itself.
    pub fn location_label(&self) -> String {
        match &self.current_location {
            Location::All => ALL_DISPLAY.to_string(),
            Location::Named(name) => match self.subscription_locations() {
                Some(crate::lazy::Lazy::Loaded(infos)) => infos
                    .iter()
                    .find(|i| i.name.eq_ignore_ascii_case(name))
                    .map(|i| i.display_name.clone())
                    .unwrap_or_else(|| name.clone()),
                _ => name.clone(),
            },
        }
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

    /// Select the visible row with this ARM id (case-insensitively — ARM
    /// ids vary in case between endpoints). `false` when no visible row
    /// has it.
    pub fn restore_selection_by_id(&mut self, id: &str) -> bool {
        match self
            .filtered_resources
            .iter()
            .position(|&i| self.resources[i].id().eq_ignore_ascii_case(id))
        {
            Some(pos) => {
                self.select(Some(pos));
                true
            }
            None => false,
        }
    }

    /// Whether any loaded row (visible or filtered out) has this id.
    fn has_resource_id(&self, id: &str) -> bool {
        self.resources.iter().any(|r| r.id().eq_ignore_ascii_case(id))
    }

    // ── Jumps ───────────────────────────────────────────────────────────

    /// The one jump mechanism (ticket 06): an ARM id becomes a
    /// `NavLocation` routed on its type, and the row resolves once its
    /// list has it. An id nebaz does not browse is copied instead.
    pub fn jump_to_arm_id(&mut self, id: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(view) = JumpView::for_arm_id(id) else {
            if id.starts_with("/subscriptions/") {
                self.copy_to_clipboard(id, "id (not a type nebaz browses)");
            }
            return;
        };
        self.push_nav_location();
        let loc = NavLocation {
            service: view.service(),
            view: Some(view),
            subscription: subscription_of(id).map(str::to_string),
            query: String::new(),
            selected_id: Some(id.to_string()),
            label: format!("{} · {}", view.label(), name_of_id(id)),
            details_focused: true,
            detail_section: None,
        };
        self.restore_nav_location(loc, event_tx);
    }

    /// Enter on a detail line: jump when its value is an ARM id.
    fn follow_detail_line(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let lines = self.get_detail_lines();
        let Some((_, value)) = lines.get(self.details_scroll) else {
            return;
        };
        let value = value.trim().to_string();
        if value.starts_with("/subscriptions/") {
            self.jump_to_arm_id(&value, event_tx);
        }
    }

    /// Try to land a pending jump on the rows loaded so far. A row hidden
    /// only by the location filter lifts the filter; a load that ends
    /// without the row clears the jump with a message.
    fn resolve_pending_jump(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some((id, focus)) = self.pending_jump.clone() else {
            return;
        };
        if !self.restore_selection_by_id(&id) && self.has_resource_id(&id) {
            self.switch_location(Location::All);
            self.toast("Location filter cleared to reach the row");
            self.restore_selection_by_id(&id);
        }
        if self.selected_index.is_some() && self.get_selected_resource_id().is_some_and(|s| s.eq_ignore_ascii_case(&id)) {
            self.pending_jump = None;
            if focus {
                self.details_focused = true;
                self.reset_detail_section_to_default(event_tx);
            }
        } else if !self.loading {
            self.pending_jump = None;
            self.error_message = Some(format!("{} is not in this list", name_of_id(&id)));
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
        let (rg_filters, text) = split_rg_filters(&text);

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
            .filter(|(i, _)| rg_filter_admits(&rg_filters, self.resources[*i].resource_group()))
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
                Some(s) => {
                    if Some(s) != self.current_service {
                        self.switch_service(s);
                    }
                    if let Some(view) = parsed.view {
                        self.switch_view(view);
                    }
                    self.search_query = parsed.search_text;
                }
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
        self.current_view = service.default_view();
        self.visited_services.insert(service);
        self.reset_list_shaping();
        self.load_service_resources();
    }

    /// Switch sub-tab within the current service. A view of another service
    /// switches service first (a routing prefix, a bookmark).
    pub fn switch_view(&mut self, view: JumpView) {
        if self.current_service != Some(view.service()) {
            self.switch_service(view.service());
        }
        if self.current_view == view {
            return;
        }
        self.push_nav_location();
        self.current_view = view;
        self.reset_list_shaping();
        self.load_service_resources();
    }

    /// Switch sub-tab by position in the service's list (digit keys).
    fn switch_view_index(&mut self, idx: usize) {
        let Some(service) = self.current_service else {
            return;
        };
        if let Some(view) = service.views().get(idx) {
            self.switch_view(*view);
        }
    }

    fn cycle_view(&mut self, forward: bool) {
        let Some(service) = self.current_service else {
            return;
        };
        let views = service.views();
        let n = views.len();
        if n < 2 {
            return;
        }
        let cur = views.iter().position(|v| *v == self.current_view).unwrap_or(0);
        let next = if forward { (cur + 1) % n } else { (cur + n - 1) % n };
        self.switch_view(views[next]);
    }

    /// What a service or sub-tab switch resets: the pane focus, the
    /// section cursor, sort, state filter and query.
    fn reset_list_shaping(&mut self) {
        self.details_focused = false;
        self.detail_section_idx = 0;
        self.list_sort = ListSort::Default;
        self.list_state_filter = None;
        self.search_query.clear();
    }

    fn switch_location(&mut self, location: Location) {
        // Client-side: nothing to fetch, just re-filter.
        self.current_location = location;
        self.update_search();
    }

    /// The `P` slot. Keeps the client (a subscription is a value on the
    /// provider, not a client to rebuild — a tenant change is the
    /// credential map's concern) and the list cache; replaces the LazyStore
    /// and bumps the load generation so nothing subscription-scoped
    /// survives (ADR 0002).
    fn switch_subscription(&mut self, subscription_id: &str, event_tx: &mpsc::UnboundedSender<Event>) -> Result<()> {
        self.azure_clients.set_subscription(subscription_id)?;
        self.apply_subscription_identity();
        // Everything subscription-scoped resets by construction.
        self.lazy = LazyStore::new(self.lazy.epoch() + 1);
        self.load_generation += 1;
        self.load_service_resources();
        App::trigger_locations(self, event_tx);
        Ok(())
    }

    /// Read the active subscription's identity off the client (no ARM
    /// call: the `az account list` entry carries the name and tenant).
    fn apply_subscription_identity(&mut self) {
        self.subscription_id = self.azure_clients.current_subscription().map(str::to_string);
        self.subscription_name = self.azure_clients.current_subscription_name().map(str::to_string);
        self.tenant_id = self.azure_clients.current_tenant().map(str::to_string);
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
            let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
                // A lazy fetch that failed for want of a token raises the
                // app-wide line; one that succeeded proves the token works.
                match &result {
                    Err(e) => {
                        if let Some(a) = AuthError::classify(e) {
                            app.auth_error = Some(a);
                        }
                    }
                    Ok(_) => app.auth_error = None,
                }
                lens(&mut app.lazy).apply(key, result)
            });
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    /// Fetch the current subscription's locations list (once per
    /// subscription; the map is keyed by subscription id). Fired at
    /// startup, after a switch and on `R`, so the picker has display names
    /// and the full region list whether or not the current list covers it.
    pub fn trigger_locations(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let sub = app.subscription_key();
        app.trigger_locations_for(&sub, event_tx);
    }

    fn trigger_locations_for(&mut self, subscription: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        if subscription.is_empty() {
            return;
        }
        let fut = self.azure_clients.locations_fetch(subscription);
        self.trigger_lazy(|s| &mut s.locations, subscription.to_string(), event_tx, move || fut);
    }

    /// On-enter hook for a subscription row's Locations section: the
    /// selected row's own subscription, which may not be the current one.
    pub fn trigger_selected_subscription_locations(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(sub) = app.selected_subscription_row_id() else {
            return;
        };
        app.trigger_locations_for(&sub, event_tx);
    }

    /// On-enter hook for a subscription row's Details section:
    /// `GET /subscriptions/{id}`, keyed by the row's ARM id.
    pub fn trigger_subscription_details(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(sub) = app.selected_subscription_row_id() else {
            return;
        };
        let key = format!("/subscriptions/{}", sub);
        let fut = app.azure_clients.subscription_details_fetch(&sub);
        app.trigger_lazy(|s| &mut s.subscription_details, key, event_tx, move || fut);
    }

    /// The bare subscription id of the selected row, when it is a
    /// subscription row.
    fn selected_subscription_row_id(&self) -> Option<String> {
        self.get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<SubscriptionRow>())
            .map(|r| r.subscription_id().to_string())
    }

    /// Where the locations endpoint list stands for the current
    /// subscription, for the `R` picker's footer.
    fn locations_endpoint_state(&self) -> EndpointState {
        match self.subscription_locations() {
            Some(crate::lazy::Lazy::Loaded(_)) => EndpointState::Loaded,
            Some(crate::lazy::Lazy::Error(e)) => EndpointState::Failed(e.clone()),
            _ => EndpointState::Loading,
        }
    }

    /// A lazy fetch keyed by the selected row's ARM id — the shape of
    /// every per-resource section in the catalog (ticket 06).
    fn trigger_selected<T, Fut>(
        &mut self,
        lens: fn(&mut LazyStore) -> &mut LazyMap<T>,
        event_tx: &mpsc::UnboundedSender<Event>,
        fetch: impl FnOnce(&AzureClients, &str) -> Fut,
    ) where
        T: Send + 'static,
        Fut: Future<Output = std::result::Result<T, String>> + Send + 'static,
    {
        let Some(id) = self.get_selected_resource_id() else {
            return;
        };
        let fut = fetch(&self.azure_clients, &id);
        self.trigger_lazy(lens, id, event_tx, move || fut);
    }

    /// On-enter hook for a VM's Instance view: `GET {vm}/instanceView`.
    pub fn trigger_vm_instance_view(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.vm_instance_views,
            event_tx,
            |c, id| c.get_fetch(&instance_view_path(id), VM_API_VERSION),
        );
    }

    /// On-enter hook for a storage account's Containers: one ARM list per
    /// account, on demand (the Storage RP's throttled budget).
    pub fn trigger_containers(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.containers,
            event_tx,
            |c, id| c.list_fetch(&containers_path(id), STORAGE_API_VERSION),
        );
    }

    /// On-enter hook for a vault's Secrets: names and attributes only.
    pub fn trigger_vault_secrets(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.vault_secrets,
            event_tx,
            |c, id| c.list_fetch(&names_path(id, "secrets"), VAULT_NAMES_API_VERSION),
        );
    }

    /// On-enter hook for a vault's Keys: names and attributes only.
    pub fn trigger_vault_keys(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.vault_keys,
            event_tx,
            |c, id| c.list_fetch(&names_path(id, "keys"), VAULT_NAMES_API_VERSION),
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
        if let Some(lines) = self.section_lines_for(resource, self.detail_section_idx) {
            return lines;
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
        use crate::clipboard::Sink;
        match self.clipboard.copy(text) {
            Ok(Sink::System) => self.toast(format!("Copied {}", what)),
            Ok(Sink::Terminal) => self.toast(format!("Copied {} via the terminal (OSC 52)", what)),
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

    /// Section `idx` of a resource with a section descriptor: the one
    /// downcast per split-pane type. `None` for types without a descriptor.
    fn section_lines_for(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let any = resource.as_any();
        if let Some(sub) = any.downcast_ref::<SubscriptionRow>() {
            return Some(subscription_section_lines(
                sub,
                SubscriptionDetailSection::from_index(idx),
                self.lazy.subscription_details.get(sub.id()),
                self.lazy.locations.get(sub.subscription_id()),
            ));
        }
        if let Some(rg) = any.downcast_ref::<ResourceGroupRow>() {
            return Some(resource_group_section_lines(
                rg,
                ResourceGroupDetailSection::from_index(idx),
            ));
        }
        if let Some(r) = any.downcast_ref::<VmRow>() {
            return Some(vm_section_lines(
                r,
                VmDetailSection::from_index(idx),
                self.lazy.vm_instance_views.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<DiskRow>() {
            return Some(disk_section_lines(r, DiskDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<NicRow>() {
            return Some(nic_section_lines(r, NicDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<StorageAccountRow>() {
            return Some(storage_account_section_lines(
                r,
                StorageAccountDetailSection::from_index(idx),
                self.lazy.containers.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<VnetRow>() {
            return Some(vnet_section_lines(r, VnetDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<SubnetRow>() {
            return Some(subnet_section_lines(r, SubnetDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<NsgRow>() {
            return Some(nsg_section_lines(r, NsgDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<VaultRow>() {
            return Some(vault_section_lines(
                r,
                VaultDetailSection::from_index(idx),
                self.lazy.vault_secrets.get(r.id()),
                self.lazy.vault_keys.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<ClusterRow>() {
            return Some(cluster_section_lines(r, ClusterDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<NodePoolRow>() {
            return Some(node_pool_section_lines(r, NodePoolDetailSection::from_index(idx)));
        }
        None
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
        desc.sections
            .iter()
            .enumerate()
            .map(|(i, s)| {
                (
                    s.label.to_string(),
                    self.section_lines_for(resource, i).unwrap_or_default(),
                )
            })
            .collect()
    }

    // ── Navigation history / bookmarks ──────────────────────────────────

    fn current_nav_location(&self) -> Option<NavLocation> {
        let service = self.current_service?;
        let selected = self.get_selected_resource();
        let place = if service.views().len() > 1 {
            format!("{} {}", service.short_name(), self.current_view.label())
        } else {
            service.short_name().to_string()
        };
        let label = match selected {
            Some(r) => format!("{} · {}", place, r.name()),
            None => place,
        };
        let detail_section = self
            .selected_descriptor()
            .and_then(|d| d.sections.get(self.detail_section_idx))
            .map(|s| s.label.to_string());
        Some(NavLocation {
            service,
            view: Some(self.current_view),
            subscription: self.subscription_id.clone(),
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
        // Another subscription: switch first, or refuse if it is unknown.
        if let Some(sub) = loc.subscription.as_deref() {
            if self.subscription_id.as_deref() != Some(sub) {
                match self.azure_clients.resolve_subscription(sub) {
                    Some(entry) => {
                        let name = entry.name.clone();
                        if let Err(e) = self.switch_subscription(sub, event_tx) {
                            self.error_message = Some(format!("Subscription switch failed: {}", e));
                            return;
                        }
                        self.toast(format!("Switched to subscription {}", name));
                    }
                    None => {
                        self.error_message = Some(format!(
                            "Subscription {} is not in the picker's list (az login to it first)",
                            sub
                        ));
                        return;
                    }
                }
            }
        }
        self.switch_service(loc.service);
        let view = loc
            .view
            .filter(|v| v.service() == loc.service)
            .unwrap_or(loc.service.default_view());
        self.switch_view(view);
        self.search_query = loc.query;
        self.update_search();
        self.pending_jump = None;
        if let Some(id) = &loc.selected_id {
            if !self.restore_selection_by_id(id) {
                // Not visible yet (still loading, or filtered out): land it
                // when it appears. The section name is not carried over.
                self.pending_jump = Some((id.clone(), loc.details_focused));
                self.resolve_pending_jump(event_tx);
                return;
            }
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
        !self.loading
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
            MacroStep::SelectId { id, .. } => {
                self.restore_selection_by_id(&id);
            }
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
            MacroStep::SwitchLocation(l) => self.switch_location(Location::parse(&l)),
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
                self.handle_stream_event(*event, event_tx);
            }
            // Untagged stream events (a provider sending directly) are
            // treated as current.
            e @ (Event::ResourcesLoaded { .. }
            | Event::ResourcesPartiallyLoaded { .. }
            | Event::ResourcesFullyLoaded { .. }
            | Event::ResourceLoadError { .. }
            | Event::ResourceLoadWarning { .. }) => self.handle_stream_event(e, event_tx),

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

            Event::AuthRetryRequested => self.retry_auth(event_tx).await,
            Event::LocationSwitchRequested { location } => self.switch_location(location),
            Event::SubscriptionSwitchRequested { subscription_id } => {
                if let Err(e) = self.switch_subscription(&subscription_id, event_tx) {
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
                    // The locations list may have landed while `R` is open.
                    if self.location_selector.visible {
                        let rows = self.location_rows();
                        let state = self.locations_endpoint_state();
                        self.location_selector.refresh_rows(rows, state);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_stream_event(&mut self, event: Event, event_tx: &mpsc::UnboundedSender<Event>) {
        match event {
            Event::ResourcesLoaded { service, resources } => {
                if Some(service) != self.current_service {
                    return;
                }
                self.auth_error = None;
                self.resources = resources;
                self.finish_load(service, event_tx);
            }
            Event::ResourcesPartiallyLoaded {
                service,
                resources,
                progress,
            } => {
                if Some(service) != self.current_service || !self.loading {
                    return;
                }
                self.auth_error = None;
                self.resources.extend(resources);
                self.loading_progress = Some(progress);
                self.update_search();
                self.resolve_pending_jump(event_tx);
            }
            Event::ResourcesFullyLoaded { service, .. } => {
                if Some(service) == self.current_service {
                    self.finish_load(service, event_tx);
                }
            }
            Event::ResourceLoadError { service, error, auth } => {
                if Some(service) == self.current_service {
                    self.loading = false;
                    self.loading_complete = true;
                    self.loading_progress = None;
                    self.pending_jump = None;
                    match auth {
                        // One app-wide line, never a per-service error.
                        Some(a) => self.auth_error = Some(a),
                        None if self.auth_error.is_none() => self.error_message = Some(error),
                        None => {}
                    }
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

    fn finish_load(&mut self, service: ServiceType, event_tx: &mpsc::UnboundedSender<Event>) {
        self.loading = false;
        self.loading_complete = true;
        self.loading_progress = None;
        let sub = self.subscription_key();
        self.cache
            .insert(service, &sub, Some(self.cache_variant().to_string()), self.resources.clone());
        if !self.load_warnings.is_empty() {
            self.error_message = Some(format!(
                "{} phase(s) failed: {}",
                self.load_warnings.len(),
                self.load_warnings.join(" · ")
            ));
        }
        self.update_search();
        self.resolve_pending_jump(event_tx);
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
                KeyCode::Enter => self.follow_detail_line(event_tx),
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
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.redraw_requested = true
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
            KeyCode::Tab => self.cycle_view(true),
            KeyCode::BackTab => self.cycle_view(false),
            KeyCode::Char(c) if crate::sections::index_for_key(c).is_some() => {
                self.switch_view_index(crate::sections::index_for_key(c).unwrap())
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
                    self.cache.invalidate(&service, &sub, Some(self.cache_variant()));
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
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.redraw_requested = true
            }
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('?') => {
                self.help_visible = true;
                self.help_scroll = 0;
            }
            KeyCode::Char('S') => self.service_selector.show(self.current_service),
            KeyCode::Char('R') if self.auth_error.is_some() => {
                let _ = _event_tx.send(Event::AuthRetryRequested);
            }
            KeyCode::Char('R') => {
                App::trigger_locations(self, _event_tx);
                let rows = self.location_rows();
                let state = self.locations_endpoint_state();
                self.location_selector.show(&self.current_location, rows, state);
            }
            KeyCode::Char('P') => self.open_subscription_picker(),
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
                // Copied verbatim: `--ids` carries the subscription, and the
                // commands without `--ids` carry `--subscription` themselves.
                let cmd = self.get_selected_resource().and_then(|r| r.cli_command());
                match cmd {
                    Some(cmd) => self.copy_to_clipboard(&cmd, "az command"),
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
        if self.auth_error.is_some() && matches!(key.code, KeyCode::Char('R')) {
            let _ = event_tx.send(Event::AuthRetryRequested);
            return;
        }
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
