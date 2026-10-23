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
use crate::azure::resource::{name_of_id, subscription_id_of, subscription_of};
use crate::azure::services::related_lines;
use crate::azure::services::aks::{
    cluster_section_lines, node_pool_section_lines, ClusterDetailSection, ClusterRow, NodePoolDetailSection,
    NodePoolRow,
};
use crate::azure::services::compute::{
    disk_section_lines, instance_view_path, nic_section_lines, vm_section_lines, DiskDetailSection, DiskRow,
    NicDetailSection, NicRow, VmDetailSection, VmRow, VM_API_VERSION,
};
use crate::azure::services::foundry::{
    child_path, foundry_section_lines, FoundryDetailSection, FoundryRow, FOUNDRY_API_VERSION,
};
use crate::azure::services::network_edge::{
    load_balancer_section_lines, nat_gateway_section_lines, public_ip_section_lines, route_table_section_lines,
    LoadBalancerDetailSection, LoadBalancerRow, NatGatewayDetailSection, NatGatewayRow, PublicIpDetailSection,
    PublicIpRow, RouteTableDetailSection, RouteTableRow,
};
use crate::azure::services::all_resources::{
    generic_resource_section_lines, GenericResourceDetailSection, GenericResourceRow,
};
use crate::azure::services::activity::{
    activity_path, activity_query, activity_rows, ACTIVITY_API_VERSION, ACTIVITY_LABEL, ACTIVITY_MAX_EVENTS,
};
use crate::azure::services::access::{
    access_rows, at_scope_filter, principal_filter, principal_ids, role_assignments_path, role_definitions_path,
    role_definitions_scope, ACCESS_API_VERSION, ACCESS_LABEL,
};
use crate::azure::services::directory::{
    app_registration_section_lines, child_key, followup_object_ids, service_principal_section_lines,
    AppRegistrationDetailSection, AppRegistrationRow, DirectoryLazy, ServicePrincipalDetailSection, ServicePrincipalRow,
};
use crate::azure::services::identity::{
    federated_credentials_path, identity_section_lines, IdentityDetailSection, IdentityRow, IDENTITY_API_VERSION,
};
use crate::azure::services::network_dns::{
    dns_child_path, dns_policy_section_lines, dns_resolver_section_lines, dns_ruleset_section_lines,
    dns_zone_section_lines, fetch_dns_topology, subnet_dns_related, vnet_dns_related, DnsPolicyDetailSection,
    DnsPolicyRow, DnsResolverDetailSection, DnsResolverRow, DnsRulesetDetailSection, DnsRulesetRow,
    DnsTopology, DnsZoneDetailSection, DnsZoneRow, DNS_API_VERSION, DNS_RECORDS_MAX, DNS_RESOLVER_API_VERSION,
};
use crate::azure::services::network_private::{
    private_dns_zone_section_lines, private_endpoint_section_lines, zone_child_path, PrivateDnsZoneDetailSection,
    PrivateDnsZoneRow, PrivateEndpointDetailSection, PrivateEndpointRow, PRIVATE_DNS_API_VERSION,
};
use crate::azure::services::app_service::{
    plan_section_lines, site_config_path, site_section_lines, PlanDetailSection, PlanRow, SiteDetailSection, SiteRow,
    WEB_API_VERSION,
};
use crate::azure::services::container_apps::{
    container_app_child_path, container_app_section_lines, environment_section_lines, job_section_lines,
    ContainerAppDetailSection, ContainerAppRow, EnvironmentDetailSection, EnvironmentRow, JobDetailSection, JobRow,
    ACA_API_VERSION,
};
use crate::azure::services::container_registry::{
    registry_child_path, registry_section_lines, RegistryDetailSection, RegistryRow, ACR_API_VERSION,
};
use crate::azure::services::cosmos::{
    cosmos_section_lines, databases_path, CosmosAccountRow, CosmosDetailSection, COSMOS_API_VERSION,
};
use crate::azure::services::monitor::{
    component_section_lines, workspace_section_lines, ComponentDetailSection, ComponentRow, WorkspaceDetailSection,
    WorkspaceRow,
};
use crate::azure::services::power_platform::{
    enterprise_policy_section_lines, subnet_policy_lines, EnterprisePolicyDetailSection, EnterprisePolicyRow,
};
use crate::azure::services::sql::{
    server_child_path, sql_server_section_lines, SqlServerDetailSection, SqlServerRow, SQL_API_VERSION,
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
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// The network access lens (`N`): open, fetch, keys.
mod all_search;
/// The metrics view (`m`): open, fetch, keys.
mod metrics;
mod command_picker;
mod network_lens;
/// The "referenced by" lens (`U`): the reverse index, keys, `L`.
mod refs_lens;
/// The ownership ribbon (#48): what it says, the deployments trigger.
mod ownership;
/// `X` / `Ctrl-X`: the export wait and the writes.
mod export;
/// The mouse: click targets, double-click, drag, right-click back.
mod mouse;
pub use mouse::{record_hint_regions, ClickAction, ClickRegion, MouseState, PopupHits};
pub use all_search::all_search_label;
/// The list pane's visual selection (`V`, `Ctrl-A`, drag) and its verbs.
mod list_visual;

/// The terminal-less `App` behind `nebaz ls` / `nebaz get` (#44).
mod headless;
pub(crate) use headless::ListShaping;

// ── Supporting types (ported by hand from neboto's app.rs) ──────────────

/// Whether a screen cell (`col`, `row`) falls inside `area`.
fn point_in(area: Rect, col: u16, row: u16) -> bool {
    col >= area.x
        && col < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
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

/// `{service} {id tail}` for the detail footer's back hint: an ARM id keeps
/// only its last `/` segment (the resource's name), capped so a long name
/// cannot crowd out the rest of the footer.
fn nav_hint_label(service: ServiceType, id: Option<&str>) -> String {
    const MAX: usize = 28;
    let Some(id) = id.filter(|id| !id.is_empty()) else {
        return service.short_name().to_string();
    };
    let tail = id.rsplit('/').find(|seg| !seg.is_empty()).unwrap_or(id);
    let tail = if tail.chars().count() > MAX {
        format!("{}…", tail.chars().take(MAX - 1).collect::<String>())
    } else {
        tail.to_string()
    };
    format!("{} {tail}", service.short_name())
}

/// Cap on the `/` search history (oldest entries drop off the front).
const SEARCH_HISTORY_MAX: usize = 50;

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

/// The current list load: the generation its stream events carry and the
/// tasks running it (the provider fetch and its tagging forwarder).
/// `supersede` is the one way to retire a load: the generation bump stops
/// its queued events from landing, the abort stops it paging ARM for a
/// list nobody will see (#57).
#[derive(Debug, Default)]
pub struct ListLoad {
    generation: u64,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl ListLoad {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Bump the generation and abort every tracked task. Returns the new
    /// generation, which the next load tags its events with.
    pub fn supersede(&mut self) -> u64 {
        self.generation += 1;
        for task in self.tasks.drain(..) {
            task.abort();
        }
        self.generation
    }

    /// Track a task of the current load so the next `supersede` aborts it.
    pub fn track(&mut self, task: tokio::task::AbortHandle) {
        self.tasks.push(task);
    }
}

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
    /// The in-flight list load. Superseded (generation bumped, tasks
    /// aborted) on every list load and every context switch; stream events
    /// carrying an older generation are dropped.
    list_load: ListLoad,

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
    /// This session's submitted `/` queries, oldest first, de-duplicated
    /// (a re-run moves to the end), capped at `SEARCH_HISTORY_MAX`. `↑`/`↓`
    /// in the search bar walk it. In memory only: queries can hold
    /// resource names and tag values.
    pub search_history: Vec<String>,
    /// Where `↑`/`↓` is in `search_history`; `None` while typing.
    pub search_history_cursor: Option<usize>,
    /// What was being typed when `↑` started a walk, restored by `↓` past
    /// the newest entry.
    pub search_history_draft: String,
    fuzzy: FuzzyMatcher,
    /// `@*` cross-cache search (#38, `app/all_search.rs`): while true,
    /// `resources` is every warm list of the subscription, flattened.
    pub all_search_mode: bool,
    /// The sub-tab each `resources` row came from, in `@*` mode.
    pub all_search_sources: Vec<JumpView>,
    pub all_search_coverage: all_search::AllSearchCoverage,
    pub list_sort: ListSort,
    pub list_state_filter: Option<String>,
    pub hide_noise: bool,
    pub hidden_noise_count: usize,
    pub noise_in_view: bool,
    /// Rows dropped by the location filter on the last `update_search`.
    pub location_hidden_count: usize,

    // Detail pane.
    pub details_focused: bool,
    /// The single cursor into the selected resource's section descriptor.
    pub detail_section_idx: usize,
    /// The cursor line in the detail body (the pane scrolls to keep it in
    /// view). `⏎` follows it, `y` copies it.
    pub details_scroll: usize,
    /// Anchor of a linewise visual selection in the detail body (vim `V`).
    /// While `Some`, the selection spans `min(anchor, cursor)..=max`;
    /// `y` copies the range. Positional, so any cursor reset clears it.
    pub detail_visual_anchor: Option<usize>,
    /// Flat detail view (`\`, config `detail_flat`): every section of the
    /// selected resource in one scroll, with `━━ Name ━━` headers; digits
    /// and Tab jump between headers instead of switching sections.
    pub detail_flat_mode: bool,
    /// The ARM id whose sections were all triggered for the flat view, so
    /// the sweep runs once per focused resource (the triggers are
    /// idempotent anyway).
    flat_triggered_for: Option<String>,
    /// `/` in the focused detail pane: typing the body filter. Keys go to
    /// the query until `⏎` (keep the filter) or `Esc` (drop it).
    pub detail_search_active: bool,
    /// The body filter (`filter_detail_rows`), applied while the pane is
    /// focused and cleared when it loses focus. Recomputed on every read,
    /// so a lazy section that lands later is filtered too.
    pub detail_search_query: String,
    /// Detail-body wrap (`Ctrl-W`, config `detail_wrap`): long values
    /// continue on hanging-indent rows instead of clipping at the pane
    /// edge. Render-only: the cursor, `y` and `V` stay on logical rows.
    pub detail_wrap: bool,
    /// The ownership ribbon on the detail pane (config `ownership_ribbon`).
    pub ownership_ribbon: bool,
    /// The tag keys it reads (config `ownership_tags`).
    pub ownership_tags: Vec<String>,
    /// The selected row's `managedBy`, parsed once per row.
    managed_by_memo: RefCell<Option<(String, Option<String>)>>,
    /// First half of a `[[` / `]]` group-jump chord in the detail pane.
    pending_bracket: Option<char>,
    /// `H` / `L` from the detail pane: focus the new sub-tab's first row
    /// once its list has one (the load may still be in flight).
    pending_detail_focus: bool,
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
    /// Set while `restore_nav_location` runs: the service, sub-tab and
    /// subscription switches it makes are the restore, not places left, so
    /// they record nothing.
    nav_restoring: bool,
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
    /// Anchor of the list pane's linewise visual selection (`V`): the range
    /// is `min(anchor, cursor)..=max` over `filtered_resources`. Positional,
    /// so `update_search` and a drill-in clear it (`app/list_visual.rs`).
    pub list_visual_anchor: Option<usize>,
    /// The export `X` armed, finished by `export_tick` (see `app/export.rs`).
    pub pending_export: Option<export::PendingExport>,
    /// Which formats and where exports write (config `export_formats` /
    /// `export_dir`).
    pub export_options: crate::export::ExportOptions,
    /// The files the last export wrote (the harness reads them back).
    pub last_export_paths: Vec<std::path::PathBuf>,

    // `$EDITOR`.
    pub editor_requested: bool,

    /// Network access lens (`N`, #50): owns the detail pane while open.
    pub network_lens: Option<crate::ui::widgets::network_lens::NetworkLensState>,
    /// The `C` command picker (#47): `Some` while open.
    pub command_picker: Option<crate::ui::widgets::command_picker::CommandPickerState>,
    /// Bumped per lens fetch; a result for an older one is dropped.
    network_lens_generation: u64,
    /// "Referenced by" lens (`U`, #49): owns the detail pane while open.
    pub refs_lens: Option<crate::ui::widgets::refs_lens::RefsLensState>,
    /// The reverse index behind `U`, reused while the caches hold.
    refs_index: Option<refs_lens::RefsIndex>,
    /// Azure Monitor metrics view (`m`, #51): owns the detail pane while open.
    pub metrics: Option<crate::ui::widgets::metrics_overlay::MetricsState>,
    /// Bumped per metrics fetch; a result for an older one is dropped.
    metrics_generation: u64,
    /// The last window the view used: sticky across opens.
    metrics_window: crate::azure::metrics::MetricWindow,

    // Mouse hit-testing, recorded by the read-only widgets each frame.
    click_regions: RefCell<Vec<ClickRegion>>,
    list_area: Cell<Rect>,
    /// The rest of the mouse's hit targets and gesture state (`app/mouse.rs`).
    pub mouse: MouseState,
}

impl App {
    pub async fn new(cli: crate::cli::Cli) -> Result<Self> {
        let mut config = Config::load();
        cli.apply_to(&mut config);
        let azure_clients = AzureClients::new(&config).await?;
        Ok(Self::from_parts(config, azure_clients, cli.macro_name.clone()))
    }

    /// The rest of `new` once the config and the clients exist; the wiring
    /// harness's `new_for_test` (default config, offline clients) shares it.
    fn from_parts(config: Config, azure_clients: AzureClients, startup_macro: Option<String>) -> Self {
        // Theme first: everything drawn after this reads the palette.
        let (palette, theme_warnings) = crate::ui::theme::Palette::from_config(
            config.theme.as_deref(),
            config.theme_colors.as_ref(),
        );
        crate::ui::theme::init_palette(palette);
        let (export_formats, export_warnings) =
            crate::export::ExportFormats::from_config(config.export_formats.as_deref());
        let export_options = crate::export::ExportOptions {
            formats: export_formats,
            dir: config.export_dir.as_deref().map(crate::export::expand_home),
        };

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
            list_load: ListLoad::default(),
            loading: false,
            loading_started: false,
            loading_complete: false,
            loading_progress: None,
            load_warnings: Vec::new(),
            tick_count: 0,
            search_active: false,
            search_query: String::new(),
            pending_search: false,
            search_history: Vec::new(),
            search_history_cursor: None,
            search_history_draft: String::new(),
            fuzzy: FuzzyMatcher::new(),
            all_search_mode: false,
            all_search_sources: Vec::new(),
            all_search_coverage: Default::default(),
            list_sort: ListSort::Default,
            list_state_filter: None,
            hide_noise: true,
            hidden_noise_count: 0,
            noise_in_view: false,
            location_hidden_count: 0,
            details_focused: false,
            detail_visual_anchor: None,
            detail_flat_mode: config.detail_flat.unwrap_or(false),
            flat_triggered_for: None,
            detail_search_active: false,
            detail_search_query: String::new(),
            detail_wrap: config.detail_wrap.unwrap_or(false),
            ownership_ribbon: config.ownership_ribbon.unwrap_or(true),
            ownership_tags: config.ownership_tags.clone().unwrap_or_else(|| {
                crate::azure::ownership::DEFAULT_OWNERSHIP_TAGS.iter().map(|s| s.to_string()).collect()
            }),
            managed_by_memo: RefCell::new(None),
            pending_bracket: None,
            pending_detail_focus: false,
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
            nav_restoring: false,
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
            startup_macro,
            watch: WatchState::new(config.watch.unwrap_or(false), config.watch_interval),
            watch_staging: None,
            deep_export_progress: None,
            list_visual_anchor: None,
            pending_export: None,
            export_options,
            last_export_paths: Vec::new(),
            editor_requested: false,
            network_lens: None,
            network_lens_generation: 0,
            refs_lens: None,
            refs_index: None,
            metrics: None,
            metrics_generation: 0,
            metrics_window: Default::default(),
            command_picker: None,
            click_regions: RefCell::new(Vec::new()),
            list_area: Cell::new(Rect::default()),
            mouse: MouseState::default(),
            config,
        };
        if let Some(w) = app.config.load_warning.take() {
            app.error_message = Some(w);
        }
        if !theme_warnings.is_empty() {
            app.error_message = Some(format!("theme: {}", theme_warnings.join("; ")));
        }
        if !export_warnings.is_empty() {
            app.error_message = Some(export_warnings.join("; "));
        }
        if let Some(s) = current_service {
            app.visited_services.insert(s);
        }
        // Config `pinned_services`: their chips show before they load.
        let (pinned, pinned_warning) = app.config.pinned_service_types();
        app.visited_services.extend(pinned);
        if let Some(w) = pinned_warning {
            app.error_message = Some(match app.error_message.take() {
                Some(prev) => format!("{prev}; {w}"),
                None => w,
            });
        }
        // No subscription resolved: open the picker with the auth line.
        if app.subscription_id.is_none() {
            app.open_subscription_picker();
        }
        app
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
        // Before the cache check: a cache hit must retire the old stream
        // too, or its late `ResourcesLoaded` lands on the cached view.
        self.supersede_loads();
        // `@*` owns `resources`: re-search the (new subscription's) caches.
        if self.all_search_mode {
            self.update_search();
            return;
        }
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
        let generation = self.supersede_loads();
        let view = self.current_view;
        let provider = self.azure_clients.service(service);
        let outer = event_tx.clone();

        // Forwarder: tag each stream event with this load's generation.
        let (inner_tx, mut inner_rx) = mpsc::unbounded_channel::<Event>();
        let fwd = outer.clone();
        let forwarder = tokio::spawn(async move {
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
        let fetch = tokio::spawn(async move {
            let _ = provider.list_resources_streaming(view, inner_tx, service).await;
        });
        self.list_load.track(fetch.abort_handle());
        self.list_load.track(forwarder.abort_handle());
    }

    /// Retire every in-flight list load (see [`ListLoad`]). Every
    /// generation bump goes through here. Only superseded tasks are
    /// aborted: the caller either serves the cache or starts the next load,
    /// so `loading` is never left waiting on an aborted stream.
    fn supersede_loads(&mut self) -> u64 {
        self.list_load.supersede()
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
        self.flat_triggered_for = None;
        self.supersede_loads();
        self.network_lens = None;
        self.refs_lens = None;
        self.metrics = None;
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
        let Some(service) = self.current_service.filter(|_| !self.all_search_mode) else {
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
            if let Some(l) = r.filter_location() {
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
            .position(|&i| self.resources[i].matches_id(id))
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
        self.resources.iter().any(|r| r.matches_id(id))
    }

    // ── Jumps ───────────────────────────────────────────────────────────

    /// The one jump mechanism (ticket 06): an ARM id becomes a
    /// `NavLocation` routed on its type, and the row resolves once its
    /// list has it. An id nebaz does not browse is copied instead.
    pub fn jump_to_arm_id(&mut self, id: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(view) = JumpView::landing_for_arm_id(id) else {
            if id.starts_with("/subscriptions/") {
                self.copy_to_clipboard(id, "id (not a type nebaz browses)");
            }
            return;
        };
        self.push_nav_location();
        // The filter belonged to the pane being left.
        self.clear_detail_filter();
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
        if view == JumpView::AllResources {
            self.toast("Not browsed yet: showing it in All resources");
        }
    }

    /// Whether the selected All resources row is a type nebaz lists in a
    /// typed tab (Enter on the list then opens it there).
    fn selected_routes_to_typed_tab(&self) -> bool {
        self.get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<GenericResourceRow>())
            .is_some_and(|r| r.view.is_some())
    }

    /// Enter on a detail line: jump when its value is an ARM id.
    fn follow_detail_line(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let lines = self.detail_body();
        let Some((_, value)) = lines.get(self.details_scroll) else {
            return;
        };
        let value = value.trim().to_string();
        if is_arm_id(&value) {
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
        if self.selected_index.is_some() && self.get_selected_resource().is_some_and(|r| r.matches_id(&id)) {
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
        self.detail_visual_anchor = None;
    }

    // ── Search ──────────────────────────────────────────────────────────

    /// Rebuild `filtered_resources` from the query, the location filter,
    /// the state filter, the noise toggle and the sort.
    pub fn update_search(&mut self) {
        // The list selection is positional: a rebuild cancels it.
        self.list_visual_anchor = None;
        let keep_id = self.get_selected_resource_id();
        let search_text = match self.sync_all_search() {
            all_search::AllSearchStep::Left => return,
            all_search::AllSearchStep::On(text) => text,
            all_search::AllSearchStep::Off => parse_query(&self.search_query).search_text,
        };
        let (tag_filters, text) = split_tag_filters(&search_text);
        let (rg_filters, text) = split_rg_filters(&text);

        // Location filter first — it decides the "of N" denominator.
        let admitted: Vec<usize> = (0..self.resources.len())
            .filter(|&i| self.current_location.admits(self.resources[i].filter_location()))
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

    /// Push the submitted query onto `search_history` (a blank one is not
    /// worth recalling; a repeat moves to the end) and end any walk.
    fn record_search_history(&mut self) {
        self.search_history_cursor = None;
        let query = self.search_query.trim();
        if query.is_empty() {
            return;
        }
        let query = query.to_string();
        self.search_history.retain(|q| *q != query);
        self.search_history.push(query);
        if self.search_history.len() > SEARCH_HISTORY_MAX {
            self.search_history.remove(0);
        }
    }

    /// One `↑` (older) / `↓` (newer) step through `search_history`: the text
    /// the bar should now hold, or `None` when there is nowhere to go. `↓`
    /// past the newest entry gives back the draft `↑` left.
    fn step_search_history(&mut self, older: bool) -> Option<String> {
        let len = self.search_history.len();
        let next = match (self.search_history_cursor, older) {
            (None, true) if len > 0 => {
                self.search_history_draft = self.search_query.clone();
                len - 1
            }
            (Some(i), true) if i > 0 => i - 1,
            (Some(i), false) if i + 1 < len => i + 1,
            (Some(_), false) => {
                self.search_history_cursor = None;
                return Some(std::mem::take(&mut self.search_history_draft));
            }
            _ => return None,
        };
        self.search_history_cursor = Some(next);
        Some(self.search_history[next].clone())
    }

    /// Apply a search query: a `@service` prefix switches service first.
    fn apply_query(&mut self, query: String) {
        self.search_query = query;
        if crate::search::query_parser::parse_all_query(&self.search_query).is_some() {
            self.pending_search = true;
            return;
        }
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
        if self.all_search_mode {
            self.leave_all_search();
        }
        self.leave_detail_pane();
        self.pending_detail_focus = false;
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
        self.flat_triggered_for = None;
        self.supersede_loads();
        self.network_lens = None;
        self.refs_lens = None;
        self.metrics = None;
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
        self.trigger_lazy_with(lens, key, event_tx, fut, true);
    }

    /// [`trigger_lazy`](Self::trigger_lazy), choosing whether the outcome
    /// may raise or clear the app-wide auth line. A Microsoft Graph read
    /// may not (ADR 0004): its token is a second scope, and a denied or
    /// consent-gated directory read is that section's warning, never
    /// "not logged in" for the whole app.
    fn trigger_lazy_with<T, F, Fut>(
        &mut self,
        lens: fn(&mut LazyStore) -> &mut LazyMap<T>,
        key: String,
        event_tx: &mpsc::UnboundedSender<Event>,
        fut: F,
        affects_auth: bool,
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
                    _ if !affects_auth => {}
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

    /// On-enter hook for a SQL server's Databases: one list per server.
    pub fn trigger_sql_databases(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.sql_databases,
            event_tx,
            |c, id| c.list_fetch(&server_child_path(id, "databases"), SQL_API_VERSION),
        );
    }

    /// On-enter hook for a SQL server's Firewall: one list per server.
    pub fn trigger_sql_firewall(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.sql_firewall_rules,
            event_tx,
            |c, id| c.list_fetch(&server_child_path(id, "firewallRules"), SQL_API_VERSION),
        );
    }

    /// On-enter hook for an app's Configuration: `GET {site}/config/web`.
    pub fn trigger_site_config(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.site_configs,
            event_tx,
            |c, id| c.get_fetch(&site_config_path(id), WEB_API_VERSION),
        );
    }

    /// On-enter hook for a private DNS zone's Records: every record set,
    /// one list per zone.
    pub fn trigger_dns_records(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.dns_records,
            event_tx,
            |c, id| c.list_fetch(&zone_child_path(id, "ALL"), PRIVATE_DNS_API_VERSION),
        );
    }

    /// On-enter hook for a private DNS zone's VNet links.
    pub fn trigger_dns_vnet_links(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.dns_vnet_links,
            event_tx,
            |c, id| c.list_fetch(&zone_child_path(id, "virtualNetworkLinks"), PRIVATE_DNS_API_VERSION),
        );
    }

    /// On-enter hook for a public DNS zone's Records (and Related, for the
    /// alias targets): every record set, capped like Activity.
    pub fn trigger_public_dns_records(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.public_dns_records,
            event_tx,
            |c, id| c.list_fetch_query_capped(&dns_child_path(id, "all"), DNS_API_VERSION, Vec::new(), DNS_RECORDS_MAX),
        );
    }

    /// On-enter hook for a forwarding ruleset's Rules.
    pub fn trigger_dns_forwarding_rules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.dns_forwarding_rules,
            event_tx,
            |c, id| c.list_fetch(&dns_child_path(id, "forwardingRules"), DNS_RESOLVER_API_VERSION),
        );
    }

    /// On-enter hook for a DNS security policy's Rules.
    pub fn trigger_dns_security_rules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.dns_security_rules,
            event_tx,
            |c, id| c.list_fetch(&dns_child_path(id, "dnsSecurityRules"), DNS_RESOLVER_API_VERSION),
        );
    }

    /// On-enter hook for every DNS link section (a resolver's Endpoints and
    /// Rulesets, VNet links, and the DNS lines of a VNet's or subnet's
    /// Related): the selected row's subscription's DNS topology, once per
    /// subscription per session.
    pub fn trigger_dns_topology(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(key) = app.get_selected_resource_id().and_then(|id| subscription_id_of(&id)) else {
            return;
        };
        let arm = app
            .azure_clients
            .arm_for_subscription(subscription_of(&key).unwrap_or_default())
            .map_err(|e| e.to_string());
        let sub = key.clone();
        app.trigger_lazy(|s| &mut s.dns_topology, key, event_tx, move || async move {
            fetch_dns_topology(arm?, sub).await
        });
    }

    /// The loaded (or loading) DNS topology of an ARM id's subscription.
    fn dns_topology_for(&self, id: &str) -> Option<&crate::lazy::Lazy<DnsTopology>> {
        subscription_id_of(id).and_then(|k| self.lazy.dns_topology.get(&k))
    }

    /// On-enter hook for every type's Access section: the role assignments
    /// that apply at the row's ARM id, and the subscription's role names.
    pub fn trigger_access(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.role_assignments,
            event_tx,
            |c, id| c.list_fetch_query(&role_assignments_path(id), ACCESS_API_VERSION, at_scope_filter()),
        );
        app.trigger_role_definitions(event_tx);
        app.trigger_principal_names(event_tx);
    }

    /// Resolve the selected row's Access principals to names through
    /// Microsoft Graph, one `GET directoryObjects/{id}` each, bounded by
    /// `PRINCIPAL_NAMES_MAX` (ADR 0004). A no-op until the assignments
    /// have loaded; the `Event::Lazy` handler calls it again when they
    /// land, and present keys never refetch.
    fn trigger_principal_names(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(id) = self.get_selected_resource_id() else {
            return;
        };
        let ids = match self.lazy.role_assignments.get(&id) {
            Some(crate::lazy::Lazy::Loaded(items)) => principal_ids(items),
            _ => return,
        };
        for oid in ids {
            if self.lazy.principals.contains(&oid) {
                continue;
            }
            let fut = self.azure_clients.directory_object_fetch(&id, &oid);
            self.trigger_lazy_with(|s| &mut s.principals, oid, event_tx, move || fut, false);
        }
    }

    /// On-enter hook for every type's Activity section: the last week of
    /// the subscription's activity log, filtered to the row.
    pub fn trigger_activity(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        app.trigger_selected(
            |s| &mut s.activity,
            event_tx,
            move |c, id| {
                let path = activity_path(id).unwrap_or_default();
                c.list_fetch_query_capped(&path, ACTIVITY_API_VERSION, activity_query(id, now), ACTIVITY_MAX_EVENTS)
            },
        );
    }

    /// On-enter hook for an identity's Can do: its principal's assignments
    /// across its subscription.
    pub fn trigger_identity_can_do(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some((principal, sub)) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<IdentityRow>())
            .and_then(|r| Some((r.principal_id.clone()?, role_definitions_scope(&r.base.id)?)))
        else {
            return;
        };
        app.trigger_selected(
            |s| &mut s.identity_role_assignments,
            event_tx,
            move |c, _| c.list_fetch_query(&role_assignments_path(&sub), ACCESS_API_VERSION, principal_filter(&principal)),
        );
        app.trigger_role_definitions(event_tx);
    }

    /// The selected row's subscription role definitions, once per
    /// subscription (shared by every Access and Can do section).
    fn trigger_role_definitions(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(key) = self.get_selected_resource_id().and_then(|id| role_definitions_scope(&id)) else {
            return;
        };
        let fut = self.azure_clients.list_fetch(&role_definitions_path(&key), ACCESS_API_VERSION);
        self.trigger_lazy(|s| &mut s.role_definitions, key, event_tx, move || fut);
    }

    // ── Directory rows (Microsoft Graph, ADR 0004) ──────────────────────

    /// One child list of the selected directory row
    /// (`/v1.0/{collection}/{id}/{child}`), keyed by `{row id}/{child}`.
    /// Graph fetches never touch the app-wide auth line.
    fn trigger_directory_child(&mut self, child: &'static str, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(id) = self.get_selected_resource_id().filter(|id| crate::azure::graph::is_row_id(id)) else {
            return;
        };
        let key = child_key(&id, child);
        let fut = self.azure_clients.graph_list_fetch(crate::azure::graph::object_path(&id, Some(child)));
        self.trigger_lazy_with(|s| &mut s.directory_children, key, event_tx, move || fut, false);
    }

    pub fn trigger_directory_owners(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_directory_child("owners", event_tx);
    }

    pub fn trigger_app_federated_credentials(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_directory_child("federatedIdentityCredentials", event_tx);
    }

    pub fn trigger_sp_app_role_assignments(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_directory_child("appRoleAssignments", event_tx);
        app.trigger_directory_followups(event_tx);
    }

    pub fn trigger_sp_oauth2_grants(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_directory_child("oauth2PermissionGrants", event_tx);
        app.trigger_directory_followups(event_tx);
    }

    /// An app registration's API permissions: each API's service principal
    /// by app id, so the permission ids read as names.
    pub fn trigger_app_api_permissions(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(app_ids) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<AppRegistrationRow>())
            .map(|r| r.resource_app_ids())
        else {
            return;
        };
        for app_id in app_ids {
            let fut = app
                .azure_clients
                .graph_get_fetch(crate::azure::graph::service_principal_by_app_id_path(&app_id));
            app.trigger_lazy_with(|s| &mut s.sp_by_app_id, app_id, event_tx, move || fut, false);
        }
    }

    /// A service principal's Azure roles: its assignments across the
    /// current subscription (the Can do lens), and the role names.
    pub fn trigger_sp_azure_roles(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some((id, oid)) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<ServicePrincipalRow>())
            .map(|r| (r.base.id.clone(), r.base.object_id.clone()))
        else {
            return;
        };
        let sub = app.subscription_key();
        if sub.is_empty() {
            return;
        }
        let scope = format!("/subscriptions/{}", sub);
        let fut = app
            .azure_clients
            .list_fetch_query(&role_assignments_path(&scope), ACCESS_API_VERSION, principal_filter(&oid));
        app.trigger_lazy(|s| &mut s.identity_role_assignments, id, event_tx, move || fut);
        let fut = app.azure_clients.list_fetch(&role_definitions_path(&scope), ACCESS_API_VERSION);
        app.trigger_lazy(|s| &mut s.role_definitions, scope, event_tx, move || fut);
    }

    /// Name what a selected service principal's loaded sections point at
    /// (an API's service principal, a consenting user): one Graph GET per
    /// object id into the shared principals map, bounded.
    fn trigger_directory_followups(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(id) = self.get_selected_resource_id().filter(|id| crate::azure::graph::is_row_id(id)) else {
            return;
        };
        for oid in followup_object_ids(&id, &self.lazy.directory_children) {
            if self.lazy.principals.contains(&oid) {
                continue;
            }
            let fut = self
                .azure_clients
                .graph_get_fetch(crate::azure::graph::directory_object_path(&oid));
            self.trigger_lazy_with(|s| &mut s.principals, oid, event_tx, move || fut, false);
        }
    }

    /// On-enter hook for an identity's Federated credentials: one ARM list
    /// per identity, on demand.
    pub fn trigger_federated_credentials(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.federated_credentials,
            event_tx,
            |c, id| c.list_fetch(&federated_credentials_path(id), IDENTITY_API_VERSION),
        );
    }

    /// On-enter hook for an AI account's Deployments: one ARM list per
    /// account, on demand.
    pub fn trigger_foundry_deployments(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.foundry_deployments,
            event_tx,
            |c, id| c.list_fetch(&child_path(id, "deployments"), FOUNDRY_API_VERSION),
        );
    }

    /// On-enter hook for an AI account's Projects: only a Foundry resource
    /// (project management on) has any, so nothing is fetched otherwise.
    pub fn trigger_foundry_projects(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let holds = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<FoundryRow>())
            .is_some_and(FoundryRow::holds_projects);
        if !holds {
            return;
        }
        app.trigger_selected(
            |s| &mut s.foundry_projects,
            event_tx,
            |c, id| c.list_fetch(&child_path(id, "projects"), FOUNDRY_API_VERSION),
        );
    }

    /// On-enter hook for an account's Databases: one list per account, on
    /// the path its API picks.
    pub fn trigger_cosmos_databases(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(api) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<CosmosAccountRow>())
            .map(|r| r.api)
        else {
            return;
        };
        app.trigger_selected(
            |s| &mut s.cosmos_databases,
            event_tx,
            move |c, id| c.list_fetch(&databases_path(id, api), COSMOS_API_VERSION),
        );
    }

    /// On-enter hook for a registry's Replications: one list per
    /// registry, and none for a non-Premium one (it cannot replicate).
    pub fn trigger_acr_replications(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let premium = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<RegistryRow>())
            .is_some_and(RegistryRow::is_premium);
        if !premium {
            return;
        }
        app.trigger_selected(
            |s| &mut s.acr_replications,
            event_tx,
            |c, id| c.list_fetch(&registry_child_path(id, "replications"), ACR_API_VERSION),
        );
    }

    /// On-enter hook for a registry's Webhooks: one list per registry.
    pub fn trigger_acr_webhooks(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.acr_webhooks,
            event_tx,
            |c, id| c.list_fetch(&registry_child_path(id, "webhooks"), ACR_API_VERSION),
        );
    }

    /// On-enter hook for a container app's Revisions: one list per app.
    pub fn trigger_aca_revisions(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.aca_revisions,
            event_tx,
            |c, id| c.list_fetch(&container_app_child_path(id, "revisions"), ACA_API_VERSION),
        );
    }

    /// On-enter hook for a container app's Auth: one list per app.
    pub fn trigger_aca_auth(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.aca_auth_configs,
            event_tx,
            |c, id| c.list_fetch(&container_app_child_path(id, "authConfigs"), ACA_API_VERSION),
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
        self.detail_visual_anchor = None;
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
        if self.flat_active() {
            return assemble_flat_detail(&self.detail_sections_snapshot());
        }
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

    // ── Detail cursor, visual selection, flat view ───────────────────────

    /// The body the pane shows and every key indexes: `get_detail_lines`
    /// narrowed by the `/` filter while the pane is focused. The cursor,
    /// `V`, `y`, `⏎`, `[[`/`]]` and the flat header jumps all read this, so
    /// a filtered view copies and jumps from the line on screen. Rebuilt on
    /// every call, so a lazy section that lands under a filter is filtered.
    pub fn detail_body(&self) -> Vec<(String, String)> {
        let lines = self.get_detail_lines();
        if self.details_focused {
            filter_detail_rows(lines, &self.detail_search_query)
        } else {
            lines
        }
    }

    fn detail_line_count(&self) -> usize {
        self.detail_body().len()
    }

    /// Move the detail cursor by `delta` lines, clamped to the body.
    fn move_detail_cursor(&mut self, delta: isize) {
        let n = self.detail_line_count();
        if n == 0 {
            self.details_scroll = 0;
            return;
        }
        let cur = self.details_scroll.min(n - 1) as isize;
        self.details_scroll = (cur + delta).clamp(0, n as isize - 1) as usize;
    }

    /// The inclusive `(start, end)` line range of the visual selection,
    /// clamped to the body. `None` outside visual mode. Rendering and copy
    /// both read it, so they cannot disagree.
    pub fn detail_visual_range(&self) -> Option<(usize, usize)> {
        let anchor = self.detail_visual_anchor?;
        let n = self.detail_line_count();
        if n == 0 {
            return None;
        }
        let a = anchor.min(n - 1);
        let b = self.details_scroll.min(n - 1);
        Some((a.min(b), a.max(b)))
    }

    /// Whether a body line is highlighted: in the visual range, or the
    /// cursor line outside visual mode.
    pub fn detail_line_in_selection(&self, idx: usize) -> bool {
        match self.detail_visual_range() {
            Some((start, end)) => idx >= start && idx <= end,
            None => self.details_scroll == idx,
        }
    }

    /// Start a selection at the cursor if none, then move one line
    /// (`J` / `K`, Shift-↓ / Shift-↑: extend as you move).
    fn detail_visual_step(&mut self, down: bool) {
        if self.detail_visual_anchor.is_none() {
            self.detail_visual_anchor = Some(self.details_scroll);
        }
        self.move_detail_cursor(if down { 1 } else { -1 });
    }

    /// `y` in the detail pane: the selection as text when one is active,
    /// else the cursor line's value.
    fn copy_detail_selection(&mut self) {
        let lines = self.detail_body();
        match self.detail_visual_range() {
            Some((start, end)) => {
                let text = selection_text(&lines, start, end);
                self.detail_visual_anchor = None;
                if text.trim().is_empty() {
                    self.error_message = Some("Nothing to copy in the selection".into());
                } else {
                    self.copy_to_clipboard(&text, &format!("{} lines", end - start + 1));
                }
            }
            None => {
                if let Some((_, v)) = lines.get(self.details_scroll) {
                    let text = v.clone();
                    if text.is_empty() {
                        self.error_message = Some("Nothing to copy on this line".into());
                    } else {
                        self.copy_to_clipboard(&text, "row");
                    }
                }
            }
        }
    }

    /// True when the body on screen is the flat concatenation: flat mode
    /// on and the resource has more than one section (a single-section
    /// resource's flat view is its section view).
    pub fn flat_active(&self) -> bool {
        self.detail_flat_mode && self.selected_descriptor().is_some_and(|d| d.len() > 1)
    }

    /// `\`: tabbed sections ↔ one scroll. The cursor resets because row
    /// indexes mean different things per mode.
    fn toggle_detail_flat_mode(&mut self) {
        self.detail_flat_mode = !self.detail_flat_mode;
        self.flat_triggered_for = None;
        self.details_scroll = 0;
        self.detail_visual_anchor = None;
        self.toast(if self.detail_flat_mode {
            "Detail view: all sections in one scroll (\\ for tabs)"
        } else {
            "Detail view: tabbed sections (\\ for one scroll)"
        });
    }

    /// `(body row, section name)` of each flat section header still in the
    /// body, in order. Under a `/` filter a section with no match has no
    /// header, so callers match on the name, never the position.
    fn flat_headers(&self) -> Vec<(usize, String)> {
        self.detail_body()
            .iter()
            .enumerate()
            .filter(|(_, (_, v))| v.is_empty())
            .filter_map(|(i, (k, _))| flat_header_name(k).map(|n| (i, n.to_string())))
            .collect()
    }

    fn flat_header_rows(&self) -> Vec<usize> {
        self.flat_headers().into_iter().map(|(i, _)| i).collect()
    }

    /// `1`–`9` in the flat view: cursor to that section's header (by label,
    /// so a filter that dropped earlier sections still lands right).
    fn flat_jump_to_section(&mut self, idx: usize) {
        let Some(label) = self.selected_descriptor().and_then(|d| d.sections.get(idx)).map(|s| s.label) else {
            return;
        };
        match self.flat_headers().into_iter().find(|(_, n)| n == label) {
            Some((row, _)) => {
                self.detail_visual_anchor = None;
                self.details_scroll = row;
            }
            None if !self.detail_search_query.is_empty() => {
                self.toast(format!("No match in {}", label));
            }
            None => {}
        }
    }

    /// Tab / Shift-Tab in the flat view: next / previous header, wrapping.
    fn flat_jump_relative(&mut self, forward: bool) {
        let headers = self.flat_header_rows();
        let Some(&first) = headers.first() else {
            return;
        };
        let cursor = self.details_scroll;
        let target = if forward {
            headers.iter().copied().find(|&i| i > cursor).unwrap_or(first)
        } else {
            headers.iter().rev().copied().find(|&i| i < cursor).unwrap_or(*headers.last().unwrap())
        };
        self.detail_visual_anchor = None;
        self.details_scroll = target;
    }

    /// Per-frame flat-view upkeep, called by the main loop before the draw:
    /// once per focused resource, fire every section's on-enter hook so the
    /// lazy sections load (the triggers are LazyMap-idempotent); and keep
    /// the section index on the header above the cursor so the tab bar
    /// highlights the section being read.
    pub fn flat_tick(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if !self.flat_active() {
            return;
        }
        if self.details_focused {
            let id = self.get_selected_resource().map(|r| r.id().to_string());
            if id.is_some() && self.flat_triggered_for != id {
                self.flat_triggered_for = id;
                if let Some(desc) = self.selected_descriptor() {
                    for i in 0..desc.len() {
                        desc.enter(i, self, event_tx);
                    }
                }
            }
        }
        let cursor = self.details_scroll;
        let name = self
            .flat_headers()
            .into_iter()
            .take_while(|(row, _)| *row <= cursor)
            .last()
            .map(|(_, n)| n);
        let section = name.and_then(|n| {
            self.selected_descriptor()
                .and_then(|d| d.sections.iter().position(|s| s.label == n))
        });
        self.detail_section_idx = section.unwrap_or(0);
    }

    // ── Detail body filter, group jumps, wrap ────────────────────────────

    /// `Ctrl-W`: wrap long values onto continuation rows, or clip them at
    /// the pane edge again. Render-only, so nothing else resets.
    fn toggle_detail_wrap(&mut self) {
        self.detail_wrap = !self.detail_wrap;
        self.toast(if self.detail_wrap {
            "Detail view: long values wrap (Ctrl-W to clip)"
        } else {
            "Detail view: long values clip (Ctrl-W to wrap)"
        });
    }

    /// Drop the `/` filter (typing or applied).
    fn clear_detail_filter(&mut self) {
        self.detail_search_active = false;
        self.detail_search_query.clear();
    }

    /// Back from the detail pane to the list (`h` / `←` / `⌫` / `Esc`): the
    /// filter and the selection go with the focus.
    fn leave_detail_pane(&mut self) {
        self.details_focused = false;
        self.detail_visual_anchor = None;
        self.pending_bracket = None;
        self.clear_detail_filter();
    }

    /// Body rows that match the filter themselves (not the headers and
    /// spacers kept for context): what `n` / `N` step through.
    pub fn detail_match_rows(&self) -> Vec<usize> {
        if self.detail_search_query.is_empty() {
            return Vec::new();
        }
        let q = self.detail_search_query.to_lowercase();
        self.detail_body()
            .iter()
            .enumerate()
            .filter(|(_, (k, v))| row_matches(k, v, &q))
            .map(|(i, _)| i)
            .collect()
    }

    /// The query changed: the cursor goes to the first match (row 0 when
    /// nothing matches), and a positional selection would mean other rows.
    fn detail_filter_changed(&mut self) {
        self.detail_visual_anchor = None;
        self.details_scroll = self.detail_match_rows().first().copied().unwrap_or(0);
    }

    /// `n` / `N`: the next / previous matching row, wrapping.
    fn detail_match_step(&mut self, forward: bool) {
        let rows = self.detail_match_rows();
        let Some(&first) = rows.first() else {
            return;
        };
        let cur = self.details_scroll;
        self.details_scroll = if forward {
            rows.iter().copied().find(|&i| i > cur).unwrap_or(first)
        } else {
            rows.iter().rev().copied().find(|&i| i < cur).unwrap_or(*rows.last().unwrap())
        };
    }

    /// `]]` / `[[`: the next / previous group header (a section's bold
    /// subheadings; in the flat view the `━━ Name ━━` headers too), or the
    /// last / first line when there is none that way. Like `j`/`k` it
    /// extends an active selection rather than dropping it.
    // ported from neboto-tui src/app.rs @ 7330ba4 (detail_next_section /
    // detail_prev_section, folded into one)
    fn detail_group_jump(&mut self, forward: bool) {
        let body = self.detail_body();
        if body.is_empty() {
            return;
        }
        let cur = self.details_scroll.min(body.len() - 1);
        let mut headers = body.iter().enumerate().filter(|(_, (k, v))| is_group_header(k, v)).map(|(i, _)| i);
        self.details_scroll = if forward {
            headers.find(|&i| i > cur).unwrap_or(body.len() - 1)
        } else {
            headers.rfind(|&i| i < cur).unwrap_or(0)
        };
    }

    /// `H` / `L`: previous / next sub-tab, from either pane, only where
    /// the service has sub-tabs. From the detail pane the new tab's first
    /// row opens there (now, from the cache, or when its list lands).
    // after neboto-tui src/app.rs @ 40b402f (step_sub_tab; nebaz cycles
    // the view directly and lands the focus when the list does)
    fn step_sub_tab(&mut self, forward: bool, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.current_service.is_none_or(|s| s.views().len() < 2) {
            return;
        }
        if self.all_search_mode {
            self.toast("@* rows come from the cache: ⏎ opens one in its tab");
            return;
        }
        let from_details = self.details_focused;
        if from_details {
            self.leave_detail_pane();
        }
        self.cycle_view(forward);
        if from_details {
            self.pending_detail_focus = true;
            self.resolve_pending_detail_focus(event_tx);
        }
    }

    /// Land a pending `H` / `L` focus once the new list has a row; a load
    /// that ends empty leaves the list focused.
    fn resolve_pending_detail_focus(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if !self.pending_detail_focus || self.pending_jump.is_some() {
            return;
        }
        if self.selected_index.is_some() {
            self.pending_detail_focus = false;
            self.details_focused = true;
            self.reset_detail_section_to_default(event_tx);
        } else if !self.loading {
            self.pending_detail_focus = false;
        }
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
        if let Some(st) = &self.network_lens {
            return crate::editor::spawn_editor_with_content(&st.as_text(), ".txt");
        }
        if let Some(st) = &self.metrics {
            return crate::editor::spawn_editor_with_content(&st.as_text(), ".txt");
        }
        if let Some(st) = &self.refs_lens {
            return crate::editor::spawn_editor_with_content(&st.as_text(), ".txt");
        }
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
        // Access is the same for every type: rendered here, not per type.
        let label = resource.detail_sections().and_then(|d| d.sections.get(idx)).map(|s| s.label);
        if label == Some(ACTIVITY_LABEL) {
            return Some(activity_rows(resource.id(), self.lazy.activity.get(resource.id())));
        }
        if label == Some(ACCESS_LABEL) {
            let roles = role_definitions_scope(resource.id()).and_then(|k| self.lazy.role_definitions.get(&k));
            return Some(access_rows(
                resource.id(),
                self.lazy.role_assignments.get(resource.id()),
                roles,
                &self.lazy.principals,
            ));
        }
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
        if let Some(r) = any.downcast_ref::<GenericResourceRow>() {
            return Some(generic_resource_section_lines(r, GenericResourceDetailSection::from_index(idx)));
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
            let section = VnetDetailSection::from_index(idx);
            if section == VnetDetailSection::Related {
                let mut rel = r.related();
                rel.extend(vnet_dns_related(self.dns_topology_for(r.id()), r.id()));
                return Some(related_lines(rel));
            }
            return Some(vnet_section_lines(r, section));
        }
        if let Some(r) = any.downcast_ref::<SubnetRow>() {
            // The reverse link to a Power Platform policy: the warm
            // policies list of the subnet's subscription, never a call.
            let policies = subscription_of(r.id()).and_then(|sub| {
                self.cache
                    .get_ref(&ServiceType::PowerPlatform, sub, Some(JumpView::EnterprisePolicies.as_str()))
            });
            let mut extra = subnet_policy_lines(r, policies);
            extra.extend(subnet_dns_related(self.dns_topology_for(r.id()), r.id()));
            return Some(subnet_section_lines(r, SubnetDetailSection::from_index(idx), extra));
        }
        if let Some(r) = any.downcast_ref::<NsgRow>() {
            return Some(nsg_section_lines(r, NsgDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<PublicIpRow>() {
            return Some(public_ip_section_lines(r, PublicIpDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<LoadBalancerRow>() {
            return Some(load_balancer_section_lines(r, LoadBalancerDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<RouteTableRow>() {
            return Some(route_table_section_lines(r, RouteTableDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<NatGatewayRow>() {
            return Some(nat_gateway_section_lines(r, NatGatewayDetailSection::from_index(idx)));
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
        if let Some(r) = any.downcast_ref::<WorkspaceRow>() {
            return Some(workspace_section_lines(r, WorkspaceDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<ComponentRow>() {
            return Some(component_section_lines(r, ComponentDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<CosmosAccountRow>() {
            return Some(cosmos_section_lines(
                r,
                CosmosDetailSection::from_index(idx),
                self.lazy.cosmos_databases.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<RegistryRow>() {
            return Some(registry_section_lines(
                r,
                RegistryDetailSection::from_index(idx),
                self.lazy.acr_replications.get(r.id()),
                self.lazy.acr_webhooks.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<ContainerAppRow>() {
            return Some(container_app_section_lines(
                r,
                ContainerAppDetailSection::from_index(idx),
                self.lazy.aca_revisions.get(r.id()),
                self.lazy.aca_auth_configs.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<EnvironmentRow>() {
            return Some(environment_section_lines(r, EnvironmentDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<JobRow>() {
            return Some(job_section_lines(r, JobDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<SqlServerRow>() {
            return Some(sql_server_section_lines(
                r,
                SqlServerDetailSection::from_index(idx),
                self.lazy.sql_databases.get(r.id()),
                self.lazy.sql_firewall_rules.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<SiteRow>() {
            return Some(site_section_lines(
                r,
                SiteDetailSection::from_index(idx),
                self.lazy.site_configs.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<PlanRow>() {
            return Some(plan_section_lines(r, PlanDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<PrivateEndpointRow>() {
            return Some(private_endpoint_section_lines(r, PrivateEndpointDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<PrivateDnsZoneRow>() {
            return Some(private_dns_zone_section_lines(
                r,
                PrivateDnsZoneDetailSection::from_index(idx),
                self.lazy.dns_records.get(r.id()),
                self.lazy.dns_vnet_links.get(r.id()),
            ));
        }
        if any.is::<ServicePrincipalRow>() || any.is::<AppRegistrationRow>() {
            let sub_scope = self.subscription_id.as_ref().map(|s| format!("/subscriptions/{}", s));
            let lazy = DirectoryLazy {
                children: &self.lazy.directory_children,
                objects: &self.lazy.principals,
                by_app_id: &self.lazy.sp_by_app_id,
                azure_roles: self.lazy.identity_role_assignments.get(resource.id()),
                role_definitions: sub_scope.as_ref().and_then(|k| self.lazy.role_definitions.get(k)),
                subscription_scope: sub_scope.as_deref(),
            };
            let now = crate::azure::services::directory::now_unix();
            if let Some(r) = any.downcast_ref::<ServicePrincipalRow>() {
                return Some(service_principal_section_lines(r, ServicePrincipalDetailSection::from_index(idx), &lazy, now));
            }
            if let Some(r) = any.downcast_ref::<AppRegistrationRow>() {
                return Some(app_registration_section_lines(r, AppRegistrationDetailSection::from_index(idx), &lazy, now));
            }
        }
        if let Some(r) = any.downcast_ref::<DnsZoneRow>() {
            return Some(dns_zone_section_lines(
                r,
                DnsZoneDetailSection::from_index(idx),
                self.lazy.public_dns_records.get(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<DnsResolverRow>() {
            return Some(dns_resolver_section_lines(
                r,
                DnsResolverDetailSection::from_index(idx),
                self.dns_topology_for(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<DnsRulesetRow>() {
            return Some(dns_ruleset_section_lines(
                r,
                DnsRulesetDetailSection::from_index(idx),
                self.lazy.dns_forwarding_rules.get(r.id()),
                self.dns_topology_for(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<DnsPolicyRow>() {
            return Some(dns_policy_section_lines(
                r,
                DnsPolicyDetailSection::from_index(idx),
                self.lazy.dns_security_rules.get(r.id()),
                self.dns_topology_for(r.id()),
            ));
        }
        if let Some(r) = any.downcast_ref::<IdentityRow>() {
            return Some(identity_section_lines(
                r,
                IdentityDetailSection::from_index(idx),
                self.lazy.federated_credentials.get(r.id()),
                self.lazy.identity_role_assignments.get(r.id()),
                role_definitions_scope(r.id()).and_then(|k| self.lazy.role_definitions.get(&k)),
            ));
        }
        if let Some(r) = any.downcast_ref::<EnterprisePolicyRow>() {
            return Some(enterprise_policy_section_lines(r, EnterprisePolicyDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<FoundryRow>() {
            return Some(foundry_section_lines(
                r,
                FoundryDetailSection::from_index(idx),
                self.lazy.foundry_deployments.get(r.id()),
                self.lazy.foundry_projects.get(r.id()),
            ));
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
        let place = if self.all_search_mode {
            crate::search::query_parser::ALL_SEARCH_PREFIX.to_string()
        } else if service.views().len() > 1 {
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
            query: self.location_query(service),
            selected_id: selected.map(|r| r.id().to_string()),
            label,
            details_focused: self.details_focused,
            detail_section,
        })
    }

    /// The query a location on `service` records. A `@service …` (or
    /// `vm:`) query is the switch *away* from here, captured mid-switch by
    /// `apply_query`, not this list's filter: it records as no filter, or
    /// as its search text when it names this very list. Restoring the raw
    /// switch query showed `@aks` as the old list's filter.
    fn location_query(&self, service: ServiceType) -> String {
        let parsed = parse_query(&self.search_query);
        // `@* …` is not a switch: it is the cross-cache results, kept whole
        // so back returns to them.
        if !parsed.is_service_switch || crate::search::query_parser::parse_all_query(&self.search_query).is_some() {
            return self.search_query.clone();
        }
        let same_list = parsed.service == Some(service)
            && parsed.view.is_none_or(|v| v == self.current_view);
        if same_list {
            parsed.search_text
        } else {
            String::new()
        }
    }

    /// Whether `loc` is the history's newest entry already (same service,
    /// sub-tab, query and row): the de-dup in `push_nav_location`.
    fn is_history_top(&self, loc: &NavLocation) -> bool {
        self.nav_history.last().is_some_and(|top| {
            top.service == loc.service
                && top.view == loc.view
                && top.subscription == loc.subscription
                && top.query == loc.query
                && top.selected_id == loc.selected_id
        })
    }

    /// Record the location being left before navigating away. Parked
    /// mid-history (after going back), the stale forward branch is dropped
    /// and the parked entry is **replaced** with where you are leaving
    /// from: you may have moved since going back to it (another row, a
    /// sub-tab), and back should return to where you left, not to the row
    /// you passed through. Live, `loc` is appended unless it repeats the
    /// top. A restore in progress records nothing.
    fn push_nav_location(&mut self) {
        if self.nav_restoring {
            return;
        }
        let Some(loc) = self.current_nav_location() else {
            return;
        };
        match self.nav_cursor.take() {
            Some(cursor) => {
                self.nav_history.truncate(cursor);
                self.nav_history.push(loc);
            }
            None => {
                if !self.is_history_top(&loc) {
                    self.nav_history.push(loc);
                }
            }
        }
        if self.nav_history.len() > NAV_HISTORY_MAX {
            self.nav_history.remove(0);
        }
    }

    fn restore_nav_location(&mut self, loc: NavLocation, event_tx: &mpsc::UnboundedSender<Event>) {
        let was = std::mem::replace(&mut self.nav_restoring, true);
        self.restore_nav_location_inner(loc, event_tx);
        self.nav_restoring = was;
    }

    fn restore_nav_location_inner(&mut self, loc: NavLocation, event_tx: &mpsc::UnboundedSender<Event>) {
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
            || self.command_picker.is_some()
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
                if generation != self.list_load.generation() {
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
                    // The Access list may just have landed: name its
                    // principals (idempotent per object id).
                    self.trigger_principal_names(event_tx);
                    self.trigger_directory_followups(event_tx);
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
        // Entering `@*` superseded the load; an untagged straggler must not
        // land on (or be cached from) the cross-cache rows either.
        if self.all_search_mode {
            return;
        }
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
                self.resolve_pending_detail_focus(event_tx);
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
                    self.pending_detail_focus = false;
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
        self.resolve_pending_detail_focus(event_tx);
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

        // Modals first — each owns the keyboard while open. Ctrl-N / Ctrl-P
        // move like Down / Up in every one of them (neboto's picker keys);
        // unmapped, they typed `n` / `p` into a picker's filter and Ctrl-N
        // started a macro recording from the macro picker.
        let key = if self.any_modal_open() { overlay_nav_key(key) } else { key };
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
        if self.command_picker.is_some() {
            self.handle_command_picker_key(key);
            return;
        }

        // Search input.
        if self.search_active {
            match key.code {
                KeyCode::Esc => {
                    self.search_active = false;
                    self.search_history_cursor = None;
                    self.search_query.clear();
                    self.pending_search = true;
                }
                KeyCode::Enter => {
                    self.search_active = false;
                    // Recorded as typed, so recalling an `@service …` query
                    // switches service again.
                    self.record_search_history();
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
                    // Editing a recalled query makes it the new draft.
                    self.search_history_cursor = None;
                    self.pending_search = true;
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.search_history_cursor = None;
                    self.pending_search = true;
                }
                KeyCode::Up | KeyCode::Down => {
                    if let Some(query) = self.step_search_history(key.code == KeyCode::Up) {
                        self.search_query = query;
                        self.pending_search = true;
                    }
                }
                _ => {}
            }
            return;
        }

        // The network access lens owns the keyboard while open.
        if self.network_lens.is_some() {
            self.handle_network_lens_key(key, event_tx);
            return;
        }
        // So do the referenced-by lens and the metrics view.
        if self.refs_lens.is_some() {
            self.handle_refs_lens_key(key, event_tx);
            return;
        }
        if self.metrics.is_some() {
            self.handle_metrics_key(key, event_tx);
            return;
        }

        // An armed export: Esc cancels it, from either pane (the detail
        // filter's input keeps its own Esc).
        if key.code == KeyCode::Esc
            && self.pending_export.is_some()
            && !(self.details_focused && self.detail_search_active)
        {
            self.cancel_pending_export();
            return;
        }

        // Detail pane focused.
        if self.details_focused {
            // `/` filter input owns the keyboard while typing.
            if self.detail_search_active {
                match key.code {
                    KeyCode::Esc => {
                        self.clear_detail_filter();
                        self.detail_filter_changed();
                    }
                    // Keep the filter, back to moving.
                    KeyCode::Enter => self.detail_search_active = false,
                    // Ctrl-W deletes a word, as in a shell (not the wrap toggle).
                    KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let q = self.detail_search_query.trim_end();
                        let keep = q.rfind(' ').map(|i| i + 1).unwrap_or(0);
                        self.detail_search_query.truncate(keep);
                        self.detail_filter_changed();
                    }
                    KeyCode::Backspace => {
                        self.detail_search_query.pop();
                        self.detail_filter_changed();
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.detail_search_query.push(c);
                        self.detail_filter_changed();
                    }
                    _ => {}
                }
                return;
            }
            let flat = self.flat_active();
            // `[[` / `]]`: any key but the matching bracket cancels the chord.
            let bracket = self.pending_bracket.take();
            match key.code {
                KeyCode::Char(c @ ('[' | ']')) if bracket == Some(c) => self.detail_group_jump(c == ']'),
                KeyCode::Char(c @ ('[' | ']')) => self.pending_bracket = Some(c),
                // Esc drops an active selection first, then the filter,
                // then leaves the pane.
                KeyCode::Esc if self.detail_visual_anchor.is_some() => {
                    self.detail_visual_anchor = None;
                }
                // ⌫ walks history (the footer's `⌫ back to …` names it);
                // with nothing behind, it leaves the pane as `h` does. The
                // filter belonged to the pane being left.
                KeyCode::Backspace if self.nav_back_index().is_some() => {
                    self.clear_detail_filter();
                    self.nav_back(event_tx)
                }
                KeyCode::Esc if !self.detail_search_query.is_empty() => {
                    self.clear_detail_filter();
                    self.detail_filter_changed();
                }
                KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => {
                    self.leave_detail_pane();
                }
                KeyCode::Char('/') => {
                    self.detail_search_active = true;
                    self.detail_search_query.clear();
                    self.detail_filter_changed();
                }
                KeyCode::Char('n') if !self.detail_search_query.is_empty() => self.detail_match_step(true),
                KeyCode::Char('N') if !self.detail_search_query.is_empty() => self.detail_match_step(false),
                KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => self.toggle_detail_wrap(),
                KeyCode::Char('H') => self.step_sub_tab(false, event_tx),
                KeyCode::Char('L') => self.step_sub_tab(true, event_tx),
                // Linewise visual selection (vim-style): `V` toggles it at the
                // cursor; `J`/`K` and Shift-↓/↑ start-and-extend in one motion;
                // once active, plain movement extends it (the anchor stays).
                KeyCode::Char('V') => {
                    self.detail_visual_anchor = match self.detail_visual_anchor {
                        Some(_) => None,
                        None => Some(self.details_scroll),
                    };
                }
                KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let n = self.detail_line_count();
                    if n > 0 {
                        self.detail_visual_anchor = Some(0);
                        self.details_scroll = n - 1;
                    }
                }
                KeyCode::Char('J') => self.detail_visual_step(true),
                KeyCode::Char('K') => self.detail_visual_step(false),
                KeyCode::Down if key.modifiers.contains(KeyModifiers::SHIFT) => self.detail_visual_step(true),
                KeyCode::Up if key.modifiers.contains(KeyModifiers::SHIFT) => self.detail_visual_step(false),
                KeyCode::Char('j') | KeyCode::Down => self.move_detail_cursor(1),
                KeyCode::Char('k') | KeyCode::Up => self.move_detail_cursor(-1),
                KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.move_detail_cursor(PAGE_STEP as isize)
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.move_detail_cursor(-(PAGE_STEP as isize))
                }
                KeyCode::Char('g') | KeyCode::Home => self.move_detail_cursor(isize::MIN / 2),
                KeyCode::Char('G') | KeyCode::End => self.move_detail_cursor(isize::MAX / 2),
                // In the flat view digits and Tab jump between section
                // headers; in the tabbed view they switch the section.
                KeyCode::Tab if flat => self.flat_jump_relative(true),
                KeyCode::BackTab if flat => self.flat_jump_relative(false),
                KeyCode::Char(c) if flat && crate::sections::index_for_key(c).is_some() => {
                    self.flat_jump_to_section(crate::sections::index_for_key(c).unwrap())
                }
                KeyCode::Tab => self.cycle_detail_section(true, event_tx),
                KeyCode::BackTab => self.cycle_detail_section(false, event_tx),
                KeyCode::Char(c) if crate::sections::index_for_key(c).is_some() => {
                    self.set_detail_section(crate::sections::index_for_key(c).unwrap(), event_tx)
                }
                KeyCode::Enter => self.follow_detail_line(event_tx),
                KeyCode::Char('y') => self.copy_detail_selection(),
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

        // List pane: the visual selection's keys first.
        if self.handle_list_visual_key(key, event_tx) {
            return;
        }
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
            KeyCode::Enter if self.all_search_mode => self.open_all_search_result(event_tx),
            KeyCode::Esc if self.all_search_mode => {
                self.search_query.clear();
                self.update_search();
            }
            // `@*` rows span services: no sub-tabs to switch, no one list to
            // reload (neither may replace the cross-cache rows).
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('r') | KeyCode::F(5) if self.all_search_mode => {
                self.toast("@* rows come from the cache: ⏎ opens one in its tab");
            }
            KeyCode::Char(c) if self.all_search_mode && crate::sections::index_for_key(c).is_some() => {
                self.toast("@* rows come from the cache: ⏎ opens one in its tab");
            }
            KeyCode::Enter if self.current_view == JumpView::AllResources && self.selected_routes_to_typed_tab() => {
                if let Some(id) = self.get_selected_resource_id() {
                    self.jump_to_arm_id(&id, event_tx);
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
            KeyCode::Backspace => self.nav_back(event_tx),
            KeyCode::Tab => self.cycle_view(true),
            KeyCode::BackTab => self.cycle_view(false),
            KeyCode::Char('H') => self.step_sub_tab(false, event_tx),
            KeyCode::Char('L') => self.step_sub_tab(true, event_tx),
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
            // `Ctrl-W` reshapes the detail preview, like `\` (before the
            // plain `w` arm, which matches any modifier).
            KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => self.toggle_detail_wrap(),
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
            _ => self.handle_global_key(key, event_tx),
        }
    }

    /// Keys that work from either pane.
    fn handle_global_key(&mut self, key: KeyEvent, _event_tx: &mpsc::UnboundedSender<Event>) {
        match key.code {
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.redraw_requested = true
            }
            // `\` works from either pane so the preview follows the mode.
            KeyCode::Char('\\') => self.toggle_detail_flat_mode(),
            KeyCode::Char('q') => self.running = false,
            // Ctrl-X arrives as `x` (or `X` with Shift) plus CONTROL.
            KeyCode::Char('x') | KeyCode::Char('X') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.export_list()
            }
            KeyCode::Char('X') => self.export_current(_event_tx),
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
            KeyCode::Char('N') => self.open_network_lens(_event_tx),
            KeyCode::Char('U') => self.open_refs_lens(_event_tx),
            KeyCode::Char('m') => self.open_metrics(_event_tx),
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
            // Copied verbatim, never run: `--ids` carries the subscription,
            // and the commands without `--ids` carry `--subscription`.
            KeyCode::Char('C') => self.open_command_picker(),
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

    /// `⌫` / `Ctrl-O`: back one place. From live, "here" is recorded first
    /// (unless it already is the newest entry) and the cursor parks on the
    /// entry before it; parked, the cursor steps one older.
    fn nav_back(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.nav_back_index().is_none() {
            return;
        }
        let cursor = match self.nav_cursor {
            None => {
                self.push_nav_location();
                // Here is now the newest entry (pushed, or already it).
                self.nav_history.len() - 2
            }
            Some(c) => c - 1,
        };
        self.nav_cursor = Some(cursor);
        if let Some(loc) = self.nav_history.get(cursor).cloned() {
            self.restore_nav_location(loc, event_tx);
        }
    }

    /// The entry `nav_back` would land on, computed without recording
    /// anything (the footer hint asks it every frame).
    fn nav_back_index(&self) -> Option<usize> {
        match self.nav_cursor {
            None => {
                let here_is_top = self
                    .current_nav_location()
                    .is_some_and(|loc| self.is_history_top(&loc));
                self.nav_history.len().checked_sub(if here_is_top { 2 } else { 1 })
            }
            Some(c) => c.checked_sub(1),
        }
    }

    /// Where `⌫` / `Ctrl-O` would go, short, for the detail footer:
    /// `VMs vm-1`, the ARM id cut to its last segment. `None` with no
    /// history behind, or when that entry is where we already are.
    pub(crate) fn nav_back_hint(&self) -> Option<String> {
        let loc = &self.nav_history[self.nav_back_index()?];
        let here = self.get_selected_resource().map(|r| r.id());
        if Some(loc.service) == self.current_service && loc.selected_id.as_deref() == here {
            return None;
        }
        Some(nav_hint_label(loc.service, loc.selected_id.as_deref()))
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


// ── Flat view and selection helpers (pure) ──────────────────────────────

/// Section-header row for the flat body: `━━ Name ━━━…` with an empty
/// value. The pane renders it brand-bold; `flat_header_name` inverts it.
fn flat_section_header(name: &str) -> (String, String) {
    let base = format!("━━ {} ", name);
    let fill = 44usize.saturating_sub(base.chars().count());
    (format!("{}{}", base, "━".repeat(fill)), String::new())
}

/// Whether a detail value is an id Enter acts on (a jump, or a copy when
/// nebaz does not browse the type): an ARM id, or a directory row's
/// synthetic `graph:/…` id (ADR 0004).
fn is_arm_id(value: &str) -> bool {
    value.starts_with("/subscriptions/") || crate::azure::graph::is_row_id(value)
}

/// The view Enter on this detail value jumps to: `Some` exactly when the
/// value is an ARM id of a type nebaz browses. The detail pane marks those
/// lines with `→`, so the marker and the jump cannot disagree.
pub fn detail_jump_view(value: &str) -> Option<JumpView> {
    let value = value.trim();
    if is_arm_id(value) {
        JumpView::landing_for_arm_id(value)
    } else {
        None
    }
}

/// Ctrl-N → Down and Ctrl-P → Up; every other key unchanged. Applied to
/// keys an open overlay receives, never to the main list or detail pane.
fn overlay_nav_key(key: KeyEvent) -> KeyEvent {
    if !key.modifiers.contains(KeyModifiers::CONTROL) {
        return key;
    }
    match key.code {
        KeyCode::Char('n') => KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        KeyCode::Char('p') => KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        _ => key,
    }
}

/// The section name if this key is a flat header row.
pub fn flat_header_name(key: &str) -> Option<&str> {
    key.strip_prefix("━━ ").map(|rest| rest.trim_end_matches('━').trim())
}

/// Concatenate the section snapshot into one body with a header per
/// section, trimming each section's own leading/trailing spacers so the
/// gaps are uniform. A single section comes back as is.
fn assemble_flat_detail(sections: &[(String, Vec<(String, String)>)]) -> Vec<(String, String)> {
    if sections.len() == 1 {
        return sections[0].1.clone();
    }
    let mut lines: Vec<(String, String)> = Vec::new();
    for (name, rows) in sections {
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines.push(flat_section_header(name));
        let blank = |(k, v): &(String, String)| k.is_empty() && v.is_empty();
        let start = rows.iter().position(|r| !blank(r)).unwrap_or(rows.len());
        let end = rows.iter().rposition(|r| !blank(r)).map(|i| i + 1).unwrap_or(start);
        lines.extend(rows[start..end].iter().cloned());
    }
    lines
}

/// A group header in the detail body: a key, no value, no leading space
/// (`style_detail_row`'s bold subheading; the flat `━━` headers too).
fn is_group_header(key: &str, value: &str) -> bool {
    !key.is_empty() && value.is_empty() && !key.starts_with(' ')
}

/// Case-insensitive substring match on a row's key or value; `q` is
/// already lowercased.
fn row_matches(key: &str, value: &str, q: &str) -> bool {
    key.to_lowercase().contains(q) || value.to_lowercase().contains(q)
}

// ported from neboto-tui src/app.rs @ 7330ba4 (filter_detail_rows, with
// c814b26's flat section-header rule)
/// The `/` body filter: case-insensitive substring over key and value,
/// group-aware so a match never loses its context. A group (a group
/// header and the rows up to the next one) is kept whole when its header
/// matches, and as header + matching rows (+ spacers) when a row does;
/// the rows before the first header are kept when anything matched. In
/// the flat view a `━━ Section ━━` header outranks the group headers
/// inside it: whenever any of its rows survive, it is kept too, so the
/// cursor's section (and the tab bar) still resolve. With no group
/// headers at all it falls back to plain line filtering.
pub fn filter_detail_rows(lines: Vec<(String, String)>, query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return lines;
    }
    let q = query.to_lowercase();
    let matches = |(k, v): &(String, String)| row_matches(k, v, &q);

    struct Group {
        start: usize,
        end: usize,
        header_matches: bool,
        any_child_matches: bool,
    }
    let mut i = 0;
    while i < lines.len() && !is_group_header(&lines[i].0, &lines[i].1) {
        i += 1;
    }
    let preamble_end = i;
    let mut groups: Vec<Group> = Vec::new();
    while i < lines.len() {
        let start = i;
        let header_matches = matches(&lines[i]);
        i += 1;
        let mut any_child_matches = false;
        while i < lines.len() && !is_group_header(&lines[i].0, &lines[i].1) {
            any_child_matches |= matches(&lines[i]);
            i += 1;
        }
        groups.push(Group { start, end: i, header_matches, any_child_matches });
    }

    let mut result = Vec::new();
    if groups.iter().any(|g| g.header_matches || g.any_child_matches) && preamble_end > 0 {
        result.extend(lines[..preamble_end].iter().cloned());
    }
    // A section header owns only the rows up to its first subgroup, so a
    // match inside a subgroup would drop it (neboto #119): hold the latest
    // unemitted section header and emit it before the first kept subgroup.
    let mut pending_section: Option<usize> = None;
    for g in &groups {
        let included = g.header_matches || g.any_child_matches;
        if flat_header_name(&lines[g.start].0).is_some() {
            pending_section = (!included).then_some(g.start);
        } else if included {
            if let Some(h) = pending_section.take() {
                result.push(lines[h].clone());
            }
        }
        if g.header_matches {
            result.extend(lines[g.start..g.end].iter().cloned());
        } else if g.any_child_matches {
            result.push(lines[g.start].clone());
            for row in &lines[g.start + 1..g.end] {
                if matches(row) || (row.0.is_empty() && row.1.is_empty()) {
                    result.push(row.clone());
                }
            }
        }
    }
    if result.is_empty() && !lines.is_empty() {
        return lines.into_iter().filter(|r| matches(r)).collect();
    }
    result
}

/// The visual selection as clipboard text: `key: value` per row, headers
/// and plain content lines as themselves, blank rows kept as blank lines.
fn selection_text(lines: &[(String, String)], start: usize, end: usize) -> String {
    lines
        .iter()
        .skip(start)
        .take(end - start + 1)
        .map(|(key, value)| {
            if value.is_empty() {
                key.trim_end().to_string()
            } else if key.trim().is_empty() {
                value.clone()
            } else {
                format!("{}: {}", key.trim(), value)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_back_hint_label_is_the_service_and_the_id_tail() {
        let vm = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web-1";
        assert_eq!(nav_hint_label(ServiceType::VirtualMachines, Some(vm)), "VMs web-1");
        let subnet = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/aks/";
        assert_eq!(nav_hint_label(ServiceType::Network, Some(subnet)), "VNet aks");
        let long = "a".repeat(40);
        let label = nav_hint_label(ServiceType::Aks, Some(&long));
        assert_eq!(label.chars().count(), "AKS ".len() + 28);
        assert!(label.ends_with('…'));
        assert_eq!(nav_hint_label(ServiceType::Aks, None), "AKS");
        assert_eq!(nav_hint_label(ServiceType::Aks, Some("")), "AKS");
    }

    fn s(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[tokio::test]
    async fn superseding_a_list_load_aborts_its_tasks() {
        let mut load = ListLoad::default();
        let first = load.supersede();
        let fetch = tokio::spawn(std::future::pending::<()>());
        let forwarder = tokio::spawn(std::future::pending::<()>());
        load.track(fetch.abort_handle());
        load.track(forwarder.abort_handle());

        let second = load.supersede();
        assert!(second > first, "the generation moves on");
        assert_eq!(load.generation(), second);
        assert!(fetch.await.unwrap_err().is_cancelled());
        assert!(forwarder.await.unwrap_err().is_cancelled());

        // The next load's task is untouched until it, too, is superseded.
        let next = tokio::spawn(std::future::pending::<()>());
        load.track(next.abort_handle());
        tokio::task::yield_now().await;
        assert!(!next.is_finished());
        load.supersede();
        assert!(next.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn ctrl_n_and_ctrl_p_are_down_and_up_in_overlays() {
        let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
        assert_eq!(overlay_nav_key(ctrl('n')).code, KeyCode::Down);
        assert_eq!(overlay_nav_key(ctrl('p')).code, KeyCode::Up);
        assert_eq!(overlay_nav_key(ctrl('n')).modifiers, KeyModifiers::NONE);
        // Plain n / p still type into a filter; other chords are untouched.
        let plain = KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE);
        assert_eq!(overlay_nav_key(plain), plain);
        assert_eq!(overlay_nav_key(ctrl('d')), ctrl('d'));
    }

    #[test]
    fn only_arm_ids_with_a_landing_carry_the_jump_marker() {
        let rg = "/subscriptions/0/resourceGroups/rg";
        assert_eq!(detail_jump_view(rg), Some(JumpView::ResourceGroups));
        let nic = format!(" {}/providers/Microsoft.Network/networkInterfaces/n ", rg);
        assert_eq!(detail_jump_view(&nic), Some(JumpView::Nics));
        // An unbrowsed top-level type lands in All resources.
        assert_eq!(
            detail_jump_view(&format!("{}/providers/Microsoft.Network/publicIPPrefixes/px", rg)),
            Some(JumpView::AllResources)
        );
        // A child of an unbrowsed type is in no list: Enter copies, no marker.
        assert_eq!(detail_jump_view(&format!("{}/providers/Microsoft.KeyVault/vaults/kv/secrets/db", rg)), None);
        assert_eq!(detail_jump_view("Standard_D2s_v3"), None);
        assert_eq!(detail_jump_view(""), None);
    }

    #[test]
    fn flat_headers_round_trip_and_sections_are_trimmed() {
        let sections = vec![
            ("Overview".to_string(), vec![s("", ""), s("Name", "vm-1"), s("", "")]),
            ("Related".to_string(), vec![s("Subscription", "/subscriptions/0")]),
        ];
        let flat = assemble_flat_detail(&sections);
        let keys: Vec<&str> = flat.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(flat_header_name(keys[0]), Some("Overview"));
        assert_eq!(keys[1], "Name");
        assert_eq!(keys[2], "");
        assert_eq!(flat_header_name(keys[3]), Some("Related"));
        assert_eq!(keys.len(), 5);
        assert_eq!(flat_header_name("Name"), None);
        // One section: no header, nothing changes.
        assert_eq!(assemble_flat_detail(&sections[1..]), sections[1].1);
    }

    #[test]
    fn selection_text_keeps_the_row_conventions() {
        let lines = vec![s("Name", "vm-1"), s("Tags", ""), s("  env", "prod"), s("", "note"), s("", "")];
        assert_eq!(selection_text(&lines, 0, 4), "Name: vm-1\nTags\nenv: prod\nnote\n");
        assert_eq!(selection_text(&lines, 2, 2), "env: prod");
    }

    #[test]
    fn body_filter_keeps_each_match_with_its_group_header() {
        let lines = vec![
            s("", "names only"),
            s("Network", ""),
            s("  Subnet", "default"),
            s("  NSG", "nsg-web"),
            s("", ""),
            s("Storage", ""),
            s("  OS disk", "vm-1-os"),
        ];
        // A row match: its header, the row, the spacers; the preamble.
        assert_eq!(
            filter_detail_rows(lines.clone(), "NSG-"),
            vec![s("", "names only"), s("Network", ""), s("  NSG", "nsg-web"), s("", "")]
        );
        // A header match keeps the whole group.
        assert_eq!(
            filter_detail_rows(lines.clone(), "storage"),
            vec![s("", "names only"), s("Storage", ""), s("  OS disk", "vm-1-os")]
        );
        assert_eq!(filter_detail_rows(lines.clone(), ""), lines);
        assert!(filter_detail_rows(lines, "nothing").is_empty());
        // No group headers at all: plain line filtering.
        let flat = vec![s("Subscription", "/subscriptions/0"), s("NIC vm-1-nic", "/subscriptions/0/nic")];
        assert_eq!(filter_detail_rows(flat, "nic"), vec![s("NIC vm-1-nic", "/subscriptions/0/nic")]);
    }

    /// neboto #119: a match under a subgroup keeps its `━━ Section` header,
    /// once, before the subgroup.
    #[test]
    fn body_filter_keeps_the_flat_section_header_of_a_subgroup_match() {
        let lines = assemble_flat_detail(&[
            ("Overview".into(), vec![s("Name", "web-1")]),
            ("Security".into(), vec![s("Role", "app-role"), s("Encryption", ""), s("KMS key", "needle")]),
        ]);
        let filtered = filter_detail_rows(lines.clone(), "needle");
        assert_eq!(flat_header_name(&filtered[0].0), Some("Security"));
        assert_eq!(filtered[1..], [s("Encryption", ""), s("KMS key", "needle")]);

        let filtered = filter_detail_rows(lines, "security");
        let headers = filtered.iter().filter(|(k, _)| flat_header_name(k) == Some("Security")).count();
        assert_eq!(headers, 1);
    }
}

/// Layer-2 wiring tests: the real `App`, offline (`src/harness_tests`).
#[cfg(test)]
#[path = "harness_tests/mod.rs"]
pub(crate) mod harness_tests;
