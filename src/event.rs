// ported from neboto-tui src/event.rs @ d483900
use crate::azure::auth::AuthError;
use crate::azure::location::Location;
use crate::azure::resource::Resource;
use crate::azure::service::ServiceType;
use crossterm::event::{KeyEvent, MouseEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Progress information for incremental resource loading
#[derive(Debug, Clone)]
pub struct LoadProgress {
    pub loaded_count: usize,
    pub total_count: Option<usize>,     // None if total unknown
    pub status_message: Option<String>, // e.g., "Listing disks…"
}

/// The provider-neutral event set. neboto's enum carries ~90 further
/// per-service `*Loaded` variants (metrics overlays, log tails, lenses,
/// object browsers); every one of them predates the apply-closure design
/// and none is needed here — new lazy fetches go through `Event::Lazy`.
#[derive(Debug)]
pub enum Event {
    // User input events
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize,

    // Async list-load events
    ResourcesLoaded {
        service: ServiceType,
        resources: Vec<Box<dyn Resource>>,
    },
    ResourcesPartiallyLoaded {
        service: ServiceType,
        resources: Vec<Box<dyn Resource>>, // Incremental batch
        progress: LoadProgress,
    },
    ResourcesFullyLoaded {
        service: ServiceType,
        total_count: usize,
    },
    /// A single resource was re-fetched in place (detail-pane `r`, or a
    /// watch-mode tick); replace the matching resource (by `id`) without
    /// reloading the whole service. `quiet` (watch mode) suppresses the
    /// "Refreshed …" toast.
    ResourceRefreshed {
        id: String,
        resource: Box<dyn Resource>,
        quiet: bool,
    },
    /// A targeted single-resource refresh failed (e.g. the resource is gone).
    ResourceRefreshFailed {
        error: String,
    },
    ResourceLoadError {
        service: ServiceType,
        error: String,
        /// Set when the load failed because no token could be obtained:
        /// the app raises the app-wide auth line instead of a per-service
        /// error.
        auth: Option<AuthError>,
    },
    /// Non-fatal: one phase of a multi-phase load failed but the load keeps
    /// streaming. Unlike `ResourceLoadError` this must NOT clear the loading
    /// state (that would make `handle_resources_partially_loaded` drop every
    /// later batch). Warnings accumulate and surface when the load completes.
    ResourceLoadWarning {
        service: ServiceType,
        warning: String,
    },
    /// A list-load stream event (`ResourcesLoaded` / `PartiallyLoaded` /
    /// `FullyLoaded` / `LoadError` / `LoadWarning`) tagged by the forwarder in
    /// `App::load_resources_async` with the `load_generation` it belongs to.
    /// `handle_event` re-checks the generation *when the event is handled*,
    /// not just when it was forwarded: while `handle_event` is blocked in a
    /// subscription switch (an awaited client build), a superseded stream's
    /// events pile up in the channel past the forwarder's check and would
    /// otherwise land on the new credentials' empty list.
    LoadStream {
        generation: u64,
        event: Box<Event>,
    },

    /// The `R` slot: location is a client-side filter over subscription-wide
    /// lists, so this never rebuilds clients — it re-filters.
    LocationSwitchRequested {
        location: Location,
    },

    /// The `P` slot: switch the active subscription (keeps the client and
    /// the list cache, replaces the `LazyStore`, bumps `load_generation`).
    SubscriptionSwitchRequested {
        subscription_id: String,
    },

    /// `R` while the auth line is up: re-read `az account list` and reload.
    AuthRetryRequested,

    /// Identity of the active subscription, fetched in the background at
    /// startup / after a switch for the service-tab badge.
    SubscriptionInfoLoaded {
        subscription_id: Option<String>,
        display_name: Option<String>,
        tenant_id: Option<String>,
    },

    /// A lazy-section fetch result: an epoch-stamped apply closure that
    /// writes into its LazyMap — the one delivery event for every lazy
    /// fetch (neboto docs/adr/0001-apply-closure-lazy-event.md). Don't add
    /// new per-fetch `*Loaded` variants for lazy sections.
    Lazy(crate::lazy::LazyApply),

    // Application events
    Tick,
}

pub struct EventHandler {
    tx: mpsc::UnboundedSender<Event>,
    rx: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }

    pub fn sender(&self) -> mpsc::UnboundedSender<Event> {
        self.tx.clone()
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

// Spawn a task to handle terminal events
pub async fn handle_terminal_events(tx: mpsc::UnboundedSender<Event>) {
    use crossterm::event::{poll, read, Event as CrosstermEvent};

    loop {
        // Poll for events with a timeout
        match tokio::task::spawn_blocking(|| {
            if poll(Duration::from_millis(100)).unwrap_or(false) {
                read().ok()
            } else {
                None
            }
        })
        .await
        {
            Ok(Some(event)) => match event {
                CrosstermEvent::Key(key) => {
                    if tx.send(Event::Key(key)).is_err() {
                        break;
                    }
                }
                CrosstermEvent::Mouse(mouse) => {
                    if tx.send(Event::Mouse(mouse)).is_err() {
                        break;
                    }
                }
                CrosstermEvent::Resize(_, _) => {
                    if tx.send(Event::Resize).is_err() {
                        break;
                    }
                }
                _ => {}
            },
            Ok(None) => {
                // No event available, continue polling
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => {
                // Task join error, break the loop
                break;
            }
        }
    }
}

// Spawn a task to generate tick events
pub async fn handle_tick_events(tx: mpsc::UnboundedSender<Event>, tick_rate: Duration) {
    let mut interval = tokio::time::interval(tick_rate);

    loop {
        interval.tick().await;
        if tx.send(Event::Tick).is_err() {
            break;
        }
    }
}
