// ported from neboto-tui src/harness_tests/mod.rs @ ae78599 (the offline
// App, the mock registry and the render-to-TestBackend loop; the driver is
// rewritten around nebaz's event set and AzureClients)
//! Layer-2 wiring tests: no network, no `az`, plain `cargo test`.
//!
//! [`Harness`] builds the real [`App`] over default config and offline
//! clients (`AzureClients::new_for_test`: fixture subscriptions in place of
//! `az account list`, a dead endpoint, and a credential that never yields a
//! token), then drives it the way `main` does: keys and events go through
//! `handle_event`, and [`Harness::settle`] runs one main-loop pass (start a
//! requested load, the per-frame ticks, a draw to a ratatui `TestBackend`,
//! the deferred search) and handles whatever the pass queued.
//!
//! Every list load and lazy fetch the app spawns stays in flight forever,
//! so a test decides what lands, through the event the real fetch would
//! send: [`Harness::land`] / [`Harness::land_page`] deliver rows as the
//! current load generation's stream, [`Harness::send`] any other event.
//!
//! Writing a test:
//!
//! ```ignore
//! let mut h = Harness::new().await;
//! h.open(JumpView::VirtualMachines).await;  // switch + arm the load
//! h.land(vec![mocks::vm("vm-1", "westeurope")]).await;
//! h.press(KeyCode::Enter).await;            // focus the detail pane
//! assert!(h.render().contains("Instance view"));
//! ```
//!
//! [`mocks`] holds one row per type that declares a section descriptor; a
//! new split pane needs one there, or the descriptor/renderer checks in
//! `wiring_test` silently skip it.

use super::*;
use crate::azure::auth::SubscriptionEntry;
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::sync::Arc;

mod load_stream_test;
pub(crate) mod mocks;
mod navigation_test;
mod wiring_test;

/// The CLI's default subscription in the fixture account list.
pub(crate) const SUB_DEV: &str = "00000000-0000-0000-0000-0000000000d1";
/// A second subscription in the same tenant, for switches.
pub(crate) const SUB_PROD: &str = "00000000-0000-0000-0000-0000000000f2";
pub(crate) const TENANT: &str = "00000000-0000-0000-0000-00000000000a";

fn fixture_subscriptions() -> Vec<SubscriptionEntry> {
    let entry = |id: &str, name: &str, default: bool| SubscriptionEntry {
        id: id.to_string(),
        name: name.to_string(),
        tenant_id: TENANT.to_string(),
        state: "Enabled".to_string(),
        is_default: default,
        cloud_name: Some("AzureCloud".to_string()),
        user: Some("dev@example.com".to_string()),
    };
    vec![entry(SUB_DEV, "Dev", true), entry(SUB_PROD, "Prod", false)]
}

/// A token that never comes: the bearer policy waits on it before any
/// request is built, so nothing reaches the (dead) endpoint, no `az` runs,
/// and every fetch stays in flight until the test ends.
#[derive(Debug)]
struct OfflineCredential;

#[async_trait::async_trait]
impl TokenCredential for OfflineCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        std::future::pending().await
    }
}

impl App {
    /// The offline `App`: default config, fixture subscriptions, no files
    /// written outside the temp dir.
    pub(crate) fn new_for_test() -> Self {
        static ENV: std::sync::Once = std::sync::Once::new();
        ENV.call_once(|| {
            // Exports, bookmarks and macros the keys write land in a temp
            // dir, never the developer's config.
            let dir = std::env::temp_dir().join("nebaz-harness");
            let _ = std::fs::create_dir_all(&dir);
            std::env::set_var("NEBAZ_EXPORT_DIR", &dir);
            std::env::set_var("NEBAZ_BOOKMARKS", dir.join("bookmarks.json"));
            std::env::set_var("NEBAZ_MACROS", dir.join("macros.json"));
        });
        let clients = AzureClients::new_for_test(fixture_subscriptions(), Arc::new(OfflineCredential));
        let mut app = Self::from_parts(Config::default(), clients, None);
        app.bookmarks.clear();
        app.macros.clear();
        app
    }
}

pub(crate) fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

pub(crate) struct Harness {
    pub app: App,
    pub tx: mpsc::UnboundedSender<Event>,
    rx: mpsc::UnboundedReceiver<Event>,
    terminal: Terminal<TestBackend>,
}

impl Harness {
    /// A 140×40 terminal on the splash (no service yet).
    pub async fn new() -> Self {
        Self::sized(140, 40).await
    }

    pub async fn sized(width: u16, height: u16) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut h = Harness {
            app: App::new_for_test(),
            tx,
            rx,
            terminal: Terminal::new(TestBackend::new(width, height)).unwrap(),
        };
        h.settle().await;
        h
    }

    /// One main-loop pass (see `main.rs`), then handle every event it or
    /// the spawned tasks queued, until the channel is quiet.
    pub async fn settle(&mut self) {
        for _ in 0..16 {
            if self.app.should_load_resources() {
                self.app.load_resources_async(&self.tx);
            }
            self.app.macro_tick(&self.tx);
            self.app.flat_tick(&self.tx);
            self.draw();
            self.app.process_pending_search();
            self.app.record_message_history();

            tokio::task::yield_now().await;
            let mut handled = false;
            while let Ok(ev) = self.rx.try_recv() {
                handled = true;
                self.app.handle_event(ev, &self.tx).await.expect("handle_event");
            }
            if !handled {
                return;
            }
        }
    }

    fn draw(&mut self) {
        let app = &self.app;
        self.terminal
            .draw(|f| crate::render_app(app, f))
            .expect("draw");
    }

    /// Deliver an event as the main loop would, then settle.
    pub async fn send(&mut self, event: Event) {
        self.app.handle_event(event, &self.tx).await.expect("handle_event");
        self.settle().await;
    }

    pub async fn press(&mut self, code: KeyCode) {
        self.press_key(key(code)).await;
    }

    pub async fn press_key(&mut self, k: KeyEvent) {
        self.send(Event::Key(k)).await;
    }

    pub async fn type_str(&mut self, s: &str) {
        for c in s.chars() {
            self.press(KeyCode::Char(c)).await;
        }
    }

    /// Switch to a sub-tab (and its service) and arm its load, as a key or
    /// a routing prefix would.
    pub async fn open(&mut self, view: JumpView) {
        self.app.switch_view(view);
        self.settle().await;
    }

    /// Wrap a list-load event in the current load's generation, as the
    /// forwarder in `load_resources_async` does.
    pub fn stream(&self, event: Event) -> Event {
        Event::LoadStream {
            generation: self.app.list_load.generation(),
            event: Box::new(event),
        }
    }

    fn service(&self) -> ServiceType {
        self.app.current_service.expect("a service is open")
    }

    /// The current load's whole list in one event (`ResourcesLoaded`).
    pub async fn land(&mut self, resources: Vec<Box<dyn Resource>>) {
        let ev = self.stream(Event::ResourcesLoaded {
            service: self.service(),
            resources,
        });
        self.send(ev).await;
    }

    /// One streamed page of the current load (`ResourcesPartiallyLoaded`).
    pub async fn land_page(&mut self, resources: Vec<Box<dyn Resource>>) {
        let loaded_count = self.app.resources.len() + resources.len();
        let ev = self.stream(Event::ResourcesPartiallyLoaded {
            service: self.service(),
            resources,
            progress: LoadProgress {
                loaded_count,
                total_count: None,
                status_message: None,
            },
        });
        self.send(ev).await;
    }

    /// The current load's end (`ResourcesFullyLoaded`).
    pub async fn finish(&mut self) {
        let ev = self.stream(Event::ResourcesFullyLoaded {
            service: self.service(),
            total_count: self.app.resources.len(),
        });
        self.send(ev).await;
    }

    /// Open a mock's sub-tab with the mock as its only row, selected.
    pub async fn install(&mut self, mock: mocks::Mock) {
        let mocks::Mock { view, resource, .. } = mock;
        self.app.details_focused = false;
        self.app.detail_flat_mode = false;
        self.app.current_location = Location::All;
        self.app.switch_view(view);
        // A fresh load even when the view was open or cached.
        let sub = self.app.subscription_key();
        self.app.cache.invalidate(&view.service(), &sub, Some(view.as_str()));
        self.app.load_service_resources();
        self.settle().await;
        self.land(vec![resource]).await;
        assert_eq!(self.app.filtered_resources.len(), 1, "the mock is visible");
    }

    /// Draw a frame and return the screen, one line per terminal row.
    pub fn render(&mut self) -> String {
        self.draw();
        let buffer = self.terminal.backend().buffer();
        let width = buffer.area.width as usize;
        buffer
            .content()
            .chunks(width)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Names of the rows the list shows, in order.
    pub fn visible_names(&self) -> Vec<String> {
        self.app
            .filtered_resources
            .iter()
            .map(|&i| self.app.resources[i].name().to_string())
            .collect()
    }

    pub fn selected_id(&self) -> Option<String> {
        self.app.get_selected_resource_id()
    }

    /// The section labels of the selected row's descriptor.
    pub fn section_labels(&self) -> Vec<&'static str> {
        self.app
            .selected_descriptor()
            .map(|d| d.sections.iter().map(|s| s.label).collect())
            .unwrap_or_default()
    }

    /// Move the detail cursor onto the first body line whose value is
    /// `value`, with `j` presses from the top of the section.
    pub async fn cursor_to_value(&mut self, value: &str) {
        let lines = self.app.get_detail_lines();
        let target = lines
            .iter()
            .position(|(_, v)| v.trim() == value)
            .unwrap_or_else(|| panic!("no detail line with value {value:?} in {lines:#?}"));
        self.press(KeyCode::Char('g')).await;
        for _ in 0..target {
            self.press(KeyCode::Char('j')).await;
        }
        assert_eq!(self.app.details_scroll, target);
    }
}
