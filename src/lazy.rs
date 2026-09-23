// ported from neboto-tui src/lazy.rs @ d483900
//! The deep module behind the "lazy section" pattern (vocabulary in
//! CONTEXT.md, the event design in docs/adr/0001-apply-closure-lazy-event.md).
//!
//! A lazy section's data lives in a [`LazyMap`] inside the app's single
//! [`LazyStore`]. Fetches are spawned through `App::trigger_lazy` and resolve
//! to a [`Lazy`] outcome delivered by the one `Event::Lazy` apply-closure
//! event. The store's epoch stamp lets a stale in-flight fetch — one spawned
//! before a subscription switch — be dropped instead of poisoning the
//! fresh store, and replacing the store wholesale on a switch makes the old
//! "clear it in `reset_subscription_scoped_state`" convention unnecessary: a new
//! map field resets by construction.

use std::collections::HashMap;

/// The three-state outcome of a lazy fetch. "Nothing found" is a normal
/// `Loaded` payload (e.g. `Loaded(None)`), never an `Error`.
#[derive(Debug, Clone)]
pub enum Lazy<T> {
    Loading,
    Loaded(T),
    Error(String),
}

/// A keyed collection of [`Lazy`] outcomes for one detail concern (e.g. flow
/// logs by VPC id). Triggering a key that is already present is a no-op, so a
/// section can be triggered from digit keys, `Tab`-cycling, and drill-in
/// alike without duplicate fetches.
#[derive(Debug, Clone)]
pub struct LazyMap<T> {
    map: HashMap<String, Lazy<T>>,
}

impl<T> Default for LazyMap<T> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<T> LazyMap<T> {
    pub fn get(&self, key: &str) -> Option<&Lazy<T>> {
        self.map.get(key)
    }

    /// The trigger idempotence guard: an entry in any state (including
    /// `Error` — failures don't auto-retry) blocks a re-fetch.
    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Mark a fetch as in flight. `App::trigger_lazy` calls this before
    /// spawning; renderers show `Loading` until the apply lands.
    pub fn insert_loading(&mut self, key: String) {
        self.map.insert(key, Lazy::Loading);
    }

    /// Deliver a fetch result (the apply-closure's body).
    pub fn apply(&mut self, key: String, result: Result<T, String>) {
        let state = match result {
            Ok(v) => Lazy::Loaded(v),
            Err(e) => Lazy::Error(e),
        };
        self.map.insert(key, state);
    }

    /// Forget one key so the next trigger refetches it (manual refresh).
    #[allow(dead_code)]
    pub fn invalidate(&mut self, key: &str) {
        self.map.remove(key);
    }

    /// Every entry, in no particular order — for consumers that aggregate
    /// across keys (the Route 53 Records tab flattens every loaded zone).
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Lazy<T>)> {
        self.map.iter()
    }

    /// How many keys are still in flight.
    pub fn loading_count(&self) -> usize {
        self.map.values().filter(|v| matches!(v, Lazy::Loading)).count()
    }
}

/// The single owner of every [`LazyMap`]. Any subscription
/// switch replaces the whole store with `LazyStore::new(epoch + 1)` — every
/// map clears and every in-flight fetch is invalidated in one move.
///
/// Adding a lazy section = add a field here + a `trigger_*` fn calling
/// `App::trigger_lazy`. No `Event` variant, no `*State` enum, no reset
/// wiring.
#[derive(Default)]
pub struct LazyStore {
    epoch: u64,

    // ── Scoping ──────────────────────────────────────────────────────────
    /// `GET /subscriptions/{id}/locations`, keyed by subscription id: what
    /// the `R` picker merges with the current list's own locations. One
    /// fetch per subscription; resets with the store on a switch.
    pub locations: LazyMap<Vec<crate::azure::location::LocationInfo>>,

    // ── Skeleton ─────────────────────────────────────────────────────────
    /// The stub resource's lazily-fetched detail text, keyed by ARM id.
    /// Exists so the trigger → apply-closure → render path is exercised
    /// end-to-end; the remaining stub services still use it.
    pub stub_details: LazyMap<String>,
}

impl LazyStore {
    /// A fresh store at the given epoch (see the type docs for when).
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            ..Default::default()
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// The payload of the one `Event::Lazy` variant: an epoch-stamped closure
/// that writes a fetch result into its [`LazyMap`]. The single handler arm in
/// `App::handle_event` runs it — or drops it when the epoch is stale.
pub struct LazyApply {
    pub epoch: u64,
    pub apply: Box<dyn FnOnce(&mut crate::app::App) + Send>,
}

impl std::fmt::Debug for LazyApply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyApply")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_maps_ok_to_loaded_and_err_to_error() {
        let mut m: LazyMap<u32> = LazyMap::default();
        m.insert_loading("a".into());
        assert!(matches!(m.get("a"), Some(Lazy::Loading)));
        m.apply("a".into(), Ok(7));
        assert!(matches!(m.get("a"), Some(Lazy::Loaded(7))));
        m.apply("b".into(), Err("denied".into()));
        assert!(matches!(m.get("b"), Some(Lazy::Error(e)) if e == "denied"));
    }

    #[test]
    fn contains_blocks_retrigger_until_invalidated() {
        let mut m: LazyMap<u32> = LazyMap::default();
        m.apply("a".into(), Err("boom".into()));
        assert!(m.contains("a"), "an Error entry must block re-trigger");
        m.invalidate("a");
        assert!(!m.contains("a"), "invalidate must allow a refetch");
    }

    #[test]
    fn new_store_is_empty_at_the_given_epoch() {
        let mut store = LazyStore::new(3);
        store.stub_details.insert_loading("/subscriptions/x".into());
        store = LazyStore::new(store.epoch() + 1);
        assert_eq!(store.epoch(), 4);
        assert!(store.stub_details.get("/subscriptions/x").is_none());
    }
}
