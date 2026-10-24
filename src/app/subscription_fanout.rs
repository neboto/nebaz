// ported from neboto-tui src/app.rs @ 7fbf5ed (the `R` fan-out:
// start_region_fanout, handle_region_fanout_loaded, region_counts,
// region_count_label; regions → subscriptions, `buffer_unordered` → a
// semaphore, the generation → a `ListLoad` that also aborts)
//! The `P` fan-out (#62): with config `subscriptions` set, opening `P`
//! lists the current sub-tab in each configured subscription that has no
//! fresh cache entry, a few at a time, each straight into its own
//! `(service, subscription, sub-tab)` cache slot, and the picker shows the
//! row count per subscription. Picking one is then a cache hit. Nothing is
//! fetched without config `subscriptions`, and nothing for a sub-tab whose
//! rows don't depend on the subscription (`JumpView::fans_out`).
//!
//! `nebaz ls --subscriptions` drives the same fan-out headlessly.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::{AzureService, JumpView};
use crate::event::Event;
use crate::ui::widgets::subscription_selector::SubscriptionCount;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Subscriptions listed at once. ARM's read budget is per subscription
/// (and per tenant pipeline token), so they parallelise, but a sub-tab can
/// be several calls and a working set can be dozens of subscriptions.
pub(crate) const SUBSCRIPTION_FANOUT: usize = 4;

/// One fan-out slot that is loading or failed: its count, and the failure's
/// message. A success *is* the cache entry, so it expires with the TTL.
pub(crate) type FanoutStatus = (SubscriptionCount, Option<String>);

impl App {
    /// Config `subscriptions` against the account list (again after an
    /// auth retry). The warning names entries `az account list` doesn't
    /// know; none while not logged in, when it knows nothing.
    pub(crate) fn resolve_configured_subscriptions(&mut self) -> Option<String> {
        let wanted = self.config.subscriptions.clone().unwrap_or_default();
        let (ids, unknown) = self.azure_clients.resolve_configured(&wanted);
        self.configured_subscriptions = ids;
        (!unknown.is_empty() && !self.azure_clients.subscriptions().is_empty())
            .then(|| format!("subscriptions: unknown subscription {}", unknown.join(", ")))
    }

    /// The sub-tab the `P` picker counts across config `subscriptions`, if
    /// any.
    pub(crate) fn fanout_view(&self) -> Option<JumpView> {
        (!self.configured_subscriptions.is_empty()
            && !self.all_search_mode
            && self.current_service.is_some()
            && self.current_view.fans_out())
        .then_some(self.current_view)
    }

    /// Opening `P`: list the current sub-tab in every configured
    /// subscription that needs it (see [`App::fanout_subscriptions`]).
    pub(crate) fn start_subscription_fanout(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(view) = self.fanout_view() else {
            return;
        };
        if self.auth_error.is_some() {
            return;
        }
        let targets = self.configured_subscriptions.clone();
        self.fanout_subscriptions(view, &targets, event_tx);
    }

    /// List `view` in each of `targets`, [`SUBSCRIPTION_FANOUT`] at a time,
    /// skipping the current subscription (the normal load's), a fresh cache
    /// slot, a slot already loading, and one that said `denied` or
    /// `disabled` (neither lifts between two presses; a plain failure is
    /// retried). A subscription that isn't `Enabled` is marked `disabled`
    /// without a call. Returns how many lists started.
    pub(crate) fn fanout_subscriptions(
        &mut self,
        view: JumpView,
        targets: &[String],
        event_tx: &mpsc::UnboundedSender<Event>,
    ) -> usize {
        let service = view.service();
        let generation = self.fanout_load.generation();
        self.fanout_load.tasks.retain(|t| !t.is_finished());
        let permits = Arc::new(tokio::sync::Semaphore::new(SUBSCRIPTION_FANOUT));
        let mut started = 0;
        for sub in targets {
            if self.subscription_id.as_deref() == Some(sub.as_str())
                || self.cache.get_ref(&service, sub, Some(view.as_str())).is_some()
            {
                continue;
            }
            let key = (view, sub.clone());
            if matches!(
                self.subscription_fanout.get(&key),
                Some((SubscriptionCount::Loading | SubscriptionCount::Denied | SubscriptionCount::Disabled, _))
            ) {
                continue;
            }
            let Some(entry) = self.azure_clients.resolve_subscription(sub) else {
                continue;
            };
            if !entry.is_enabled() {
                let why = format!("subscription is {}", entry.state.to_lowercase());
                self.subscription_fanout.insert(key, (SubscriptionCount::Disabled, Some(why)));
                continue;
            }
            let Some(provider) = self.azure_clients.service_in(service, sub) else {
                continue;
            };
            self.subscription_fanout.insert(key, (SubscriptionCount::Loading, None));
            let tx = event_tx.clone();
            let permits = permits.clone();
            let subscription = sub.clone();
            let task = tokio::spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else {
                    return;
                };
                // Partial-load warnings are dropped: the rows still count,
                // and switching there reloads nothing, so `r` shows them.
                let result = collect_list(provider, view).await.map(|(rows, _)| rows);
                let _ = tx.send(Event::SubscriptionFanoutLoaded {
                    generation,
                    view,
                    subscription,
                    result,
                });
            });
            self.fanout_load.track(task.abort_handle());
            started += 1;
        }
        started
    }

    /// Retire the fan-out: an auth retry may change what each
    /// subscription returns. Its late results are dropped, its tasks
    /// aborted (#57's rule for list loads).
    pub(crate) fn supersede_fanout(&mut self) {
        self.fanout_load.supersede();
        self.subscription_fanout.clear();
    }

    pub(crate) fn handle_subscription_fanout_loaded(
        &mut self,
        generation: u64,
        view: JumpView,
        subscription: String,
        result: std::result::Result<Vec<Box<dyn Resource>>, String>,
    ) {
        if generation != self.fanout_load.generation() {
            return;
        }
        let key = (view, subscription);
        match result {
            Ok(rows) => {
                self.subscription_fanout.remove(&key);
                let (view, subscription) = key;
                self.cache
                    .insert(view.service(), &subscription, Some(view.as_str().to_string()), rows);
            }
            Err(e) => {
                self.subscription_fanout.insert(key, (SubscriptionCount::from_error(&e), Some(e)));
            }
        }
    }

    /// One slot's fan-out state, when it is loading or failed.
    pub(crate) fn fanout_status(&self, view: JumpView, subscription: &str) -> Option<&FanoutStatus> {
        self.subscription_fanout.get(&(view, subscription.to_string()))
    }

    /// What the `P` picker shows beside each configured subscription (and
    /// the current one): the active sub-tab's rows there, from that
    /// subscription's cache slot, or the fan-out's status. Nothing for a
    /// subscription that hasn't been listed: never a `0`.
    pub fn subscription_counts(&self) -> HashMap<String, SubscriptionCount> {
        let mut out = HashMap::new();
        let Some(view) = self.fanout_view() else {
            return out;
        };
        let service = view.service();
        let subs = self.subscription_id.iter().chain(self.configured_subscriptions.iter());
        for sub in subs {
            if let Some((count, _)) = self.fanout_status(view, sub) {
                out.insert(sub.clone(), *count);
            } else if let Some(rows) = self.cache.get_ref(&service, sub, Some(view.as_str())) {
                out.insert(sub.clone(), SubscriptionCount::Count(rows.len()));
            }
        }
        out
    }

    /// What `subscription_counts` counts, for the picker's title.
    pub fn subscription_count_label(&self) -> Option<String> {
        let view = self.fanout_view()?;
        Some(if view.service().views().len() > 1 {
            format!("{} {}", view.service().short_name(), view.label())
        } else {
            view.label().to_string()
        })
    }
}

/// Run one sub-tab's list load to completion off the app, collecting every
/// streamed page the way `handle_stream_event` would: a whole-list event
/// replaces, a page extends, a load error fails it, a phase warning is
/// returned alongside the rows. Providers send synchronously before their
/// stream returns, so the channel is complete once it has.
pub(crate) async fn collect_list(
    provider: Arc<dyn AzureService>,
    view: JumpView,
) -> std::result::Result<(Vec<Box<dyn Resource>>, Vec<String>), String> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let outcome = provider.list_resources_streaming(view, tx, view.service()).await;
    let mut rows: Vec<Box<dyn Resource>> = Vec::new();
    let mut warnings = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        match ev {
            Event::ResourcesLoaded { resources, .. } => rows = resources,
            Event::ResourcesPartiallyLoaded { resources, .. } => rows.extend(resources),
            Event::ResourceLoadError { error, auth, .. } => {
                return Err(auth.map(|a| a.status_line()).unwrap_or(error));
            }
            Event::ResourceLoadWarning { warning, .. } => warnings.push(warning),
            _ => {}
        }
    }
    outcome.map_err(|e| e.to_string())?;
    Ok((rows, warnings))
}
