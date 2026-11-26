//! The glue for Event Grid (#159, SERVICES.md rule 50): the section
//! dispatch and the two lazy reads (a parent's event subscriptions, a
//! domain's topics), each outlined before the store keeps it. The rows and
//! renderers are `src/azure/services/event_grid.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::event_grid::{
    domain_topic_outline, event_grid_section_lines, subscription_outline, subscriptions_path, EventGridContext,
    EVENT_GRID_API_VERSION, MAX_DOMAIN_TOPICS, MAX_SUBSCRIPTIONS,
};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Event Grid arm of `section_lines_for`; `None` for another type.
    pub(crate) fn event_grid_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let cx = EventGridContext {
            subscriptions: self.lazy.eg_subscriptions.get(id),
            domain_topics: self.lazy.eg_domain_topics.get(id),
        };
        event_grid_section_lines(resource, idx, &cx)
    }

    /// On-enter hook for Subscriptions on a topic, system topic or domain.
    pub fn trigger_eg_subscriptions(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.eg_subscriptions, event_tx, eg_subscriptions_fetch);
    }

    /// On-enter hook for a domain's Topics.
    pub fn trigger_eg_domain_topics(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.eg_domain_topics,
            event_tx,
            |c, id| {
                let path = format!("{}/topics", id.trim_end_matches('/'));
                let top = vec![("$top".to_string(), "100".to_string())];
                let fetch = c.list_fetch_query_capped(&path, EVENT_GRID_API_VERSION, top, MAX_DOMAIN_TOPICS);
                async move { fetch.await.map(|items| items.iter().map(domain_topic_outline).collect()) }
            },
        );
    }

    /// `@audit`'s read for `eventgrid-subscription-delivery`: each cached
    /// parent's event subscriptions, through the section's own map.
    pub(crate) fn trigger_eg_subscriptions_for(&mut self, id: String, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = eg_subscriptions_fetch(&self.azure_clients, &id);
        self.trigger_lazy(|s| &mut s.eg_subscriptions, id, event_tx, move || fut);
    }
}

/// A parent's event subscriptions, the first [`MAX_SUBSCRIPTIONS`],
/// outlined.
fn eg_subscriptions_fetch(
    c: &crate::azure::client::AzureClients,
    id: &str,
) -> impl std::future::Future<Output = std::result::Result<Vec<serde_json::Value>, String>> + Send + 'static {
    let top = vec![("$top".to_string(), MAX_SUBSCRIPTIONS.to_string())];
    let fetch = c.list_fetch_query_capped(&subscriptions_path(id), EVENT_GRID_API_VERSION, top, MAX_SUBSCRIPTIONS);
    async move { fetch.await.map(|items| items.iter().map(subscription_outline).collect()) }
}
