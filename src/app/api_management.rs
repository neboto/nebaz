//! The glue for API Management (#159, SERVICES.md rule 48): the section
//! dispatch and the four lazy reads per instance (APIs, products,
//! backends, named values), each capped and scrubbed before the store
//! keeps it. The rows and renderers are `src/azure/services/api_management.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::api_management::{
    apim_section_lines, child_path, without_secrets, ApimLazy, APIM_API_VERSION, MAX_CHILDREN,
};
use crate::azure::services::directory::now_unix;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The API Management arm of `section_lines_for`; `None` for another
    /// type.
    pub(crate) fn apim_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let lazy = ApimLazy {
            apis: self.lazy.apim_apis.get(id),
            products: self.lazy.apim_products.get(id),
            backends: self.lazy.apim_backends.get(id),
            named_values: self.lazy.apim_named_values.get(id),
        };
        apim_section_lines(resource, idx, lazy, now_unix())
    }

    /// On-enter hook for an instance's APIs.
    pub fn trigger_apim_apis(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.apim_apis, event_tx, |c, id| scrubbed_list(c, id, "apis"));
    }

    /// On-enter hook for an instance's Products.
    pub fn trigger_apim_products(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.apim_products, event_tx, |c, id| scrubbed_list(c, id, "products"));
    }

    /// On-enter hook for an instance's Backends (and Related, which names
    /// the resources they front).
    pub fn trigger_apim_backends(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.apim_backends, event_tx, |c, id| scrubbed_list(c, id, "backends"));
    }

    /// On-enter hook for an instance's Named values.
    pub fn trigger_apim_named_values(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.apim_named_values, event_tx, |c, id| scrubbed_list(c, id, "namedValues"));
    }
}

/// `GET {service}/{child}`, at most [`MAX_CHILDREN`], scrubbed before the
/// store keeps it.
fn scrubbed_list(
    c: &crate::azure::client::AzureClients,
    id: &str,
    child: &str,
) -> impl std::future::Future<Output = Result<Vec<serde_json::Value>, String>> + Send + 'static {
    let fetch = c.list_fetch_query_capped(&child_path(id, child), APIM_API_VERSION, Vec::new(), MAX_CHILDREN);
    async move { fetch.await.map(|items| items.iter().map(without_secrets).collect()) }
}
