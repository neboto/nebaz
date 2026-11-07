//! The glue for Static Web Apps (#200, SERVICES.md rule 43): the section
//! dispatch and the three lazy reads per site, its environments, custom
//! domains and linked backends. The rows and renderers are
//! `src/azure/services/static_web_apps.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::app_service::WEB_API_VERSION;
use crate::azure::services::static_web_apps::{site_child_path, static_site_section_lines, without_secrets};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The static web app arm of `section_lines_for`; `None` for another
    /// type.
    pub(crate) fn static_site_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        static_site_section_lines(
            resource,
            idx,
            self.lazy.swa_builds.get(id),
            self.lazy.swa_domains.get(id),
            self.lazy.swa_backends.get(id),
        )
    }

    /// On-enter hook for a site's Environments: one list per site.
    pub fn trigger_swa_builds(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.swa_builds, event_tx, |c, id| scrubbed_list(c, id, "builds"));
    }

    /// On-enter hook for a site's Custom domains: one list per site.
    pub fn trigger_swa_domains(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.swa_domains, event_tx, |c, id| scrubbed_list(c, id, "customDomains"));
    }

    /// On-enter hook for a site's Backends (and Related, which names
    /// them): one list per site.
    pub fn trigger_swa_backends(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(|s| &mut s.swa_backends, event_tx, |c, id| scrubbed_list(c, id, "linkedBackends"));
    }
}

/// `GET {site}/{child}`, scrubbed before the store keeps it.
fn scrubbed_list(
    c: &crate::azure::client::AzureClients,
    id: &str,
    child: &str,
) -> impl std::future::Future<Output = Result<Vec<serde_json::Value>, String>> + Send + 'static {
    let fetch = c.list_fetch(&site_child_path(id, child), WEB_API_VERSION);
    async move { fetch.await.map(|items| items.iter().map(without_secrets).collect()) }
}
