//! The glue for Deployments (#225, SERVICES.md rule 47): the section
//! dispatch and the lazy Operations read. The rows and renderers are
//! `src/azure/services/deployments.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::deployments::{deployment_section_lines, operations_path, without_values, MAX_OPERATIONS};
use crate::azure::timeline::DEPLOYMENTS_API_VERSION;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The deployment arm of `section_lines_for`; `None` for another type.
    pub(crate) fn deployment_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        deployment_section_lines(resource, idx, self.lazy.deployment_operations.get(resource.id()))
    }

    /// On-enter hook for Operations: `{deployment}/operations`, capped,
    /// without each operation's request and response bodies.
    pub fn trigger_deployment_operations(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.deployment_operations,
            event_tx,
            |c, id| {
                let fetch = c.list_fetch_query_capped(&operations_path(id), DEPLOYMENTS_API_VERSION, Vec::new(), MAX_OPERATIONS);
                async move { fetch.await.map(|ops| ops.iter().map(without_values).collect()) }
            },
        );
    }
}
