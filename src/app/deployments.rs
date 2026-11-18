//! The glue for Deployments (#225, SERVICES.md rule 47): the section
//! dispatch and the lazy reads (a deployment's Operations, a template
//! spec's Versions). The rows and renderers are
//! `src/azure/services/{deployments,deployment_stacks}.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::deployment_stacks::{
    stack_section_lines, template_spec_section_lines, version_summary, versions_path, MAX_VERSIONS,
    TEMPLATE_SPECS_API_VERSION,
};
use crate::azure::services::deployments::{deployment_section_lines, operations_path, without_values, MAX_OPERATIONS};
use crate::azure::timeline::DEPLOYMENTS_API_VERSION;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The deployment arm of `section_lines_for`; `None` for another type.
    pub(crate) fn deployment_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        deployment_section_lines(resource, idx, self.lazy.deployment_operations.get(resource.id()))
            .or_else(|| stack_section_lines(resource, idx))
            .or_else(|| template_spec_section_lines(resource, idx, self.lazy.template_spec_versions.get(resource.id())))
    }

    /// On-enter hook for a template spec's Versions: `{spec}/versions`,
    /// capped, each reduced to its summary before it is kept.
    pub fn trigger_template_spec_versions(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.template_spec_versions,
            event_tx,
            |c, id| {
                let fetch = c.list_fetch_query_capped(&versions_path(id), TEMPLATE_SPECS_API_VERSION, Vec::new(), MAX_VERSIONS);
                async move { fetch.await.map(|versions| versions.iter().map(version_summary).collect()) }
            },
        );
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
