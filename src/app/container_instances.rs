//! The glue for Container Instances (#197, SERVICES.md rule 39): the
//! section dispatch, which pairs each registry server with its warm ACR
//! row, and the one lazy read per group, its own `GET` (the instance
//! views the list leaves out). The rows and renderers are
//! `src/azure/services/container_instances.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::container_instances::{
    container_group_section_lines, without_secrets, ContainerGroupRow, ACI_API_VERSION,
};
use crate::azure::services::container_registry::RegistryRow;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The container group arm of `section_lines_for`; `None` for another
    /// type.
    pub(crate) fn container_group_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let group = resource.as_any().downcast_ref::<ContainerGroupRow>()?;
        let registry_ids: Vec<(String, String)> = self
            .warm_list(group.id(), JumpView::Registries)
            .unwrap_or_default()
            .iter()
            .filter_map(|r| r.as_any().downcast_ref::<RegistryRow>())
            .filter_map(|r| Some((r.login_server.clone()?, r.id().to_string())))
            .collect();
        container_group_section_lines(resource, idx, self.lazy.aci_instance_views.get(group.id()), &registry_ids)
    }

    /// On-enter hook for a group's Containers: `GET {group}`, scrubbed
    /// before the store keeps it.
    pub fn trigger_aci_instance_view(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.aci_instance_views,
            event_tx,
            |c, id| {
                let fetch = c.get_fetch(id, ACI_API_VERSION);
                async move { fetch.await.map(|v| without_secrets(&v)) }
            },
        );
    }
}
