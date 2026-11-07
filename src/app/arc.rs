//! The glue for Azure Arc (#199, SERVICES.md rule 45): the section
//! dispatch and the one lazy read, an Arc server's extensions. The rows
//! and renderers are `src/azure/services/arc.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::arc::{arc_section_lines, extensions_path, without_settings, HYBRID_COMPUTE_API_VERSION};
use crate::azure::services::directory::now_unix;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Arc arm of `section_lines_for`; `None` for another type.
    pub(crate) fn arc_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        arc_section_lines(resource, idx, self.lazy.arc_extensions.get(resource.id()), now_unix())
    }

    /// On-enter hook for an Arc server's Extensions, settings stripped
    /// before the store keeps them.
    pub fn trigger_arc_extensions(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.arc_extensions,
            event_tx,
            |c, id| {
                let fetch = c.list_fetch(&extensions_path(id), HYBRID_COMPUTE_API_VERSION);
                async move { fetch.await.map(|items| items.iter().map(without_settings).collect()) }
            },
        );
    }
}
