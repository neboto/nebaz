//! The glue for AI Search (#196, SERVICES.md rule 38): the section
//! dispatch and the one lazy read per service, its shared private links.
//! The rows and renderers are `src/azure/services/ai_search.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::services::ai_search::{search_section_lines, shared_links_path, SEARCH_API_VERSION};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The search service arm of `section_lines_for`; `None` for another
    /// type.
    pub(crate) fn ai_search_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        search_section_lines(resource, idx, self.lazy.search_shared_links.get(resource.id()))
    }

    /// On-enter hook for a service's Shared private links (and Related,
    /// which names their targets): one list per service.
    pub fn trigger_search_shared_links(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.search_shared_links,
            event_tx,
            |c, id| c.list_fetch(&shared_links_path(id), SEARCH_API_VERSION),
        );
    }
}
