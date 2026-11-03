//! The glue for the Defender tab (#156, ADR 0010): the section dispatch,
//! which reads the warm Recommendations list (a recommendation's other
//! resources, a control's unhealthy recommendations), and the hook that
//! loads that list when its sub-tab has not been opened. The rows and
//! renderers are `src/azure/services/defender.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::defender::defender_section_lines;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Defender arm of `section_lines_for`; `None` for another type.
    pub(crate) fn defender_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        defender_section_lines(resource, idx, self.section_list(JumpView::DefenderRecommendations))
    }

    /// On-enter hook for a recommendation's Resources and a control's
    /// Recommendations.
    pub fn trigger_defender_recommendations(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::DefenderRecommendations, event_tx);
    }
}
