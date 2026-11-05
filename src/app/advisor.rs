//! The glue for the Advisor tab (#157, ADR 0011): the section dispatch,
//! which reads the warm Recommendations list (a recommendation's other
//! resources, a score's recommendations), and the hook that loads that
//! list when its sub-tab has not been opened. The rows and renderers are
//! `src/azure/services/advisor.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::advisor::advisor_section_lines;
use crate::azure::services::directory::now_unix;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Advisor arm of `section_lines_for`; `None` for another type.
    pub(crate) fn advisor_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        advisor_section_lines(resource, idx, self.section_list(JumpView::AdvisorRecommendations), now_unix())
    }

    /// On-enter hook for a recommendation's Resources and a score's
    /// Recommendations.
    pub fn trigger_advisor_recommendations(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::AdvisorRecommendations, event_tx);
    }
}
