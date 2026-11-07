//! The glue for application security groups (#203, SERVICES.md rule 40):
//! the section dispatch, which reads the current subscription's NICs and
//! NSGs (warm, or loaded for the section), and the hooks that load them.
//! The rows and renderers are `src/azure/services/network_asg.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::network_asg::asg_section_lines;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The ASG arm of `section_lines_for`; `None` for another type.
    pub(crate) fn asg_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        asg_section_lines(resource, idx, self.section_list(JumpView::Nics), self.section_list(JumpView::NetworkSecurityGroups))
    }

    /// On-enter hook for an ASG's Members: the NICs list, unless warm.
    pub fn trigger_asg_members(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::Nics, event_tx);
    }

    /// On-enter hook for an ASG's Rules: the NSGs list, unless warm.
    pub fn trigger_asg_rules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::NetworkSecurityGroups, event_tx);
    }

    /// On-enter hook for an ASG's Related, which names both.
    pub fn trigger_asg_joins(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        Self::trigger_asg_members(app, event_tx);
        Self::trigger_asg_rules(app, event_tx);
    }
}
