//! The glue for Logic Apps (#159, SERVICES.md rule 49): the section
//! dispatch, a workflow's two lazy reads (its triggers, its latest runs),
//! each outlined before the store keeps it, and the warm lists each side
//! reads of the other (a workflow's connections' status, a connection's
//! workflows). The rows and renderers are `src/azure/services/logic_apps.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::logic_apps::{
    child_path, logic_section_lines, run_outline, trigger_outline, LogicContext, LOGIC_API_VERSION, MAX_RUNS,
    MAX_TRIGGERS,
};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Logic Apps arm of `section_lines_for`; `None` for another type.
    pub(crate) fn logic_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let cx = LogicContext {
            triggers: self.lazy.logic_triggers.get(id),
            runs: self.lazy.logic_runs.get(id),
            connections: self.section_list(JumpView::ApiConnections),
            workflows: self.section_list(JumpView::LogicWorkflows),
        };
        logic_section_lines(resource, idx, &cx)
    }

    /// On-enter hook for a workflow's Triggers.
    pub fn trigger_logic_triggers(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.logic_triggers,
            event_tx,
            |c, id| {
                let fetch = c.list_fetch_query_capped(&child_path(id, "triggers"), LOGIC_API_VERSION, Vec::new(), MAX_TRIGGERS);
                async move { fetch.await.map(|items| items.iter().map(trigger_outline).collect()) }
            },
        );
    }

    /// On-enter hook for a workflow's Runs: the latest [`MAX_RUNS`], newest
    /// first, outcomes only.
    pub fn trigger_logic_runs(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.logic_runs,
            event_tx,
            |c, id| {
                let top = vec![("$top".to_string(), MAX_RUNS.to_string())];
                let fetch = c.list_fetch_query_capped(&child_path(id, "runs"), LOGIC_API_VERSION, top, MAX_RUNS);
                async move { fetch.await.map(|items| items.iter().map(run_outline).collect()) }
            },
        );
    }

    /// On-enter hook for a workflow's Connections: the API connections list.
    pub fn trigger_logic_connection_list(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::ApiConnections, event_tx);
    }

    /// On-enter hook for a connection's Used by and Related: the workflows
    /// list.
    pub fn trigger_logic_workflow_list(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::LogicWorkflows, event_tx);
    }
}
