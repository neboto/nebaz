//! The glue for the Governance tab (#155, ADR 0009): the section dispatch,
//! which reads the current subscription's governance lists (an
//! assignment's definition and exemptions, a definition's assignments),
//! and the lazy reads behind it: a built-in definition by id, and a list
//! whose sub-tab has not been opened, loaded for the section. The rows and
//! renderers are `src/azure/services/governance.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::governance::{
    governance_section_lines, is_builtin_definition, GovernanceContext, PolicyAssignmentRow, Warm, POLICY_API_VERSION,
};
use crate::event::Event;
use crate::lazy::Lazy;
use tokio::sync::mpsc;

impl App {
    /// A governance list of the current subscription, the one every
    /// governance row was found through whatever scope it was made at: the
    /// list cache, else what a section loaded.
    fn governance_list(&self, view: JumpView) -> Warm<'_> {
        let Some(sub) = self.subscription_id.as_deref() else {
            return Warm::Cold;
        };
        if let Some(rows) = self.cache.get_ref(&ServiceType::Governance, sub, Some(view.as_str())) {
            return Warm::Rows(rows);
        }
        match self.lazy.governance_lists.get(&format!("{}|{}", sub, view.as_str())) {
            Some(Lazy::Loaded(rows)) => Warm::Rows(rows),
            Some(Lazy::Loading) => Warm::Loading,
            Some(Lazy::Error(e)) => Warm::Failed(e),
            None => Warm::Cold,
        }
    }

    /// Load a cold governance list for a section, through the provider's
    /// own list call. A cached or already-triggered list is left alone.
    fn trigger_governance_list(&mut self, view: JumpView, event_tx: &mpsc::UnboundedSender<Event>) {
        if !matches!(self.governance_list(view), Warm::Cold) {
            return;
        }
        let Some(sub) = self.subscription_id.clone() else {
            return;
        };
        let provider = self.azure_clients.service(ServiceType::Governance);
        let key = format!("{}|{}", sub, view.as_str());
        self.trigger_lazy(|s| &mut s.governance_lists, key, event_tx, move || async move {
            provider.list_resources(view).await.map_err(|e| e.to_string())
        });
    }

    /// The governance arm of `section_lines_for`; `None` for another type.
    pub(crate) fn governance_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let builtin = resource
            .as_any()
            .downcast_ref::<PolicyAssignmentRow>()
            .and_then(|a| a.definition_id.as_deref())
            .and_then(|d| self.lazy.policy_definitions.get(d));
        let cx = GovernanceContext {
            assignments: self.governance_list(JumpView::PolicyAssignments),
            exemptions: self.governance_list(JumpView::PolicyExemptions),
            definitions: self.governance_list(JumpView::PolicyDefinitions),
            builtin_definition: builtin,
        };
        governance_section_lines(resource, idx, &cx)
    }

    /// On-enter hook for an assignment's Definition: a built-in is read by
    /// id (readable by anyone); a custom one comes from the Definitions
    /// list, never a GET at the management group (ADR 0009, decision 2).
    pub fn trigger_policy_definition(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(def) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<PolicyAssignmentRow>())
            .and_then(|a| a.definition_id.clone())
        else {
            return;
        };
        if !is_builtin_definition(&def) {
            app.trigger_governance_list(JumpView::PolicyDefinitions, event_tx);
            return;
        }
        let fut = app.azure_clients.get_fetch(&def, POLICY_API_VERSION);
        app.trigger_lazy(|s| &mut s.policy_definitions, def, event_tx, move || fut);
    }

    /// On-enter hook for an assignment's Exemptions.
    pub fn trigger_policy_exemptions(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_governance_list(JumpView::PolicyExemptions, event_tx);
    }

    /// On-enter hook for a definition's Assignments.
    pub fn trigger_policy_assignments(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_governance_list(JumpView::PolicyAssignments, event_tx);
    }
}
