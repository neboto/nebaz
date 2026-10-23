// copy-adapted from neboto-tui src/ui/widgets/details_pane/mod.rs @ 03760c0
// (`render_ownership_ribbon`: one central hook, half-pane budget); the
// deployment trigger is new in nebaz
//! The ownership ribbon (#48) on `App`: what it says for the selected row
//! (`azure::ownership` resolves it), and `ownership_tick`, which fires the
//! one lazy call behind it, the resource group's deployments, when the
//! detail pane is focused on a row in a group. The drawing is one line in
//! `details_pane.rs` (the top border, right-aligned).

use super::App;
use crate::azure::ownership::{fetch_rg_deployments, managed_by_of, resource_ownership};
use crate::azure::resource::{arm_type_chain, resource_group_id_of};
use crate::event::Event;
use crate::lazy::Lazy;
use tokio::sync::mpsc;

/// The group id a row's deployments are read from: a resource below a
/// provider inside a group (a group, a subscription or a directory row has
/// none). Lowercased: the lazy key.
fn deployments_key(id: &str) -> Option<String> {
    arm_type_chain(id)?;
    resource_group_id_of(id).map(|rg| rg.to_lowercase())
}

/// What the ribbon says, one part each.
#[derive(Debug, Clone, PartialEq)]
pub struct Ribbon {
    pub parts: Vec<String>,
    /// The deployment lookup failed (the last part is its `⚠` text).
    pub warning: bool,
}

impl Ribbon {
    pub fn text(&self) -> String {
        format!("⛓ {}", self.parts.join(" · "))
    }
}

impl App {
    /// The selected row's ARM `managedBy`, parsed from its raw body once
    /// per row (the ribbon asks every frame).
    fn selected_managed_by(&self) -> Option<String> {
        let r = self.get_selected_resource()?;
        let mut memo = self.managed_by_memo.borrow_mut();
        if let Some((id, m)) = memo.as_ref() {
            if id == r.id() {
                return m.clone();
            }
        }
        let m = managed_by_of(r);
        *memo = Some((r.id().to_string(), m.clone()));
        m
    }

    /// The ribbon for the selected row, or `None` when it is off or has
    /// nothing to say. Tags and `managedBy` always; the deployment once the
    /// group's list has landed (`⧗` while it loads, `⚠` if it failed).
    pub fn ownership_ribbon(&self) -> Option<Ribbon> {
        if !self.ownership_ribbon {
            return None;
        }
        let r = self.get_selected_resource()?;
        let managed_by = self.selected_managed_by();
        let mut parts = resource_ownership(r.tags(), managed_by, &self.ownership_tags).parts();
        let mut warning = false;
        if let Some(key) = deployments_key(r.id()) {
            match self.lazy.rg_deployments.get(&key) {
                Some(Lazy::Loaded(d)) => {
                    if let Some(dep) = d.last_for(r.id()) {
                        parts.push(dep.describe());
                    }
                }
                Some(Lazy::Loading) => parts.push("⧗ deployments".into()),
                Some(Lazy::Error(e)) => {
                    let first = e.lines().next().unwrap_or("").trim();
                    let short: String = first.chars().take(60).collect();
                    parts.push(format!("⚠ deployments: {}", short));
                    warning = true;
                }
                None => {}
            }
        }
        (!parts.is_empty()).then_some(Ribbon { parts, warning })
    }

    /// Once per main-loop pass: with the pane focused on a row in a
    /// resource group, read that group's deployments (one lazy call per
    /// group per subscription visit; a present key is a no-op).
    pub fn ownership_tick(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if !self.ownership_ribbon || !self.details_focused {
            return;
        }
        let Some(key) = self.get_selected_resource().and_then(|r| deployments_key(r.id())) else {
            return;
        };
        if self.lazy.rg_deployments.contains(&key) {
            return;
        }
        let arm = self.azure_clients.arm_for_path(&key);
        let rg = key.clone();
        self.trigger_lazy(|s| &mut s.rg_deployments, key, event_tx, move || async move {
            fetch_rg_deployments(arm?, rg).await
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_resources_inside_a_group_have_a_deployments_key() {
        assert_eq!(
            deployments_key("/subscriptions/0/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm").as_deref(),
            Some("/subscriptions/0/resourcegroups/rg")
        );
        assert_eq!(deployments_key("/subscriptions/0/resourceGroups/rg"), None);
        assert_eq!(deployments_key("/subscriptions/0"), None);
        assert_eq!(deployments_key("graph:/servicePrincipals/x"), None);
    }
}
