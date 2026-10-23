//! The ownership ribbon (#48): tags and ARM's `managedBy` with zero calls,
//! the group's deployments fetched once when the pane is focused (the
//! harness lands them by hand), a failed lookup as `⚠` text, the
//! `managedBy` line in Related that `⏎` follows, and `ownership_ribbon =
//! false`.

use super::mocks::{arm_id, RG};
use super::*;
use crate::azure::ownership::RgDeployments;
use crate::azure::services::compute::VmRow;
use serde_json::json;

/// `vm-own`: owner and Terraform tags, managed by `aks-1`.
fn owned_vm() -> Box<dyn Resource> {
    Box::new(
        VmRow::from_json(
            &json!({"id": arm_id("Microsoft.Compute/virtualMachines/vm-own"), "name": "vm-own", "location": "westeurope",
                "tags": {"Owner": "alice", "managed-by": "terraform"},
                "managedBy": arm_id("Microsoft.ContainerService/managedClusters/aks-1"),
                "properties": {"provisioningState": "Succeeded"}}),
            Some(TENANT),
        )
        .unwrap(),
    )
}

fn rg_key() -> String {
    format!("/subscriptions/{}/resourcegroups/{}", SUB_DEV, RG).to_lowercase()
}

/// The ribbon's text on screen (the top border row of the detail pane).
fn ribbon(h: &mut Harness) -> String {
    let screen = h.render();
    screen.lines().find(|l| l.contains('⛓')).unwrap_or("").to_string()
}

#[tokio::test]
async fn the_ribbon_reads_tags_and_managed_by_then_the_deployment_once_focused() {
    let mut h = Harness::new().await;
    h.install(mocks::Mock { view: JumpView::VirtualMachines, label: "VmRow", resource: owned_vm() }).await;

    // Unfocused: tags and managedBy only, no call.
    assert!(!h.app.lazy.rg_deployments.contains(&rg_key()), "nothing is read until the pane is focused");
    let text = h.app.ownership_ribbon().expect("a ribbon").text();
    assert_eq!(text, "⛓ managed by aks-1 · terraform · owner alice");
    assert!(ribbon(&mut h).contains("managed by aks-1 · terraform · owner alice"), "{}", h.render());

    // Focused: one lazy read of the group's deployments.
    h.press(KeyCode::Enter).await;
    assert!(h.app.lazy.rg_deployments.contains(&rg_key()));
    assert!(h.app.ownership_ribbon().unwrap().text().ends_with("· ⧗ deployments"));
    assert!(ribbon(&mut h).contains("⛓ managed by"), "the ribbon is cut to the border, never dropped");

    let rows = vec![json!({"name": "main", "properties": {"timestamp": "2026-10-20T14:03:11Z", "provisioningState": "Succeeded",
        "outputResources": [{"id": arm_id("Microsoft.Compute/virtualMachines/vm-own")}]}})];
    h.app.lazy.rg_deployments.apply(rg_key(), Ok(RgDeployments::from_parts(&rows, Default::default(), Vec::new())));
    h.settle().await;
    assert_eq!(
        h.app.ownership_ribbon().unwrap().text(),
        "⛓ managed by aks-1 · terraform · owner alice · deployed by main 2026-10-20 14:03"
    );

    // managedBy is a Related line, so ⏎ goes there (an unbrowsed cluster id
    // lands in its typed tab, AKS).
    let idx = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    h.cursor_to_value(&arm_id("Microsoft.ContainerService/managedClusters/aks-1")).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::Clusters);
}

#[tokio::test]
async fn a_failed_lookup_is_a_warning_on_the_ribbon_and_the_config_can_hide_it() {
    let mut h = Harness::new().await;
    h.install(mocks::Mock { view: JumpView::VirtualMachines, label: "VmRow", resource: owned_vm() }).await;
    h.press(KeyCode::Enter).await;
    h.app.lazy.rg_deployments.apply(rg_key(), Err("403 AuthorizationFailed\nmore".into()));
    h.settle().await;
    let r = h.app.ownership_ribbon().unwrap();
    assert!(r.warning);
    assert!(r.text().ends_with("⚠ deployments: 403 AuthorizationFailed"), "{}", r.text());

    // Off: no ribbon, and no call for another group's row.
    h.app.ownership_ribbon = false;
    assert!(h.app.ownership_ribbon().is_none());
    assert!(!h.render().contains('⛓'));
    h.app.lazy = crate::lazy::LazyStore::new(h.app.lazy.epoch() + 1);
    h.settle().await;
    assert!(!h.app.lazy.rg_deployments.contains(&rg_key()));
}

#[tokio::test]
async fn a_row_without_ownership_and_with_no_group_has_no_ribbon() {
    let mut h = Harness::new().await;
    let sub = mocks::all_mocks().into_iter().find(|m| m.view == JumpView::Subscriptions).unwrap();
    h.install(sub).await;
    h.press(KeyCode::Enter).await;
    assert!(h.app.ownership_ribbon().is_none());
    assert!(h.app.lazy.rg_deployments.iter().next().is_none(), "a subscription has no group to read");
}
