//! Deployments (#225): the groups' batches land in any order and the list
//! reads newest first; Operations fires its read, and a failed operation's
//! resource is a jump to its typed tab.

use super::mocks::arm_id;
use super::*;
use crate::azure::services::deployments::DeploymentRow;
use crate::lazy::Lazy;
use serde_json::json;

fn deployment(name: &str, timestamp: &str, state: &str) -> Box<dyn Resource> {
    let v = json!({"id": arm_id(&format!("Microsoft.Resources/deployments/{name}")), "name": name,
        "properties": {"provisioningState": state, "timestamp": timestamp}});
    Box::new(DeploymentRow::from_json(&v, None).unwrap())
}

#[tokio::test]
async fn batches_read_newest_first_and_a_failed_operation_jumps_to_its_resource() {
    let mut h = Harness::new().await;
    h.open(JumpView::GroupDeployments).await;
    h.land_page(vec![deployment("older", "2026-10-01T08:00:00Z", "Succeeded")]).await;
    h.land_page(vec![
        deployment("oldest", "2026-09-01T08:00:00Z", "Succeeded"),
        deployment("newest", "2026-11-01T08:00:00Z", "Failed"),
    ])
    .await;
    h.finish().await;
    assert_eq!(h.visible_names(), ["newest", "older", "oldest"]);

    let id = arm_id("Microsoft.Resources/deployments/newest");
    let vm_id = arm_id("Microsoft.Compute/virtualMachines/vm-web");
    // The selection stays on the row that landed first; the newest is above it.
    h.press(KeyCode::Char('k')).await;
    assert_eq!(h.selected_id().as_deref(), Some(id.as_str()));
    h.press(KeyCode::Enter).await;
    let operations = h.section_labels().iter().position(|l| *l == "Operations").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(operations).unwrap())).await;
    assert!(matches!(h.app.lazy.deployment_operations.get(&id), Some(Lazy::Loading)), "the operations read fired");

    let ops = vec![json!({"properties": {"provisioningOperation": "Create", "provisioningState": "Failed",
        "statusCode": "Conflict", "statusMessage": {"error": {"code": "SkuNotAvailable", "message": "no capacity"}},
        "targetResource": {"id": vm_id, "resourceType": "Microsoft.Compute/virtualMachines"}}})];
    h.app.lazy.deployment_operations.apply(id.clone(), Ok(ops));
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "  Error" && v == "SkuNotAvailable: no capacity"));
    h.cursor_to_value(&vm_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines));
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
}

#[tokio::test]
async fn a_change_row_s_deployment_link_lands_in_the_deployments_tab() {
    let id = arm_id("Microsoft.Resources/deployments/main");
    assert_eq!(JumpView::landing_for_arm_id(&id), Some(JumpView::GroupDeployments));
    let row = crate::azure::timeline::TimelineRow::from_deployment(
        &json!({"id": id, "name": "main", "properties": {"provisioningState": "Succeeded", "timestamp": "2026-11-01T08:00:00Z"}}),
    );
    assert_eq!(row.links[0], ("Deployment · main".to_string(), id));
}

#[tokio::test]
async fn a_stack_s_resource_is_a_jump_and_the_ribbon_names_the_stack_once_the_list_is_warm() {
    use crate::azure::services::deployment_stacks::StackRow;
    let vm_id = arm_id("Microsoft.Compute/virtualMachines/vm-web");
    let vm = || -> Box<dyn Resource> {
        let v = json!({"id": vm_id, "name": "vm-web", "location": "westeurope", "properties": {}});
        Box::new(crate::azure::services::compute::VmRow::from_json(&v, None).unwrap())
    };
    let mut h = Harness::new().await;
    h.app.ownership_ribbon = true;

    // Before the Stacks list was ever opened the ribbon has nothing to say.
    h.open(JumpView::VirtualMachines).await;
    h.land_page(vec![vm()]).await;
    h.finish().await;
    assert!(!h.app.ownership_ribbon().is_some_and(|r| r.text().contains("in stack")));

    h.open(JumpView::DeploymentStacks).await;
    let stack = json!({"id": arm_id("Microsoft.Resources/deploymentStacks/orders"), "name": "orders",
        "properties": {"provisioningState": "succeeded", "denySettings": {"mode": "denyDelete"},
            "resources": [{"id": vm_id, "status": "managed", "denyStatus": "denyDelete"}]}});
    h.land_page(vec![Box::new(StackRow::from_json(&stack, None).unwrap())]).await;
    h.finish().await;
    h.press(KeyCode::Enter).await;
    let resources = h.section_labels().iter().position(|l| *l == "Resources").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(resources).unwrap())).await;
    h.cursor_to_value(&vm_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    h.land_page(vec![vm()]).await;
    h.finish().await;
    assert_eq!(h.selected_id().as_deref(), Some(vm_id.as_str()));
    let ribbon = h.app.ownership_ribbon().expect("the ribbon has the stack");
    assert_eq!(ribbon.parts[0], "in stack orders");
}

#[tokio::test]
async fn a_template_spec_s_versions_read_fires_and_keeps_only_the_summary() {
    use crate::azure::services::deployment_stacks::{version_summary, TemplateSpecRow};
    let id = arm_id("Microsoft.Resources/templateSpecs/ts-orders");
    let mut h = Harness::new().await;
    h.open(JumpView::TemplateSpecs).await;
    let spec = json!({"id": id, "name": "ts-orders", "location": "westeurope", "properties": {}});
    h.land_page(vec![Box::new(TemplateSpecRow::from_json(&spec, None).unwrap())]).await;
    h.finish().await;
    h.press(KeyCode::Enter).await;
    let versions = h.section_labels().iter().position(|l| *l == "Versions").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(versions).unwrap())).await;
    assert!(matches!(h.app.lazy.template_spec_versions.get(&id), Some(Lazy::Loading)), "the versions read fired");

    let version = json!({"id": format!("{id}/versions/1.0.0"), "name": "1.0.0", "properties": {"mainTemplate": {
        "parameters": {"adminPassword": {"type": "securestring", "defaultValue": "PLANTED"}},
        "resources": [{"type": "Microsoft.Storage/storageAccounts"}]}}});
    h.app.lazy.template_spec_versions.apply(id.clone(), Ok(vec![version_summary(&version)]));
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l == "    adminPassword" && v == "securestring"));
    assert!(lines.iter().any(|(_, v)| v == "    Microsoft.Storage/storageAccounts"));
    assert!(!format!("{:?}", lines).contains("PLANTED"));
}
