//! Azure Arc (#199): an Arc server's Extensions fires its one read, a
//! private link scope in Related jumps to the Private link scopes
//! sub-tab, and an Automation hybrid worker on an Arc server lands on the
//! Arc tab instead of All resources.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::arc::ArcMachineRow;
use crate::lazy::Lazy;
use serde_json::json;

#[tokio::test]
async fn extensions_fire_and_the_scope_is_a_jump() {
    let mut h = Harness::new().await;
    let machine_id = arm_id("Microsoft.HybridCompute/machines/srv-1");
    let scope_id = arm_id("Microsoft.HybridCompute/privateLinkScopes/pls-1");
    let machine = ArcMachineRow::from_json(
        &json!({"id": machine_id, "name": "srv-1", "location": "westeurope",
            "properties": {"status": "Connected", "privateLinkScopeResourceId": scope_id}}),
        None,
    )
    .unwrap();
    h.install(Mock { view: JumpView::ArcMachines, label: "ArcMachineRow", resource: Box::new(machine) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    let extensions = at(&h, "Extensions");
    h.press(KeyCode::Char(crate::sections::key_for(extensions).unwrap())).await;
    assert!(matches!(h.app.lazy.arc_extensions.get(&machine_id), Some(Lazy::Loading)), "the extensions read fired");

    let related = at(&h, "Related");
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    h.cursor_to_value(&scope_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Arc));
    assert_eq!(h.app.current_view, JumpView::ArcPrivateLinkScopes);
}

#[test]
fn an_arc_server_id_lands_on_the_arc_tab() {
    let id = arm_id("Microsoft.HybridCompute/machines/srv-1");
    assert_eq!(JumpView::landing_for_arm_id(&id), Some(JumpView::ArcMachines));
    let ext = arm_id("Microsoft.HybridCompute/machines/srv-1/extensions/AzureMonitorWindowsAgent");
    assert_eq!(JumpView::landing_for_arm_id(&ext), None, "an extension is in no list of its own");
}
