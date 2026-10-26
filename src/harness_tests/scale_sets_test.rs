//! VM scale sets (#30): the VMs tab's fourth sub-tab at 80×24, the lazy
//! Instances section, and the Flexible VM's link back to its set.

use super::mocks::{self, arm_id};
use super::*;

/// Every section of a scale set draws at 80×24, the chip is on screen,
/// and entering Instances starts its one read, keyed by the set.
#[tokio::test]
async fn the_scale_sets_tab_fits_80_by_24_and_instances_read_lazily() {
    let mut h = Harness::sized(80, 24).await;
    let mock = mocks::all_mocks().into_iter().find(|m| m.view == JumpView::ScaleSets).unwrap();
    let id = mock.resource.id().to_string();
    h.install(mock).await;
    let screen = h.render();
    assert!(screen.contains("Scale sets"), "{screen}");
    h.press(KeyCode::Enter).await;
    let instances = h.section_labels().iter().position(|l| *l == "Instances").unwrap();
    assert!(instances < 9);
    assert!(!h.app.lazy.vmss_instances.contains(&id), "nothing read before the section opens");
    for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9'] {
        h.press(KeyCode::Char(c)).await;
        h.render();
    }
    assert!(h.app.lazy.vmss_instances.contains(&id), "Instances fired its read");
    // The fourth chip is the 4 key from the list.
    h.press(KeyCode::Esc).await;
    h.open(JumpView::VirtualMachines).await;
    h.press(KeyCode::Char('4')).await;
    assert_eq!(h.app.current_view, JumpView::ScaleSets);
}

/// A Flexible set's VM names its set in Related, and ⏎ there jumps to the
/// Scale sets sub-tab, waiting for the set to land.
#[tokio::test]
async fn a_flexible_vm_jumps_to_its_scale_set() {
    let mut h = Harness::new().await;
    let set = arm_id("Microsoft.Compute/virtualMachineScaleSets/vmss-flex");
    let vm = serde_json::json!({
        "id": arm_id("Microsoft.Compute/virtualMachines/vmss-flex_1a2b3c4d"),
        "name": "vmss-flex_1a2b3c4d", "location": "westeurope",
        "properties": {"provisioningState": "Succeeded", "virtualMachineScaleSet": {"id": set}}
    });
    let row = crate::azure::services::compute::VmRow::from_json(&vm, None).unwrap();
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![Box::new(row)]).await;
    h.press(KeyCode::Enter).await;
    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    h.cursor_to_value(&set).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::ScaleSets);
    assert_eq!(h.app.pending_jump, Some((set, true)));
}
