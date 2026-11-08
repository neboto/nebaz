//! Azure Virtual Desktop (#198): Session hosts fires the pool's read,
//! Related loads the scaling plans list too, and once the read lands a
//! session host's VM names its pool in its own Related, a jump back.

use super::mocks::{arm_id, vm, Mock};
use super::*;
use crate::azure::services::virtual_desktop::HostPoolRow;
use crate::lazy::Lazy;
use serde_json::json;

#[tokio::test]
async fn session_hosts_fire_their_read_and_the_vm_jumps_back_to_its_pool() {
    let mut h = Harness::new().await;
    let pool_id = arm_id("Microsoft.DesktopVirtualization/hostPools/hp-1");
    let vm_id = arm_id("Microsoft.Compute/virtualMachines/vm-avd-0");
    let pool = HostPoolRow::from_json(
        &json!({"id": pool_id, "name": "hp-1", "location": "westeurope", "properties": {"hostPoolType": "Pooled"}}),
        None,
    )
    .unwrap();
    h.install(Mock { view: JumpView::HostPools, label: "HostPoolRow", resource: Box::new(pool) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    let hosts = at(&h, "Session hosts");
    h.press(KeyCode::Char(crate::sections::key_for(hosts).unwrap())).await;
    assert!(matches!(h.app.lazy.avd_session_hosts.get(&pool_id), Some(Lazy::Loading)), "the session hosts read fired");

    h.app.lazy.avd_session_hosts.apply(
        pool_id.clone(),
        Ok(vec![json!({"name": "hp-1/vm-avd-0.corp.example", "properties": {"status": "Available", "resourceId": vm_id}})]),
    );
    let related = at(&h, "Related");
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    let plans = format!("{}|{}", h.app.subscription_key(), JumpView::ScalingPlans.as_str());
    assert!(matches!(h.app.lazy.section_lists.get(&plans), Some(Lazy::Loading)), "the scaling plans list loads");
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Session host vm-avd-0.corp.example" && *v == vm_id));

    h.install(Mock { view: JumpView::VirtualMachines, label: "VmRow", resource: vm("vm-avd-0", "westeurope") }).await;
    h.press(KeyCode::Enter).await;
    let related = at(&h, "Related");
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Session host in pool hp-1" && *v == pool_id));
    h.cursor_to_value(&pool_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualDesktop));
    assert_eq!(h.app.current_view, JumpView::HostPools);
}
