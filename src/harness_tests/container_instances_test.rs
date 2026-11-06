//! Container Instances (#197): entering a group's Containers fires its own
//! `GET` (the list leaves the instance views out), and a registry its
//! credentials name becomes a jump once the ACR list is warm.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::container_instances::ContainerGroupRow;
use crate::azure::services::container_registry::RegistryRow;
use crate::lazy::Lazy;
use serde_json::json;

#[tokio::test]
async fn containers_fire_the_group_get_and_a_warm_registry_is_a_jump() {
    let mut h = Harness::new().await;
    let group_id = arm_id("Microsoft.ContainerInstance/containerGroups/cg-1");
    let acr_id = arm_id("Microsoft.ContainerRegistry/registries/acr1");
    let group = ContainerGroupRow::from_json(
        &json!({
            "id": group_id, "name": "cg-1", "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded", "osType": "Linux",
                "containers": [{"name": "app", "properties": {"image": "acr1.registry.example/app:1"}}],
                "imageRegistryCredentials": [{"server": "acr1.registry.example", "username": "acr1"}]
            }
        }),
        None,
    )
    .unwrap();
    let acr = RegistryRow::from_json(
        &json!({"id": acr_id, "name": "acr1", "location": "westeurope",
            "properties": {"loginServer": "acr1.registry.example"}}),
        None,
    )
    .unwrap();
    let sub = crate::azure::resource::subscription_of(&group_id).unwrap().to_string();
    h.app.cache.insert(ServiceType::ContainerRegistry, &sub, Some(JumpView::Registries.as_str().into()), vec![Box::new(acr)]);
    h.install(Mock { view: JumpView::ContainerGroups, label: "ContainerGroupRow", resource: Box::new(group) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    let containers = at(&h, "Containers");
    h.press(KeyCode::Char(crate::sections::key_for(containers).unwrap())).await;
    assert!(matches!(h.app.lazy.aci_instance_views.get(&group_id), Some(Lazy::Loading)), "the GET fired");
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l == "  Image" && v == "acr1.registry.example/app:1"), "the spec renders meanwhile");

    let related = at(&h, "Related");
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Registry acr1" && *v == acr_id));
    h.cursor_to_value(&acr_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::ContainerRegistry));
    assert_eq!(h.app.current_view, JumpView::Registries);
}
