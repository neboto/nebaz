//! Static Web Apps (#200): each lazy section fires its own list, and
//! Related names the linked backend from the body before any list lands,
//! so `⏎` on it opens the container app.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::static_web_apps::StaticSiteRow;
use crate::lazy::Lazy;
use serde_json::json;

#[tokio::test]
async fn each_lazy_section_fires_its_list_and_related_jumps_to_the_backend() {
    let mut h = Harness::new().await;
    let site_id = arm_id("Microsoft.Web/staticSites/swa-1");
    let api_id = arm_id("Microsoft.App/containerApps/ca-api");
    let site = StaticSiteRow::from_json(
        &json!({
            "id": site_id, "name": "swa-1", "location": "westeurope", "sku": {"name": "Standard"},
            "properties": {"defaultHostname": "swa-1.example", "linkedBackends": [{"backendResourceId": api_id}]}
        }),
        None,
    )
    .unwrap();
    h.install(Mock { view: JumpView::StaticSites, label: "StaticSiteRow", resource: Box::new(site) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    for label in ["Environments", "Custom domains", "Backends"] {
        let idx = at(&h, label);
        h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    }
    assert!(matches!(h.app.lazy.swa_builds.get(&site_id), Some(Lazy::Loading)), "environments fired");
    assert!(matches!(h.app.lazy.swa_domains.get(&site_id), Some(Lazy::Loading)), "domains fired");
    assert!(matches!(h.app.lazy.swa_backends.get(&site_id), Some(Lazy::Loading)), "backends fired");

    let related = at(&h, "Related");
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Backend ca-api" && *v == api_id));
    h.cursor_to_value(&api_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::ContainerApps));
    assert_eq!(h.app.current_view, JumpView::ContainerApps);
}
