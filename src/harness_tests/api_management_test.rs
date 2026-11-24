//! API Management (#159): each lazy section fires its own list, a landed
//! named values list never shows a value, and Related names the resource
//! a backend fronts once the backends land, so `⏎` on it opens the
//! container app.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::api_management::{without_secrets, ApimServiceRow};
use crate::lazy::{Lazy, LazyApply};
use serde_json::json;

#[tokio::test]
async fn each_lazy_section_fires_its_list_and_related_jumps_to_a_backends_resource() {
    let mut h = Harness::new().await;
    let id = arm_id("Microsoft.ApiManagement/service/apim-1");
    let api_id = arm_id("Microsoft.App/containerApps/ca-api");
    let row = ApimServiceRow::from_json(
        &json!({"id": id, "name": "apim-1", "location": "westeurope", "sku": {"name": "Developer", "capacity": 1},
                "properties": {"platformVersion": "stv2"}}),
        None,
    )
    .unwrap();
    h.install(Mock { view: JumpView::ApimServices, label: "ApimServiceRow", resource: Box::new(row) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    for label in ["APIs", "Products", "Backends", "Named values"] {
        let idx = at(&h, label);
        h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    }
    assert!(matches!(h.app.lazy.apim_apis.get(&id), Some(Lazy::Loading)), "APIs fired");
    assert!(matches!(h.app.lazy.apim_products.get(&id), Some(Lazy::Loading)), "products fired");
    assert!(matches!(h.app.lazy.apim_backends.get(&id), Some(Lazy::Loading)), "backends fired");
    assert!(matches!(h.app.lazy.apim_named_values.get(&id), Some(Lazy::Loading)), "named values fired");

    // What the fetch hands the store: scrubbed.
    let nv = without_secrets(&json!({"name": "env", "properties": {"displayName": "env", "secret": false, "value": "planted"}}));
    let backend = json!({"name": "api", "properties": {"url": "https://ca-api.example", "resourceId": format!("https://management.example{api_id}")}});
    let (key, epoch) = (id.clone(), h.app.lazy.epoch());
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        app.lazy.apim_named_values.apply(key.clone(), Ok(vec![nv]));
        app.lazy.apim_backends.apply(key, Ok(vec![backend]));
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l == "env" && v == "plain"), "{lines:#?}");
    assert!(!h.render().contains("planted"));

    // Related is past the digits: Tab there.
    let related = at(&h, "Related");
    for _ in 0..h.section_labels().len() {
        if h.app.detail_section_idx == related {
            break;
        }
        h.press(KeyCode::Tab).await;
    }
    assert_eq!(h.app.detail_section_idx, related);
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Backend ca-api" && *v == api_id));
    h.cursor_to_value(&api_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::ContainerApps));
    assert_eq!(h.app.current_view, JumpView::ContainerApps);
}
