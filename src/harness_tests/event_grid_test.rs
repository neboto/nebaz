//! Event Grid (#159): a topic's Subscriptions fires its own list, the
//! loaded list flags a subscription with no dead-letter, and `⏎` on its
//! destination opens the Service Bus namespace.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::event_grid::{subscription_outline, EventGridRow};
use crate::lazy::{Lazy, LazyApply};
use serde_json::json;

#[tokio::test]
async fn a_topic_fires_subscriptions_and_its_destination_opens() {
    let mut h = Harness::new().await;
    let id = arm_id("Microsoft.EventGrid/topics/egt-1");
    let ns = arm_id("Microsoft.ServiceBus/namespaces/sb-1");
    let row = EventGridRow::from_json(
        &json!({"id": id, "name": "egt-1", "location": "westeurope", "properties": {"publicNetworkAccess": "Enabled"}}),
        None,
    )
    .unwrap();
    h.install(Mock { view: JumpView::EventGridTopics, label: "EventGridRow", resource: Box::new(row) }).await;

    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == "Subscriptions").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    assert!(matches!(h.app.lazy.eg_subscriptions.get(&id), Some(Lazy::Loading)), "subscriptions fired");

    let sub = subscription_outline(&json!({"id": format!("{id}/providers/Microsoft.EventGrid/eventSubscriptions/to-queue"), "name": "to-queue",
        "properties": {"provisioningState": "Succeeded",
                       "destination": {"endpointType": "ServiceBusQueue", "properties": {"resourceId": format!("{ns}/queues/orders")}}}}));
    let epoch = h.app.lazy.epoch();
    let key = id.clone();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| app.lazy.eg_subscriptions.apply(key, Ok(vec![sub])));
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l == "to-queue" && v == "ServiceBusQueue → sb-1/orders"), "{lines:#?}");
    assert!(lines.iter().any(|(l, v)| l == "  Dead-letter" && v.starts_with("⚠ none")), "{lines:#?}");

    h.cursor_to_value(&ns).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Messaging));
    assert_eq!(h.app.current_view, JumpView::ServiceBusNamespaces);
}
