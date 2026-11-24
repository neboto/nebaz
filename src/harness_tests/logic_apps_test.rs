//! Logic Apps (#159): a workflow's Triggers and Runs fire their own lists,
//! Connections loads the API connections list once and shows the status
//! of the one the workflow uses, and `⏎` on it opens the connection, whose
//! Used by loads the workflows list and names the workflow back.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::logic_apps::{ApiConnectionRow, WorkflowRow};
use crate::lazy::{Lazy, LazyApply};
use serde_json::json;

#[tokio::test]
async fn a_workflow_fires_triggers_and_runs_and_its_connection_names_it_back() {
    let mut h = Harness::new().await;
    let id = arm_id("Microsoft.Logic/workflows/la-1");
    let conn = arm_id("Microsoft.Web/connections/office365");
    let wf_json = json!({"id": id, "name": "la-1", "location": "westeurope", "properties": {"state": "Enabled",
        "definition": {"triggers": {"manual": {"type": "Request"}},
                       "actions": {"Send": {"type": "ApiConnection",
                                            "inputs": {"host": {"connection": {"name": "@parameters('$connections')['office365']['connectionId']"}}}}}},
        "parameters": {"$connections": {"value": {"office365": {"connectionId": conn}}}}}});
    let row = WorkflowRow::from_json(&wf_json, None).unwrap();
    h.install(Mock { view: JumpView::LogicWorkflows, label: "WorkflowRow", resource: Box::new(row) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    for label in ["Triggers", "Runs", "Connections"] {
        let idx = at(&h, label);
        h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    }
    assert!(matches!(h.app.lazy.logic_triggers.get(&id), Some(Lazy::Loading)), "triggers fired");
    assert!(matches!(h.app.lazy.logic_runs.get(&id), Some(Lazy::Loading)), "runs fired");
    let sub = h.app.subscription_key();
    let key = format!("{sub}|api-connections");
    assert!(matches!(h.app.lazy.section_lists.get(&key), Some(Lazy::Loading)), "Connections loads the API connections list");

    let c = ApiConnectionRow::from_json(
        &json!({"id": conn, "name": "office365", "location": "westeurope",
                "properties": {"api": {"name": "office365", "displayName": "Office 365 Outlook"},
                               "statuses": [{"status": "Error", "error": {"code": "Unauthenticated"}}]}}),
        None,
    )
    .unwrap();
    let rows: Vec<Box<dyn Resource>> = vec![Box::new(c)];
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| app.lazy.section_lists.apply(key, Ok(rows)));
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l == "office365 · Office 365 Outlook" && v == "⚠ Error (Unauthenticated)"), "{lines:#?}");

    h.cursor_to_value(&conn).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::LogicApps));
    assert_eq!(h.app.current_view, JumpView::ApiConnections);
}
