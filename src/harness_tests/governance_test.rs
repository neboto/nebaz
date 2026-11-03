//! The Governance tab (#155, ADR 0009): an assignment made at a management
//! group opens in the current subscription, its Definition loads the cold
//! Definitions list for the section, and its definition line jumps.

use super::mocks::all_mocks;
use super::*;
use crate::azure::services::governance::{PolicyAssignmentRow, PolicyDefinitionRow};
use crate::lazy::Lazy;

fn mock(label: &str) -> super::mocks::Mock {
    all_mocks().into_iter().find(|m| m.label == label).expect("a mock")
}

#[tokio::test]
async fn an_inherited_assignment_loads_its_definition_and_jumps_to_it() {
    let mut h = Harness::new().await;
    h.install(mock("PolicyAssignmentRow")).await;
    let sub = h.app.subscription_key();
    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == "Definition").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;

    // The mock's definition is a built-in: one GET by id, nothing listed.
    let builtin = "/providers/Microsoft.Authorization/policyDefinitions/00000000-0000-0000-0000-000000000001";
    assert!(matches!(h.app.lazy.policy_definitions.get(builtin), Some(Lazy::Loading)), "the built-in read fired");
    assert!(h.app.lazy.section_lists.get(&format!("{sub}|policy-definitions")).is_none(), "no list for a built-in");
    assert!(h.app.get_detail_lines().iter().any(|(_, v)| v == "Loading…"));

    // A custom definition at a management group: the Definitions list,
    // loaded for the section, never a GET at the group.
    let def = "/providers/Microsoft.Management/managementGroups/mg-1/providers/Microsoft.Authorization/policyDefinitions/pd-mg";
    let mut assignment = mock("PolicyAssignmentRow");
    {
        let mut a = assignment.resource.as_any().downcast_ref::<PolicyAssignmentRow>().unwrap().clone();
        a.definition_id = Some(def.to_string());
        assignment.resource = Box::new(a);
    }
    h.install(assignment).await;
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    let key = format!("{sub}|policy-definitions");
    assert!(matches!(h.app.lazy.section_lists.get(&key), Some(Lazy::Loading)), "the list read fired");
    assert!(h.app.lazy.policy_definitions.get(def).is_none());

    let row = PolicyDefinitionRow::from_json(
        &serde_json::json!({"id": def, "name": "pd-mg", "properties": {"displayName": "Deny everything", "policyType": "Custom",
            "mode": "All", "policyRule": {"if": {"field": "type", "equals": "x"}, "then": {"effect": "deny"}}}}),
        None,
    )
    .unwrap();
    let rows: Vec<Box<dyn Resource>> = vec![Box::new(row)];
    let apply: Box<dyn FnOnce(&mut App) + Send> =
        Box::new(move |app: &mut App| app.lazy.section_lists.apply(key, Ok(rows)));
    let epoch = h.app.lazy.epoch();
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let lines = h.app.get_detail_lines();
    assert!(lines.contains(&("Stored at".to_string(), "management group mg-1".to_string())), "{lines:#?}");
    assert!(lines.contains(&("Effect".to_string(), "deny".to_string())), "{lines:#?}");

    // Its id is above the subscription and still jumps, staying in it.
    h.cursor_to_value(def).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Governance));
    assert_eq!(h.app.current_view, JumpView::PolicyDefinitions);
    assert_eq!(h.app.subscription_key(), sub, "no subscription switch");
    assert_eq!(h.app.pending_jump, Some((def.to_string(), true)));
}

#[tokio::test]
async fn an_inherited_assignment_has_no_activity_call() {
    let mut h = Harness::new().await;
    h.install(mock("PolicyAssignmentRow")).await;
    let id = h.selected_id().unwrap();
    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == "Activity").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    assert!(h.app.lazy.activity.get(&id).is_none(), "the Activity Log is per subscription");
    assert!(h.app.get_detail_lines().iter().any(|(_, v)| v.starts_with("Made above the subscription")));
}
