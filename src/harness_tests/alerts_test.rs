//! Alert rules on every row (#194): entering a resource's Related loads
//! the three rule lists, shows the rule that watches it, and jumps there.

use super::mocks::all_mocks;
use super::*;
use crate::lazy::Lazy;

fn mock(label: &str) -> super::mocks::Mock {
    all_mocks().into_iter().find(|m| m.label == label).expect("a mock")
}

#[tokio::test]
async fn a_vms_related_loads_the_rule_lists_and_jumps_to_its_alert() {
    let mut h = Harness::new().await;
    h.install(mock("VmRow")).await;
    let sub = h.app.subscription_key();
    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;
    for view in ["metric-alerts", "log-alerts", "activity-log-alerts"] {
        let key = format!("{sub}|{view}");
        assert!(matches!(h.app.lazy.section_lists.get(&key), Some(Lazy::Loading)), "{view} fired");
    }
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Alert rules" && v == "Loading…"));

    // The mock metric alert watches vm-1; the other two lists are empty.
    let rule = mock("MetricAlertRow");
    let rule_id = rule.resource.id().to_string();
    let rows: Vec<Box<dyn Resource>> = vec![rule.resource];
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        app.lazy.section_lists.apply(format!("{sub}|metric-alerts"), Ok(rows));
        app.lazy.section_lists.apply(format!("{sub}|log-alerts"), Ok(vec![]));
        app.lazy.section_lists.apply(format!("{sub}|activity-log-alerts"), Ok(vec![]));
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(l, v)| l == "Metric alert · cpu-high" && *v == rule_id), "{lines:#?}");

    h.cursor_to_value(&rule_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Monitor));
    assert_eq!(h.app.current_view, JumpView::MetricAlerts);
}
