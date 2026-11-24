//! Alert thresholds on the chart (#230): opening the charts loads the
//! metric alert list once (the same lazy list a row's Related reads), a
//! rule on the charted metric draws its line with its name in the title,
//! and a rule the chart would misread is named with why it is not drawn.

use super::metrics_test::land_series;
use super::*;
use crate::azure::metrics::tests::fixture;
use crate::azure::services::alerts::MetricAlertRow;
use crate::lazy::{Lazy, LazyApply};
use serde_json::json;

fn rule(vm: &str, name: &str, agg: &str, threshold: f64) -> Box<dyn Resource> {
    let rg = vm.split("/providers/").next().unwrap();
    Box::new(
        MetricAlertRow::from_json(
            &json!({
                "id": format!("{rg}/providers/Microsoft.Insights/metricAlerts/{name}"), "name": name, "location": "global",
                "properties": {"enabled": true, "scopes": [vm], "windowSize": "PT5M",
                               "criteria": {"odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                                            "allOf": [{"name": "c1", "metricName": "Percentage CPU", "timeAggregation": agg,
                                                       "operator": "GreaterThan", "threshold": threshold,
                                                       "criterionType": "StaticThresholdCriterion"}]}}
            }),
            None,
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn the_charts_load_the_metric_alerts_and_draw_a_rule_on_the_charted_metric() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("vm-1", "westeurope")]).await;
    let vm = h.app.get_selected_resource().unwrap().id().to_string();
    let sub = h.app.subscription_key();

    h.press(KeyCode::Char('m')).await;
    let key = format!("{sub}|metric-alerts");
    assert!(matches!(h.app.lazy.section_lists.get(&key), Some(Lazy::Loading)), "m loads the metric alert list");
    land_series(&mut h, fixture()).await;
    assert!(h.app.threshold_source().is_some_and(|t| t.loading));
    assert!(h.render().contains("reading alert rules…"));

    let rows = vec![rule(&vm, "cpu-high", "Average", 80.0), rule(&vm, "cpu-max", "Maximum", 95.0)];
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> =
        Box::new(move |app: &mut App| app.lazy.section_lists.apply(format!("{sub}|metric-alerts"), Ok(rows)));
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;

    let t = h.app.threshold_source().expect("two rules on Percentage CPU");
    assert_eq!(t.lines(), vec![80.0], "only the average is drawn on an average chart");
    let screen = h.render();
    assert!(screen.contains("┄ cpu-high > 80"), "{screen}");
    assert!(screen.contains("· cpu-max: the chart reads avg"), "{screen}");

    // A metric no rule watches: nothing said. Closing and reopening does
    // not fetch the list again.
    h.press(KeyCode::Char('j')).await;
    assert!(h.app.threshold_source().is_none());
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('m')).await;
    assert!(matches!(h.app.lazy.section_lists.get(&key), Some(Lazy::Loaded(_))));
}
