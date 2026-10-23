//! The metrics view (`m`, #51): opening on a VM fires the default
//! section's hook and owns the detail pane, a landed response draws the
//! lines and the chart, the window keys refetch, the `a` picker charts
//! one metric, and `Esc` hands the pane back. The harness never lets a
//! fetch land: each answer is delivered through the apply-closure event
//! the real task sends.

use super::*;
use crate::azure::metrics::{parse_definitions, parse_metrics, tests::fixture, MetricWindow};
use crate::lazy::LazyApply;
use serde_json::json;

/// Deliver what the series task would, for the view's current queries.
pub(super) async fn land_series(h: &mut Harness, body: serde_json::Value) {
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        let st = app.metrics.as_mut().expect("the view is open");
        let series = parse_metrics(&body, &st.queries);
        // The fixture's window ends at 12:00.
        let end = crate::azure::metrics::parse_iso_utc("2026-10-23T12:00:00Z").unwrap();
        st.set_series(end, series);
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
}

#[tokio::test]
async fn m_on_a_vm_charts_the_default_set_and_esc_hands_the_pane_back() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("vm-1", "westeurope")]).await;
    assert!(h.render().contains("m metrics"), "the status bar offers m on a VM");

    h.press(KeyCode::Char('m')).await;
    let st = h.app.metrics.as_ref().expect("m opens the view");
    assert!(st.loading && st.curated);
    assert_eq!(st.window, MetricWindow::OneHour);
    assert_eq!(st.queries[0].name, "Percentage CPU");
    assert!(h.app.details_focused, "opening from the list focuses the pane");
    assert_eq!(h.app.detail_section_idx, 0, "behind the view: the default section");
    assert!(h.render().contains("METRICS"));

    land_series(&mut h, fixture()).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert!(!st.loading);
    assert_eq!(st.series.len(), st.queries.len(), "one line per default metric");
    let screen = h.render();
    for s in ["METRICS", "default set", "CPU", "last 20.0%", "InvalidSamplingType", "Percentage CPU (avg)", "1h ago", "now"] {
        assert!(screen.contains(s), "{s:?} missing:\n{screen}");
    }

    // The window keys refetch.
    h.press(KeyCode::Char(']')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert_eq!(st.window, MetricWindow::SixHours);
    assert!(st.loading);
    h.press(KeyCode::Char('4')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::SevenDays);
    h.press(KeyCode::Char('[')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::OneDay);

    // Esc closes; the detail pane is the VM's again, and the window sticks.
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_none());
    assert!(h.app.details_focused);
    assert!(!h.render().contains("METRICS"));
    h.press(KeyCode::Char('m')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::OneDay);
}

#[tokio::test]
async fn the_picker_lists_definitions_and_charts_the_one_picked() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Char('m')).await;

    h.press(KeyCode::Char('a')).await;
    assert!(h.app.metrics.as_ref().unwrap().picker.as_ref().unwrap().loading);
    let epoch = h.app.lazy.epoch();
    let defs = json!({"value": [
        {"name": {"value": "Percentage CPU", "localizedValue": "Percentage CPU"}, "unit": "Percent", "primaryAggregationType": "Average"},
        {"name": {"value": "Inbound Flows", "localizedValue": "Inbound Flows"}, "unit": "Count", "primaryAggregationType": "Total"}
    ]});
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        let p = app.metrics.as_mut().unwrap().picker.as_mut().unwrap();
        p.loading = false;
        p.defs = parse_definitions(&defs);
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
    let screen = h.render();
    assert!(screen.contains("all metrics") && screen.contains("Inbound Flows"), "{screen}");

    h.press(KeyCode::Enter).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert!(st.picker.is_none());
    assert!(!st.curated);
    assert_eq!(st.queries.len(), 1);
    assert_eq!(st.queries[0].name, "Inbound Flows");
    assert!(st.loading);

    // `d` returns to the default set.
    h.press(KeyCode::Char('d')).await;
    let st = h.app.metrics.as_ref().unwrap();
    assert!(st.curated && st.queries.len() > 1);
}

#[tokio::test]
async fn a_type_with_no_default_set_opens_on_the_picker() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![mocks::vnet("vnet-1", "westeurope")]).await;
    assert!(!h.render().contains("m metrics"), "no hint without a default set");
    h.press(KeyCode::Char('m')).await;
    let st = h.app.metrics.as_ref().expect("m still opens");
    assert!(st.queries.is_empty() && !st.loading);
    assert!(st.picker.as_ref().is_some_and(|p| p.loading));
    // Esc leaves the picker, then the view.
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.as_ref().unwrap().picker.is_none());
    assert!(h.render().contains("No default metrics"));
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_none());
}
