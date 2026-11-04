//! Change markers on the `m` chart (#152; neboto-tui#259, #284, #289): `m`
//! fetches the `W` timeline's sources for the charted resource once, the
//! chart draws them at their times with a legend, `c` hides them, `W`
//! opens the timeline on the same rows and `Esc` there comes back to the
//! charts with the range kept, and `[` wrapping to 30d widens the rows.
//! The harness never lets a fetch land: answers go through the
//! apply-closure event the real tasks send.

use super::mocks::arm_id;
use super::*;
use crate::azure::metrics::{tests::fixture, MetricWindow};
use crate::azure::timeline::{LensWindow, TimelineSource};
use crate::lazy::LazyApply;
use crate::ui::theme;
use serde_json::{json, Value};

// The fixture series' window ends at 2026-10-23T12:00:00Z.

fn vm_id() -> String {
    arm_id("Microsoft.Compute/virtualMachines/vm-1")
}

fn event(ts: &str, corr: &str, op: &str, status: &str) -> Value {
    json!({
        "eventTimestamp": ts, "correlationId": corr,
        "operationName": {"value": op, "localizedValue": ""},
        "status": {"value": status}, "caller": "ops@contoso.com",
        "level": if status == "Failed" { "Error" } else { "Informational" },
        "resourceId": vm_id()
    })
}

/// A harness with the VM's metrics view open and its series landed.
async fn charts() -> Harness {
    let mut h = Harness::sized(170, 48).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Char('m')).await;
    super::metrics_test::land_series(&mut h, fixture()).await;
    h
}

/// Land the Activity Log answer into whichever state holds the timeline.
async fn land_activity(h: &mut Harness, events: Vec<Value>) {
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        let st = app.timeline.as_mut().or(app.chart_timeline.as_mut()).expect("a timeline state");
        st.since = 0; // the fixture's dates, whatever today is
        st.set_activity(events, false);
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
}

/// Everything else the sources would answer: nothing.
async fn land_rest(h: &mut Harness) {
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        let st = app.timeline.as_mut().or(app.chart_timeline.as_mut()).expect("a timeline state");
        for s in [TimelineSource::Alert, TimelineSource::Health, TimelineSource::Deployment] {
            st.set_rows(s, vec![]);
        }
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
}

#[tokio::test]
async fn m_fetches_the_timeline_sources_once_and_c_hides_the_markers() {
    let mut h = charts().await;
    let tl = h.app.chart_timeline.as_ref().expect("m seeds the markers' timeline");
    assert_eq!(tl.resource_id, vm_id());
    assert_eq!(tl.window, LensWindow::Week, "a 1h chart needs a week of rows at most");
    let mut pending = tl.pending.clone();
    pending.sort_by_key(|s| crate::azure::timeline::slot(*s));
    assert_eq!(pending, TimelineSource::ALL, "the same four sources as W");
    assert!(h.app.timeline.is_none(), "the lens itself is not open");

    // Hiding keeps the rows; showing again fetches nothing.
    let generation = h.app.timeline_generation;
    h.press(KeyCode::Char('c')).await;
    assert!(!h.app.chart_markers && h.app.chart_timeline.is_some());
    h.press(KeyCode::Char('c')).await;
    assert!(h.app.chart_markers);
    assert_eq!(h.app.timeline_generation, generation, "no second fetch");

    // Closing drops them; with markers off `m` fetches nothing.
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_none() && h.app.chart_timeline.is_none());
    h.app.chart_markers = false;
    h.press(KeyCode::Char('m')).await;
    assert!(h.app.chart_timeline.is_none(), "markers off: no timeline fetch");
    h.press(KeyCode::Char('c')).await;
    assert!(h.app.chart_timeline.is_some(), "the first show fetches");
}

#[tokio::test]
async fn events_in_the_window_are_drawn_with_a_legend_and_older_ones_are_not() {
    let mut h = charts().await;
    let plain = {
        h.press(KeyCode::Char('c')).await;
        let s = h.render();
        h.press(KeyCode::Char('c')).await;
        s
    };
    assert!(!plain.contains("┊"), "no legend while hidden:\n{plain}");

    land_activity(
        &mut h,
        vec![
            event("2026-10-23T11:10:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Succeeded"),
            event("2026-10-23T11:20:00Z", "c2", "Microsoft.Compute/virtualMachines/write", "Succeeded"),
            event("2026-10-23T11:40:00Z", "c3", "Microsoft.Compute/virtualMachines/deallocate/action", "Failed"),
            // Yesterday: inside the week's rows, outside the 1h chart.
            event("2026-10-22T09:00:00Z", "c4", "Microsoft.Compute/virtualMachines/restart/action", "Succeeded"),
        ],
    )
    .await;
    land_rest(&mut h).await;
    assert_eq!(h.app.chart_timeline.as_ref().unwrap().rows.len(), 4);

    let screen = h.render();
    assert_ne!(screen, plain, "markers change the frame");
    assert!(screen.contains("deallocate/action"), "the failed change is named:\n{screen}");
    assert!(screen.contains("virtualMachines/write ×2"), "a repeated change is named once with a count:\n{screen}");
    assert!(!screen.contains("restart/action"), "yesterday's change is outside the 1h chart:\n{screen}");
    assert!(screen.contains("c hide") && screen.contains("W timeline"), "{screen}");
    assert!(h.has_fg(theme::error()), "a failed change is error-coloured");

    // The same rows on the 7d chart now include yesterday's restart.
    h.press(KeyCode::Char('4')).await;
    super::metrics_test::land_series(&mut h, fixture()).await;
    h.press(KeyCode::Char('Z')).await; // full width: room for all three names
    let screen = h.render();
    assert!(screen.contains("restart/action"), "{screen}");
}

#[tokio::test]
async fn w_opens_the_timeline_on_the_same_rows_and_esc_returns_to_the_charts_with_the_range() {
    let mut h = charts().await;
    land_activity(&mut h, vec![event("2026-10-23T11:40:00Z", "c3", "Microsoft.Compute/virtualMachines/write", "Failed")]).await;
    land_rest(&mut h).await;
    h.press(KeyCode::Char(']')).await; // 6h
    super::metrics_test::land_series(&mut h, fixture()).await;
    h.press(KeyCode::Char('j')).await;
    let generation = h.app.timeline_generation;

    h.press(KeyCode::Char('W')).await;
    assert!(h.app.metrics.is_none() && h.app.metrics_parked.is_some(), "the view is parked, not dropped");
    let lens = h.app.timeline.as_ref().expect("W opens the timeline");
    assert_eq!(lens.resource_id, vm_id());
    assert_eq!(lens.rows.len(), 1, "the markers' rows are the lens's rows");
    assert_eq!(h.app.timeline_generation, generation, "no second fetch");
    assert!(h.app.chart_timeline.is_none(), "one state at a time");
    assert!(h.render().contains("TIMELINE"));

    h.press(KeyCode::Esc).await;
    assert!(h.app.timeline.is_none() && h.app.metrics_parked.is_none());
    let st = h.app.metrics.as_ref().expect("Esc returns to the charts");
    assert_eq!(st.window, MetricWindow::SixHours, "the range is kept");
    assert_eq!(st.selected, 1, "so is the cursor");
    assert_eq!(h.app.chart_timeline.as_ref().unwrap().rows.len(), 1, "the rows are back behind the markers");
    assert!(h.render().contains("METRICS"));

    // W again, and W closes it the same way; a fresh W from the list
    // is a plain lens that closes to the list's pane.
    h.press(KeyCode::Char('W')).await;
    h.press(KeyCode::Char('W')).await;
    assert!(h.app.metrics.is_some() && h.app.timeline.is_none());
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('W')).await;
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_none() && h.app.timeline.is_none() && h.app.metrics_parked.is_none());
}

#[tokio::test]
async fn w_with_the_markers_hidden_fetches_for_the_lens_and_still_returns() {
    let mut h = charts().await;
    h.app.chart_timeline = None; // as when the markers were off at open
    h.app.chart_markers = false;
    h.press(KeyCode::Char('W')).await;
    let lens = h.app.timeline.as_ref().expect("W opens the timeline");
    assert!(lens.is_loading(), "nothing was held, so the lens fetches");
    h.press(KeyCode::Esc).await;
    assert!(h.app.metrics.is_some());
}

#[tokio::test]
async fn bracket_back_to_thirty_days_widens_the_timeline_too() {
    let mut h = charts().await;
    assert_eq!(h.app.chart_timeline.as_ref().unwrap().window, LensWindow::Week);
    land_rest(&mut h).await;
    land_activity(&mut h, vec![]).await;
    let generation = h.app.timeline_generation;

    // From 1h `[` wraps to 30d.
    h.press(KeyCode::Char('[')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::ThirtyDays);
    let tl = h.app.chart_timeline.as_ref().unwrap();
    assert_eq!(tl.window, LensWindow::Month, "the markers' rows now cover the chart");
    assert!(tl.is_loading());
    assert!(h.app.timeline_generation > generation);

    // W opens on the month, not the week.
    h.press(KeyCode::Char('W')).await;
    assert_eq!(h.app.timeline.as_ref().unwrap().window, LensWindow::Month);
    h.press(KeyCode::Esc).await;

    // A shorter range filters at draw time: no refetch.
    let generation = h.app.timeline_generation;
    h.press(KeyCode::Char('1')).await;
    assert_eq!(h.app.timeline_generation, generation);
    // `5` is 30d again, already covered.
    h.press(KeyCode::Char('5')).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::ThirtyDays);
    assert_eq!(h.app.timeline_generation, generation, "the month is already held");

    // The window is sticky across opens, so the next `m` seeds a month.
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('m')).await;
    assert_eq!(h.app.chart_timeline.as_ref().unwrap().window, LensWindow::Month);
}

#[tokio::test]
async fn a_30d_chart_shows_a_change_from_three_weeks_ago() {
    let mut h = charts().await;
    h.press(KeyCode::Char('5')).await;
    super::metrics_test::land_series(&mut h, fixture()).await;
    land_activity(&mut h, vec![event("2026-10-02T09:00:00Z", "c9", "Microsoft.Compute/virtualMachines/write", "Succeeded")]).await;
    land_rest(&mut h).await;
    let screen = h.render();
    assert!(screen.contains("30d ago") && screen.contains("virtualMachines/write"), "{screen}");
}
