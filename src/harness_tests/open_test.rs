//! `nebaz open` (neboto-tui#334): the TUI starts at a resource, a section
//! of it, or its charts. The place is planned from the arguments before
//! the TUI starts and lands once the startup list has the row.

use super::mocks::vm;
use super::*;
use crate::azure::metrics::MetricWindow;
use crate::cli::OpenArgs;

fn args(target: &str) -> OpenArgs {
    OpenArgs { target: target.to_string(), within: None, section: None, charts: None, metric: None, full: false }
}

fn rows() -> Vec<Box<dyn Resource>> {
    vec![vm("vm-1", "westeurope"), vm("vm-2", "westeurope")]
}

fn vm_id(name: &str) -> String {
    vm(name, "westeurope").id().to_string()
}

/// A fresh process started with `open …`, its restore run and nothing
/// loaded yet.
async fn started(args: &OpenArgs) -> Harness {
    let (place, req) = crate::open::plan(args).expect("a plan");
    let mut h = Harness::new().await;
    h.app.startup_place = Some(place);
    h.app.startup_open = Some(req);
    h.app.restore_startup_location(&h.tx);
    h.settle().await;
    h
}

async fn opened(args: &OpenArgs) -> Harness {
    let mut h = started(args).await;
    h.land(rows()).await;
    h
}

#[tokio::test]
async fn an_id_opens_its_row_in_the_detail_pane() {
    let h = opened(&args(&vm_id("vm-2"))).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.selected_id(), Some(vm_id("vm-2")));
    assert!(h.app.details_focused);
    assert_eq!(h.app.detail_section_idx, 0);
    assert!(h.app.metrics.is_none());
    assert_eq!(h.app.error_message, None);
    assert_eq!(h.app.pending_place, None);
}

#[tokio::test]
async fn section_matches_any_case_and_a_wrong_one_lists_the_real_ones() {
    let mut a = args(&vm_id("vm-2"));
    a.section = Some("tags".into());
    let h = opened(&a).await;
    let tags = h.section_labels().iter().position(|l| *l == "Tags").unwrap();
    assert_eq!(h.app.detail_section_idx, tags);

    a.section = Some("nope".into());
    let h = opened(&a).await;
    assert_eq!(h.selected_id(), Some(vm_id("vm-2")), "the row still opens");
    assert_eq!(h.app.detail_section_idx, 0);
    let err = h.app.error_message.clone().unwrap_or_default();
    assert!(err.contains("no section \"nope\"") && err.contains("Overview") && err.contains("Tags"), "{err}");
}

#[tokio::test]
async fn charts_open_at_the_window_on_the_metric_and_full_width() {
    let mut a = args(&vm_id("vm-1"));
    a.charts = Some("7d".into());
    a.metric = Some("network out".into());
    a.full = true;
    let h = opened(&a).await;
    let st = h.app.metrics.as_ref().expect("the charts open");
    assert_eq!(st.window, MetricWindow::SevenDays);
    assert_eq!(st.queries[st.selected].label, "Network out");
    assert_eq!(h.app.layout_mode, crate::app::LayoutMode::DetailsOnly);
    assert_eq!(h.app.error_message, None);
}

#[tokio::test]
async fn metric_alone_opens_the_charts_and_a_wrong_one_lists_the_rows() {
    let mut a = args(&vm_id("vm-1"));
    a.metric = Some("Percentage CPU".into());
    let h = opened(&a).await;
    let st = h.app.metrics.as_ref().expect("--metric implies the charts");
    assert_eq!(st.window, MetricWindow::default());
    assert_eq!(st.queries[st.selected].label, "CPU");

    a.metric = Some("latency".into());
    let h = opened(&a).await;
    assert!(h.app.metrics.is_some(), "the charts still open");
    let err = h.app.error_message.clone().unwrap_or_default();
    assert!(err.contains("isn't charted") && err.contains("CPU (Percentage CPU)"), "{err}");
}

#[tokio::test]
async fn a_name_waits_for_the_whole_list_then_opens_the_one_row() {
    let mut a = args("vm-2");
    a.within = Some("vm".into());
    a.section = Some("Tags".into());
    let mut h = started(&a).await;
    h.land_page(vec![vm("vm-1", "westeurope")]).await;
    assert!(h.app.pending_jump.is_some(), "more rows may come");
    h.land_page(vec![vm("vm-2", "westeurope")]).await;
    h.finish().await;
    assert_eq!(h.selected_id(), Some(vm_id("vm-2")));
    assert!(h.app.details_focused);
    let tags = h.section_labels().iter().position(|l| *l == "Tags").unwrap();
    assert_eq!(h.app.detail_section_idx, tags);
}

#[tokio::test]
async fn a_missing_resource_says_so_instead_of_landing_on_row_0() {
    let h = opened(&args(&vm_id("vm-9"))).await;
    assert!(!h.app.details_focused);
    assert_eq!(h.app.pending_place, None);
    let err = h.app.error_message.clone().unwrap_or_default();
    assert!(err.contains("vm-9") && err.contains("not in this list"), "{err}");

    let mut a = args("vm-9");
    a.within = Some("vm".into());
    let h = opened(&a).await;
    assert!(!h.app.details_focused);
    assert!(h.app.error_message.clone().unwrap_or_default().contains("vm-9"));
}

#[tokio::test]
async fn a_bookmark_opens_as_it_was_saved() {
    let (place, _) = crate::open::plan(&args(&vm_id("vm-2"))).unwrap();
    let mut loc = place.loc;
    loc.detail_section = Some("Tags".into());
    let mut h = Harness::new().await;
    h.app.startup_place = Some(crate::split::Place { loc, chart_window: None });
    h.app.restore_startup_location(&h.tx);
    h.settle().await;
    h.land(rows()).await;
    assert_eq!(h.selected_id(), Some(vm_id("vm-2")));
    let tags = h.section_labels().iter().position(|l| *l == "Tags").unwrap();
    assert_eq!(h.app.detail_section_idx, tags);
    assert_eq!(h.app.error_message, None);
}
