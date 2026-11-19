//! Watch mode (`w`, #228; neboto's loop and neboto-tui#329): a due tick
//! re-runs the list's load into staging, so the rows on screen stay until
//! the new set lands and swaps in with the row kept; a failed pass keeps
//! the rows and says so once; modals, search and lenses hold it over; the
//! charts take over the cadence, never under a minute. Ticks are sent by
//! hand: the harness has no tick task.

use super::mocks::vm;
use super::*;
use std::time::{Duration, Instant};

/// VMs with two rows, `vm-2` selected, watch on and its first pass run
/// (so the next one waits out the interval).
async fn watching() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope"), vm("vm-2", "westeurope")]).await;
    h.press(KeyCode::Char('j')).await;
    h.press(KeyCode::Char('w')).await;
    h
}

/// Make the next pass due now.
fn due(h: &mut Harness) {
    h.app.watch.last_refresh = Some(Instant::now() - Duration::from_secs(3600));
}

fn vm_id(name: &str) -> String {
    super::mocks::arm_id(&format!("Microsoft.Compute/virtualMachines/{name}"))
}

fn names(h: &Harness) -> Vec<String> {
    h.app.resources.iter().map(|r| r.name().to_string()).collect()
}

#[tokio::test]
async fn a_pass_keeps_the_rows_until_the_new_set_lands_and_keeps_the_row() {
    let mut h = watching().await;
    assert!(h.app.watch.enabled);
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.contains("refreshing the list every 30s")), "{:?}", h.app.success_message);

    // `w` makes the first pass due at once.
    h.send(Event::Tick).await;
    assert!(h.app.watch_refresh_active(), "the pass streams into staging");
    assert!(h.app.loading && !h.app.show_loading_indicator(), "no loading indicator: the chip spins");
    assert!(h.app.watch_spinning());
    assert_eq!(names(&h), ["vm-1", "vm-2"], "the rows on screen stay");
    assert!(h.render().contains("watch 30s"));

    // A page lands into staging, not onto the list.
    h.land_page(vec![vm("vm-0", "westeurope"), vm("vm-1", "westeurope")]).await;
    assert_eq!(names(&h), ["vm-1", "vm-2"]);
    h.land_page(vec![vm("vm-2", "westeurope")]).await;
    h.finish().await;
    assert!(!h.app.watch_refresh_active() && !h.app.loading);
    assert_eq!(names(&h), ["vm-0", "vm-1", "vm-2"], "the new set, swapped in whole");
    assert_eq!(h.app.selected_index, Some(2), "vm-2 moved down a row");
    assert_eq!(h.selected_id().as_deref(), Some(vm_id("vm-2").as_str()), "the row is kept by id");

    // Not due again until the interval has passed.
    h.send(Event::Tick).await;
    assert!(!h.app.watch_refresh_active());
    due(&mut h);
    h.send(Event::Tick).await;
    assert!(h.app.watch_refresh_active());
    // One event with the whole list works the same.
    h.land(vec![vm("vm-2", "westeurope")]).await;
    assert_eq!(names(&h), ["vm-2"]);
    assert_eq!(h.selected_id().as_deref(), Some(vm_id("vm-2").as_str()));
}

/// `-w` (config `watch`): the startup load is the first read, so the
/// first pass waits out the interval instead of reading the list again.
#[tokio::test]
async fn watch_from_startup_does_not_reread_the_list_it_just_loaded() {
    let mut h = Harness::new().await;
    h.app.watch.enabled = true;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.send(Event::Tick).await;
    assert!(!h.app.watch_refresh_active());
    due(&mut h);
    h.send(Event::Tick).await;
    assert!(h.app.watch_refresh_active());
}

#[tokio::test]
async fn a_failed_pass_keeps_the_rows_and_says_so_once() {
    let mut h = watching().await;
    let fail = |h: &Harness, error: &str| {
        h.stream(Event::ResourceLoadError { service: h.app.current_service.unwrap(), error: error.into(), auth: None })
    };
    h.send(Event::Tick).await;
    let ev = fail(&h, "429 TooManyRequests: slow down");
    h.send(ev).await;
    assert_eq!(names(&h), ["vm-1", "vm-2"]);
    assert!(!h.app.loading && !h.app.watch_refresh_active());
    let said = h.app.error_message.clone().expect("the failure is said");
    assert!(said.contains("429 TooManyRequests") && said.contains("stays on screen"), "{said}");
    assert!(h.app.watch.enabled, "and watch carries on");

    // The same failure again is not repeated.
    h.app.error_message = None;
    due(&mut h);
    h.send(Event::Tick).await;
    let ev = fail(&h, "429 TooManyRequests: slow down");
    h.send(ev).await;
    assert!(h.app.error_message.is_none(), "{:?}", h.app.error_message);
    // A different one is.
    due(&mut h);
    h.send(Event::Tick).await;
    let ev = fail(&h, "503 ServiceUnavailable: later");
    h.send(ev).await;
    assert!(h.app.error_message.as_deref().is_some_and(|m| m.contains("503")));
    // A pass that works clears it, so the next failure is said again.
    due(&mut h);
    h.send(Event::Tick).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    assert!(h.app.watch.failed.is_none());
}

#[tokio::test]
async fn search_a_lens_and_a_modal_hold_the_pass_over_and_a_switch_drops_one() {
    let mut h = watching().await;
    h.press(KeyCode::Char('/')).await;
    h.send(Event::Tick).await;
    assert!(!h.app.watch_refresh_active(), "typing a search");
    h.press(KeyCode::Esc).await;

    h.press(KeyCode::Char('?')).await;
    h.send(Event::Tick).await;
    assert!(!h.app.watch_refresh_active(), "under help");
    h.press(KeyCode::Esc).await;

    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('U')).await;
    assert!(h.app.refs_lens.is_some());
    h.send(Event::Tick).await;
    assert!(!h.app.watch_refresh_active(), "a lens is about the row");
    h.press(KeyCode::Esc).await;

    h.send(Event::Tick).await;
    assert!(h.app.watch_refresh_active());
    // Another sub-tab mid-pass: its load is a normal one, never staged.
    h.app.switch_view(JumpView::Disks);
    h.settle().await;
    assert!(!h.app.watch_refresh_active());
    assert!(h.app.show_loading_indicator());

    h.press(KeyCode::Char('w')).await;
    assert!(!h.app.watch.enabled);
    h.send(Event::Tick).await;
    assert!(!h.app.watch_refresh_active(), "off is off");
}

#[tokio::test]
async fn over_the_charts_watch_refetches_them_not_the_list_never_under_a_minute() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Char('m')).await;
    // `w` works over the charts, and says what it refreshes.
    h.press(KeyCode::Char('w')).await;
    assert!(h.app.watch.enabled);
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.contains("the charts every 60s")), "{:?}", h.app.success_message);
    assert_eq!(h.app.watch_cadence(), Duration::from_secs(60), "30s, floored at a minute");
    assert!(h.render().contains("watch 60s"));

    // The open fetch is in flight (the harness never lands one): no pass.
    let g = h.app.metrics_generation;
    h.send(Event::Tick).await;
    assert_eq!(h.app.metrics_generation, g);
    // Landed, and a minute old: a pass refetches the charts, not the list.
    h.app.metrics.as_mut().unwrap().loading = false;
    due(&mut h);
    h.send(Event::Tick).await;
    assert_eq!(h.app.metrics_generation, g + 1, "the charts refetch");
    assert!(!h.app.watch_refresh_active(), "the list behind them does not");
    assert!(h.app.metrics.as_ref().unwrap().loading && h.app.watch_spinning());
    // Not again within the minute.
    h.app.metrics.as_mut().unwrap().loading = false;
    h.send(Event::Tick).await;
    assert_eq!(h.app.metrics_generation, g + 1);

    // `+` past the floor: the charts follow the interval.
    h.press(KeyCode::Char('+')).await;
    h.press(KeyCode::Char('+')).await;
    assert_eq!(h.app.watch.interval, Duration::from_secs(120));
    assert_eq!(h.app.watch_cadence(), Duration::from_secs(120));
    h.press(KeyCode::Char('-')).await;
    h.press(KeyCode::Char('-')).await;
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.contains("the charts: 60s")), "{:?}", h.app.success_message);

    // Closed: the list's cadence again.
    h.press(KeyCode::Esc).await;
    assert_eq!(h.app.watch_cadence(), Duration::from_secs(30));
}
