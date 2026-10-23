// ported from neboto-tui src/harness_tests/changes_test.rs @ 08fcd0c
// (adapted: the harness lands the rows; nebaz has no demo clients)
//! `@changes` (#61): one list per window, newest first whatever order the
//! sources stream in; the sub-tabs filter it without a call; `a` hides
//! the noise; `[` / `]` step the window (a new cache entry); `W` on a
//! change opens the timeline of what it happened to.

use super::mocks::{arm_id, change_activity, change_deployment, change_health};
use super::*;
use crate::azure::services::changes::{ChangeRow, ChangesWindow};
use serde_json::json;

/// An Activity Log change made by a managed identity: noise.
fn identity_change() -> Box<dyn Resource> {
    let e = json!({
        "eventTimestamp": "2026-10-23T12:00:00Z", "correlationId": "c-mi",
        "operationName": {"value": "Microsoft.Storage/storageAccounts/write"}, "status": {"value": "Succeeded"},
        "caller": "1b2c3d4e-0000-4000-8000-0123456789ab", "level": "Informational",
        "resourceId": arm_id("Microsoft.Storage/storageAccounts/stapp")
    });
    let row = crate::azure::timeline::activity_rows(&[e], 0, false).remove(0);
    Box::new(ChangeRow::new(row, Some("managed identity".into()), Some(TENANT.into())))
}

#[tokio::test]
async fn changes_list_newest_first_by_source_tab_with_the_window_on_the_tab_row() {
    let mut h = Harness::sized(170, 40).await;
    h.open(JumpView::ChangesAll).await;
    assert_eq!(h.app.cache_variant(), "changes-1h", "one list per window");
    // Streamed per source, oldest batch first: the default sort restores
    // newest first.
    h.land_page(vec![change_deployment()]).await; // 09:00
    h.land_page(vec![change_health()]).await; // 11:00
    h.land_page(vec![change_activity("c1", "Microsoft.Compute/virtualMachines/write"), identity_change()]).await; // 10:00, 12:00
    h.finish().await;
    // Noise is hidden by default (`a`, as everywhere): show it.
    assert!(h.app.hide_noise);
    assert_eq!(h.visible_names().len(), 3, "the managed identity's change is noise");
    h.press(KeyCode::Char('a')).await;
    assert_eq!(
        h.visible_names(),
        [
            "Microsoft.Storage/storageAccounts/write  stapp",
            "Unavailable  vm-1",
            "Microsoft.Compute/virtualMachines/write  vm-1",
            "Deployment succeeded  main",
        ]
    );
    let screen = h.render();
    for s in ["All", "Activity", "Deployments", "Health", "[ ] window", " 1h ", "Unavailable  vm-1  2026-10-23 11:00 · -"] {
        assert!(screen.contains(s), "{s:?} missing:\n{screen}");
    }

    // The sub-tabs filter the same list: no reload.
    h.press(KeyCode::Char('2')).await;
    assert_eq!(h.app.current_view, JumpView::ChangesActivity);
    assert!(!h.app.loading, "served from the window's cache entry");
    assert_eq!(h.visible_names().len(), 2);
    h.press(KeyCode::Char('3')).await;
    assert_eq!(h.visible_names(), ["Deployment succeeded  main"]);
    h.press(KeyCode::Char('4')).await;
    assert_eq!(h.visible_names(), ["Unavailable  vm-1"]);

    // A change's pane: Overview, then Related, which jumps to the VM.
    h.press(KeyCode::Enter).await;
    assert_eq!(h.section_labels(), ["Overview", "Related"]);
    let body = h.app.detail_body();
    assert!(body.iter().any(|(k, v)| k == "State" && v == "Unavailable"), "{body:#?}");
    h.press(KeyCode::Esc).await;

    // W on a change: the timeline of the VM it happened to.
    h.press(KeyCode::Char('W')).await;
    let st = h.app.timeline.as_ref().expect("W opens on the change's resource");
    assert_eq!(st.resource_id, arm_id("Microsoft.Compute/virtualMachines/vm-1"));
    h.press(KeyCode::Esc).await;
    h.press(KeyCode::Char('h')).await;

    // `]` widens the window: another cache entry, so a load.
    h.press(KeyCode::Char(']')).await;
    assert_eq!(h.app.changes_window, ChangesWindow::SixHours);
    assert_eq!(h.app.cache_variant(), "changes-6h");
    assert!(h.app.loading, "a window not loaded yet loads");
    // `[` comes back to the hour: cached.
    h.press(KeyCode::Char('[')).await;
    assert_eq!(h.app.changes_window, ChangesWindow::OneHour);
    assert!(!h.app.loading);
    assert_eq!(h.visible_names(), ["Unavailable  vm-1"], "still the Health sub-tab");
}
