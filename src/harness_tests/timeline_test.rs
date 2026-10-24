//! The change timeline (`W`, #52): opening on a VM fans out one fetch per
//! source and owns the detail pane, sources land independently and merge
//! newest first, an auxiliary failure is a note, a stale answer is
//! dropped, and the keys (`f`, `a`, `[` / `]`, `⏎`, `Esc`) and the mouse
//! work. The harness never lets a fetch land: each answer goes through
//! the apply-closure event the real task sends.

use super::mocks::arm_id;
use super::*;
use crate::azure::timeline::{
    activity_rows, alert_rows, deployment_rows, health_rows, LensWindow, TimelineSource,
};
use crate::lazy::LazyApply;
use crate::ui::widgets::timeline_lens::TimelineLensState;
use serde_json::{json, Value};

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

/// Deliver one source's answer as its task would, for generation `g`.
async fn land(h: &mut Harness, g: u64, f: impl FnOnce(&mut TimelineLensState) + Send + 'static) {
    let epoch = h.app.lazy.epoch();
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
        if app.timeline_generation != g {
            return;
        }
        if let Some(st) = app.timeline.as_mut() {
            f(st);
        }
    });
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;
}

#[tokio::test]
async fn w_on_a_vm_merges_four_sources_newest_first_and_esc_hands_the_pane_back() {
    let mut h = Harness::sized(170, 40).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("vm-1", "westeurope")]).await;
    assert!(h.render().contains("W changes"), "the status bar offers W");

    h.press(KeyCode::Char('W')).await;
    let st = h.app.timeline.as_ref().expect("W opens the timeline");
    assert_eq!(st.resource_id, vm_id());
    assert_eq!(st.window, LensWindow::Week);
    let mut pending = st.pending.clone();
    pending.sort_by_key(|s| crate::azure::timeline::slot(*s));
    assert_eq!(pending, TimelineSource::ALL, "one fetch per source");
    assert!(h.app.details_focused, "opening from the list focuses the pane");
    assert!(h.render().contains("TIMELINE"));

    let g = h.app.timeline_generation;
    land(&mut h, g, |st| {
        st.since = 0; // the fixture's dates, whatever today is
        st.set_activity(
            vec![
                event("2026-10-23T10:00:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Started"),
                event("2026-10-23T10:02:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Succeeded"),
                event("2026-10-23T12:00:00Z", "c2", "Microsoft.Compute/virtualMachines/deallocate/action", "Failed"),
            ],
            false,
        )
    })
    .await;
    let vm = vm_id();
    land(&mut h, g, move |st| {
        let items = vec![json!({
            "id": format!("{}/providers/Microsoft.ResourceHealth/availabilityStatuses/current", vm),
            "properties": {"availabilityState": "Unavailable", "summary": "Your VM is stopped",
                "reasonType": "UserInitiated", "occuredTime": "2026-10-23T12:01:00Z"}
        })];
        st.set_rows(TimelineSource::Health, health_rows(&items, 0))
    })
    .await;
    let vm = vm_id();
    land(&mut h, g, move |st| {
        let items = vec![json!({"id": "/subscriptions/x/providers/Microsoft.AlertsManagement/alerts/a1", "name": "vm-cpu",
            "properties": {"essentials": {"severity": "Sev3", "monitorService": "Platform", "targetResource": vm,
                "startDateTime": "2026-10-23T09:00:00Z"}}})];
        st.set_rows(TimelineSource::Alert, alert_rows(&items, 0))
    })
    .await;
    land(&mut h, g, |st| st.set_source_error(TimelineSource::Deployment, "no access".into())).await;

    let st = h.app.timeline.as_ref().unwrap();
    assert!(!st.is_loading());
    let order: Vec<&str> = st.rows.iter().map(|r| r.what.as_str()).collect();
    assert_eq!(
        order,
        [
            "Unavailable",
            "Microsoft.Compute/virtualMachines/deallocate/action",
            "Microsoft.Compute/virtualMachines/write",
            "Alert fired · Sev3"
        ]
    );
    h.press(KeyCode::Char('Z')).await; // full width: every column
    let screen = h.render();
    h.press(KeyCode::Char('Z')).await;
    for s in ["TIMELINE", "last 7d", "HLTH", "ACT", "ALRT", "Deployments: no access", "Your VM is stopped", "ops@contoso.com"] {
        assert!(screen.contains(s), "{s:?} missing:\n{screen}");
    }

    // `f` keeps one source; `a` shows the operation that never finished… (none here: Started collapsed into Succeeded).
    h.press(KeyCode::Char('f')).await;
    assert!(h.app.timeline.as_ref().unwrap().rows.iter().all(|r| r.source() == TimelineSource::Activity));
    for _ in 0..4 {
        h.press(KeyCode::Char('f')).await;
    }
    assert_eq!(h.app.timeline.as_ref().unwrap().rows.len(), 4);

    // ⏎ opens the selected row's named fields in the editor.
    h.press(KeyCode::Char('j')).await;
    h.press(KeyCode::Enter).await;
    assert!(h.app.editor_requested);
    h.app.editor_requested = false;
    let text = h.app.timeline.as_ref().unwrap().editor_text();
    assert!(text.contains("Operation name") && text.contains("deallocate/action") && text.contains("Failed"), "{text}");

    // `]` widens the window: a new generation, so a stale answer is dropped.
    h.press(KeyCode::Char(']')).await;
    let st = h.app.timeline.as_ref().unwrap();
    assert_eq!(st.window, LensWindow::Month);
    assert!(st.is_loading());
    land(&mut h, g, |st| st.set_rows(TimelineSource::Deployment, deployment_rows(&[], 0, None))).await;
    assert!(
        h.app.timeline.as_ref().unwrap().pending.contains(&TimelineSource::Deployment),
        "the old generation's answer is dropped"
    );

    // Esc closes; the window sticks for the next open.
    h.press(KeyCode::Esc).await;
    assert!(h.app.timeline.is_none());
    assert!(h.app.details_focused);
    assert!(!h.render().contains("TIMELINE"));
    h.press(KeyCode::Char('W')).await;
    assert_eq!(h.app.timeline.as_ref().unwrap().window, LensWindow::Month);
}

#[tokio::test]
async fn a_resource_group_has_no_health_and_the_mouse_selects_rows() {
    let mut h = Harness::sized(170, 40).await;
    let rg = mocks::all_mocks().into_iter().find(|m| m.view == JumpView::ResourceGroups).unwrap();
    h.install(rg).await;
    h.press(KeyCode::Char('W')).await;
    let st = h.app.timeline.as_ref().expect("W opens on a group");
    assert!(!st.pending.contains(&TimelineSource::Health));
    assert!(st.notes.iter().any(|n| n.contains("resources only")));

    let g = h.app.timeline_generation;
    land(&mut h, g, |st| {
        st.since = 0; // the fixture's dates, whatever today is
        st.set_activity(
            vec![
                event("2026-10-23T10:00:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Succeeded"),
                event("2026-10-23T11:00:00Z", "c2", "Microsoft.Compute/virtualMachines/delete", "Succeeded"),
            ],
            false,
        )
    })
    .await;
    assert_eq!(activity_rows(&h.app.timeline.as_ref().unwrap().activity_events, 0, false).len(), 2);

    // A click puts the cursor on a row; right-click closes.
    let at = h.find("virtualMachines/write ");
    h.click(at).await;
    assert_eq!(h.app.timeline.as_ref().unwrap().selected, 1);
    h.right_click(at).await;
    assert!(h.app.timeline.is_none());
}

#[tokio::test]
async fn the_counts_row_carries_the_ownership_line() {
    let mut h = Harness::sized(170, 40).await;
    let vm = crate::azure::services::compute::VmRow::from_json(
        &json!({"id": arm_id("Microsoft.Compute/virtualMachines/vm-own"), "name": "vm-own", "location": "westeurope",
            "tags": {"Owner": "alice"}, "properties": {"provisioningState": "Succeeded"}}),
        Some(TENANT),
    )
    .unwrap();
    h.install(mocks::Mock { view: JumpView::VirtualMachines, label: "VmRow", resource: Box::new(vm) }).await;
    h.press(KeyCode::Char('W')).await;
    let screen = h.render();
    let counts = screen.lines().find(|l| l.contains("ACT ")).unwrap_or_default();
    assert!(counts.contains('⛓') && counts.contains("alice"), "{screen}");
}
