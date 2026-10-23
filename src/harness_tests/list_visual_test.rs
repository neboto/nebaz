// ported from neboto-tui src/harness_tests/mod.rs and deep_export_test.rs
// @ 03760c0 (list_visual_selection_selects_copies_and_cancels,
// deep_export_cap_refuses_oversized_selections, the select-all-then-X
// test), rewritten on the nebaz harness
//! The list pane's visual selection (#39) through the real App: the range
//! keys, the positional cancellation, the selection-aware copy and export
//! verbs, and the deep export's wait over several rows.

use super::export_test::{expire_wait, land_vm_sections, written};
use super::*;
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use serde_json::Value;

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// The VMs tab with `names` as its rows, the first selected.
async fn vms(h: &mut Harness, names: &[&str]) {
    h.app.current_location = Location::All;
    h.open(JumpView::VirtualMachines).await;
    h.land(names.iter().map(|n| mocks::vm(n, "westeurope")).collect()).await;
    assert_eq!(h.visible_names(), names);
    assert_eq!(h.app.selected_index, Some(0));
}

#[tokio::test]
async fn v_selects_extends_and_cancels() {
    let mut h = Harness::new().await;
    vms(&mut h, &["vm-v-a", "vm-v-b", "vm-v-c"]).await;

    // V anchors at the cursor; plain j extends, the anchor stays.
    h.press(KeyCode::Char('V')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 0)));
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 1)));
    assert!(h.app.list_row_in_selection(1) && !h.app.list_row_in_selection(2));
    h.press(KeyCode::Char('G')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 2)));
    h.press(KeyCode::Char('g')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 0)));

    // Esc cancels; V toggles too.
    h.press(KeyCode::Esc).await;
    assert_eq!(h.app.list_visual_range(), None);
    h.press(KeyCode::Char('V')).await;
    h.press(KeyCode::Char('V')).await;
    assert_eq!(h.app.list_visual_range(), None);

    // J / K and Shift-↓ / ↑ start and extend in one motion.
    h.press(KeyCode::Char('J')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 1)));
    h.press_key(KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT)).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 2)));
    h.press(KeyCode::Char('K')).await;
    h.press_key(KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT)).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 0)));
    h.press(KeyCode::Esc).await;

    // Ctrl-A selects every visible row, and no longer toggles noise (the
    // `a` arm matched any modifier).
    let noise = h.app.hide_noise;
    h.press_key(ctrl('a')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 2)));
    assert_eq!(h.app.hide_noise, noise, "Ctrl-A is not `a`");
    // The selected rows are painted.
    let screen = h.render();
    assert!(screen.contains("vm-v-b"));
}

#[tokio::test]
async fn a_rebuild_or_a_drill_in_cancels_the_selection() {
    let mut h = Harness::new().await;
    vms(&mut h, &["vm-r-a", "vm-r-b", "vm-r-c"]).await;

    // A sort rebuilds the list.
    h.press_key(ctrl('a')).await;
    h.press(KeyCode::Char('z')).await;
    assert_eq!(h.app.list_visual_range(), None);

    // So does a search edit.
    h.press(KeyCode::Char('V')).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("vm-r").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.list_visual_range(), None);

    // A drill-in.
    h.press(KeyCode::Char('V')).await;
    h.press(KeyCode::Enter).await;
    assert!(h.app.details_focused);
    assert_eq!(h.app.list_visual_range(), None);
}

#[tokio::test]
async fn y_copies_the_rows_and_ctrl_x_exports_only_them() {
    let mut h = Harness::new().await;
    vms(&mut h, &["vm-y-a", "vm-y-b", "vm-y-c"]).await;
    h.press(KeyCode::Char('J')).await;

    // y copies a Markdown table (the clipboard may be unavailable
    // headless; the selection is dropped either way).
    h.press(KeyCode::Char('y')).await;
    assert_eq!(h.app.list_visual_range(), None);
    let msg = format!("{:?}{:?}", h.app.success_message, h.app.error_message);
    assert!(msg.contains("2 rows") || msg.contains("Clipboard"), "{msg}");

    // Ctrl-X with a selection writes just those rows.
    h.press(KeyCode::Char('g')).await;
    h.press(KeyCode::Char('J')).await;
    h.press_key(ctrl('x')).await;
    assert_eq!(h.app.list_visual_range(), None, "the export drops the selection");
    let csv = written(&h, "csv");
    assert!(csv.contains("vm-y-a") && csv.contains("vm-y-b") && !csv.contains("vm-y-c"), "{csv}");
    let md = written(&h, "md");
    assert!(md.contains("(2)"), "{md}");

    // Without a selection Ctrl-X is the whole list again.
    h.press_key(ctrl('x')).await;
    assert!(written(&h, "csv").contains("vm-y-c"));
}

#[tokio::test]
async fn x_deep_exports_the_selection_once_every_row_lands() {
    let mut h = Harness::new().await;
    let names = ["vm-deep-a", "vm-deep-b", "vm-deep-c"];
    vms(&mut h, &names).await;
    h.press_key(ctrl('a')).await;
    let ids: Vec<String> = h
        .app
        .filtered_resources
        .iter()
        .map(|&i| h.app.resources[i].id().to_string())
        .collect();

    h.press(KeyCode::Char('X')).await;
    let pending = h.app.pending_export.as_ref().expect("armed");
    assert!(!pending.single);
    assert_eq!(pending.ids, ids);
    assert!(h.app.last_export_paths.is_empty());
    for id in &ids {
        assert!(h.app.lazy.vm_instance_views.contains(id), "every row's sections fired");
    }
    let progress = h.app.deep_export_progress.clone().unwrap_or_default();
    assert!(progress.contains("0/3 ready"), "{progress}");
    assert_eq!(h.app.selected_index, Some(2), "the walk puts the cursor back");

    // Two rows land: still waiting.
    land_vm_sections(&mut h, &ids[0]);
    land_vm_sections(&mut h, &ids[1]);
    h.settle().await;
    let progress = h.app.deep_export_progress.clone().unwrap_or_default();
    assert!(progress.contains("2/3 ready"), "{progress}");

    // A rebuild drops the positional selection but not the armed export.
    h.app.update_search();
    assert_eq!(h.app.list_visual_range(), None);
    assert!(h.app.pending_export.is_some());

    land_vm_sections(&mut h, &ids[2]);
    h.settle().await;
    assert!(h.app.pending_export.is_none());
    let stem = h.app.last_export_paths[0].file_stem().unwrap().to_string_lossy().into_owned();
    assert!(stem.contains("-deep-"), "{stem}");
    let v: Value = serde_json::from_str(&written(&h, "json")).unwrap();
    let arr = v.as_array().expect("a JSON array");
    assert_eq!(arr.len(), 3);
    for (obj, id) in arr.iter().zip(&ids) {
        assert_eq!(obj["resource"]["id"], id.as_str());
        assert!(!obj["sections"]["Instance view"].is_null());
    }
    let md = written(&h, "md");
    assert!(md.contains("(3)"), "{md}");
    for name in names {
        assert!(md.contains(&format!(": {name}\n")), "{name} chapter");
    }
    let csv = written(&h, "csv");
    assert!(ids.iter().all(|id| csv.contains(&format!("{id},Instance view,"))));
    let msg = h.app.success_message.clone().unwrap_or_default();
    assert!(msg.starts_with("Exported 3 "), "{msg}");
}

#[tokio::test]
async fn a_deep_export_past_its_limit_writes_and_counts_the_incomplete_rows() {
    let mut h = Harness::new().await;
    vms(&mut h, &["vm-dl-a", "vm-dl-b"]).await;
    h.press_key(ctrl('a')).await;
    h.press(KeyCode::Char('X')).await;
    let first = h.app.pending_export.as_ref().unwrap().ids[0].clone();
    land_vm_sections(&mut h, &first);
    expire_wait(&mut h).await;
    let msg = h.app.success_message.clone().unwrap_or_default();
    assert!(msg.contains("1 still loading"), "{msg}");
    let v: Value = serde_json::from_str(&written(&h, "json")).unwrap();
    assert!(!v[0]["sections"]["Instance view"].is_null());
    assert!(v[1]["sections"]["Instance view"].is_null());
}

#[tokio::test]
async fn the_deep_export_cap_refuses_and_keeps_the_selection() {
    let mut h = Harness::new().await;
    let names: Vec<String> = (0..51).map(|i| format!("vm-cap-{i:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    vms(&mut h, &refs).await;
    h.press_key(ctrl('a')).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 50)));
    h.press(KeyCode::Char('X')).await;
    let err = h.app.error_message.clone().unwrap_or_default();
    assert!(err.contains("capped at 50"), "{err}");
    assert!(h.app.pending_export.is_none());
    assert_eq!(h.app.list_visual_range(), Some((0, 50)), "kept, to narrow it");
}

#[tokio::test]
async fn a_left_drag_over_the_list_selects_rows() {
    let mut h = Harness::new().await;
    vms(&mut h, &["vm-m-a", "vm-m-b", "vm-m-c"]).await;
    h.render();
    let list = h.app.list_area.get();
    let at = |kind, row: u16| {
        Event::Mouse(MouseEvent { kind, column: list.x + 2, row: list.y + 1 + row, modifiers: KeyModifiers::NONE })
    };
    h.send(at(MouseEventKind::Down(MouseButton::Left), 0)).await;
    h.send(at(MouseEventKind::Drag(MouseButton::Left), 1)).await;
    h.send(at(MouseEventKind::Drag(MouseButton::Left), 2)).await;
    assert_eq!(h.app.list_visual_range(), Some((0, 2)));
    // A plain click starts over.
    h.send(at(MouseEventKind::Down(MouseButton::Left), 1)).await;
    assert_eq!(h.app.list_visual_range(), None);
    assert_eq!(h.app.selected_index, Some(1));
}
