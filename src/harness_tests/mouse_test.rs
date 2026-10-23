// ported from neboto-tui src/harness_tests/mouse_{hints,misc,modals,
// pane_views}_test.rs @ 03760c0 (the behaviours they pin), rewritten on
// the nebaz harness
//! The mouse (#42) through the real App: every gesture is an event the
//! main loop would deliver, aimed at what the last frame drew.

use super::mocks::{nic, nic_id, vm};
use super::*;
use crate::azure::metrics::{tests::fixture, MetricWindow};

/// The VMs tab with `names` as its rows, the first selected.
async fn vms(names: &[&str]) -> Harness {
    let mut h = Harness::new().await;
    h.app.current_location = Location::All;
    h.open(JumpView::VirtualMachines).await;
    h.land(names.iter().map(|n| vm(n, "westeurope")).collect()).await;
    h
}

/// List row `i`'s cell (rows start below the top border).
fn list_row(h: &Harness, i: u16) -> (u16, u16) {
    let list = h.app.list_area.get();
    (list.x + 3, list.y + 1 + i)
}

/// The detail body's screen row `i` (a cell a few columns in).
fn body_row(h: &Harness, i: u16) -> (u16, u16) {
    let body = h.app.mouse.detail_body.get().expect("the detail body is drawn");
    (body.x + 4, body.y + i)
}

/// Focus the detail pane by clicking a section chip, then go to Related
/// (its chip may be scrolled off a narrow strip).
async fn open_related(h: &mut Harness) {
    let chip = h.region(ClickAction::Detail(KeyCode::Char('2')));
    h.click(chip).await;
    assert!(h.app.details_focused, "a section chip focuses the pane");
    assert_eq!(h.app.detail_section_idx, 1);
    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
}

fn body_index(h: &Harness, value: &str) -> usize {
    h.app.detail_body().iter().position(|(_, v)| v.trim() == value).expect("the line is in the body")
}

#[tokio::test]
async fn a_click_selects_a_row_and_a_double_click_drills_in() {
    let mut h = vms(&["vm-a", "vm-b", "vm-c"]).await;
    let row1 = list_row(&h, 1);
    h.click(row1).await;
    assert_eq!(h.app.selected_index, Some(1));
    assert!(!h.app.details_focused, "one click never acts");

    let row2 = list_row(&h, 2);
    h.double_click(row2).await;
    assert_eq!(h.app.selected_index, Some(2));
    assert!(h.app.details_focused, "a double-click is ⏎");
}

#[tokio::test]
async fn the_wheel_scrolls_the_pane_under_the_pointer() {
    let mut h = vms(&["vm-a", "vm-b", "vm-c"]).await;
    let row0 = list_row(&h, 0);
    h.scroll(row0, true).await;
    assert_eq!(h.app.selected_index, Some(1));
    h.scroll(row0, false).await;
    assert_eq!(h.app.selected_index, Some(0));

    // Over the detail body it moves the line cursor, three at a time,
    // focusing the pane, and leaves the list alone.
    let body = body_row(&h, 0);
    assert!(h.app.detail_body().len() > 4);
    h.scroll(body, true).await;
    assert!(h.app.details_focused);
    assert_eq!(h.app.details_scroll, 3);
    assert_eq!(h.app.selected_index, Some(0));
    h.scroll(body, false).await;
    assert_eq!(h.app.details_scroll, 0);

    // Over the tab strip: nothing.
    h.scroll((2, 0), true).await;
    assert_eq!(h.app.selected_index, Some(0));
}

#[tokio::test]
async fn a_body_click_moves_the_cursor_and_a_double_click_follows_the_id() {
    let mut h = vms(&["vm-1"]).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    open_related(&mut h).await;
    let target = nic_id("vm-1-nic");
    let idx = body_index(&h, &target);

    let at = h.find("vm-1-nic");
    h.click(at).await;
    assert_eq!(h.app.details_scroll, idx, "the click put the cursor on the NIC line");
    assert_eq!(h.app.current_view, JumpView::VirtualMachines, "one click never jumps");

    h.double_click(at).await;
    assert_eq!(h.app.current_view, JumpView::Nics);
    assert_eq!(h.app.pending_jump, Some((target.clone(), true)));
    h.land(vec![nic("vm-1-nic", "westeurope")]).await;
    assert_eq!(h.selected_id(), Some(target));

    // A right-click is ⌫: back to the VM.
    let body = body_row(&h, 0);
    h.right_click(body).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.app.get_selected_resource().map(|r| r.name().to_string()).as_deref(), Some("vm-1"));
}

#[tokio::test]
async fn a_click_lands_on_the_right_line_under_wrap_and_under_the_filter() {
    // A narrow pane, so the ARM id wraps over several screen rows.
    let mut h = Harness::sized(100, 40).await;
    h.app.current_location = Location::All;
    h.app.detail_wrap = true;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Enter).await;

    let id = h.selected_id().unwrap();
    let id_line = body_index(&h, &id);
    let next = id_line + 1;
    let rows = h.app.mouse.detail_rows.borrow().clone();
    let first = rows.first().copied().unwrap();
    let screen_row = rows.iter().position(|&r| r == next).expect("the line after the id is drawn");
    assert!(screen_row > next - first, "the id wraps, so later lines sit lower: {rows:?}");

    let at = body_row(&h, screen_row as u16);
    h.click(at).await;
    assert_eq!(h.app.details_scroll, next);
    // A continuation row of the id is the id.
    let id_row = rows.iter().position(|&r| r == id_line).unwrap();
    let at = body_row(&h, id_row as u16 + 1);
    h.click(at).await;
    assert_eq!(h.app.details_scroll, id_line);

    // Filtered: the click lands on the filtered row on screen.
    h.app.detail_wrap = false;
    h.press(KeyCode::Char('/')).await;
    h.type_str("b2s").await;
    h.press(KeyCode::Enter).await;
    let body = h.app.detail_body();
    let want = body.iter().position(|(_, v)| v.contains("Standard_B2s")).expect("the size line matches");
    let shown = h.app.mouse.detail_rows.borrow().iter().position(|&r| r == want).unwrap();
    let at = body_row(&h, shown as u16);
    h.click(at).await;
    assert_eq!(h.app.details_scroll, want);
    assert!(h.app.detail_body()[h.app.details_scroll].1.contains("Standard_B2s"));
}

#[tokio::test]
async fn a_click_does_not_scroll_the_line_it_hit() {
    // A short pane: the cursor at the bottom, then a click near the top.
    let mut h = Harness::sized(140, 26).await;
    h.app.current_location = Location::All;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('G')).await;
    h.render();
    let top = h.app.mouse.detail_top.get();
    assert!(top > 0, "the body is taller than the pane");
    let at = body_row(&h, 1);
    h.click(at).await;
    assert_eq!(h.app.details_scroll, top + 1);
    h.render();
    assert_eq!(h.app.mouse.detail_top.get(), top, "the view stayed put");
}

#[tokio::test]
async fn a_drag_over_the_body_selects_lines() {
    let mut h = vms(&["vm-1"]).await;
    h.press(KeyCode::Enter).await;
    let (from, to) = (body_row(&h, 1), body_row(&h, 3));
    h.drag(from, to).await;
    assert_eq!(h.app.detail_visual_range(), Some((1, 3)));
    // A plain click starts over.
    let at = body_row(&h, 2);
    h.click(at).await;
    assert_eq!(h.app.detail_visual_range(), None);
    assert_eq!(h.app.details_scroll, 2);
}

#[tokio::test]
async fn right_click_without_history_leaves_the_detail_pane() {
    let mut h = vms(&["vm-a", "vm-b"]).await;
    h.press(KeyCode::Enter).await;
    let at = body_row(&h, 0);
    h.right_click(at).await;
    assert!(!h.app.details_focused);
    // While typing a query, a right-click does nothing (⌫ would delete).
    h.press(KeyCode::Char('/')).await;
    h.type_str("vm").await;
    let at = list_row(&h, 0);
    h.right_click(at).await;
    assert!(h.app.search_active);
    assert_eq!(h.app.search_query, "vm");
}

#[tokio::test]
async fn chips_markers_and_bars_switch() {
    let mut h = vms(&["vm-1"]).await;
    // A sub-tab chip, from the detail pane too (it is a list control).
    h.press(KeyCode::Enter).await;
    let disks = h.region(ClickAction::List(KeyCode::Char('2')));
    h.click(disks).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert!(!h.app.details_focused);

    // A service chip.
    h.open(JumpView::StorageAccounts).await;
    let chip = h.region(ClickAction::Service(ServiceType::VirtualMachines));
    h.click(chip).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines));

    // The search bar starts a search.
    let bar = h.find(" Search ");
    h.click(bar).await;
    assert!(h.app.search_active);
    h.press(KeyCode::Esc).await;

    // The detail title bar toggles full width.
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    let title = h.region(ClickAction::Detail(KeyCode::Char('Z')));
    h.click(title).await;
    assert!(h.app.details_focused);
    assert_eq!(h.app.layout_mode, LayoutMode::DetailsOnly);
}

#[tokio::test]
async fn an_overflow_marker_steps_one_sub_tab() {
    let mut h = Harness::sized(60, 30).await;
    h.open(JumpView::VirtualNetworks).await;
    assert!(h.render().contains('›'), "the strip overflows");
    let next = h.region(ClickAction::List(KeyCode::Char('L')));
    h.click(next).await;
    assert_eq!(h.app.current_view, JumpView::Subnets);
    // Step right until the strip scrolls and shows `‹`, then step back.
    while !h.app.click_regions.borrow().iter().any(|r| r.action == ClickAction::List(KeyCode::Char('H'))) {
        let next = h.region(ClickAction::List(KeyCode::Char('L')));
        h.click(next).await;
        h.render();
    }
    let view = h.app.current_view;
    let prev = h.region(ClickAction::List(KeyCode::Char('H')));
    h.click(prev).await;
    let views = ServiceType::Network.views();
    let pos = |v| views.iter().position(|x| *x == v).unwrap();
    assert_eq!(pos(h.app.current_view) + 1, pos(view));
}

#[tokio::test]
async fn hints_badges_and_the_location_chip_press_their_keys() {
    let mut h = vms(&["vm-a", "vm-b"]).await;
    // Status bar: `/ search`.
    let search = h.region(ClickAction::Press(KeyCode::Char('/')));
    h.click(search).await;
    assert!(h.app.search_active);
    h.press(KeyCode::Esc).await;
    // `q` is never a click target.
    h.render();
    assert!(!h.app.click_regions.borrow().iter().any(|r| r.action == ClickAction::Press(KeyCode::Char('q'))));

    // The location chip opens the location filter; a click outside closes it.
    let chip = h.region(ClickAction::Press(KeyCode::Char('R')));
    h.click(chip).await;
    assert!(h.app.location_selector.visible);
    h.click((0, 0)).await;
    assert!(!h.app.location_selector.visible);

    // The subscription badge opens the subscription picker.
    let badge = h.region(ClickAction::Press(KeyCode::Char('P')));
    h.click(badge).await;
    assert!(h.app.subscription_selector.visible);
    let at = list_row(&h, 0);
    h.right_click(at).await;
    assert!(!h.app.subscription_selector.visible);

    // Detail footer: `h list` goes back to the list.
    h.press(KeyCode::Enter).await;
    let list = h.find("h list");
    h.click(list).await;
    assert!(!h.app.details_focused);
}

#[tokio::test]
async fn the_footer_back_hint_walks_history() {
    let mut h = vms(&["vm-1"]).await;
    open_related(&mut h).await;
    h.cursor_to_value(&nic_id("vm-1-nic")).await;
    h.press(KeyCode::Enter).await;
    h.land(vec![nic("vm-1-nic", "westeurope")]).await;
    let back = h.find("⌫ back to");
    h.click(back).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
}

#[tokio::test]
async fn the_service_picker_takes_clicks_and_nothing_falls_through() {
    let mut h = vms(&["vm-a", "vm-b"]).await;
    h.press(KeyCode::Char('S')).await;
    let start = h.app.service_selector.selected_index;
    h.scroll((70, 20), true).await;
    assert_ne!(h.app.service_selector.selected_index, start, "the wheel moves the highlight");

    let row = h.find(ServiceType::KeyVault.description());
    h.click(row).await;
    assert!(h.app.service_selector.visible, "one click highlights");
    assert_eq!(h.app.service_selector.selected_service(), Some(ServiceType::KeyVault));
    h.click(row).await;
    assert!(!h.app.service_selector.visible, "a click on the highlighted row opens it");
    assert_eq!(h.app.current_service, Some(ServiceType::KeyVault));

    // A click outside a modal closes it and goes no further.
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-a", "westeurope"), vm("vm-b", "westeurope")]).await;
    h.press(KeyCode::Char('?')).await;
    let row1 = list_row(&h, 1);
    h.click(row1).await;
    assert!(!h.app.help_visible);
    assert_eq!(h.app.selected_index, Some(0), "the click did not reach the list");
}

#[tokio::test]
async fn help_scrolls_with_the_wheel() {
    let mut h = Harness::sized(140, 26).await;
    h.open(JumpView::VirtualMachines).await;
    h.press(KeyCode::Char('?')).await;
    assert!(h.app.help_max_scroll.get() > 3);
    let popup = h.app.mouse.popup.borrow().area.unwrap();
    let inside = (popup.x + 2, popup.y + 2);
    h.scroll(inside, true).await;
    assert_eq!(h.app.help_scroll, 3);
    h.click(inside).await;
    assert!(h.app.help_visible, "a click inside help keeps it");
    h.right_click(inside).await;
    assert!(!h.app.help_visible);
}

#[tokio::test]
async fn a_jump_list_double_click_jumps_and_the_macro_prompt_ignores_the_mouse() {
    let mut h = vms(&["vm-1"]).await;
    open_related(&mut h).await;
    h.cursor_to_value(&nic_id("vm-1-nic")).await;
    h.press(KeyCode::Enter).await;
    h.land(vec![nic("vm-1-nic", "westeurope")]).await;
    h.press(KeyCode::Esc).await;

    h.press(KeyCode::Char('`')).await;
    let rows = h.app.mouse.popup.borrow().rows.clone();
    let (_, vm_row) = *rows
        .iter()
        .find(|(i, _)| h.app.nav_history[h.app.nav_history.len() - 1 - i].view == Some(JumpView::VirtualMachines))
        .expect("the VM is in the jump list");
    h.double_click((vm_row.x + 2, vm_row.y)).await;
    assert!(!h.app.jump_list_visible);
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);

    // Naming a macro: Esc would discard the recording, so the mouse can't.
    h.app.macro_picker_visible = true;
    h.app.macro_name_input = Some(String::new());
    h.right_click((1, 1)).await;
    h.click((1, 1)).await;
    assert!(h.app.macro_picker_visible && h.app.macro_name_input.is_some());
}

#[tokio::test]
async fn lens_rows_take_clicks_and_a_right_click_closes() {
    use super::network_lens_test::{nsg_id, vnet, warm};
    let mut h = Harness::new().await;
    let subnet = vnet().subnets.remove(0);
    h.install(mocks::Mock { view: JumpView::Subnets, label: "SubnetRow", resource: Box::new(subnet) }).await;
    warm(&mut h, false);
    h.press(KeyCode::Char('N')).await;
    h.render();

    let rule = h.app.network_lens.as_ref().unwrap().lines.iter().position(|l| l.rule.is_some()).unwrap();
    let rect = h.app.mouse.pane_rows.borrow().rows.iter().find(|(i, _)| *i == rule).unwrap().1;
    let at = (rect.x + 4, rect.y);
    h.click(at).await;
    assert_eq!(h.app.network_lens.as_ref().unwrap().selected, rule);

    // A footer hint presses its key and keeps the lens.
    let direction = h.find("t direction");
    h.click(direction).await;
    let lens = h.app.network_lens.as_ref().expect("a hint keeps the lens");
    assert_eq!(lens.direction, crate::ui::widgets::network_lens::LensDirection::Inbound);

    // Right-click closes; reopen and double-click a rule: it goes to the NSG.
    let pane = h.app.mouse.detail_pane.get().unwrap();
    h.right_click((pane.x + 2, pane.y + 2)).await;
    assert!(h.app.network_lens.is_none());
    h.press(KeyCode::Char('N')).await;
    h.render();
    let rect = h.app.mouse.pane_rows.borrow().rows.iter().find(|(i, _)| *i == rule).unwrap().1;
    h.double_click((rect.x + 4, rect.y)).await;
    assert!(h.app.network_lens.is_none());
    assert_eq!(h.selected_id(), Some(nsg_id()));
}

#[tokio::test]
async fn metrics_rows_and_range_chips_take_clicks() {
    let mut h = vms(&["vm-1"]).await;
    h.press(KeyCode::Char('m')).await;
    super::metrics_test::land_series(&mut h, fixture()).await;
    h.render();
    let rect = h.app.mouse.pane_rows.borrow().rows.iter().find(|(i, _)| *i == 1).unwrap().1;
    h.click((rect.x + 4, rect.y)).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().selected, 1);

    let week = h.region(ClickAction::Press(KeyCode::Char('4')));
    h.click(week).await;
    assert_eq!(h.app.metrics.as_ref().unwrap().window, MetricWindow::SevenDays);

    // A click on the list leaves the view and selects as usual.
    let at = list_row(&h, 0);
    h.click(at).await;
    assert!(h.app.metrics.is_none());
}

/// The `C` command picker (#47) is a mouse modal like the others: a click
/// highlights a command, a click on the highlighted one or a double-click
/// copies it, the wheel moves the highlight, and a right-click or a click
/// outside closes it, a typed filter and all, copying nothing.
#[tokio::test]
async fn the_command_picker_is_a_mouse_modal() {
    let mut h = vms(&["vm-a"]).await;
    let catalogue = crate::azure::cli_actions::actions_for(h.app.get_selected_resource().unwrap());
    let command = |label: &str| catalogue.iter().find(|a| a.label == label).unwrap().command.clone();

    h.press(KeyCode::Char('C')).await;
    let at = h.find("vm get-instance-view");
    h.click(at).await;
    let picker = h.app.command_picker.as_ref().expect("one click never copies");
    assert_eq!(picker.selected, 1);
    assert_eq!(h.app.clipboard.last(), None);
    h.click(at).await;
    assert!(h.app.command_picker.is_none(), "a click on the highlighted row copies");
    assert_eq!(h.app.clipboard.last(), Some(command("vm get-instance-view").as_str()));

    h.press(KeyCode::Char('C')).await;
    let popup = h.app.mouse.popup.borrow().area.expect("the picker records its rect");
    let inside = (popup.x + 2, popup.y + 2);
    h.scroll(inside, true).await;
    h.scroll(inside, true).await;
    h.scroll(inside, false).await;
    assert_eq!(h.app.command_picker.as_ref().unwrap().selected, 1, "the wheel moves the highlight");
    let restart = h.find("vm restart");
    h.double_click(restart).await;
    assert!(h.app.command_picker.is_none());
    assert_eq!(h.app.clipboard.last(), Some(command("vm restart").as_str()));

    h.press(KeyCode::Char('C')).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("vm").await;
    h.right_click(inside).await;
    assert!(h.app.command_picker.is_none(), "a right-click closes, filter or not");

    h.press(KeyCode::Char('C')).await;
    h.click((0, 0)).await;
    assert!(h.app.command_picker.is_none(), "a click outside closes");
    assert_eq!(h.app.clipboard.last(), Some(command("vm restart").as_str()), "and copies nothing");
}
