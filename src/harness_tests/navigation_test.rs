//! Service and sub-tab switches, the Related jump, the detail pane's
//! section keys and flat view, the location filter, and copy.

use super::mocks::{arm_id, disk, nic, nic_id, vm};
use super::*;

#[tokio::test]
async fn service_and_sub_tab_switches_render() {
    let mut h = Harness::new().await;
    assert_eq!(h.app.current_service, None, "the splash opens with no service");

    // A routing prefix through search switches service.
    h.press(KeyCode::Char('/')).await;
    h.type_str("@vm").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines));
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(h.app.loading_started, "the main loop started the load");
    h.land(vec![vm("vm-1", "westeurope")]).await;
    let screen = h.render();
    for chip in ["VMs", "Disks", "NICs", "vm-1"] {
        assert!(screen.contains(chip), "{chip:?} missing:\n{screen}");
    }

    // Tab: the next sub-tab, its own load.
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert!(h.app.loading);
    h.land(vec![disk("disk-1", "westeurope")]).await;
    let screen = h.render();
    assert!(screen.contains("disk-1") && !screen.contains("vm-1"), "{screen}");

    // A digit: back to the first sub-tab, served from the cache.
    h.press(KeyCode::Char('1')).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(!h.app.loading, "a cached sub-tab needs no load");
    assert!(h.render().contains("vm-1"));

    // Another service: its first sub-tab.
    h.press(KeyCode::Char('/')).await;
    h.type_str("@vnet").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::VirtualNetworks);
    h.land(vec![super::mocks::vnet("vnet-1", "westeurope")]).await;
    let screen = h.render();
    assert!(screen.contains("vnet-1") && screen.contains("Subnets"), "{screen}");
}

/// Enter on a Related ARM id jumps to its sub-tab; the row is not loaded
/// yet, so the jump waits in `pending_jump` and lands, focused, when the
/// target list's page arrives.
#[tokio::test]
async fn a_related_jump_lands_when_the_target_list_loads() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Enter).await;

    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    let target = nic_id("vm-1-nic");
    h.cursor_to_value(&target).await;
    h.press(KeyCode::Enter).await;

    assert_eq!(h.app.current_view, JumpView::Nics);
    assert_eq!(h.app.pending_jump, Some((target.clone(), true)));
    assert!(h.app.loading);
    assert!(h.app.nav_history.iter().any(|l| l.view == Some(JumpView::VirtualMachines)), "the jump is in history");

    // Another NIC first: the jump keeps waiting.
    h.land_page(vec![nic("other-nic", "westeurope")]).await;
    assert!(h.app.pending_jump.is_some());

    h.land_page(vec![nic("vm-1-nic", "westeurope")]).await;
    assert_eq!(h.app.pending_jump, None);
    assert_eq!(h.selected_id().as_deref(), Some(target.as_str()));
    assert!(h.app.details_focused, "the jump lands with the pane focused");
    assert_eq!(h.app.detail_section_idx, 0);
    assert!(h.render().contains("vm-1-nic"));

    // Back (Ctrl-O) returns to the VM.
    h.press_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL)).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.app.get_selected_resource().map(|r| r.name().to_string()).as_deref(), Some("vm-1"));
}

/// A jump whose list ends without the row clears with a message.
#[tokio::test]
async fn a_jump_to_a_missing_row_clears_when_the_load_ends() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.app.jump_to_arm_id(&nic_id("gone"), &h.tx);
    h.settle().await;
    assert!(h.app.pending_jump.is_some());
    h.land(vec![nic("vm-1-nic", "westeurope")]).await;
    assert_eq!(h.app.pending_jump, None);
    assert!(h.app.error_message.as_deref().is_some_and(|e| e.contains("gone")), "{:?}", h.app.error_message);
}

#[tokio::test]
async fn section_keys_and_the_flat_view() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Char('l')).await;
    let labels = h.section_labels();
    assert_eq!(labels[1], "Instance view");

    // Digits and Tab move the tab bar and the body.
    h.press(KeyCode::Char('4')).await;
    assert_eq!(labels[3], "Storage");
    assert_eq!(h.app.detail_section_idx, 3);
    assert!(h.app.get_detail_lines().iter().any(|(k, _)| k.contains("vm-1-os")), "the Storage body");
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.detail_section_idx, 4);
    h.press(KeyCode::BackTab).await;
    h.press(KeyCode::BackTab).await;
    assert_eq!(h.app.detail_section_idx, 2);

    // `\`: every section in one scroll, a header per section.
    h.press(KeyCode::Char('\\')).await;
    assert!(h.app.flat_active());
    let lines = h.app.get_detail_lines();
    let headers: Vec<&str> = lines.iter().filter_map(|(k, _)| flat_header_name(k)).collect();
    assert_eq!(headers, labels, "one header per section, in order");
    let screen = h.render();
    assert!(screen.contains("━━ Overview ━━"), "{screen}");

    // In the flat view digits and Tab jump between headers, and the tab
    // bar follows the cursor.
    let header_row = |h: &Harness, name: &str| {
        h.app
            .get_detail_lines()
            .iter()
            .position(|(k, _)| flat_header_name(k) == Some(name))
            .unwrap()
    };
    h.press(KeyCode::Char('4')).await;
    assert_eq!(h.app.details_scroll, header_row(&h, "Storage"));
    assert_eq!(h.app.detail_section_idx, 3);
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.details_scroll, header_row(&h, labels[4]));
    assert_eq!(h.app.detail_section_idx, 4);

    // Back to tabs.
    h.press(KeyCode::Char('\\')).await;
    assert!(!h.app.flat_active());
    assert!(h.app.get_detail_lines().iter().all(|(k, _)| flat_header_name(k).is_none()));
}

/// `R` is a client-side filter: picking a location hides the other rows
/// without a load, and All brings them back.
#[tokio::test]
async fn the_location_filter_hides_and_shows_rows() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("we-1", "westeurope"), vm("eu-1", "eastus"), vm("we-2", "westeurope")]).await;
    let generation = h.app.list_load.generation();

    h.press(KeyCode::Char('R')).await;
    assert!(h.app.location_selector.visible);
    h.type_str("eastus").await;
    h.press(KeyCode::Enter).await;
    assert!(!h.app.location_selector.visible);
    assert_eq!(h.app.current_location, Location::Named("eastus".into()));
    assert_eq!(h.visible_names(), ["eu-1"]);
    assert_eq!(h.app.location_hidden_count, 2);
    assert_eq!(h.app.list_load.generation(), generation, "a location change never loads");
    let screen = h.render();
    assert!(screen.contains("eu-1") && !screen.contains("we-1"), "{screen}");

    h.press(KeyCode::Char('R')).await;
    h.press(KeyCode::Home).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_location, Location::All);
    assert_eq!(h.visible_names(), ["we-1", "eu-1", "we-2"]);
    assert!(h.render().contains("we-2"));
}

/// `y` copies the selected row's ARM id from the list, the cursor line's
/// value from the pane; `C` copies the row's `az` command.
#[tokio::test]
async fn copy_puts_the_expected_text_on_the_clipboard() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    let id = arm_id("Microsoft.Compute/virtualMachines/vm-1");

    h.press(KeyCode::Char('y')).await;
    assert_eq!(h.app.clipboard.last(), Some(id.as_str()));
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.starts_with("Copied")));

    h.press(KeyCode::Char('C')).await;
    let command = h.app.get_selected_resource().unwrap().cli_command().unwrap();
    assert!(command.ends_with(&id), "{command}");
    assert_eq!(h.app.clipboard.last(), Some(command.as_str()));

    h.press(KeyCode::Enter).await;
    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    let nic = nic_id("vm-1-nic");
    h.cursor_to_value(&nic).await;
    h.press(KeyCode::Char('y')).await;
    assert_eq!(h.app.clipboard.last(), Some(nic.as_str()));
}
