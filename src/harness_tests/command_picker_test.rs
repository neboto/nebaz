// ported from neboto-tui src/harness_tests/cli_picker_test.rs @ 343ef65 (adapted: Azure rows, the `/` filter, no batching or role gate)
//! The `C` command picker (#47): opens on the read command, groups the
//! tiers, filters, copies with `⏎` / `y` / a digit, and closes on `Esc`.
//! Nothing is run: the only effect is the clipboard.

use super::mocks::{arm_id, sp_application, vm, APP_ID};
use super::*;

async fn vm_picker() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Char('C')).await;
    assert!(h.app.command_picker.is_some(), "C opens the picker");
    h
}

#[tokio::test]
async fn c_opens_the_tiers_with_the_read_command_on_top() {
    let mut h = vm_picker().await;
    let id = arm_id("Microsoft.Compute/virtualMachines/vm-1");
    let screen = h.render();
    for text in ["Copy az command", "Inspect", "Connect", "Change", "changes Azure", "nebaz never runs these"] {
        assert!(screen.contains(text), "{text} missing:\n{screen}");
    }
    let p = h.app.command_picker.as_ref().unwrap();
    assert_eq!(p.selected_action().unwrap().command, format!("az vm show --ids {id}"));
    // The preview wraps the long id; its head is on one screen line.
    assert!(screen.contains("az vm show --ids /subscriptions/"), "the preview shows the command:\n{screen}");
}

#[tokio::test]
async fn y_copies_the_selected_command_and_closes() {
    let mut h = vm_picker().await;
    h.press(KeyCode::Char('j')).await;
    let want = h.app.command_picker.as_ref().unwrap().selected_action().unwrap().command.clone();
    h.press(KeyCode::Char('y')).await;
    assert!(h.app.command_picker.is_none());
    assert_eq!(h.app.clipboard.last(), Some(want.as_str()));
}

#[tokio::test]
async fn the_filter_narrows_and_enter_copies_a_change_command_with_a_warning_toast() {
    let mut h = vm_picker().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("dealloc").await;
    assert!(h.render().contains("/ dealloc"));
    let p = h.app.command_picker.as_ref().unwrap();
    assert_eq!(p.visible().len(), 1, "{:?}", p.visible());
    h.press(KeyCode::Enter).await;
    // The Change command comes from the catalogue: only it may spell one.
    let r = h.app.get_selected_resource().unwrap();
    let want = crate::azure::cli_actions::actions_for(r)
        .into_iter()
        .find(|a| a.label == "vm deallocate")
        .unwrap()
        .command;
    assert!(want.ends_with(&arm_id("Microsoft.Compute/virtualMachines/vm-1")));
    assert_eq!(h.app.clipboard.last(), Some(want.as_str()));
    let toast = h.app.success_message.clone().unwrap_or_default();
    assert!(toast.contains("changes Azure; not run"), "{toast}");
}

#[tokio::test]
async fn esc_clears_the_filter_then_closes_without_copying() {
    let mut h = vm_picker().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("zzz").await;
    assert!(h.render().contains("no command matches"));
    h.press(KeyCode::Esc).await;
    let p = h.app.command_picker.as_ref().unwrap();
    assert!(p.query.is_empty() && !p.filtering);
    h.press(KeyCode::Esc).await;
    assert!(h.app.command_picker.is_none());
    assert_eq!(h.app.clipboard.last(), None, "nothing copied");
}

#[tokio::test]
async fn a_digit_copies_that_row() {
    let mut h = vm_picker().await;
    h.press(KeyCode::Char('2')).await;
    assert!(h.app.command_picker.is_none());
    let id = arm_id("Microsoft.Compute/virtualMachines/vm-1");
    assert_eq!(h.app.clipboard.last(), Some(format!("az vm get-instance-view --ids {id}").as_str()));
}

#[tokio::test]
async fn a_service_principal_offers_credential_metadata_reads_only() {
    let mut h = Harness::new().await;
    h.open(JumpView::ServicePrincipals).await;
    h.land(vec![sp_application()]).await;
    h.press(KeyCode::Char('C')).await;
    let screen = h.render();
    assert!(screen.contains("ad sp credential list"), "{screen}");
    assert!(!screen.contains("Change"), "no Change tier for a directory object:\n{screen}");
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.clipboard.last(), Some(format!("az ad sp show --id {APP_ID}").as_str()));
}

#[tokio::test]
async fn keys_do_not_leak_to_the_list_while_open() {
    let mut h = vm_picker().await;
    // `q` would quit the app, `r` refresh: the picker owns the keyboard.
    h.press(KeyCode::Char('r')).await;
    assert!(h.app.command_picker.is_some());
    h.press(KeyCode::Char('q')).await;
    assert!(h.app.command_picker.is_none());
    assert!(h.app.running);
}
