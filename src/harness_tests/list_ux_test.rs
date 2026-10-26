// ported from neboto-tui src/harness_tests/list_ux_test.rs @ 3183ba1 (the
// pinned chips, search history, back hint and history-sync cases, driven
// through nebaz's Harness; the Ctrl-F forward and clickable-hint cases are
// not ported, nebaz has neither)
//! #58 polish: pinned service chips, `/` search history, the detail
//! footer's `⌫ back to …` hint (and the two history fixes it made
//! visible), and the list's per-type summary column.

use super::mocks::{nic, nic_id, vm};
use super::*;

/// A config-built offline `App`, as `App::new_for_test` builds the default.
fn app_with_config(toml_text: &str) -> App {
    let config: Config = toml::from_str(toml_text).unwrap();
    let clients = AzureClients::new_for_test(fixture_subscriptions(), Arc::new(OfflineCredential));
    App::from_parts(config, clients, None)
}

#[tokio::test]
async fn pinned_services_show_as_chips_before_they_load() {
    let app = app_with_config(r#"pinned_services = ["aks", "kv", "nosuchservice"]"#);
    assert!(app.visited_services.contains(&ServiceType::Aks));
    assert!(app.visited_services.contains(&ServiceType::KeyVault));
    assert_eq!(app.visited_services.len(), 2);
    // No default_service: still the splash, nothing loading.
    assert_eq!(app.current_service, None);
    assert!(!app.should_load_resources());
    assert!(
        app.error_message.as_deref().is_some_and(|e| e.contains("pinned_services: unknown service nosuchservice")),
        "{:?}",
        app.error_message
    );

    let mut h = Harness::new().await;
    h.app = app;
    let screen = h.render();
    let strip = screen.lines().next().unwrap_or_default();
    assert!(strip.contains("AKS") && strip.contains("Key Vault"), "{strip}");
}

#[tokio::test]
async fn up_and_down_walk_the_search_history_and_restore_the_draft() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("web", "westeurope"), vm("api", "westeurope")]).await;
    for query in ["web", "api", "web"] {
        h.press(KeyCode::Char('/')).await;
        h.app.search_query.clear();
        h.type_str(query).await;
        h.press(KeyCode::Enter).await;
    }
    // A repeat moves to the end rather than appearing twice.
    assert_eq!(h.app.search_history, vec!["api".to_string(), "web".to_string()]);

    h.press(KeyCode::Char('/')).await;
    h.app.search_query.clear();
    h.type_str("dr").await;
    h.press(KeyCode::Up).await;
    assert_eq!(h.app.search_query, "web");
    assert_eq!(h.visible_names(), vec!["web"], "a recalled query filters as typed");
    h.press(KeyCode::Up).await;
    assert_eq!(h.app.search_query, "api");
    // At the oldest entry, ↑ stays put.
    h.press(KeyCode::Up).await;
    assert_eq!(h.app.search_query, "api");
    h.press(KeyCode::Down).await;
    assert_eq!(h.app.search_query, "web");
    // ↓ past the newest gives back what was being typed.
    h.press(KeyCode::Down).await;
    assert_eq!(h.app.search_query, "dr");
    h.press(KeyCode::Down).await;
    assert_eq!(h.app.search_query, "dr");

    // Editing a recalled entry starts a fresh walk from the newest.
    h.press(KeyCode::Up).await;
    h.press(KeyCode::Up).await;
    h.type_str("-v2").await;
    assert_eq!(h.app.search_query, "api-v2");
    h.press(KeyCode::Up).await;
    assert_eq!(h.app.search_query, "web");

    // Blank submissions are not recorded.
    h.app.search_query.clear();
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.search_history.len(), 2);
}

#[tokio::test]
async fn the_search_history_is_capped() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    for i in 0..60 {
        h.press(KeyCode::Char('/')).await;
        h.app.search_query.clear();
        h.type_str(&format!("q{i}")).await;
        h.press(KeyCode::Enter).await;
    }
    assert_eq!(h.app.search_history.len(), 50);
    assert_eq!(h.app.search_history.first().map(String::as_str), Some("q10"));
    assert_eq!(h.app.search_history.last().map(String::as_str), Some("q59"));
}

/// Focus `name`'s detail pane and follow its NIC through Related; the NIC
/// list lands with that NIC in it.
async fn jump_to_nic_of(h: &mut Harness, name: &str) {
    let idx = h.visible_names().iter().position(|n| n == name).unwrap();
    h.app.select(Some(idx));
    h.press(KeyCode::Enter).await;
    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    h.cursor_to_value(&nic_id(&format!("{name}-nic"))).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::Nics);
    if h.app.loading {
        h.land(vec![nic("vm-a-nic", "westeurope"), nic("vm-b-nic", "westeurope")]).await;
    }
    assert_eq!(h.selected_id(), Some(nic_id(&format!("{name}-nic"))));
}

async fn two_vms() -> Harness {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-a", "westeurope"), vm("vm-b", "westeurope")]).await;
    h
}

#[tokio::test]
async fn the_detail_footer_names_where_back_goes() {
    let mut h = two_vms().await;
    h.press(KeyCode::Enter).await;
    let screen = h.render();
    assert!(!screen.contains("back to"), "no history, no hint:\n{screen}");
    assert!(screen.contains("h list"), "h says it goes to the list:\n{screen}");

    h.press(KeyCode::Char('h')).await;
    jump_to_nic_of(&mut h, "vm-a").await;
    assert_eq!(h.app.nav_back_hint().as_deref(), Some("VMs vm-a"));
    let screen = h.render();
    assert!(screen.contains("⌫ back to VMs vm-a"), "{screen}");

    // ⌫ in the detail pane walks history.
    assert!(h.app.details_focused);
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert_eq!(h.app.get_selected_resource().map(|r| r.name().to_string()).as_deref(), Some("vm-a"));
}

/// With nothing behind, ⌫ in the detail pane still leaves it, as `h` does.
#[tokio::test]
async fn backspace_without_history_leaves_the_detail_pane() {
    let mut h = two_vms().await;
    h.press(KeyCode::Enter).await;
    assert!(h.app.details_focused);
    h.press(KeyCode::Backspace).await;
    assert!(!h.app.details_focused);
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
}

/// Back to A, move to B, jump away: back (and the hint) must say B, the
/// place you left from, not the A you passed through.
#[tokio::test]
async fn back_returns_to_where_you_left_not_where_you_went_back_to() {
    let mut h = two_vms().await;
    jump_to_nic_of(&mut h, "vm-a").await;
    h.press(KeyCode::Backspace).await; // back to vm-a, parked
    assert_eq!(h.app.nav_cursor, Some(0));
    h.press(KeyCode::Char('h')).await;
    jump_to_nic_of(&mut h, "vm-b").await;
    assert_eq!(h.app.nav_back_hint().as_deref(), Some("VMs vm-b"));
    assert_eq!(h.app.nav_history.len(), 1, "{:?}", h.app.nav_history);

    h.press(KeyCode::Backspace).await;
    assert_eq!(h.selected_id().map(|id| name_of_id(&id).to_string()).as_deref(), Some("vm-b"));
}

/// Back twice across services walks the history instead of bouncing:
/// the switches a restore makes are not recorded as places left.
#[tokio::test]
async fn back_twice_walks_the_history() {
    let mut h = two_vms().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("@vnet").await;
    h.press(KeyCode::Enter).await;
    h.land(vec![super::mocks::vnet("vnet-1", "westeurope")]).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("@aks").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Aks));

    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Network));
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines));
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines), "the oldest: nowhere further");
}

/// `@vnet` from VMs, then ⌫: back lands on VMs with no filter. The switch
/// used to record the half-typed `@vnet` as the VM list's query.
#[tokio::test]
async fn back_after_a_service_search_restores_no_filter() {
    let mut h = two_vms().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("@vnet").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Network));
    assert_eq!(h.app.nav_history[0].query, "");

    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines));
    assert_eq!(h.app.search_query, "");
    assert_eq!(h.visible_names(), vec!["vm-a", "vm-b"]);
}

/// A filter on the list being left is kept: only the switch query is dropped.
#[tokio::test]
async fn a_same_list_filter_is_still_recorded() {
    let mut h = two_vms().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("vm-b").await;
    h.press(KeyCode::Enter).await;
    h.press(KeyCode::Char('/')).await;
    h.app.search_query.clear();
    h.type_str("@vnet").await;
    h.press(KeyCode::Enter).await;
    // Typing `@vnet` replaced the filter in the bar, so the VM list is
    // recorded unfiltered: the switch query is never its filter.
    assert_eq!(h.app.nav_history[0].query, "");

    h.press(KeyCode::Backspace).await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("vm-b").await;
    h.press(KeyCode::Enter).await;
    jump_to_nic_of(&mut h, "vm-b").await;
    assert_eq!(h.app.nav_history.last().map(|l| l.query.as_str()), Some("vm-b"));
}

#[tokio::test]
async fn the_list_shows_the_summary_column() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    let screen = h.render();
    let row = screen.lines().find(|l| l.contains("○ vm-1")).unwrap_or_default();
    // The mock's size, where the ARM id used to be (the list is the left
    // pane, so only the left half of the row is the list's).
    let list_side: String = row.chars().take(60).collect();
    assert!(list_side.contains("vm-1  Standard_B2s"), "{screen}");
    assert!(!list_side.contains("/subscriptions/"), "{screen}");
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// Ctrl-F undoes a back; navigating somewhere new drops what was ahead.
#[tokio::test]
async fn forward_undoes_back_until_you_go_somewhere_new() {
    let mut h = two_vms().await;
    assert_eq!(h.app.nav_forward_index(), None, "live: nothing ahead");
    jump_to_nic_of(&mut h, "vm-a").await;
    let nic = h.selected_id();
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.selected_id().map(|id| name_of_id(&id).to_string()).as_deref(), Some("vm-a"));

    h.press_key(ctrl('f')).await;
    assert_eq!(h.selected_id(), nic, "forward returns to the NIC");
    assert_eq!(h.app.nav_forward_index(), None, "at the newest entry");
    h.press_key(ctrl('f')).await;
    assert_eq!(h.selected_id(), nic, "nothing further ahead");

    h.press(KeyCode::Backspace).await;
    assert!(h.app.nav_forward_index().is_some());
    h.press(KeyCode::Char('h')).await;
    jump_to_nic_of(&mut h, "vm-b").await;
    assert_eq!(h.app.nav_forward_index(), None, "a new place drops the forward branch");
}

/// The service strip's `←` / `→` are back and forward for the mouse.
#[tokio::test]
async fn the_strip_arrows_go_back_and_forward() {
    let mut h = two_vms().await;
    h.app.banner_visible = false;
    let screen = h.render();
    assert!(screen.lines().any(|l| l.starts_with(" ←  → │ nebaz")), "{screen}");
    // Nothing behind: a click does nothing.
    let at = h.region(ClickAction::Back);
    h.click(at).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);

    jump_to_nic_of(&mut h, "vm-a").await;
    let nic = h.selected_id();
    let at = h.region(ClickAction::Back);
    h.click(at).await;
    assert_eq!(h.selected_id().map(|id| name_of_id(&id).to_string()).as_deref(), Some("vm-a"));
    let at = h.region(ClickAction::Forward);
    h.click(at).await;
    assert_eq!(h.selected_id(), nic);
}
