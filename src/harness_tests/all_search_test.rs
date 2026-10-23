//! `@*` cross-cache search (#38): what it searches (warm caches only, the
//! location filter on top), how ⏎ lands in the typed tab, Ctrl-O back to
//! the results, and that a load in flight can't land on the foreign rows.

use super::mocks::{arm_id, nic, sp_application, vm};
use super::*;

/// Warm the VMs and NICs caches (two loads), leaving NICs open.
async fn warm_vms_and_nics(h: &mut Harness) {
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("web-vm", "westeurope"), vm("db-vm", "eastus")]).await;
    h.open(JumpView::Nics).await;
    h.land(vec![nic("web-nic", "westeurope"), nic("db-nic", "westeurope")]).await;
}

async fn search(h: &mut Harness, query: &str) {
    h.press(KeyCode::Char('/')).await;
    h.type_str(query).await;
    h.press(KeyCode::Enter).await;
}

fn select_name(h: &mut Harness, name: &str) {
    let pos = h
        .visible_names()
        .iter()
        .position(|n| n == name)
        .unwrap_or_else(|| panic!("{name} not in {:?}", h.visible_names()));
    h.app.select(Some(pos));
}

#[tokio::test]
async fn searches_every_warm_cache_and_opens_a_row_in_its_typed_tab() {
    let mut h = Harness::new().await;
    warm_vms_and_nics(&mut h).await;

    search(&mut h, "@* web").await;
    assert!(h.app.all_search_mode);
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines), "no service switch");
    let mut names = h.visible_names();
    names.sort();
    assert_eq!(names, ["web-nic", "web-vm"], "both warm lists, matches only");
    assert!(!h.app.loading, "@* never fetches");

    let screen = h.render();
    assert!(screen.contains("VMs/NICs") && screen.contains("VMs/VMs"), "rows carry their list:\n{screen}");
    assert!(screen.contains("2 of"), "the title counts the warm lists:\n{screen}");
    assert!(screen.contains("not checked") && screen.contains("Storage"), "the unchecked services:\n{screen}");

    // ⏎ on the VM: its typed tab, served from the cache, pane focused.
    select_name(&mut h, "web-vm");
    h.press(KeyCode::Enter).await;
    assert!(!h.app.all_search_mode);
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(!h.app.loading, "a warm tab needs no load");
    assert_eq!(h.selected_id(), Some(arm_id("Microsoft.Compute/virtualMachines/web-vm")));
    assert!(h.app.details_focused);
    assert_eq!(h.visible_names(), ["web-vm", "db-vm"], "the tab's own list, unfiltered");

    // Ctrl-O: back to the results, the row still selected.
    h.press_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL)).await;
    assert!(h.app.all_search_mode, "the results come back");
    assert_eq!(h.app.search_query, "@* web");
    assert_eq!(h.visible_names().len(), 2);
    assert_eq!(h.selected_id(), Some(arm_id("Microsoft.Compute/virtualMachines/web-vm")));

    // ⏎ on the NIC: the sub-tab open under the results gets its list back.
    h.press(KeyCode::Esc).await; // the pane, if focused
    h.app.details_focused = false;
    select_name(&mut h, "web-nic");
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::Nics);
    assert_eq!(h.selected_id(), Some(super::mocks::nic_id("web-nic")));
    assert_eq!(h.visible_names(), ["web-nic", "db-nic"]);
}

#[tokio::test]
async fn location_filter_applies_and_esc_restores_the_list() {
    let mut h = Harness::new().await;
    warm_vms_and_nics(&mut h).await;
    h.app.switch_location(Location::Named("eastus".into()));

    search(&mut h, "@*").await;
    assert_eq!(h.visible_names(), ["db-vm"], "only the eastus row passes R");

    // Esc on the list leaves the mode and re-serves the open tab.
    h.press(KeyCode::Esc).await;
    assert!(!h.app.all_search_mode);
    assert_eq!(h.app.current_view, JumpView::Nics);
    assert!(h.visible_names().is_empty(), "NICs are all westeurope");
    h.app.switch_location(Location::All);
    assert_eq!(h.visible_names(), ["web-nic", "db-nic"]);
}

#[tokio::test]
async fn a_load_in_flight_is_superseded_and_never_cached_from_the_results() {
    let mut h = Harness::new().await;
    warm_vms_and_nics(&mut h).await;
    h.open(JumpView::Disks).await;
    assert!(h.app.loading_started, "the Disks load is in flight");
    let stale = h.app.list_load.generation();

    search(&mut h, "@* web").await;
    assert!(!h.app.loading);
    assert_ne!(h.app.list_load.generation(), stale, "entering @* retired the load");

    // The retired load's rows are dropped, and nothing is cached as Disks.
    h.send(Event::LoadStream {
        generation: stale,
        event: Box::new(Event::ResourcesLoaded {
            service: ServiceType::VirtualMachines,
            resources: vec![super::mocks::disk("late-disk", "westeurope")],
        }),
    })
    .await;
    assert!(!h.visible_names().contains(&"late-disk".to_string()));
    let sub = h.app.subscription_key();
    assert!(h.app.cache.get_ref(&ServiceType::VirtualMachines, &sub, Some("disks")).is_none());

    // Leaving re-arms the Disks load.
    h.press(KeyCode::Esc).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert!(h.app.loading && h.app.loading_started, "the cold tab loads again");
}

#[tokio::test]
async fn a_directory_row_opens_in_its_graph_tab() {
    let mut h = Harness::new().await;
    h.open(JumpView::ServicePrincipals).await;
    h.land(vec![sp_application()]).await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;

    search(&mut h, "@* sp-orders").await;
    assert_eq!(h.visible_names(), ["sp-orders"]);
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::ServicePrincipals);
    assert!(h.selected_id().is_some_and(|id| id.starts_with("graph:/")));
    assert!(h.app.details_focused);
}

#[tokio::test]
async fn sub_tab_keys_and_reload_do_not_replace_the_results() {
    let mut h = Harness::new().await;
    warm_vms_and_nics(&mut h).await;
    search(&mut h, "@* web").await;
    for code in [KeyCode::Tab, KeyCode::Char('1'), KeyCode::Char('r'), KeyCode::Char('L')] {
        h.press(code).await;
        assert!(h.app.all_search_mode, "{code:?} kept the results");
        assert_eq!(h.visible_names().len(), 2);
        assert!(!h.app.loading);
    }
}

fn generic(provider_path: &str, arm_type: &str) -> Box<dyn Resource> {
    let id = arm_id(provider_path);
    let v = serde_json::json!({
        "id": id, "name": crate::azure::resource::name_of_id(&id),
        "type": arm_type, "location": "westeurope", "properties": {}
    });
    Box::new(
        crate::azure::services::all_resources::GenericResourceRow::from_json(&v, Some(super::TENANT))
            .expect("a generic row"),
    )
}

/// All resources only adds ids no typed list has: a VM is its one typed
/// row, an unbrowsed type still matches and opens in All resources.
#[tokio::test]
async fn all_resources_rows_fill_in_only_what_typed_lists_lack() {
    let mut h = Harness::new().await;
    h.open(JumpView::AllResources).await;
    h.land(vec![
        generic("Microsoft.Compute/virtualMachines/web-vm", "Microsoft.Compute/virtualMachines"),
        generic("Microsoft.Network/publicIPPrefixes/web-prefix", "Microsoft.Network/publicIPPrefixes"),
    ])
    .await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("web-vm", "westeurope")]).await;

    search(&mut h, "@* web").await;
    assert_eq!(h.visible_names().len(), 2, "{:?}", h.visible_names());
    assert!(h.render().contains("Subs/All resources"));
    select_name(&mut h, "web-prefix");
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::AllResources);
    assert_eq!(h.selected_id(), Some(arm_id("Microsoft.Network/publicIPPrefixes/web-prefix")));
}
