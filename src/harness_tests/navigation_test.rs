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

/// A VNet's Related asks for the subscription's DNS topology; once it
/// lands, the resolver in the VNet and the ruleset linked to it are lines
/// that jump to the DNS tab.
#[tokio::test]
async fn a_vnet_related_lists_its_dns_once_the_topology_lands() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![super::mocks::vnet("vnet-hub", "westeurope")]).await;
    h.press(KeyCode::Enter).await;
    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;

    let key = format!("/subscriptions/{}", super::SUB_DEV);
    assert!(
        matches!(h.app.lazy.dns_topology.get(&key), Some(crate::lazy::Lazy::Loading)),
        "entering Related fired the topology fetch"
    );
    assert!(h.app.get_detail_lines().iter().any(|(k, v)| k == "DNS links" && v == "Loading…"));

    let topology = super::mocks::dns_topology("vnet-hub", "vnet-hub");
    let apply: Box<dyn FnOnce(&mut App) + Send> =
        Box::new(move |app: &mut App| app.lazy.dns_topology.apply(key, Ok(topology)));
    let epoch = h.app.lazy.epoch();
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;

    let resolver = arm_id("Microsoft.Network/dnsResolvers/dnspr-hub");
    let ruleset = arm_id("Microsoft.Network/dnsForwardingRulesets/rs-onprem");
    let lines = h.app.get_detail_lines();
    assert!(lines.contains(&("DNS resolver dnspr-hub".to_string(), resolver.clone())), "{lines:#?}");
    assert!(lines.contains(&("Forwarding ruleset rs-onprem".to_string(), ruleset)), "{lines:#?}");
    assert!(h.render().contains("DNS resolver dnspr-hub"));

    // Enter on the resolver line opens the DNS tab's Resolvers sub-tab.
    h.cursor_to_value(&resolver).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Dns));
    assert_eq!(h.app.current_view, JumpView::DnsResolvers);
    assert_eq!(h.app.pending_jump, Some((resolver, true)));
}

/// A VNet's Flow logs section asks for the subscription's flow logs once;
/// when they land the VNet's own flow log renders and its storage account
/// line jumps to Storage (#143).
#[tokio::test]
async fn a_vnet_flow_logs_section_reads_the_subscription_once_and_jumps() {
    use crate::azure::services::flow_logs::{FlowLog, FlowLogs};
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualNetworks).await;
    h.land(vec![super::mocks::vnet("vnet-hub", "westeurope")]).await;
    h.press(KeyCode::Enter).await;
    let idx = h.section_labels().iter().position(|l| *l == "Flow logs").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(idx).unwrap())).await;

    let key = format!("/subscriptions/{}", super::SUB_DEV);
    assert!(matches!(h.app.lazy.flow_logs.get(&key), Some(crate::lazy::Lazy::Loading)), "entering Flow logs fired the read");
    assert!(h.app.get_detail_lines().iter().any(|(k, v)| k == "Flow logs" && v == "Loading…"));

    let storage = arm_id("Microsoft.Storage/storageAccounts/stflowlogs");
    let watcher = arm_id("Microsoft.Network/networkWatchers/NetworkWatcher_westeurope");
    let log = FlowLog::from_json(
        &serde_json::json!({"id": format!("{watcher}/flowLogs/fl-hub"), "name": "fl-hub",
            "properties": {"targetResourceId": arm_id("Microsoft.Network/virtualNetworks/vnet-hub"),
                "enabled": true, "storageId": storage, "retentionPolicy": {"days": 7, "enabled": true}}}),
        &watcher,
    )
    .unwrap();
    let logs = FlowLogs { logs: vec![log], warnings: Vec::new(), watchers: 1 };
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| app.lazy.flow_logs.apply(key, Ok(logs)));
    let epoch = h.app.lazy.epoch();
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;

    let lines = h.app.get_detail_lines();
    assert!(lines.iter().any(|(k, _)| k == "VNet flow log · fl-hub"), "{lines:#?}");
    assert!(lines.contains(&("  Retention".to_string(), "7 days".to_string())), "{lines:#?}");
    assert!(h.render().contains("fl-hub"));

    h.cursor_to_value(&storage).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Storage));
    assert_eq!(h.app.pending_jump, Some((storage, true)));
}

/// A VM's Related names the vault that backs it up once that vault's
/// protected items are in the lazy store (#32, no call), and Enter on the
/// line opens the vault in the Backup tab.
#[tokio::test]
async fn a_vm_related_names_its_backup_vault_once_the_items_are_read() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    h.press(KeyCode::Enter).await;
    let related = h.section_labels().iter().position(|l| *l == "Related").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    assert!(!h.app.get_detail_lines().iter().any(|(k, _)| k.starts_with("Backed up by")));

    let vault = arm_id("Microsoft.RecoveryServices/vaults/rsv-1");
    let item = serde_json::json!({"name": "VM;iaasvmcontainerv2;rg-app;vm-1", "properties": {
        "friendlyName": "vm-1", "sourceResourceId": arm_id("Microsoft.Compute/virtualMachines/vm-1"),
        "protectionState": "Protected", "policyName": "DefaultPolicy", "lastBackupStatus": "Completed"}});
    let key = vault.clone();
    let apply: Box<dyn FnOnce(&mut App) + Send> =
        Box::new(move |app: &mut App| app.lazy.backup_protected_items.apply(key, Ok(vec![item])));
    let epoch = h.app.lazy.epoch();
    h.send(Event::Lazy(LazyApply { epoch, apply })).await;

    let lines = h.app.get_detail_lines();
    assert!(
        lines.contains(&("Backed up by rsv-1 · DefaultPolicy · last backup completed".to_string(), vault.clone())),
        "{lines:#?}"
    );
    h.cursor_to_value(&vault).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Backup));
    assert_eq!(h.app.current_view, JumpView::RecoveryVaults);
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
/// value from the pane; `C` `⏎` copies the row's `az` command.
#[tokio::test]
async fn copy_puts_the_expected_text_on_the_clipboard() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-1", "westeurope")]).await;
    let id = arm_id("Microsoft.Compute/virtualMachines/vm-1");

    h.press(KeyCode::Char('y')).await;
    assert_eq!(h.app.clipboard.last(), Some(id.as_str()));
    assert!(h.app.success_message.as_deref().is_some_and(|m| m.starts_with("Copied")));

    // `C` opens the command picker on the read command; `⏎` copies it.
    h.press(KeyCode::Char('C')).await;
    h.press(KeyCode::Enter).await;
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

/// A switch to another sub-tab lands on its top row, even when that list is
/// served from the cache: the old list's row index never carries over
/// (opening `@audit` from row 1 once landed on audit row 1). `⌫` still
/// puts the cursor back where it was.
#[tokio::test]
async fn a_sub_tab_switch_lands_on_the_top_row_and_back_restores() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![vm("vm-a", "westeurope"), vm("vm-b", "westeurope"), vm("vm-c", "westeurope")]).await;
    h.press(KeyCode::Tab).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    h.land(vec![disk("disk-a", "westeurope"), disk("disk-b", "westeurope"), disk("disk-c", "westeurope")]).await;
    h.press(KeyCode::Char('j')).await;
    assert_eq!(h.app.selected_index, Some(1));
    let disk_b = h.selected_id().unwrap();
    assert!(disk_b.ends_with("/disk-b"), "{disk_b}");

    // Back to the cached VM list: its top row, not row 1.
    h.press(KeyCode::Char('1')).await;
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
    assert!(!h.app.loading, "served from the cache");
    assert_eq!(h.app.selected_index, Some(0));
    assert!(h.selected_id().unwrap().ends_with("/vm-a"));

    // History restores the row it left.
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_view, JumpView::Disks);
    assert_eq!(h.selected_id().as_deref(), Some(disk_b.as_str()));
}

/// A route whose next hop is a `VirtualAppliance` IP resolves against the
/// warm load balancers: the line under it names the internal LB's
/// frontend, and Enter on it opens the LB (#137). A route to an IP no warm
/// list knows says which lists were cold.
#[tokio::test]
async fn enter_on_a_resolved_next_hop_jumps_to_the_load_balancer() {
    use crate::azure::services::network_edge::{LoadBalancerRow, RouteTableRow};
    let mut h = Harness::new().await;
    let lb_id = arm_id("Microsoft.Network/loadBalancers/lb-nva");
    let lb = LoadBalancerRow::from_json(
        &serde_json::json!({"id": lb_id, "name": "lb-nva", "location": "westeurope",
            "properties": {"frontendIPConfigurations": [{"name": "fe-trust", "properties": {"privateIPAddress": "10.0.1.10"}}]}}),
        Some(super::TENANT),
    )
    .unwrap();
    h.open(JumpView::LoadBalancers).await;
    h.land(vec![Box::new(lb)]).await;

    let rt = RouteTableRow::from_json(
        &serde_json::json!({"id": arm_id("Microsoft.Network/routeTables/rt-spoke"), "name": "rt-spoke", "location": "westeurope",
            "properties": {"routes": [
                {"name": "default", "properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.1.10"}},
                {"name": "other", "properties": {"addressPrefix": "10.9.0.0/16", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.9.4"}}]}}),
        Some(super::TENANT),
    )
    .unwrap();
    h.open(JumpView::RouteTables).await;
    h.land(vec![Box::new(rt)]).await;
    h.press(KeyCode::Enter).await;
    let routes = h.section_labels().iter().position(|l| *l == "Routes").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(routes).unwrap())).await;

    let lines = h.app.get_detail_lines();
    assert!(lines.contains(&("  → Load balancer lb-nva · frontend fe-trust".to_string(), lb_id.clone())), "{lines:#?}");
    assert!(
        lines.iter().any(|(_, v)| v == "10.0.9.4 not matched; not loaded: @nic @fw @ngfw (open them to match more)"),
        "the NICs were never opened: {lines:#?}"
    );

    h.cursor_to_value(&lb_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::LoadBalancers);
    assert_eq!(h.selected_id().as_deref(), Some(lb_id.as_str()), "the warm list lands the jump at once");
}

/// A route to a Cloud NGFW's trust IP resolves against the warm Cloud NGFW
/// list (the demo's `rt-spoke-egress` 0.0.0.0/0 → `ngfw-hub-prod`), and
/// Enter on the line opens the firewall in its own tab.
#[tokio::test]
async fn enter_on_a_next_hop_to_a_cloud_ngfw_jumps_to_the_firewall() {
    use crate::azure::services::firewall::CloudNgfwRow;
    use crate::azure::services::network_edge::RouteTableRow;
    let mut h = Harness::new().await;
    let ngfw_id = arm_id("PaloAltoNetworks.Cloudngfw/firewalls/ngfw-hub");
    let ngfw = CloudNgfwRow::from_json(
        &serde_json::json!({"id": ngfw_id, "name": "ngfw-hub", "location": "westeurope",
            "properties": {"networkProfile": {"networkType": "VNET",
                "vnetConfiguration": {"ipOfTrustSubnetForUdr": {"address": "10.10.11.4"}}}}}),
        Some(super::TENANT),
    )
    .unwrap();
    h.open(JumpView::CloudNgfws).await;
    h.land(vec![Box::new(ngfw)]).await;

    let rt = RouteTableRow::from_json(
        &serde_json::json!({"id": arm_id("Microsoft.Network/routeTables/rt-spoke"), "name": "rt-spoke", "location": "westeurope",
            "properties": {"routes": [
                {"name": "default", "properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.10.11.4"}}]}}),
        Some(super::TENANT),
    )
    .unwrap();
    h.open(JumpView::RouteTables).await;
    h.land(vec![Box::new(rt)]).await;
    h.press(KeyCode::Enter).await;
    let routes = h.section_labels().iter().position(|l| *l == "Routes").unwrap();
    h.press(KeyCode::Char(crate::sections::key_for(routes).unwrap())).await;

    let lines = h.app.get_detail_lines();
    assert!(lines.contains(&("  → Cloud NGFW ngfw-hub · trust IP".to_string(), ngfw_id.clone())), "{lines:#?}");

    h.cursor_to_value(&ngfw_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::CloudNgfws);
    assert_eq!(h.selected_id().as_deref(), Some(ngfw_id.as_str()), "the warm list lands the jump at once");
}
