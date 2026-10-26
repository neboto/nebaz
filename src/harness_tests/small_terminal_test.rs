//! Small terminals (#103): every screen draws inside the frame, whatever
//! its size, instead of panicking on an out-of-bounds buffer write.

use super::*;

/// The sizes the issue names plus a couple of narrower ones.
const SIZES: [(u16, u16); 6] = [(80, 20), (80, 10), (40, 10), (40, 8), (20, 5), (1, 1)];

#[tokio::test]
async fn splash_renders_at_small_sizes() {
    for (w, h) in SIZES {
        let mut harness = Harness::sized(w, h).await;
        assert!(harness.app.current_service.is_none(), "{w}x{h}: on the splash");
        harness.render();
    }
}

#[tokio::test]
async fn splash_keeps_the_menu_when_the_logo_does_not_fit() {
    let mut h = Harness::sized(80, 14).await;
    let screen = h.render();
    assert!(screen.contains("Open the service picker"), "{screen}");
}

/// Each modal and in-pane view opened by its key, drawn, then closed.
const OVERLAY_KEYS: [char; 13] = ['?', 'S', 'R', 'P', '`', '\'', 'M', ',', 'C', 'm', 'N', 'U', 'W'];

async fn open_each_overlay(h: &mut Harness) {
    for c in OVERLAY_KEYS {
        h.press(KeyCode::Char(c)).await;
        h.render();
        h.press(KeyCode::Esc).await;
        h.press(KeyCode::Esc).await;
    }
}

#[tokio::test]
async fn main_screen_and_overlays_render_at_small_sizes() {
    for (w, hgt) in [(40, 10), (20, 5), (1, 1)] {
        // The splash's own overlays first, then a loaded list.
        let mut h = Harness::sized(w, hgt).await;
        open_each_overlay(&mut h).await;
        for (view, resource) in [
            (JumpView::VirtualMachines, mocks::vm("vm-1", "westeurope")),
            (JumpView::VirtualNetworks, mocks::vnet("vnet-1", "westeurope")),
        ] {
            h.install(mocks::Mock { view, label: "small", resource }).await;
            h.render();
            open_each_overlay(&mut h).await;
            // The detail pane, split and flat.
            h.press(KeyCode::Enter).await;
            h.render();
            open_each_overlay(&mut h).await;
            h.press(KeyCode::Char('\\')).await;
            h.render();
            h.press(KeyCode::Char('\\')).await;
            h.press(KeyCode::Esc).await;
        }
    }
}

/// The Edge tab at 80×24 (#31): its three sub-tabs and every section of
/// each row draw, and the sub-tab bar names the one on screen.
#[tokio::test]
async fn the_edge_tab_fits_80_by_24() {
    let mut h = Harness::sized(80, 24).await;
    for view in [JumpView::AppGateways, JumpView::FrontDoorProfiles, JumpView::WafPolicies] {
        let mock = mocks::all_mocks().into_iter().find(|m| m.view == view).unwrap();
        h.install(mock).await;
        let screen = h.render();
        assert!(screen.contains(view.label()), "{view:?}:\n{screen}");
        h.press(KeyCode::Enter).await;
        for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'] {
            h.press(KeyCode::Char(c)).await;
            h.render();
        }
        h.press(KeyCode::Esc).await;
    }
}

/// The Hybrid tab at 80×24 (#135): its four sub-tabs and every section of
/// each row draw, and the sub-tab bar names the one on screen.
#[tokio::test]
async fn the_hybrid_tab_fits_80_by_24() {
    let mut h = Harness::sized(80, 24).await;
    for view in [JumpView::ExpressRouteCircuits, JumpView::VnetGateways, JumpView::GatewayConnections, JumpView::LocalGateways] {
        let mock = mocks::all_mocks().into_iter().find(|m| m.view == view).unwrap();
        h.install(mock).await;
        let screen = h.render();
        assert!(screen.contains(view.label()), "{view:?}:\n{screen}");
        h.press(KeyCode::Enter).await;
        for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'] {
            h.press(KeyCode::Char(c)).await;
            h.render();
        }
        h.press(KeyCode::Esc).await;
    }
}

/// Network's ten sub-tabs (#137: Bastion and DDoS reach the digit-key
/// ceiling) all reach their chip and every digit at 80×24; the last
/// sub-tab is `0`.
#[tokio::test]
async fn the_network_tab_with_ten_sub_tabs_fits_80_by_24() {
    let mut h = Harness::sized(80, 24).await;
    assert_eq!(ServiceType::Network.views().len(), 10);
    for view in [JumpView::BastionHosts, JumpView::DdosPlans] {
        let mock = mocks::all_mocks().into_iter().find(|m| m.view == view).unwrap();
        h.install(mock).await;
        let screen = h.render();
        assert!(screen.contains(view.label()), "{view:?}:\n{screen}");
        h.press(KeyCode::Enter).await;
        for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'] {
            h.press(KeyCode::Char(c)).await;
            h.render();
        }
        h.press(KeyCode::Esc).await;
    }
    // The tenth sub-tab is the 0 key from the list.
    h.open(JumpView::VirtualNetworks).await;
    h.press(KeyCode::Char('0')).await;
    assert_eq!(h.app.current_view, JumpView::DdosPlans);
}

/// The Firewall tab at 80×24 (#136): its five sub-tabs and every section
/// of each row draw. Entering a rules section starts its lazy read: a
/// policy's rule collection groups, a rulestack's (and an NGFW's
/// rulestack's) local rules; Objects and Status theirs.
#[tokio::test]
async fn the_firewall_tab_fits_80_by_24_and_rules_sections_read_lazily() {
    use crate::azure::services::firewall::rules_key;
    let mut h = Harness::sized(80, 24).await;
    for view in [
        JumpView::AzureFirewalls,
        JumpView::FirewallPolicies,
        JumpView::IpGroups,
        JumpView::CloudNgfws,
        JumpView::NgfwRulestacks,
    ] {
        let mock = mocks::all_mocks().into_iter().find(|m| m.view == view).unwrap();
        h.install(mock).await;
        let screen = h.render();
        assert!(screen.contains(view.label()), "{view:?}:\n{screen}");
        h.press(KeyCode::Enter).await;
        for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'] {
            h.press(KeyCode::Char(c)).await;
            h.render();
        }
        h.press(KeyCode::Esc).await;
    }
    let policy = mocks::arm_id("Microsoft.Network/firewallPolicies/fwp-1");
    let rulestack = mocks::arm_id("PaloAltoNetworks.Cloudngfw/localRulestacks/lrs-1");
    assert!(h.app.lazy.firewall_rule_collection_groups.contains(&rules_key(&policy)));
    assert!(h.app.lazy.ngfw_local_rules.contains(&rules_key(&rulestack)));
    assert!(h.app.lazy.ngfw_prefix_lists.contains(&rules_key(&rulestack)));
    assert!(h.app.lazy.ngfw_status.contains(&mocks::arm_id("PaloAltoNetworks.Cloudngfw/firewalls/ngfw-1")));
}

/// The Backup tab at 80×24 (#32): both sub-tabs and every section draw.
/// Entering Protected items reads a Recovery Services vault's items and
/// policies; a Backup vault's instances read its jobs too; Policies and
/// (Failed) jobs each read theirs.
#[tokio::test]
async fn the_backup_tab_fits_80_by_24_and_vault_sections_read_lazily() {
    let mut h = Harness::sized(80, 24).await;
    for view in [JumpView::RecoveryVaults, JumpView::BackupVaults] {
        let mock = mocks::all_mocks().into_iter().find(|m| m.view == view).unwrap();
        h.install(mock).await;
        let screen = h.render();
        assert!(screen.contains(view.label()), "{view:?}:\n{screen}");
        h.press(KeyCode::Enter).await;
        for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9'] {
            h.press(KeyCode::Char(c)).await;
            h.render();
        }
        h.press(KeyCode::Esc).await;
    }
    let rsv = mocks::arm_id("Microsoft.RecoveryServices/vaults/rsv-1");
    let bv = mocks::arm_id("Microsoft.DataProtection/backupVaults/bv-1");
    assert!(h.app.lazy.backup_protected_items.contains(&rsv));
    assert!(h.app.lazy.backup_policies.contains(&rsv));
    assert!(h.app.lazy.backup_jobs.contains(&rsv));
    assert!(h.app.lazy.backup_instances.contains(&bv));
    assert!(h.app.lazy.backup_policies.contains(&bv));
    assert!(h.app.lazy.backup_jobs.contains(&bv));
}
