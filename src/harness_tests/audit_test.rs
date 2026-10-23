// ported from neboto-tui src/harness_tests/audit_test.rs @ 693449a (the
// scenarios; the rows and the landing path are nebaz's)
//! `@audit` (#60): findings computed from the warm caches with no load,
//! coverage notes for what isn't cached, Enter opening the resource,
//! `l` reading the finding, and `r` loading the missing sources in the
//! background into their own cache slots (a late result after a
//! subscription switch is dropped by the lazy epoch).

use super::mocks::arm_id;
use super::*;
use crate::audit::AuditFinding;
use crate::azure::services::network::NsgRow;
use crate::azure::services::storage::StorageAccountRow;
use crate::lazy::LazyApply;
use serde_json::json;

fn nsg_id() -> String {
    arm_id("Microsoft.Network/networkSecurityGroups/nsg-ssh")
}

/// An NSG with SSH open to the internet.
fn open_nsg() -> Box<dyn Resource> {
    Box::new(
        NsgRow::from_json(
            &json!({"id": nsg_id(), "name": "nsg-ssh", "location": "westeurope", "properties": {"securityRules": [
                {"name": "ssh-anywhere", "properties": {"priority": 100, "direction": "Inbound", "access": "Allow",
                    "protocol": "Tcp", "sourceAddressPrefix": "*", "sourcePortRange": "*",
                    "destinationAddressPrefix": "*", "destinationPortRange": "22"}}
            ]}}),
            Some(TENANT),
        )
        .unwrap(),
    )
}

/// A storage account that allows plain HTTP.
fn http_account() -> Box<dyn Resource> {
    Box::new(
        StorageAccountRow::from_json(
            &json!({"id": arm_id("Microsoft.Storage/storageAccounts/sthttp"), "name": "sthttp", "location": "eastus",
                "properties": {"supportsHttpsTrafficOnly": false, "allowSharedKeyAccess": false,
                    "publicNetworkAccess": "Disabled"}}),
            Some(TENANT),
        )
        .unwrap(),
    )
}

fn warm(h: &mut Harness, view: JumpView, rows: Vec<Box<dyn Resource>>) {
    let sub = h.app.subscription_key();
    h.app.cache.insert(view.service(), &sub, Some(view.as_str().to_string()), rows);
}

fn findings(h: &Harness) -> Vec<&AuditFinding> {
    h.app
        .filtered_resources
        .iter()
        .filter_map(|&i| h.app.resources[i].as_any().downcast_ref::<AuditFinding>())
        .collect()
}

fn row<'a>(h: &'a Harness, check: &str) -> &'a AuditFinding {
    findings(h).into_iter().find(|f| f.check_id == check).unwrap_or_else(|| panic!("no {check} row"))
}

#[tokio::test]
async fn audit_with_nothing_cached_is_all_coverage_notes_and_starts_no_load() {
    let mut h = Harness::new().await;
    h.open(JumpView::Audit).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Audit));
    assert!(!h.app.loading && !h.app.should_load_resources(), "@audit never streams a list");
    assert_eq!(row(&h, "nsg-open-internet").list_cell(), "not checked — load @vnet NSGs");
    assert!(findings(&h).iter().all(|f| !f.is_finding()));
    let screen = h.render();
    assert!(screen.contains("NSG allows inbound from the internet  not checked"), "{screen}");
}

#[tokio::test]
async fn warm_lists_become_findings_worst_first_and_enter_opens_the_resource() {
    let mut h = Harness::new().await;
    warm(&mut h, JumpView::NetworkSecurityGroups, vec![open_nsg()]);
    warm(&mut h, JumpView::StorageAccounts, vec![http_account()]);
    h.open(JumpView::Audit).await;
    let first = findings(&h)[0];
    assert_eq!((first.check_id, first.state_label().as_str()), ("nsg-open-internet", "critical"));
    assert_eq!(row(&h, "storage-https-only").state_label(), "high");

    // `l` reads the finding: evidence and remediation, text only.
    h.press(KeyCode::Char('l')).await;
    assert!(h.app.details_focused);
    let body: Vec<String> = h.app.detail_body().into_iter().map(|(k, v)| format!("{k} {v}")).collect();
    assert!(body.iter().any(|l| l.contains("ssh-anywhere")), "{body:#?}");
    assert!(body.iter().any(|l| l.starts_with("Remediation")), "{body:#?}");
    // ⏎ on the Resource line jumps, like any ARM id in a detail pane.
    h.cursor_to_value(&nsg_id()).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::NetworkSecurityGroups);
    assert_eq!(h.selected_id().as_deref(), Some(nsg_id().as_str()));

    // Back to @audit, Enter on the list row jumps straight there.
    h.press(KeyCode::Backspace).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Audit));
    h.app.details_focused = false;
    h.press(KeyCode::Char('g')).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_view, JumpView::NetworkSecurityGroups);
    assert!(h.app.details_focused, "the jump lands in the resource's pane");
}

#[tokio::test]
async fn f_filters_by_severity() {
    let mut h = Harness::new().await;
    warm(&mut h, JumpView::NetworkSecurityGroups, vec![open_nsg()]);
    warm(&mut h, JumpView::StorageAccounts, vec![http_account()]);
    h.open(JumpView::Audit).await;
    h.press(KeyCode::Char('F')).await;
    assert_eq!(h.app.list_state_filter.as_deref(), Some("critical"));
    assert_eq!(h.visible_names(), vec!["nsg-ssh".to_string()]);
}

#[tokio::test]
async fn r_loads_missing_sources_into_their_cache_slots_and_re_audits_as_each_lands() {
    let mut h = Harness::new().await;
    warm(&mut h, JumpView::NetworkSecurityGroups, vec![open_nsg()]);
    h.open(JumpView::Audit).await;
    h.press(KeyCode::Char('r')).await;
    let loading = h.app.audit.loading.clone();
    assert!(loading.contains(&JumpView::StorageAccounts), "{loading:?}");
    assert!(!loading.contains(&JumpView::NetworkSecurityGroups), "a cached source is left alone");
    assert_eq!(row(&h, "storage-https-only").list_cell(), "loading…");
    // The lazy reads the checks need start too, through their own maps.
    let scope = format!("/subscriptions/{}", SUB_DEV);
    assert!(h.app.lazy.role_assignments.contains(&scope));

    // The storage list lands (the apply closure the real task sends).
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(|app: &mut App| {
        app.audit_source_landed(JumpView::StorageAccounts, SUB_DEV, Ok((vec![http_account()], Vec::new())))
    });
    h.send(Event::Lazy(LazyApply { epoch: h.app.lazy.epoch(), apply })).await;
    assert!(!h.app.audit.loading.contains(&JumpView::StorageAccounts));
    assert!(
        h.app.cache.get_ref(&ServiceType::Storage, SUB_DEV, Some("accounts")).is_some(),
        "cached under the Storage tab's own key"
    );
    assert_eq!(row(&h, "storage-https-only").state_label(), "high", "re-audited on arrival");

    // A second `r` while loads are in flight starts nothing new.
    let before = h.app.audit.loading.clone();
    h.press(KeyCode::Char('r')).await;
    assert_eq!(h.app.audit.loading, before);
}

#[tokio::test]
async fn a_source_landing_after_a_subscription_switch_is_dropped() {
    let mut h = Harness::new().await;
    h.open(JumpView::Audit).await;
    h.press(KeyCode::Char('r')).await;
    let stale_epoch = h.app.lazy.epoch();
    h.send(Event::SubscriptionSwitchRequested {
        subscription_id: SUB_PROD.to_string(),
    })
    .await;
    assert!(h.app.audit.loading.is_empty(), "the switch resets what r had in flight");
    let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(|app: &mut App| {
        app.audit_source_landed(JumpView::StorageAccounts, SUB_DEV, Ok((vec![http_account()], Vec::new())))
    });
    h.send(Event::Lazy(LazyApply { epoch: stale_epoch, apply })).await;
    assert!(h.app.cache.get_ref(&ServiceType::Storage, SUB_DEV, Some("accounts")).is_none());
}

#[tokio::test]
async fn a_failed_source_is_one_status_error_and_its_checks_stay_not_checked() {
    let mut h = Harness::new().await;
    h.open(JumpView::Audit).await;
    h.press(KeyCode::Char('r')).await;
    let pending = h.app.audit.loading.clone();
    for view in pending {
        let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
            let result = if view == JumpView::KeyVaults { Err("403 AuthorizationFailed".to_string()) } else { Ok((Vec::new(), Vec::new())) };
            app.audit_source_landed(view, SUB_DEV, result)
        });
        h.send(Event::Lazy(LazyApply { epoch: h.app.lazy.epoch(), apply })).await;
    }
    assert!(h.app.audit.loading.is_empty());
    let err = h.app.error_message.clone().unwrap_or_default();
    assert!(err.contains("@kv") && err.contains("403"), "{err}");
    assert_eq!(row(&h, "kv-soft-delete").list_cell(), "not checked — load @kv");
}

#[tokio::test]
async fn the_audit_prefix_opens_it_from_search() {
    let mut h = Harness::new().await;
    h.press(KeyCode::Char('/')).await;
    h.type_str("@audit").await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::Audit));
    assert_eq!(h.app.current_view, JumpView::Audit);
}

/// The wiring smash over `@audit` (it has no mock: its rows are computed),
/// with findings, notes and the detail pane's flat `details()` view.
#[tokio::test]
async fn keymap_smash_on_audit_never_panics() {
    let mut h = Harness::new().await;
    warm(&mut h, JumpView::NetworkSecurityGroups, vec![open_nsg()]);
    for k in super::wiring_test::smash_sequence() {
        if h.app.current_service != Some(ServiceType::Audit) {
            h.open(JumpView::Audit).await;
        }
        h.press_key(k).await;
    }
    assert!(!h.app.any_modal_open());
}
