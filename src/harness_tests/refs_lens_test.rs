//! The referenced-by lens (`U`, #49): what points at a subnet and at an
//! identity from the warm lists, coverage, the per-service filter, the jump
//! to a referrer, `L` loading the likely lists in the background, and the
//! mouse. Zero calls: every row is warm in the list cache.

use super::mocks::{arm_id, sp_managed_identity};
use super::network_lens_test::{subnet_id, vnet};
use super::*;
use crate::azure::services::{compute::NicRow, power_platform::EnterprisePolicyRow};
use serde_json::json;

/// `nic-aca` in `snet-aca`.
fn nic() -> Box<dyn Resource> {
    Box::new(
        NicRow::from_json(
            &json!({"id": mocks::nic_id("nic-aca"), "name": "nic-aca", "location": "westeurope", "properties": {
                "ipConfigurations": [{"name": "ipconfig1", "properties": {"primary": true, "subnet": {"id": subnet_id()}}}]}}),
            Some(TENANT),
        )
        .unwrap(),
    )
}

/// A Power Platform policy injecting into `vnet-1/snet-aca`.
fn policy() -> Box<dyn Resource> {
    Box::new(
        EnterprisePolicyRow::from_json(
            &json!({"id": arm_id("Microsoft.PowerPlatform/enterprisePolicies/ep-aca"), "name": "ep-aca",
                "type": "Microsoft.PowerPlatform/enterprisePolicies", "kind": "NetworkInjection", "location": "unitedstates",
                "properties": {"networkInjection": {"virtualNetworks": [
                    {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1"), "subnet": {"name": "snet-aca"}}]}}}),
            Some(TENANT),
        )
        .unwrap(),
    )
}

fn mock_of(view: JumpView) -> mocks::Mock {
    mocks::all_mocks().into_iter().find(|m| m.view == view).expect("a mock for the view")
}

fn warm(h: &mut Harness, view: JumpView, rows: Vec<Box<dyn Resource>>) {
    let sub = h.app.subscription_key();
    h.app.cache.insert(view.service(), &sub, Some(view.as_str().to_string()), rows);
}

fn ref_names(h: &Harness) -> Vec<(String, String)> {
    let st = h.app.refs_lens.as_ref().expect("the lens is open");
    st.rows.iter().map(|r| (r.name.clone(), r.via.clone())).collect()
}

#[tokio::test]
async fn u_on_a_subnet_lists_the_nic_environment_and_policy_pointing_at_it_and_jumps() {
    let mut h = Harness::new().await;
    let subnet = vnet().subnets.remove(0);
    h.install(mocks::Mock { view: JumpView::Subnets, label: "SubnetRow", resource: Box::new(subnet) }).await;
    warm(&mut h, JumpView::Nics, vec![nic(), mocks::nic("nic-other", "westeurope")]);
    warm(&mut h, JumpView::ContainerAppEnvironments, vec![mock_of(JumpView::ContainerAppEnvironments).resource]);
    warm(&mut h, JumpView::EnterprisePolicies, vec![policy()]);
    warm(&mut h, JumpView::VirtualNetworks, vec![Box::new(vnet())]);

    h.press(KeyCode::Char('U')).await;
    assert!(h.app.details_focused);
    assert_eq!(
        ref_names(&h),
        vec![
            ("nic-aca".to_string(), "Subnet snet-aca · ipconfig1".to_string()),
            ("ep-aca".to_string(), "Subnet vnet-1/snet-aca".to_string()),
            ("cae-1".to_string(), "Infrastructure subnet snet-aca".to_string()),
        ],
        "the VNet that contains the subnet is not a reference"
    );
    let st = h.app.refs_lens.as_ref().unwrap();
    // The Subnets list is on screen and warm; PEs, Apps, NAT, the flexible
    // servers, app gateways VNet gateways, both firewalls and Private Link
    // services are likely but cold.
    assert_eq!(
        st.coverage.likely_cold,
        vec![
            JumpView::PrivateEndpoints,
            JumpView::WebApps,
            JumpView::NatGateways,
            JumpView::PostgresServers,
            JumpView::MysqlServers,
            JumpView::AppGateways,
            JumpView::VnetGateways,
            JumpView::AzureFirewalls,
            JumpView::CloudNgfws,
            JumpView::PrivateLinkServices
        ]
    );
    h.press(KeyCode::Char('Z')).await;
    let screen = h.render();
    for s in ["REFERENCED BY", "nic-aca", "VMs/NICs", "via Infrastructure subnet snet-aca", "not checked — load VNet/PEs, App Svc/Apps, VNet/NAT"] {
        assert!(screen.contains(s), "{s:?} missing:\n{screen}");
    }
    h.press(KeyCode::Char('Z')).await;

    // f narrows to one service, then cycles back to all.
    h.press(KeyCode::Char('f')).await;
    assert_eq!(ref_names(&h).len(), 1);
    for _ in 0..3 {
        h.press(KeyCode::Char('f')).await;
    }
    assert_eq!(ref_names(&h).len(), 3);

    // ⏎ jumps to the referrer in its tab; the NICs list is warm.
    h.press(KeyCode::Char('g')).await;
    h.press(KeyCode::Enter).await;
    assert!(h.app.refs_lens.is_none(), "the jump closes the lens");
    assert_eq!(h.app.current_view, JumpView::Nics);
    assert_eq!(h.selected_id().as_deref(), Some(mocks::nic_id("nic-aca").as_str()));
    // Ctrl-O returns to the subnet.
    h.press_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL)).await;
    assert_eq!(h.app.current_view, JumpView::Subnets);
}

#[tokio::test]
async fn u_on_an_identity_finds_the_app_and_its_service_principal_and_l_loads_the_likely_lists() {
    let mut h = Harness::new().await;
    h.install(mock_of(JumpView::Identities)).await;
    warm(&mut h, JumpView::ContainerApps, vec![mock_of(JumpView::ContainerApps).resource]);

    h.press(KeyCode::Char('U')).await;
    assert_eq!(ref_names(&h).len(), 1, "{:?}", ref_names(&h));
    let likely = h.app.refs_lens.as_ref().unwrap().coverage.likely_cold.clone();
    assert!(likely.contains(&JumpView::ServicePrincipals) && likely.contains(&JumpView::VirtualMachines), "{likely:?}");

    // L starts a background load of each likely list (they stay in flight
    // in the harness), without touching the visible list's load.
    let generation = h.app.list_load.generation();
    h.press(KeyCode::Char('L')).await;
    assert_eq!(h.app.refs_lens.as_ref().unwrap().warming, likely);
    assert_eq!(h.app.list_load.generation(), generation);
    assert!(h.render().contains("loading"));

    // One lands (as its lazy apply would), one fails: the lens rescans.
    let sub = h.app.subscription_key();
    h.app.refs_list_landed(JumpView::ServicePrincipals, &sub, Ok(vec![sp_managed_identity()]));
    h.app.refs_list_landed(JumpView::VirtualMachines, &sub, Err("403 AuthorizationFailed".into()));
    h.settle().await;
    let names = ref_names(&h);
    assert!(names.iter().any(|(n, v)| n == "id-1" && v == "Managed identity"), "{names:?}");
    let st = h.app.refs_lens.as_ref().unwrap();
    assert!(!st.warming.contains(&JumpView::ServicePrincipals) && !st.coverage.likely_cold.contains(&JumpView::ServicePrincipals));
    assert_eq!(st.warnings, vec!["VMs/VMs: 403 AuthorizationFailed".to_string()]);
    assert!(h.render().contains("⚠ VMs/VMs: 403"));

    h.press(KeyCode::Char('r')).await;
    assert_eq!(h.app.refs_lens.as_ref().unwrap().message.as_deref(), Some("rescanned"));
    h.press(KeyCode::Esc).await;
    assert!(h.app.refs_lens.is_none());
}

#[tokio::test]
async fn the_mouse_selects_a_referrer_and_a_right_click_closes() {
    let mut h = Harness::new().await;
    let subnet = vnet().subnets.remove(0);
    h.install(mocks::Mock { view: JumpView::Subnets, label: "SubnetRow", resource: Box::new(subnet) }).await;
    warm(&mut h, JumpView::Nics, vec![nic()]);
    warm(&mut h, JumpView::EnterprisePolicies, vec![policy()]);
    h.press(KeyCode::Char('U')).await;

    let at = h.find("ep-aca");
    h.click(at).await;
    assert_eq!(h.app.refs_lens.as_ref().unwrap().selected_row().unwrap().name, "ep-aca");
    h.right_click(at).await;
    assert!(h.app.refs_lens.is_none());
}

/// A gateway whose backend pool is the environment's static IP: a link only
/// the warm lists can make (no `related()` id names the environment).
#[tokio::test]
async fn u_on_an_environment_finds_the_app_gateway_whose_backend_matches_it() {
    use crate::azure::services::edge::AppGatewayRow;
    let mut h = Harness::new().await;
    h.install(mock_of(JumpView::ContainerAppEnvironments)).await;
    let gw = AppGatewayRow::from_json(
        &json!({"id": arm_id("Microsoft.Network/applicationGateways/agw-aca"), "name": "agw-aca", "location": "eastus",
            "properties": {"backendAddressPools": [{"name": "pool-aca", "properties": {
                "backendAddresses": [{"ipAddress": "10.0.16.4"}, {"fqdn": "other.example"}]}}]}}),
        Some(TENANT),
    )
    .unwrap();
    warm(&mut h, JumpView::AppGateways, vec![Box::new(gw)]);

    h.press(KeyCode::Char('U')).await;
    assert_eq!(
        ref_names(&h),
        vec![("agw-aca".to_string(), "Backend Container Apps environment cae-1 (pool-aca: 10.0.16.4)".to_string())]
    );
    let likely = h.app.refs_lens.as_ref().unwrap().coverage.likely_cold.clone();
    assert!(likely.contains(&JumpView::FrontDoorProfiles) && !likely.contains(&JumpView::AppGateways), "{likely:?}");
}
