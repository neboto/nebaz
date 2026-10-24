//! The network access lens (`N`, #50): opening from a subnet and from a
//! Container Apps environment (through its infrastructure subnet), the
//! default rules, the jump to a rule's NSG, and closing. The harness never
//! lets a fetch land, so every row the lens needs is warm in the list
//! cache: the lens then resolves without a call.

use super::mocks::arm_id;
use super::*;
use crate::azure::services::network::{NsgRow, VnetRow};
use serde_json::json;

pub(super) fn nsg_id() -> String {
    arm_id("Microsoft.Network/networkSecurityGroups/aca-nsg")
}

pub(super) fn subnet_id() -> String {
    arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-aca")
}

/// `vnet-1` with one subnet, `snet-aca` (the shared ACA environment mock's infrastructure subnet), guarded by `aca-nsg`.
pub(super) fn vnet() -> VnetRow {
    VnetRow::from_json(
        &json!({"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1"), "name": "vnet-1", "location": "westeurope",
            "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": [
                {"id": subnet_id(), "name": "snet-aca", "properties": {
                    "addressPrefix": "10.0.0.0/23", "networkSecurityGroup": {"id": nsg_id()}}}
            ]}}),
        Some(TENANT),
    )
    .unwrap()
}

/// `aca-nsg`: one custom inbound rule; the body carries no default rules,
/// so the lens adds Azure's.
fn nsg() -> NsgRow {
    NsgRow::from_json(
        &json!({"id": nsg_id(), "name": "aca-nsg", "location": "westeurope", "properties": {"securityRules": [
            {"name": "allow-pp-https", "properties": {"priority": 100, "direction": "Inbound", "access": "Allow",
                "protocol": "Tcp", "sourceAddressPrefix": "10.20.0.0/24", "sourcePortRange": "*",
                "destinationAddressPrefix": "*", "destinationPortRange": "443"}}
        ], "subnets": [{"id": subnet_id()}]}}),
        Some(TENANT),
    )
    .unwrap()
}

/// Warm the NSGs list (and, for the environment case, the VNets list).
pub(super) fn warm(h: &mut Harness, with_vnet: bool) {
    let sub = h.app.subscription_key();
    h.app.cache.insert(
        ServiceType::Network,
        &sub,
        Some(JumpView::NetworkSecurityGroups.as_str().to_string()),
        vec![Box::new(nsg())],
    );
    if with_vnet {
        h.app.cache.insert(
            ServiceType::Network,
            &sub,
            Some(JumpView::VirtualNetworks.as_str().to_string()),
            vec![Box::new(vnet())],
        );
    }
}

fn lens_texts(h: &Harness) -> Vec<String> {
    h.app.network_lens.as_ref().expect("the lens is open").lines.iter().map(|l| l.copy_text()).collect()
}

#[tokio::test]
async fn n_on_a_subnet_shows_its_nsg_with_the_default_rules_and_jumps_to_the_nsg() {
    let mut h = Harness::new().await;
    let subnet = vnet().subnets.remove(0);
    h.install(mocks::Mock { view: JumpView::Subnets, label: "SubnetRow", resource: Box::new(subnet) }).await;
    warm(&mut h, false);

    h.press(KeyCode::Char('N')).await;
    let st = h.app.network_lens.as_ref().expect("N opens the lens");
    assert!(!st.loading, "warm rows resolve without a call");
    let texts = lens_texts(&h);
    assert!(texts.iter().any(|t| t.contains("allow-pp-https")), "{texts:#?}");
    assert!(texts.iter().any(|t| t.contains("DenyAllInBound") && t.contains("(default)")), "{texts:#?}");
    let screen = h.render();
    // The footer reads like every other hint bar, ` · ` between hints.
    for s in ["NETWORK ACCESS", "not Azure's effective view", "aca-nsg", "DenyAllInBound", "(default)", "select  ·  ⏎ go to NSG"] {
        assert!(screen.contains(s), "{s:?} missing:\n{screen}");
    }

    // ⏎ on a rule line jumps to its NSG.
    let at = h.app.network_lens.as_ref().unwrap().lines.iter().position(|l| l.rule.is_some()).unwrap();
    h.press(KeyCode::Char('g')).await;
    for _ in 0..at {
        h.press(KeyCode::Char('j')).await;
    }
    assert!(h.app.network_lens.as_ref().unwrap().selected_line().unwrap().rule.is_some());
    h.press(KeyCode::Enter).await;
    assert!(h.app.network_lens.is_none(), "the jump closes the lens");
    assert_eq!(h.app.current_view, JumpView::NetworkSecurityGroups);
    // The NSGs list is warm: the jump lands at once.
    assert_eq!(h.selected_id().as_deref(), Some(nsg_id().as_str()));
}

#[tokio::test]
async fn n_on_a_container_apps_environment_reaches_its_infrastructure_subnet() {
    let mut h = Harness::new().await;
    let env = mocks::all_mocks()
        .into_iter()
        .find(|m| m.view == JumpView::ContainerAppEnvironments)
        .expect("the shared environment mock");
    h.install(env).await;
    warm(&mut h, true);

    h.press(KeyCode::Char('N')).await;
    let st = h.app.network_lens.as_ref().expect("N opens the lens");
    assert_eq!(st.seed.subnets, vec![subnet_id()], "the seed is the infrastructure subnet");
    let texts = lens_texts(&h);
    assert!(texts.iter().any(|t| t == "Subnet vnet-1/snet-aca (rules for anything placed in it)"), "{texts:#?}");
    assert!(texts.iter().any(|t| t.contains("allow-pp-https")), "{texts:#?}");
    assert!(!texts.iter().any(|t| t.starts_with('!')), "nothing unread: {texts:#?}");

    // Esc closes and leaves the row where it was.
    h.press(KeyCode::Esc).await;
    assert!(h.app.network_lens.is_none());
    assert_eq!(h.app.current_view, JumpView::ContainerAppEnvironments);
    assert!(!h.render().contains("NETWORK ACCESS"));
}
