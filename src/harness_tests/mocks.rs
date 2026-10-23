//! One row per type that declares a section descriptor, built from minimal
//! ARM JSON through its real `from_json`, so the harness exercises the same
//! parse the list does. A new split pane adds its row here.

use super::{SUB_DEV, TENANT};
use crate::azure::auth::SubscriptionEntry;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::{
    aks, all_resources, app_service, compute, container_registry, cosmos, foundry, identity, keyvault, monitor,
    network, network_edge, network_private, power_platform, sql, storage, subscriptions,
};
use serde_json::{json, Value};

pub(crate) struct Mock {
    /// The sub-tab that lists the row.
    pub view: JumpView,
    /// The concrete type, for failure messages.
    pub label: &'static str,
    pub resource: Box<dyn Resource>,
}

pub(crate) const RG: &str = "rg-app";

/// The ARM id of `provider_path` (`Microsoft.Compute/virtualMachines/vm-1`)
/// in the fixture group of the default subscription.
pub(crate) fn arm_id(provider_path: &str) -> String {
    format!("/subscriptions/{}/resourceGroups/{}/providers/{}", SUB_DEV, RG, provider_path)
}

fn body(id: &str, location: &str, properties: Value) -> Value {
    json!({
        "id": id,
        "name": crate::azure::resource::name_of_id(id),
        "location": location,
        "tags": {"env": "test"},
        "properties": properties,
    })
}

fn parse<T: Resource + 'static>(label: &str, parsed: Option<T>) -> Box<dyn Resource> {
    Box::new(parsed.unwrap_or_else(|| panic!("{label}: from_json rejected the fixture")))
}

/// A VM in `location` with one NIC and an OS disk, both in the fixture group.
pub(crate) fn vm(name: &str, location: &str) -> Box<dyn Resource> {
    let id = arm_id(&format!("Microsoft.Compute/virtualMachines/{name}"));
    let v = body(
        &id,
        location,
        json!({
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": "Standard_B2s"},
            "storageProfile": {"osDisk": {"name": format!("{name}-os"), "osType": "Linux", "diskSizeGB": 30,
                "managedDisk": {"id": arm_id(&format!("Microsoft.Compute/disks/{name}-os"))}}},
            "networkProfile": {"networkInterfaces": [
                {"id": nic_id(&format!("{name}-nic")), "properties": {"primary": true}}
            ]}
        }),
    );
    parse("VmRow", compute::VmRow::from_json(&v, Some(TENANT)))
}

pub(crate) fn nic_id(name: &str) -> String {
    arm_id(&format!("Microsoft.Network/networkInterfaces/{name}"))
}

pub(crate) fn nic(name: &str, location: &str) -> Box<dyn Resource> {
    let v = body(&nic_id(name), location, json!({"provisioningState": "Succeeded"}));
    parse("NicRow", compute::NicRow::from_json(&v, Some(TENANT)))
}

pub(crate) fn disk(name: &str, location: &str) -> Box<dyn Resource> {
    let id = arm_id(&format!("Microsoft.Compute/disks/{name}"));
    let v = body(&id, location, json!({"diskSizeGB": 30, "diskState": "Attached"}));
    parse("DiskRow", compute::DiskRow::from_json(&v, Some(TENANT)))
}

pub(crate) fn vnet(name: &str, location: &str) -> Box<dyn Resource> {
    let id = arm_id(&format!("Microsoft.Network/virtualNetworks/{name}"));
    let v = body(&id, location, json!({"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}));
    parse("VnetRow", network::VnetRow::from_json(&v, Some(TENANT)))
}

/// One row of every split-pane type, each with the sub-tab that lists it.
pub(crate) fn all_mocks() -> Vec<Mock> {
    let l = "westeurope";
    let m = |view, label, resource| Mock { view, label, resource };
    let simple = |path: &str| body(&arm_id(path), l, json!({"provisioningState": "Succeeded"}));
    let t = Some(TENANT);
    let out = vec![
        m(
            JumpView::Subscriptions,
            "SubscriptionRow",
            Box::new(subscriptions::SubscriptionRow::new(SubscriptionEntry {
                id: SUB_DEV.into(),
                name: "Dev".into(),
                tenant_id: TENANT.into(),
                state: "Enabled".into(),
                is_default: true,
                cloud_name: None,
                user: None,
            })) as Box<dyn Resource>,
        ),
        m(
            JumpView::ResourceGroups,
            "ResourceGroupRow",
            parse(
                "ResourceGroupRow",
                subscriptions::ResourceGroupRow::from_json(
                    &body(&format!("/subscriptions/{SUB_DEV}/resourceGroups/{RG}"), l, json!({"provisioningState": "Succeeded"})),
                    t,
                ),
            ),
        ),
        m(
            JumpView::AllResources,
            "GenericResourceRow",
            parse("GenericResourceRow", {
                let mut v = simple("Microsoft.Network/publicIPPrefixes/px-1");
                v["type"] = json!("Microsoft.Network/publicIPPrefixes");
                all_resources::GenericResourceRow::from_json(&v, t)
            }),
        ),
        m(JumpView::VirtualMachines, "VmRow", vm("vm-1", l)),
        m(JumpView::Disks, "DiskRow", disk("disk-1", l)),
        m(JumpView::Nics, "NicRow", nic("nic-1", l)),
        m(
            JumpView::StorageAccounts,
            "StorageAccountRow",
            parse("StorageAccountRow", storage::StorageAccountRow::from_json(&simple("Microsoft.Storage/storageAccounts/st1"), t)),
        ),
        m(JumpView::VirtualNetworks, "VnetRow", vnet("vnet-1", l)),
        m(
            JumpView::Subnets,
            "SubnetRow",
            parse(
                "SubnetRow",
                network::SubnetRow::from_json(
                    &json!({"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-1"), "name": "snet-1",
                            "properties": {"addressPrefix": "10.0.1.0/24", "provisioningState": "Succeeded"}}),
                    t,
                ),
            ),
        ),
        m(
            JumpView::NetworkSecurityGroups,
            "NsgRow",
            parse("NsgRow", network::NsgRow::from_json(&simple("Microsoft.Network/networkSecurityGroups/nsg-1"), t)),
        ),
        m(
            JumpView::PublicIps,
            "PublicIpRow",
            parse("PublicIpRow", network_edge::PublicIpRow::from_json(&simple("Microsoft.Network/publicIPAddresses/pip-1"), t)),
        ),
        m(
            JumpView::LoadBalancers,
            "LoadBalancerRow",
            parse("LoadBalancerRow", network_edge::LoadBalancerRow::from_json(&simple("Microsoft.Network/loadBalancers/lb-1"), t)),
        ),
        m(
            JumpView::RouteTables,
            "RouteTableRow",
            parse("RouteTableRow", network_edge::RouteTableRow::from_json(&simple("Microsoft.Network/routeTables/rt-1"), t)),
        ),
        m(
            JumpView::NatGateways,
            "NatGatewayRow",
            parse("NatGatewayRow", network_edge::NatGatewayRow::from_json(&simple("Microsoft.Network/natGateways/nat-1"), t)),
        ),
        m(
            JumpView::PrivateEndpoints,
            "PrivateEndpointRow",
            parse(
                "PrivateEndpointRow",
                network_private::PrivateEndpointRow::from_json(&simple("Microsoft.Network/privateEndpoints/pe-1"), t),
            ),
        ),
        m(
            JumpView::PrivateDnsZones,
            "PrivateDnsZoneRow",
            parse(
                "PrivateDnsZoneRow",
                network_private::PrivateDnsZoneRow::from_json(
                    &body(&arm_id("Microsoft.Network/privateDnsZones/privatelink.example.com"), "global", json!({})),
                    t,
                ),
            ),
        ),
        m(
            JumpView::KeyVaults,
            "VaultRow",
            parse("VaultRow", keyvault::VaultRow::from_json(&simple("Microsoft.KeyVault/vaults/kv-1"), t)),
        ),
        m(
            JumpView::Identities,
            "IdentityRow",
            parse(
                "IdentityRow",
                identity::IdentityRow::from_json(&simple("Microsoft.ManagedIdentity/userAssignedIdentities/id-1"), t),
            ),
        ),
        m(
            JumpView::Clusters,
            "ClusterRow",
            parse("ClusterRow", aks::ClusterRow::from_json(&simple("Microsoft.ContainerService/managedClusters/aks-1"), t)),
        ),
        m(
            JumpView::NodePools,
            "NodePoolRow",
            parse(
                "NodePoolRow",
                aks::NodePoolRow::from_json(
                    &json!({"id": arm_id("Microsoft.ContainerService/managedClusters/aks-1/agentPools/np1"), "name": "np1",
                            "properties": {"count": 2, "vmSize": "Standard_B2s", "mode": "System"}}),
                    t,
                ),
            ),
        ),
        m(
            JumpView::Registries,
            "RegistryRow",
            parse("RegistryRow", container_registry::RegistryRow::from_json(&simple("Microsoft.ContainerRegistry/registries/acr1"), t)),
        ),
        m(
            JumpView::WebApps,
            "SiteRow",
            parse("SiteRow", app_service::SiteRow::from_json(&simple("Microsoft.Web/sites/app-1"), t)),
        ),
        m(
            JumpView::AppServicePlans,
            "PlanRow",
            parse("PlanRow", app_service::PlanRow::from_json(&simple("Microsoft.Web/serverfarms/plan-1"), t)),
        ),
        m(
            JumpView::SqlServers,
            "SqlServerRow",
            parse("SqlServerRow", sql::SqlServerRow::from_json(&simple("Microsoft.Sql/servers/sql-1"), t)),
        ),
        m(
            JumpView::CosmosAccounts,
            "CosmosAccountRow",
            parse(
                "CosmosAccountRow",
                cosmos::CosmosAccountRow::from_json(&simple("Microsoft.DocumentDB/databaseAccounts/cosmos-1"), t),
            ),
        ),
        m(
            JumpView::AiAccounts,
            "FoundryRow",
            parse("FoundryRow", foundry::FoundryRow::from_json(&simple("Microsoft.CognitiveServices/accounts/ai-1"), t)),
        ),
        m(
            JumpView::LogWorkspaces,
            "WorkspaceRow",
            parse("WorkspaceRow", monitor::WorkspaceRow::from_json(&simple("Microsoft.OperationalInsights/workspaces/law-1"), t)),
        ),
        m(
            JumpView::AppInsights,
            "ComponentRow",
            parse("ComponentRow", monitor::ComponentRow::from_json(&simple("Microsoft.Insights/components/appi-1"), t)),
        ),
        m(
            JumpView::EnterprisePolicies,
            "EnterprisePolicyRow",
            parse(
                "EnterprisePolicyRow",
                power_platform::EnterprisePolicyRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.PowerPlatform/enterprisePolicies/ep-vnet"),
                        "name": "ep-vnet",
                        "type": "Microsoft.PowerPlatform/enterprisePolicies",
                        "kind": "NetworkInjection",
                        "location": "unitedstates",
                        "properties": {
                            "healthStatus": "Healthy",
                            "networkInjection": {"virtualNetworks": [
                                {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1"), "subnet": {"name": "snet-pp"}}
                            ]}
                        }
                    }),
                    t,
                ),
            ),
        ),
    ];
    // Lost coverage fails loudly. One row per sub-tab, except Function apps
    // (the sites list, SiteRow); `every_sub_tab_has_a_mock` names a gap.
    let sub_tabs: usize = crate::azure::service::ServiceType::all().iter().map(|s| s.views().len()).sum();
    assert!(out.len() >= sub_tabs - 1, "{} mock rows for {} sub-tabs", out.len(), sub_tabs);
    out
}
