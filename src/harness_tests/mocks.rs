//! One row per type that declares a section descriptor, built from minimal
//! ARM JSON through its real `from_json`, so the harness exercises the same
//! parse the list does. A new split pane adds its row here.

use super::{SUB_DEV, TENANT};
use crate::azure::auth::SubscriptionEntry;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::{
    aks, all_resources, app_service, changes, compute, container_apps, container_registry, cosmos, directory, edge, firewall, foundry,
    hybrid, identity, keyvault, messaging, monitor, network, network_dns, network_edge, network_hub, network_private, postgres_mysql, power_platform, private_link, redis, scale_sets, sql, storage, subscriptions,
    traffic_manager,
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

/// A Uniform scale set of two in `location`.
pub(crate) fn scale_set(name: &str, location: &str) -> Box<dyn Resource> {
    let mut v = body(
        &arm_id(&format!("Microsoft.Compute/virtualMachineScaleSets/{name}")),
        location,
        json!({"provisioningState": "Succeeded", "orchestrationMode": "Uniform"}),
    );
    v["sku"] = json!({"name": "Standard_D2s_v5", "capacity": 2});
    parse("ScaleSetRow", scale_sets::ScaleSetRow::from_json(&v, Some(TENANT)))
}

pub(crate) fn vnet(name: &str, location: &str) -> Box<dyn Resource> {
    let id = arm_id(&format!("Microsoft.Network/virtualNetworks/{name}"));
    let v = body(&id, location, json!({"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}));
    parse("VnetRow", network::VnetRow::from_json(&v, Some(TENANT)))
}

// ── Directory rows (Microsoft Graph, ADR 0004) ────────────────────────

pub(crate) const APP_ID: &str = "11111111-2222-3333-4444-555555555555";
pub(crate) const SP_OBJECT_ID: &str = "00af5dfb-85da-4b41-a677-0c6b86dd34f8";

/// An ISO time `days` from now (negative: the past), as Graph writes it.
pub(crate) fn iso_in_days(days: i64) -> String {
    let t = directory::now_unix() + days * 86_400;
    format!("{}:00Z", crate::azure::services::json::unix_to_ymdhm(t).replacen(' ', "T", 1))
}

/// A tenant-owned application's service principal with a year-long
/// secret: state `ok`, Related to its app registration by app id.
pub(crate) fn sp_application() -> Box<dyn Resource> {
    let v = json!({
        "id": SP_OBJECT_ID, "appId": APP_ID, "displayName": "sp-orders",
        "servicePrincipalType": "Application", "appOwnerOrganizationId": TENANT, "accountEnabled": true,
        "passwordCredentials": [{"displayName": "ci", "keyId": "aaaaaaaa-0000-0000-0000-000000000001",
            "startDateTime": iso_in_days(-30), "endDateTime": iso_in_days(365)}],
        "keyCredentials": []
    });
    parse("ServicePrincipalRow", directory::ServicePrincipalRow::from_json(&v, Some(TENANT), directory::now_unix()))
}

/// A user-assigned managed identity's service principal: no credentials
/// (stateless), Related to the identity's ARM id.
pub(crate) fn sp_managed_identity() -> Box<dyn Resource> {
    let v = json!({
        "id": "22222222-0000-0000-0000-000000000000", "appId": "33333333-0000-0000-0000-000000000000",
        "displayName": "id-1", "servicePrincipalType": "ManagedIdentity",
        "alternativeNames": ["isExplicit=True", arm_id("Microsoft.ManagedIdentity/userAssignedIdentities/id-1")],
        "passwordCredentials": [], "keyCredentials": []
    });
    parse("ServicePrincipalRow", directory::ServicePrincipalRow::from_json(&v, Some(TENANT), directory::now_unix()))
}

/// An app registration whose one secret ends in 10 days (`expiring`). Its
/// federated credential is a lazy child: [`app_federated_credential`].
pub(crate) fn app_registration() -> Box<dyn Resource> {
    let v = json!({
        "id": "44444444-0000-0000-0000-000000000000", "appId": APP_ID, "displayName": "app-orders",
        "signInAudience": "AzureADMyOrg",
        "web": {"redirectUris": ["https://orders.example/signin-oidc"]},
        "requiredResourceAccess": [],
        "passwordCredentials": [{"displayName": "deploy", "keyId": "bbbbbbbb-0000-0000-0000-000000000002",
            "startDateTime": iso_in_days(-80), "endDateTime": iso_in_days(10)}],
        "keyCredentials": []
    });
    parse("AppRegistrationRow", directory::AppRegistrationRow::from_json(&v, Some(TENANT), directory::now_unix()))
}

/// What `GET /v1.0/applications/{id}/federatedIdentityCredentials` returns
/// for [`app_registration`]: GitHub Actions OIDC.
pub(crate) fn app_federated_credential() -> Value {
    json!({"name": "gh-main", "issuer": "https://token.actions.githubusercontent.com",
           "subject": "repo:contoso/orders:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]})
}

/// The DNS topology of the fixture subscription: resolver `dnspr-hub` in
/// `vnet_hub` (an inbound endpoint in its `dns-in` subnet, an outbound one
/// in `dns-out`), and ruleset `rs-onprem` forwarding through that outbound
/// endpoint and linked to `vnet_spoke`.
pub(crate) fn dns_topology(vnet_hub: &str, vnet_spoke: &str) -> network_dns::DnsTopology {
    let resolver = arm_id("Microsoft.Network/dnsResolvers/dnspr-hub");
    let hub = arm_id(&format!("Microsoft.Network/virtualNetworks/{vnet_hub}"));
    let endpoint = |name: &str, inbound: bool, props: Value| {
        let dir = if inbound { "inboundEndpoints" } else { "outboundEndpoints" };
        network_dns::DnsEndpoint::from_json(&json!({"id": format!("{resolver}/{dir}/{name}"), "name": name, "properties": props}), inbound)
            .unwrap_or_else(|| panic!("{name}: from_json rejected the fixture"))
    };
    network_dns::DnsTopology {
        resolvers: vec![network_dns::ResolverNode {
            id: resolver.clone(),
            name: "dnspr-hub".into(),
            vnet_id: Some(hub.clone()),
            endpoints: vec![
                endpoint("in", true, json!({"ipConfigurations": [
                    {"subnet": {"id": format!("{hub}/subnets/dns-in")}, "privateIpAddress": "10.0.0.4"}]})),
                endpoint("out", false, json!({"subnet": {"id": format!("{hub}/subnets/dns-out")}})),
            ],
        }],
        rulesets: vec![network_dns::LinkedParent {
            id: arm_id("Microsoft.Network/dnsForwardingRulesets/rs-onprem"),
            name: "rs-onprem".into(),
            outbound_endpoint_ids: vec![format!("{resolver}/outboundEndpoints/out")],
            links: vec![network_dns::VnetLink::from_json(&json!({"name": "spoke", "properties": {
                "virtualNetwork": {"id": arm_id(&format!("Microsoft.Network/virtualNetworks/{vnet_spoke}"))}}}))],
        }],
        ..Default::default()
    }
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
        m(JumpView::ScaleSets, "ScaleSetRow", scale_set("vmss-1", l)),
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
            JumpView::BastionHosts,
            "BastionRow",
            parse("BastionRow", network_hub::BastionRow::from_json(&simple("Microsoft.Network/bastionHosts/bas-1"), t)),
        ),
        m(
            JumpView::DdosPlans,
            "DdosPlanRow",
            parse("DdosPlanRow", network_hub::DdosPlanRow::from_json(&simple("Microsoft.Network/ddosProtectionPlans/ddos-1"), t)),
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
            JumpView::DnsZones,
            "DnsZoneRow",
            parse(
                "DnsZoneRow",
                network_dns::DnsZoneRow::from_json(
                    &body(
                        &arm_id("Microsoft.Network/dnszones/example.com"),
                        "global",
                        json!({"numberOfRecordSets": 2, "maxNumberOfRecordSets": 10000,
                            "nameServers": ["ns1-01.azure-dns.com."], "zoneType": "Public"}),
                    ),
                    t,
                ),
            ),
        ),
        m(
            JumpView::DnsResolvers,
            "DnsResolverRow",
            parse(
                "DnsResolverRow",
                network_dns::DnsResolverRow::from_json(
                    &body(
                        &arm_id("Microsoft.Network/dnsResolvers/dnspr-hub"),
                        l,
                        json!({"provisioningState": "Succeeded", "dnsResolverState": "Connected",
                            "virtualNetwork": {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1")}}),
                    ),
                    t,
                ),
            ),
        ),
        m(
            JumpView::DnsForwardingRulesets,
            "DnsRulesetRow",
            parse(
                "DnsRulesetRow",
                network_dns::DnsRulesetRow::from_json(
                    &body(
                        &arm_id("Microsoft.Network/dnsForwardingRulesets/rs-onprem"),
                        l,
                        json!({"provisioningState": "Succeeded", "dnsResolverOutboundEndpoints": [
                            {"id": arm_id("Microsoft.Network/dnsResolvers/dnspr-hub/outboundEndpoints/out")}]}),
                    ),
                    t,
                ),
            ),
        ),
        m(
            JumpView::DnsResolverPolicies,
            "DnsPolicyRow",
            parse(
                "DnsPolicyRow",
                network_dns::DnsPolicyRow::from_json(
                    &body(&arm_id("Microsoft.Network/dnsResolverPolicies/pol-1"), l, json!({"provisioningState": "Succeeded"})),
                    t,
                ),
            ),
        ),
        m(
            JumpView::TrafficManagerProfiles,
            "TrafficManagerRow",
            parse(
                "TrafficManagerRow",
                traffic_manager::TrafficManagerRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/trafficManagerProfiles/tm-1"),
                        "name": "tm-1",
                        "location": "global",
                        "properties": {
                            "profileStatus": "Enabled",
                            "trafficRoutingMethod": "Priority",
                            "dnsConfig": {"relativeName": "tm-1", "fqdn": "tm-1.trafficmanager.example", "ttl": 30},
                            "monitorConfig": {"profileMonitorStatus": "Online", "protocol": "HTTPS", "port": 443, "path": "/"},
                            "endpoints": [{"name": "ep-1", "type": "Microsoft.Network/trafficManagerProfiles/azureEndpoints",
                                "properties": {"targetResourceId": arm_id("Microsoft.Network/publicIPAddresses/pip-1"),
                                    "endpointStatus": "Enabled", "endpointMonitorStatus": "Online", "priority": 1}}]
                        }
                    }),
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
        // Directory rows (Graph, ADR 0004): no ARM id, a synthetic one.
        m(JumpView::ServicePrincipals, "ServicePrincipalRow (application)", sp_application()),
        m(JumpView::ServicePrincipals, "ServicePrincipalRow (managed identity)", sp_managed_identity()),
        m(JumpView::AppRegistrations, "AppRegistrationRow", app_registration()),
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
            JumpView::PostgresServers,
            "FlexibleServerRow (PostgreSQL)",
            parse(
                "FlexibleServerRow",
                postgres_mysql::FlexibleServerRow::from_json(
                    &body(
                        &arm_id("Microsoft.DBforPostgreSQL/flexibleServers/pg-1"),
                        l,
                        json!({
                            "state": "Ready", "version": "16",
                            "network": {"publicNetworkAccess": "Disabled",
                                "delegatedSubnetResourceId": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-pg"),
                                "privateDnsZoneArmResourceId": arm_id("Microsoft.Network/privateDnsZones/pg-1.private.example")},
                            "authConfig": {"activeDirectoryAuth": "Enabled", "passwordAuth": "Enabled"}
                        }),
                    ),
                    t,
                ),
            ),
        ),
        m(
            JumpView::MysqlServers,
            "FlexibleServerRow (MySQL)",
            parse(
                "FlexibleServerRow",
                postgres_mysql::FlexibleServerRow::from_json(
                    &body(
                        &arm_id("Microsoft.DBforMySQL/flexibleServers/mysql-1"),
                        l,
                        json!({"state": "Ready", "version": "8.0.21", "network": {"publicNetworkAccess": "Enabled"}}),
                    ),
                    t,
                ),
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
        m(
            JumpView::ContainerApps,
            "ContainerAppRow",
            parse(
                "ContainerAppRow",
                container_apps::ContainerAppRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.App/containerApps/aca-1"),
                        "name": "aca-1",
                        "location": "East US",
                        "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                            arm_id("Microsoft.ManagedIdentity/userAssignedIdentities/id-1"): {"clientId": "c-1", "principalId": "p-1"}
                        }},
                        "properties": {
                            "provisioningState": "Succeeded",
                            "runningStatus": "Running",
                            "environmentId": arm_id("Microsoft.App/managedEnvironments/cae-1"),
                            "configuration": {
                                "secrets": [{"name": "db-password"}],
                                "ingress": {"external": true, "targetPort": 8080, "allowInsecure": false,
                                    "ipSecurityRestrictions": [{"name": "office", "action": "Allow", "ipAddressRange": "203.0.113.0/24"}]}
                            },
                            "template": {"containers": [{"name": "api", "image": "example/api:1",
                                "env": [{"name": "DB_PASSWORD", "secretRef": "db-password"}]}]}
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::ContainerAppEnvironments,
            "EnvironmentRow",
            parse(
                "EnvironmentRow",
                container_apps::EnvironmentRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.App/managedEnvironments/cae-1"),
                        "name": "cae-1",
                        "location": "East US",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "staticIp": "10.0.16.4",
                            "defaultDomain": "cae-1.eastus.example",
                            "vnetConfiguration": {"internal": true,
                                "infrastructureSubnetId": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-aca")}
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::ContainerAppJobs,
            "JobRow",
            parse(
                "JobRow",
                container_apps::JobRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.App/jobs/job-1"),
                        "name": "job-1",
                        "location": "East US",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "environmentId": arm_id("Microsoft.App/managedEnvironments/cae-1"),
                            "configuration": {"triggerType": "Schedule", "replicaTimeout": 600,
                                "scheduleTriggerConfig": {"cronExpression": "0 2 * * *", "parallelism": 1}},
                            "template": {"containers": [{"name": "run", "image": "example/job:1"}]}
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::RedisCaches,
            "RedisCacheRow",
            parse(
                "RedisCacheRow",
                redis::RedisCacheRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Cache/Redis/redis-1"),
                        "name": "redis-1",
                        "location": "East US",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "sku": {"name": "Premium", "family": "P", "capacity": 1},
                            "enableNonSslPort": false,
                            "minimumTlsVersion": "1.2",
                            "publicNetworkAccess": "Disabled",
                            "accessKeys": {"primaryKey": "mock-redis-key"},
                            "redisConfiguration": {"aad-enabled": "true",
                                "rdb-storage-connection-string": "AccountKey=mock-redis-key"},
                            "privateEndpointConnections": [{"properties": {
                                "privateEndpoint": {"id": arm_id("Microsoft.Network/privateEndpoints/pe-redis")},
                                "privateLinkServiceConnectionState": {"status": "Approved"}}}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::ManagedRedis,
            "ManagedRedisRow",
            parse(
                "ManagedRedisRow",
                redis::ManagedRedisRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Cache/redisEnterprise/amr-1"),
                        "name": "amr-1",
                        "location": "East US",
                        "sku": {"name": "Balanced_B1"},
                        "properties": {
                            "provisioningState": "Succeeded",
                            "resourceState": "Running",
                            "highAvailability": "Enabled",
                            "publicNetworkAccess": "Disabled",
                            "minimumTlsVersion": "1.2"
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::ServiceBusNamespaces,
            "ServiceBusRow",
            parse(
                "ServiceBusRow",
                messaging::ServiceBusRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.ServiceBus/namespaces/sb-1"),
                        "name": "sb-1",
                        "location": "East US",
                        "sku": {"name": "Premium", "tier": "Premium", "capacity": 1},
                        "properties": {
                            "provisioningState": "Succeeded",
                            "status": "Active",
                            "publicNetworkAccess": "Disabled",
                            "disableLocalAuth": true,
                            "minimumTlsVersion": "1.2",
                            "privateEndpointConnections": [{"properties": {
                                "privateEndpoint": {"id": arm_id("Microsoft.Network/privateEndpoints/pe-sb-1")},
                                "privateLinkServiceConnectionState": {"status": "Approved"}
                            }}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::EventHubNamespaces,
            "EventHubsRow",
            parse(
                "EventHubsRow",
                messaging::EventHubsRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.EventHub/namespaces/eh-1"),
                        "name": "eh-1",
                        "location": "East US",
                        "sku": {"name": "Standard", "tier": "Standard", "capacity": 1},
                        "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                            arm_id("Microsoft.ManagedIdentity/userAssignedIdentities/id-1"): {"clientId": "c-1", "principalId": "p-1"}
                        }},
                        "properties": {
                            "provisioningState": "Succeeded",
                            "status": "Active",
                            "kafkaEnabled": true,
                            "publicNetworkAccess": "Enabled"
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::AppGateways,
            "AppGatewayRow",
            parse(
                "AppGatewayRow",
                edge::AppGatewayRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/applicationGateways/agw-1"),
                        "name": "agw-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "operationalState": "Running",
                            "sku": {"name": "WAF_v2", "tier": "WAF_v2", "capacity": 2},
                            "gatewayIPConfigurations": [{"name": "gw", "properties": {
                                "subnet": {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-agw")}}}],
                            "frontendIPConfigurations": [{"name": "fe", "properties": {
                                "publicIPAddress": {"id": arm_id("Microsoft.Network/publicIPAddresses/pip-agw")}}}],
                            "frontendPorts": [{"name": "p80", "properties": {"port": 80}}],
                            "httpListeners": [{"name": "l-1", "properties": {"protocol": "Http",
                                "frontendIPConfiguration": {"id": arm_id("Microsoft.Network/applicationGateways/agw-1/frontendIPConfigurations/fe")},
                                "frontendPort": {"id": arm_id("Microsoft.Network/applicationGateways/agw-1/frontendPorts/p80")}}}],
                            "backendAddressPools": [{"name": "pool-1", "properties": {"backendAddresses": [{"ipAddress": "10.0.0.4"}]}}],
                            "requestRoutingRules": [{"name": "r-1", "properties": {"ruleType": "Basic", "priority": 100,
                                "httpListener": {"id": arm_id("Microsoft.Network/applicationGateways/agw-1/httpListeners/l-1")},
                                "backendAddressPool": {"id": arm_id("Microsoft.Network/applicationGateways/agw-1/backendAddressPools/pool-1")}}}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::FrontDoorProfiles,
            "FrontDoorProfileRow",
            parse(
                "FrontDoorProfileRow",
                edge::FrontDoorProfileRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Cdn/profiles/afd-1"),
                        "name": "afd-1",
                        "location": "Global",
                        "sku": {"name": "Premium_AzureFrontDoor"},
                        "properties": {"provisioningState": "Succeeded", "resourceState": "Active", "frontDoorId": "fd-1"}
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::WafPolicies,
            "WafPolicyRow",
            parse(
                "WafPolicyRow",
                edge::WafPolicyRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-1"),
                        "name": "waf-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "resourceState": "Enabled",
                            "policySettings": {"state": "Enabled", "mode": "Prevention"},
                            "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}]},
                            "applicationGateways": [{"id": arm_id("Microsoft.Network/applicationGateways/agw-1")}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::PrivateLinkServices,
            "PrivateLinkServiceRow",
            parse(
                "PrivateLinkServiceRow",
                private_link::PrivateLinkServiceRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/privateLinkServices/pls-1"),
                        "name": "pls-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "alias": "pls-1.00000000-0000-0000-0000-000000000000.eastus.azure.privatelinkservice",
                            "loadBalancerFrontendIpConfigurations": [{"id": arm_id("Microsoft.Network/loadBalancers/lb-1/frontendIPConfigurations/fe-1")}],
                            "ipConfigurations": [{"name": "nat-1", "properties": {"privateIPAddress": "10.0.1.10",
                                "subnet": {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/default")}}}],
                            "privateEndpointConnections": [{"name": "pe-1.conn", "properties": {
                                "privateEndpoint": {"id": arm_id("Microsoft.Network/privateEndpoints/pe-1")},
                                "privateLinkServiceConnectionState": {"status": "Approved"}}}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::ExpressRouteCircuits,
            "CircuitRow",
            parse(
                "CircuitRow",
                hybrid::CircuitRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/expressRouteCircuits/erc-1"),
                        "name": "erc-1",
                        "location": "eastus",
                        "sku": {"name": "Standard_MeteredData", "tier": "Standard", "family": "MeteredData"},
                        "properties": {
                            "provisioningState": "Succeeded",
                            "circuitProvisioningState": "Enabled",
                            "serviceProviderProvisioningState": "Provisioned",
                            "serviceKey": "00000000-0000-0000-0000-000000000001",
                            "serviceProviderProperties": {"serviceProviderName": "Equinix", "peeringLocation": "Washington DC", "bandwidthInMbps": 1000},
                            "peerings": [{"name": "AzurePrivatePeering", "properties": {"peeringType": "AzurePrivatePeering",
                                "state": "Enabled", "vlanId": 100, "peerASN": 65010,
                                "primaryPeerAddressPrefix": "172.16.0.0/30", "secondaryPeerAddressPrefix": "172.16.0.4/30"}}],
                            "authorizations": [{"name": "auth-1", "properties": {"authorizationUseStatus": "Available"}}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::VnetGateways,
            "GatewayRow",
            parse(
                "GatewayRow",
                hybrid::GatewayRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/virtualNetworkGateways/vgw-1"),
                        "name": "vgw-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "gatewayType": "ExpressRoute",
                            "sku": {"name": "ErGw1AZ", "tier": "ErGw1AZ"},
                            "ipConfigurations": [{"name": "default", "properties": {"privateIPAllocationMethod": "Dynamic",
                                "subnet": {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/GatewaySubnet")},
                                "publicIPAddress": {"id": arm_id("Microsoft.Network/publicIPAddresses/pip-vgw-1")}}}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::GatewayConnections,
            "ConnectionRow",
            parse(
                "ConnectionRow",
                hybrid::ConnectionRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/connections/cn-1"),
                        "name": "cn-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "connectionType": "IPsec",
                            "connectionStatus": "Connected",
                            "connectionProtocol": "IKEv2",
                            "virtualNetworkGateway1": {"id": arm_id("Microsoft.Network/virtualNetworkGateways/vgw-1")},
                            "localNetworkGateway2": {"id": arm_id("Microsoft.Network/localNetworkGateways/lgw-1")}
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::LocalGateways,
            "LocalGatewayRow",
            parse(
                "LocalGatewayRow",
                hybrid::LocalGatewayRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/localNetworkGateways/lgw-1"),
                        "name": "lgw-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "gatewayIpAddress": "203.0.113.10",
                            "localNetworkAddressSpace": {"addressPrefixes": ["192.168.0.0/16"]}
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::AzureFirewalls,
            "AzureFirewallRow",
            parse(
                "AzureFirewallRow",
                firewall::AzureFirewallRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/azureFirewalls/afw-1"),
                        "name": "afw-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "sku": {"name": "AZFW_VNet", "tier": "Premium"},
                            "firewallPolicy": {"id": arm_id("Microsoft.Network/firewallPolicies/fwp-1")},
                            "ipConfigurations": [{"name": "ipc", "properties": {"privateIPAddress": "10.0.9.4",
                                "subnet": {"id": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/AzureFirewallSubnet")},
                                "publicIPAddress": {"id": arm_id("Microsoft.Network/publicIPAddresses/pip-afw")}}}]
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::FirewallPolicies,
            "FirewallPolicyRow",
            parse(
                "FirewallPolicyRow",
                firewall::FirewallPolicyRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/firewallPolicies/fwp-1"),
                        "name": "fwp-1",
                        "location": "eastus",
                        "properties": {"provisioningState": "Succeeded", "sku": {"tier": "Premium"}, "threatIntelMode": "Deny",
                            "firewalls": [{"id": arm_id("Microsoft.Network/azureFirewalls/afw-1")}]}
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::IpGroups,
            "IpGroupRow",
            parse(
                "IpGroupRow",
                firewall::IpGroupRow::from_json(
                    &json!({
                        "id": arm_id("Microsoft.Network/ipGroups/ipg-1"),
                        "name": "ipg-1",
                        "location": "eastus",
                        "properties": {"provisioningState": "Succeeded", "ipAddresses": ["10.1.0.0/16"]}
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::CloudNgfws,
            "CloudNgfwRow",
            parse(
                "CloudNgfwRow",
                firewall::CloudNgfwRow::from_json(
                    &json!({
                        "id": arm_id("PaloAltoNetworks.Cloudngfw/firewalls/ngfw-1"),
                        "name": "ngfw-1",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "networkProfile": {"networkType": "VNET", "enableEgressNat": "ENABLED", "publicIps": [],
                                "vnetConfiguration": {"ipOfTrustSubnetForUdr": {"address": "10.0.11.4"},
                                    "vnet": {"resourceId": arm_id("Microsoft.Network/virtualNetworks/vnet-1")},
                                    "trustSubnet": {"resourceId": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/trust")},
                                    "unTrustSubnet": {"resourceId": arm_id("Microsoft.Network/virtualNetworks/vnet-1/subnets/untrust")}}},
                            "associatedRulestack": {"resourceId": arm_id("PaloAltoNetworks.Cloudngfw/localRulestacks/lrs-1")},
                            "dnsSettings": {"enableDnsProxy": "DISABLED"},
                            "planData": {"billingCycle": "MONTHLY", "planId": "panw-cngfw-payg"},
                            "marketplaceDetails": {"offerId": "pan_swfw_cloud_ngfw", "publisherId": "paloaltonetworks",
                                "marketplaceSubscriptionStatus": "Subscribed"}
                        }
                    }),
                    t,
                ),
            ),
        ),
        m(
            JumpView::NgfwRulestacks,
            "RulestackRow",
            parse(
                "RulestackRow",
                firewall::RulestackRow::from_json(
                    &json!({
                        "id": arm_id("PaloAltoNetworks.Cloudngfw/localRulestacks/lrs-1"),
                        "name": "lrs-1",
                        "location": "eastus",
                        "properties": {"provisioningState": "Succeeded", "scope": "LOCAL", "defaultMode": "IPS"}
                    }),
                    t,
                ),
            ),
        ),
        m(JumpView::ChangesAll, "ChangeRow (activity)", change_activity("c-all", "Microsoft.Compute/virtualMachines/write")),
        m(JumpView::ChangesActivity, "ChangeRow (activity)", change_activity("c-act", "Microsoft.Compute/virtualMachines/delete")),
        m(JumpView::ChangesDeployments, "ChangeRow (deployment)", change_deployment()),
        m(JumpView::ChangesHealth, "ChangeRow (health)", change_health()),
    ];
    // Lost coverage fails loudly. One row per sub-tab, except Function apps
    // (the sites list, SiteRow) and the virtual `@audit`;
    // `every_sub_tab_has_a_mock` names a gap.
    let sub_tabs: usize = crate::azure::service::ServiceType::all()
        .iter()
        .filter(|s| !s.is_virtual())
        .map(|s| s.views().len())
        .sum();
    assert!(out.len() >= sub_tabs - 1, "{} mock rows for {} sub-tabs", out.len(), sub_tabs);
    out
}

// ── @changes rows (#61) ──────────────────────────────────────────────────

/// An Activity Log change on `vm-1` by a person.
pub(crate) fn change_activity(correlation: &str, op: &str) -> Box<dyn Resource> {
    let e = json!({
        "eventTimestamp": "2026-10-23T10:00:00Z", "correlationId": correlation,
        "operationName": {"value": op, "localizedValue": ""}, "status": {"value": "Succeeded"},
        "caller": "ops@contoso.com", "level": "Informational",
        "resourceId": arm_id("Microsoft.Compute/virtualMachines/vm-1")
    });
    let row = crate::azure::timeline::activity_rows(&[e], 0, false).remove(0);
    Box::new(changes::ChangeRow::new(row, None, Some(TENANT.into())))
}

/// A deployment in the fixture group that deployed `vm-1`.
pub(crate) fn change_deployment() -> Box<dyn Resource> {
    let d = json!({
        "id": arm_id("Microsoft.Resources/deployments/main"), "name": "main",
        "properties": {"timestamp": "2026-10-23T09:00:00Z", "provisioningState": "Succeeded", "duration": "PT2M",
            "outputResources": [{"id": arm_id("Microsoft.Compute/virtualMachines/vm-1")}]}
    });
    let row = crate::azure::timeline::deployment_rows(&[d], 0, None).remove(0);
    Box::new(changes::ChangeRow::new(row, None, Some(TENANT.into())))
}

/// `vm-1` going unavailable.
pub(crate) fn change_health() -> Box<dyn Resource> {
    let vm = arm_id("Microsoft.Compute/virtualMachines/vm-1");
    let h = json!({
        "id": format!("{vm}/providers/Microsoft.ResourceHealth/availabilityStatuses/current"),
        "properties": {"availabilityState": "Unavailable", "summary": "Stopped by a user", "occuredTime": "2026-10-23T11:00:00Z"}
    });
    let row = crate::azure::timeline::health_rows(&[h], 0).remove(0);
    Box::new(changes::ChangeRow::new(row, None, Some(TENANT.into())))
}
