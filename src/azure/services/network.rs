//! The Network service (ticket 06): virtual networks, their embedded
//! subnets (own sub-tab, flattened from the VNet list; named
//! `vnet/subnet`, inheriting the VNet's location) and network security
//! groups. All three are stateless: only a provisioning transition or
//! failure colours a row. The edge types (public IPs, load balancers,
//! route tables, NAT gateways) live in `network_edge.rs`, private
//! endpoints and private DNS zones in `network_private.rs`; the provider
//! here lists all nine.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::network_edge::{
    LoadBalancerRow, NatGatewayRow, PublicIpRow, RouteTableRow, LOAD_BALANCERS_PATH, NAT_GATEWAYS_PATH,
    PUBLIC_IPS_PATH, ROUTE_TABLES_PATH,
};
use crate::azure::services::network_private::{
    PrivateDnsZoneRow, PrivateEndpointRow, PRIVATE_DNS_API_VERSION, PRIVATE_DNS_ZONES_PATH, PRIVATE_ENDPOINTS_PATH,
};
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub const NETWORK_API_VERSION: &str = "2025-09-01";
const VNETS_PATH: &str = "/providers/Microsoft.Network/virtualNetworks";
const NSGS_PATH: &str = "/providers/Microsoft.Network/networkSecurityGroups";

crate::sections! {
    pub enum VnetDetailSection,
    pub static VNET_SECTIONS = [
        Overview "Overview",
        Subnets "Subnets",
        Peerings "Peerings",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum SubnetDetailSection,
    pub static SUBNET_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum NsgDetailSection,
    pub static NSG_SECTIONS = [
        Overview "Overview",
        Inbound "Inbound",
        Outbound "Outbound",
        UsedBy "Used by",
        Related "Related",
        Tags "Tags",
    ]
}

// ── Virtual network ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Peering {
    pub name: String,
    pub remote_id: Option<String>,
    pub state: Option<String>,
    pub allow_forwarded_traffic: Option<bool>,
    pub allow_gateway_transit: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct VnetRow {
    pub base: ArmBase,
    pub address_prefixes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub ddos_protection: Option<bool>,
    pub guid: Option<String>,
    pub subnets: Vec<SubnetRow>,
    pub peerings: Vec<Peering>,
}

impl VnetRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VnetRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let subnets = json::arr(v, &format!("{}/subnets", p))
            .iter()
            .filter_map(|s| SubnetRow::from_embedded(s, &base))
            .collect();
        let peerings = json::arr(v, &format!("{}/virtualNetworkPeerings", p))
            .iter()
            .map(|pe| Peering {
                name: json::text(pe, "/name"),
                remote_id: json::arm_id(json::id_at(pe, "/properties/remoteVirtualNetwork")),
                state: json::str_at(pe, "/properties/peeringState"),
                allow_forwarded_traffic: json::bool_at(pe, "/properties/allowForwardedTraffic"),
                allow_gateway_transit: json::bool_at(pe, "/properties/allowGatewayTransit"),
            })
            .collect();
        Some(VnetRow {
            address_prefixes: json::strings_at(v, &format!("{}/addressSpace/addressPrefixes", p)),
            dns_servers: json::strings_at(v, &format!("{}/dhcpOptions/dnsServers", p)),
            ddos_protection: json::bool_at(v, &format!("{}/enableDdosProtection", p)),
            guid: json::str_at(v, &format!("{}/resourceGuid", p)),
            subnets,
            peerings,
            base,
        })
    }
}

impl Resource for VnetRow {
    arm_row!("Virtual Network");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VNET_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.address_prefixes.join(" "),
            self.subnets.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(" "),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Address space".into(), json::join(&self.address_prefixes)),
            ("DNS servers".into(), if self.dns_servers.is_empty() { "Azure-provided".into() } else { self.dns_servers.join(", ") }),
            ("DDoS protection".into(), json::yes_no(self.ddos_protection)),
            ("Subnets".into(), self.subnets.len().to_string()),
            ("Peerings".into(), self.peerings.len().to_string()),
            ("GUID".into(), json::opt(self.guid.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in &self.subnets {
            v.push((format!("Subnet {}", s.name), s.id.clone()));
        }
        for p in &self.peerings {
            if let Some(r) = &p.remote_id {
                v.push((format!("Peered VNet {}", name_of_id(r)), r.clone()));
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vnet show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn vnet_section_lines(r: &VnetRow, section: VnetDetailSection) -> Vec<(String, String)> {
    match section {
        VnetDetailSection::Overview => overview_rows(r),
        VnetDetailSection::Subnets => {
            if r.subnets.is_empty() {
                return vec![(String::new(), "No subnets".into())];
            }
            r.subnets
                .iter()
                .map(|s| {
                    (
                        format!(
                            "{} · {}",
                            s.name,
                            json::join(&s.prefixes)
                        ),
                        s.id.clone(),
                    )
                })
                .collect()
        }
        VnetDetailSection::Peerings => {
            if r.peerings.is_empty() {
                return vec![(String::new(), "No peerings".into())];
            }
            let mut lines = Vec::new();
            for p in &r.peerings {
                let mut flags = Vec::new();
                if p.allow_forwarded_traffic == Some(true) {
                    flags.push("forwarded traffic");
                }
                if p.allow_gateway_transit == Some(true) {
                    flags.push("gateway transit");
                }
                lines.push((
                    format!(
                        "{} · {}{}",
                        p.name,
                        json::opt(p.state.clone()).to_lowercase(),
                        if flags.is_empty() { String::new() } else { format!(" · {}", flags.join(", ")) }
                    ),
                    p.remote_id.clone().unwrap_or_else(|| "-".into()),
                ));
            }
            lines
        }
        VnetDetailSection::Related => related_rows(r),
        VnetDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Subnet (embedded child) ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SubnetRow {
    pub id: String,
    /// The bare subnet name; `name()` is `vnet/subnet`.
    pub name: String,
    display_name: String,
    pub vnet_id: String,
    pub vnet_name: String,
    /// Inherited from the VNet when flattened; unknown on a standalone GET.
    pub location: Option<String>,
    tenant: Option<String>,
    raw: String,
    tags: HashMap<String, String>,
    pub provisioning_state: Option<String>,
    pub prefixes: Vec<String>,
    pub nsg_id: Option<String>,
    pub route_table_id: Option<String>,
    pub nat_gateway_id: Option<String>,
    pub delegations: Vec<String>,
    pub service_endpoints: Vec<String>,
    pub private_endpoint_policies: Option<String>,
    pub ip_configuration_count: usize,
    pub private_endpoint_count: usize,
}

impl SubnetRow {
    /// One element of a VNet's embedded `subnets[]`.
    pub fn from_embedded(v: &Value, vnet: &ArmBase) -> Option<SubnetRow> {
        Self::parse(v, &vnet.id, &vnet.name, Some(vnet.location.clone()), vnet.tenant.as_deref())
    }

    /// A standalone subnet body (`GET …/subnets/{name}`), the VNet read
    /// from the id.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<SubnetRow> {
        let id = json::str_at(v, "/id")?;
        let (vnet_id, vnet_name) = parent_of(&id, "subnets")?;
        Self::parse(v, &vnet_id, &vnet_name, None, tenant)
    }

    fn parse(v: &Value, vnet_id: &str, vnet_name: &str, location: Option<String>, tenant: Option<&str>) -> Option<SubnetRow> {
        let id = json::str_at(v, "/id")?;
        let name = json::str_at(v, "/name").unwrap_or_else(|| name_of_id(&id).to_string());
        let p = "/properties";
        let mut prefixes = json::strings_at(v, &format!("{}/addressPrefixes", p));
        if let Some(one) = json::str_at(v, &format!("{}/addressPrefix", p)) {
            prefixes.insert(0, one);
        }
        Some(SubnetRow {
            display_name: format!("{}/{}", vnet_name, name),
            vnet_id: vnet_id.to_string(),
            vnet_name: vnet_name.to_string(),
            location: location.filter(|l| !l.is_empty()),
            tenant: tenant.map(str::to_string),
            raw: serde_json::to_string_pretty(v).unwrap_or_default(),
            tags: HashMap::new(),
            provisioning_state: json::str_at(v, &format!("{}/provisioningState", p)),
            prefixes,
            nsg_id: json::arm_id(json::id_at(v, &format!("{}/networkSecurityGroup", p))),
            route_table_id: json::arm_id(json::id_at(v, &format!("{}/routeTable", p))),
            nat_gateway_id: json::arm_id(json::id_at(v, &format!("{}/natGateway", p))),
            delegations: json::arr(v, &format!("{}/delegations", p))
                .iter()
                .filter_map(|d| json::str_at(d, "/properties/serviceName"))
                .collect(),
            service_endpoints: json::arr(v, &format!("{}/serviceEndpoints", p))
                .iter()
                .filter_map(|e| json::str_at(e, "/service"))
                .collect(),
            private_endpoint_policies: json::str_at(v, &format!("{}/privateEndpointNetworkPolicies", p)),
            ip_configuration_count: json::arr(v, &format!("{}/ipConfigurations", p)).len(),
            private_endpoint_count: json::arr(v, &format!("{}/privateEndpoints", p)).len(),
            id,
            name,
        })
    }
}

/// `(parent id, parent name)` of a child ARM id, the segment before
/// `/{child_type}/`.
fn parent_of(id: &str, child_type: &str) -> Option<(String, String)> {
    let needle = format!("/{}/", child_type);
    let pos = id.to_lowercase().rfind(&needle.to_lowercase())?;
    let parent = &id[..pos];
    Some((parent.to_string(), name_of_id(parent).to_string()))
}

impl Resource for SubnetRow {
    fn id(&self) -> &str {
        &self.id
    }
    /// `vnet/subnet` on the sub-tab; the bare `name` field inside the
    /// VNet's own section.
    #[allow(clippy::misnamed_getters)]
    fn name(&self) -> &str {
        &self.display_name
    }
    fn resource_type(&self) -> &str {
        "Subnet"
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SUBNET_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }
    fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }
    fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
    fn raw_content(&self) -> Option<String> {
        Some(self.raw.clone())
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.id,
            self.display_name,
            self.name,
            self.resource_group().unwrap_or(""),
            self.prefixes.join(" "),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.name.clone()),
            ("Virtual network".into(), self.vnet_name.clone()),
            ("Id".into(), self.id.clone()),
            ("Location".into(), self.location.clone().unwrap_or_else(|| "(the VNet's)".into())),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.provisioning_state.clone())),
            ("Address prefix".into(), json::join(&self.prefixes)),
            ("NSG".into(), self.nsg_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("Route table".into(), self.route_table_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("NAT gateway".into(), self.nat_gateway_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("Delegations".into(), json::join(&self.delegations)),
            ("Service endpoints".into(), json::join(&self.service_endpoints)),
            ("Private endpoint policies".into(), json::opt(self.private_endpoint_policies.clone())),
            ("IP configurations".into(), self.ip_configuration_count.to_string()),
            ("Private endpoints".into(), self.private_endpoint_count.to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.id);
        v.push((format!("Virtual network {}", self.vnet_name), self.vnet_id.clone()));
        if let Some(n) = &self.nsg_id {
            v.push((format!("NSG {}", name_of_id(n)), n.clone()));
        }
        if let Some(r) = &self.route_table_id {
            v.push((format!("Route table {}", name_of_id(r)), r.clone()));
        }
        if let Some(n) = &self.nat_gateway_id {
            v.push((format!("NAT gateway {}", name_of_id(n)), n.clone()));
        }
        v
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vnet subnet show --ids {}", shell_quote(&self.id)))
    }
}

pub fn subnet_section_lines(r: &SubnetRow, section: SubnetDetailSection) -> Vec<(String, String)> {
    match section {
        SubnetDetailSection::Overview => overview_rows(r),
        SubnetDetailSection::Related => related_rows(r),
        SubnetDetailSection::Tags => vec![(String::new(), "Subnets carry no tags (the VNet's apply)".into())],
    }
}

// ── Network security group ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityRule {
    pub name: String,
    pub priority: Option<i64>,
    pub direction: String,
    pub access: String,
    pub protocol: String,
    pub source: String,
    pub source_port: String,
    pub destination: String,
    pub destination_port: String,
    pub is_default: bool,
}

impl SecurityRule {
    fn from_json(v: &Value, is_default: bool) -> SecurityRule {
        let p = "/properties";
        let one_or_many = |one: &str, many: &str| -> String {
            json::str_at(v, &format!("{}/{}", p, one))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| json::join(&json::strings_at(v, &format!("{}/{}", p, many))))
        };
        SecurityRule {
            name: json::text(v, "/name"),
            priority: json::int_at(v, &format!("{}/priority", p)),
            direction: json::text(v, &format!("{}/direction", p)),
            access: json::text(v, &format!("{}/access", p)),
            protocol: json::text(v, &format!("{}/protocol", p)),
            source: one_or_many("sourceAddressPrefix", "sourceAddressPrefixes"),
            source_port: one_or_many("sourcePortRange", "sourcePortRanges"),
            destination: one_or_many("destinationAddressPrefix", "destinationAddressPrefixes"),
            destination_port: one_or_many("destinationPortRange", "destinationPortRanges"),
            is_default,
        }
    }

    fn line(&self) -> (String, String) {
        (
            format!("{} {}", json::num(self.priority), self.name),
            format!(
                "{} {} · {}:{} → {}:{}",
                self.access.to_lowercase(),
                self.protocol,
                self.source,
                self.source_port,
                self.destination,
                self.destination_port
            ),
        )
    }
}

#[derive(Debug, Clone)]
pub struct NsgRow {
    pub base: ArmBase,
    pub rules: Vec<SecurityRule>,
    pub nic_ids: Vec<String>,
    pub subnet_ids: Vec<String>,
    pub flow_logs: usize,
}

impl NsgRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<NsgRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let mut rules: Vec<SecurityRule> = json::arr(v, &format!("{}/securityRules", p))
            .iter()
            .map(|r| SecurityRule::from_json(r, false))
            .collect();
        rules.extend(
            json::arr(v, &format!("{}/defaultSecurityRules", p))
                .iter()
                .map(|r| SecurityRule::from_json(r, true)),
        );
        rules.sort_by_key(|r| (r.is_default, r.priority.unwrap_or(i64::MAX)));
        Some(NsgRow {
            rules,
            nic_ids: json::ids_at(v, &format!("{}/networkInterfaces", p)),
            subnet_ids: json::ids_at(v, &format!("{}/subnets", p)),
            flow_logs: json::arr(v, &format!("{}/flowLogs", p)).len(),
            base,
        })
    }

    fn custom_count(&self, direction: &str) -> usize {
        self.rules
            .iter()
            .filter(|r| !r.is_default && r.direction.eq_ignore_ascii_case(direction))
            .count()
    }

    fn rule_lines(&self, direction: &str) -> Vec<(String, String)> {
        let mut lines: Vec<(String, String)> = self
            .rules
            .iter()
            .filter(|r| !r.is_default && r.direction.eq_ignore_ascii_case(direction))
            .map(SecurityRule::line)
            .collect();
        if lines.is_empty() {
            lines.push((String::new(), "No custom rules".into()));
        }
        let defaults: Vec<(String, String)> = self
            .rules
            .iter()
            .filter(|r| r.is_default && r.direction.eq_ignore_ascii_case(direction))
            .map(SecurityRule::line)
            .collect();
        if !defaults.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Default rules".into(), String::new()));
            lines.extend(defaults.into_iter().map(|(k, v)| (format!("  {}", k), v)));
        }
        lines
    }
}

impl Resource for NsgRow {
    arm_row!("Network Security Group");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&NSG_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Inbound rules".into(), self.custom_count("Inbound").to_string()),
            ("Outbound rules".into(), self.custom_count("Outbound").to_string()),
            ("Network interfaces".into(), self.nic_ids.len().to_string()),
            ("Subnets".into(), self.subnet_ids.len().to_string()),
            ("Flow logs".into(), self.flow_logs.to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in &self.subnet_ids {
            v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
        }
        for n in &self.nic_ids {
            v.push((format!("NIC {}", name_of_id(n)), n.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network nsg show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn nsg_section_lines(r: &NsgRow, section: NsgDetailSection) -> Vec<(String, String)> {
    match section {
        NsgDetailSection::Overview => overview_rows(r),
        NsgDetailSection::Inbound => r.rule_lines("Inbound"),
        NsgDetailSection::Outbound => r.rule_lines("Outbound"),
        NsgDetailSection::UsedBy => {
            let mut lines: Vec<(String, String)> = r
                .subnet_ids
                .iter()
                .map(|s| (format!("Subnet {}", name_of_id(s)), s.clone()))
                .chain(r.nic_ids.iter().map(|n| (format!("NIC {}", name_of_id(n)), n.clone())))
                .collect();
            if lines.is_empty() {
                lines.push((String::new(), "Not associated with any subnet or NIC".into()));
            }
            lines
        }
        NsgDetailSection::Related => related_rows(r),
        NsgDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct NetworkService {
    scope: Scope,
}

impl NetworkService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<R: Resource + 'static>(rows: Vec<R>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    /// The sub-tabs that are one plain list each (every Network type but
    /// VNets, their embedded subnets and NSGs): path, api-version, and
    /// the loading label. Private DNS is its own spec, on its own version.
    fn flat_list(view: JumpView) -> Option<(&'static str, &'static str, &'static str)> {
        Some(match view {
            JumpView::PublicIps => (PUBLIC_IPS_PATH, NETWORK_API_VERSION, "Listing public IPs…"),
            JumpView::LoadBalancers => (LOAD_BALANCERS_PATH, NETWORK_API_VERSION, "Listing load balancers…"),
            JumpView::RouteTables => (ROUTE_TABLES_PATH, NETWORK_API_VERSION, "Listing route tables…"),
            JumpView::NatGateways => (NAT_GATEWAYS_PATH, NETWORK_API_VERSION, "Listing NAT gateways…"),
            JumpView::PrivateEndpoints => (PRIVATE_ENDPOINTS_PATH, NETWORK_API_VERSION, "Listing private endpoints…"),
            JumpView::PrivateDnsZones => (PRIVATE_DNS_ZONES_PATH, PRIVATE_DNS_API_VERSION, "Listing private DNS zones…"),
            _ => return None,
        })
    }

    /// One page of a `flat_list` sub-tab, parsed by that sub-tab's row
    /// type. Empty for any other view.
    fn flat_rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::PublicIps => Self::boxed(page.iter().filter_map(|v| PublicIpRow::from_json(v, tenant)).collect()),
            JumpView::LoadBalancers => {
                Self::boxed(page.iter().filter_map(|v| LoadBalancerRow::from_json(v, tenant)).collect())
            }
            JumpView::RouteTables => {
                Self::boxed(page.iter().filter_map(|v| RouteTableRow::from_json(v, tenant)).collect())
            }
            JumpView::NatGateways => {
                Self::boxed(page.iter().filter_map(|v| NatGatewayRow::from_json(v, tenant)).collect())
            }
            JumpView::PrivateEndpoints => {
                Self::boxed(page.iter().filter_map(|v| PrivateEndpointRow::from_json(v, tenant)).collect())
            }
            JumpView::PrivateDnsZones => {
                Self::boxed(page.iter().filter_map(|v| PrivateDnsZoneRow::from_json(v, tenant)).collect())
            }
            _ => Vec::new(),
        }
    }

    /// Every subnet of every VNet in a page, flattened.
    fn subnets_of(page: &[Value], tenant: Option<&str>) -> Vec<SubnetRow> {
        page.iter()
            .filter_map(|v| VnetRow::from_json(v, tenant))
            .flat_map(|vnet| vnet.subnets)
            .collect()
    }
}

#[async_trait]
impl AzureService for NetworkService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Network
    }

    fn name(&self) -> &str {
        "Network"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        if let Some((path, api_version, _)) = Self::flat_list(view) {
            return Ok(Self::flat_rows(view, &self.scope.list(path, api_version).await?, tenant));
        }
        Ok(match view {
            JumpView::NetworkSecurityGroups => Self::boxed(
                self.scope
                    .list(NSGS_PATH, NETWORK_API_VERSION)
                    .await?
                    .iter()
                    .filter_map(|v| NsgRow::from_json(v, tenant))
                    .collect(),
            ),
            JumpView::Subnets => {
                let page = self.scope.list(VNETS_PATH, NETWORK_API_VERSION).await?;
                Self::boxed(Self::subnets_of(&page, tenant))
            }
            _ => Self::boxed(
                self.scope
                    .list(VNETS_PATH, NETWORK_API_VERSION)
                    .await?
                    .iter()
                    .filter_map(|v| VnetRow::from_json(v, tenant))
                    .collect(),
            ),
        })
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        if let Some((path, api_version, label)) = Self::flat_list(view) {
            let r = self
                .scope
                .stream(path, api_version, &[], service_type, label, &event_tx, |page| {
                    Self::flat_rows(view, &page, tenant.as_deref())
                })
                .await;
            return finish_stream(service_type, r, &event_tx);
        }
        let r = match view {
            JumpView::NetworkSecurityGroups => {
                self.scope
                    .stream(NSGS_PATH, NETWORK_API_VERSION, &[], service_type, "Listing network security groups…", &event_tx, |page| {
                        Self::boxed(page.iter().filter_map(|v| NsgRow::from_json(v, tenant.as_deref())).collect())
                    })
                    .await
            }
            JumpView::Subnets => {
                self.scope
                    .stream(VNETS_PATH, NETWORK_API_VERSION, &[], service_type, "Listing subnets…", &event_tx, |page| {
                        Self::boxed(Self::subnets_of(&page, tenant.as_deref()))
                    })
                    .await
            }
            _ => {
                self.scope
                    .stream(VNETS_PATH, NETWORK_API_VERSION, &[], service_type, "Listing virtual networks…", &event_tx, |page| {
                        Self::boxed(page.iter().filter_map(|v| VnetRow::from_json(v, tenant.as_deref())).collect())
                    })
                    .await
            }
        };
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let tenant = self.scope.tenant();
        let not_found = || Error::ResourceNotFound(id.to_string());
        let view = JumpView::for_arm_id(id);
        let api_version = view
            .and_then(Self::flat_list)
            .map(|(_, v, _)| v)
            .unwrap_or(NETWORK_API_VERSION);
        let v = self.scope.get(id, api_version).await?;
        match view {
            Some(JumpView::VirtualNetworks) => Ok(Box::new(VnetRow::from_json(&v, tenant).ok_or_else(not_found)?)),
            Some(JumpView::Subnets) => Ok(Box::new(SubnetRow::from_json(&v, tenant).ok_or_else(not_found)?)),
            Some(JumpView::NetworkSecurityGroups) => Ok(Box::new(NsgRow::from_json(&v, tenant).ok_or_else(not_found)?)),
            Some(view) if Self::flat_list(view).is_some() => {
                Self::flat_rows(view, std::slice::from_ref(&v), tenant).pop().ok_or_else(not_found)
            }
            _ => Err(not_found()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-net";

    fn vnet_json() -> Value {
        let vnet = format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-prod", RG);
        serde_json::json!({
            "id": vnet,
            "name": "vnet-prod",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                "subnets": [
                    {"id": format!("{}/subnets/default", vnet), "name": "default",
                     "properties": {"addressPrefix": "10.0.0.0/24", "provisioningState": "Succeeded",
                                    "networkSecurityGroup": {"id": format!("{}/providers/Microsoft.Network/networkSecurityGroups/web-nsg", RG)},
                                    "ipConfigurations": [{"id": "x"}, {"id": "y"}],
                                    "delegations": [{"name": "d", "properties": {"serviceName": "Microsoft.Web/serverFarms"}}]}},
                    {"id": format!("{}/subnets/aks", vnet), "name": "aks",
                     "properties": {"addressPrefixes": ["10.0.8.0/22"], "provisioningState": "Updating"}}
                ],
                "virtualNetworkPeerings": [{"name": "to-hub", "properties": {
                    "peeringState": "Connected", "allowForwardedTraffic": true,
                    "remoteVirtualNetwork": {"id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-hub", RG)}}}]
            }
        })
    }

    #[test]
    fn vnet_row_embeds_subnets_named_parent_child_with_the_vnet_location() {
        let row = VnetRow::from_json(&vnet_json(), Some("t-1")).unwrap();
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.subnets.len(), 2);
        let s = &row.subnets[0];
        assert_eq!(s.name(), "vnet-prod/default");
        assert_eq!(s.name, "default");
        assert_eq!(s.location(), Some("westeurope"));
        assert_eq!(s.tenant_id(), Some("t-1"));
        assert_eq!(s.resource_group(), Some("rg-net"));
        assert_eq!(s.prefixes, vec!["10.0.0.0/24".to_string()]);
        assert_eq!(s.ip_configuration_count, 2);
        assert_eq!(s.delegations, vec!["Microsoft.Web/serverFarms".to_string()]);
        assert!(s.related().iter().any(|(l, _)| l == "Virtual network vnet-prod"));
        assert!(s.related().iter().any(|(l, _)| l == "NSG web-nsg"));
        assert_eq!(row.subnets[1].state(), ResourceState::Pending);
        assert_eq!(row.subnets[1].state_label(), "updating");
        let related = row.related();
        assert!(related.iter().any(|(l, _)| l == "Subnet aks"));
        assert!(related.iter().any(|(l, _)| l == "Peered VNet vnet-hub"));
        let peer = vnet_section_lines(&row, VnetDetailSection::Peerings);
        assert_eq!(peer[0].0, "to-hub · connected · forwarded traffic");
        let subnets = vnet_section_lines(&row, VnetDetailSection::Subnets);
        assert_eq!(subnets[0].0, "default · 10.0.0.0/24");
        assert!(subnets[0].1.ends_with("/subnets/default"));
    }

    #[test]
    fn a_standalone_subnet_reads_its_vnet_from_the_id() {
        let v = serde_json::json!({
            "id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/default", RG),
            "name": "default",
            "properties": {"addressPrefix": "10.0.0.0/24"}
        });
        let s = SubnetRow::from_json(&v, None).unwrap();
        assert_eq!(s.vnet_name, "vnet-prod");
        assert!(s.vnet_id.ends_with("/virtualNetworks/vnet-prod"));
        assert_eq!(s.location(), None);
        assert_eq!(
            s.cli_command().unwrap(),
            format!("az network vnet subnet show --ids {}/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/default", RG)
        );
    }

    #[test]
    fn nsg_rules_sort_custom_before_default_and_group_by_direction() {
        let v = serde_json::json!({
            "id": format!("{}/providers/Microsoft.Network/networkSecurityGroups/web-nsg", RG),
            "name": "web-nsg",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "securityRules": [
                    {"name": "allow-https", "properties": {"priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                        "sourceAddressPrefix": "Internet", "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRange": "443"}},
                    {"name": "deny-out", "properties": {"priority": 200, "direction": "Outbound", "access": "Deny", "protocol": "*",
                        "sourceAddressPrefix": "*", "sourcePortRange": "*", "destinationAddressPrefixes": ["10.1.0.0/16", "10.2.0.0/16"], "destinationPortRanges": ["22", "3389"]}}
                ],
                "defaultSecurityRules": [
                    {"name": "AllowVnetInBound", "properties": {"priority": 65000, "direction": "Inbound", "access": "Allow", "protocol": "*",
                        "sourceAddressPrefix": "VirtualNetwork", "sourcePortRange": "*", "destinationAddressPrefix": "VirtualNetwork", "destinationPortRange": "*"}}
                ],
                "subnets": [{"id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/default", RG)}],
                "networkInterfaces": [{"id": format!("{}/providers/Microsoft.Network/networkInterfaces/web-1-nic", RG)}]
            }
        });
        let row = NsgRow::from_json(&v, None).unwrap();
        assert_eq!(row.state_label(), "");
        let inbound = nsg_section_lines(&row, NsgDetailSection::Inbound);
        assert_eq!(inbound[0], ("100 allow-https".to_string(), "allow Tcp · Internet:* → *:443".to_string()));
        assert_eq!(inbound[2].0, "Default rules");
        assert!(inbound[3].0.starts_with("  65000 AllowVnetInBound"));
        let outbound = nsg_section_lines(&row, NsgDetailSection::Outbound);
        assert_eq!(outbound[0].1, "deny * · *:* → 10.1.0.0/16, 10.2.0.0/16:22, 3389");
        let used = nsg_section_lines(&row, NsgDetailSection::UsedBy);
        assert_eq!(used.len(), 2);
        assert!(row.related().iter().any(|(l, _)| l == "NIC web-1-nic"));
        assert!(row.details().iter().any(|(k, v)| k == "Inbound rules" && v == "1"));
    }
}
