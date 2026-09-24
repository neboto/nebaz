//! The Network service's edge types (issue #3): public IPs, load
//! balancers, route tables and NAT gateways. Each is one subscription-wide
//! list, a sub-tab of Network; `NetworkService` (network.rs) dispatches to
//! the rows here. Before these, the NIC, Subnet and VNet sections listed
//! their ids as copy-only (SERVICES.md rule 3); now they jump.
//!
//! Load-balancer frontends, pools and rules and a route table's routes
//! arrive embedded in the list body: no lazy calls.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::services::{arm_row, json, overview_rows, related_rows, tag_rows, ArmBase};
use serde_json::Value;

pub const PUBLIC_IPS_PATH: &str = "/providers/Microsoft.Network/publicIPAddresses";
pub const LOAD_BALANCERS_PATH: &str = "/providers/Microsoft.Network/loadBalancers";
pub const ROUTE_TABLES_PATH: &str = "/providers/Microsoft.Network/routeTables";
pub const NAT_GATEWAYS_PATH: &str = "/providers/Microsoft.Network/natGateways";

crate::sections! {
    pub enum PublicIpDetailSection,
    pub static PUBLIC_IP_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum LoadBalancerDetailSection,
    pub static LOAD_BALANCER_SECTIONS = [
        Overview "Overview",
        Frontends "Frontends",
        BackendPools "Backend pools",
        Rules "Rules",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum RouteTableDetailSection,
    pub static ROUTE_TABLE_SECTIONS = [
        Overview "Overview",
        Routes "Routes",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum NatGatewayDetailSection,
    pub static NAT_GATEWAY_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

/// The resource that owns a child configuration id: the id minus its last
/// `/{collection}/{name}` pair. An IP configuration
/// (`…/networkInterfaces/nic/ipConfigurations/ipconfig1`) belongs to the
/// NIC; a frontend (`…/loadBalancers/lb/frontendIPConfigurations/fe`) to
/// the load balancer. `None` when the id has no such pair under a
/// provider.
pub fn owner_of(child_id: &str) -> Option<String> {
    let trimmed = child_id.trim_end_matches('/');
    let mut cut = trimmed.rsplitn(3, '/');
    let (_name, _collection, owner) = (cut.next()?, cut.next()?, cut.next()?);
    let lower = owner.to_lowercase();
    let (_, after_provider) = lower.split_once("/providers/")?;
    // `{namespace}/{type}/{name}` at least: the owner is itself a resource.
    (after_provider.split('/').count() >= 3).then(|| owner.to_string())
}

/// Owner ids, deduplicated in first-seen order.
fn owners(child_ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in child_ids.iter().filter_map(|c| owner_of(c)) {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&id)) {
            out.push(id);
        }
    }
    out
}

/// A `Related` label for an id whose type the label should name.
fn kind_label(id: &str) -> &'static str {
    let lower = id.to_lowercase();
    if lower.contains("/networkinterfaces/") {
        "NIC"
    } else if lower.contains("/loadbalancers/") {
        "Load balancer"
    } else if lower.contains("/virtualnetworkgateways/") {
        "VNet gateway"
    } else if lower.contains("/applicationgateways/") {
        "Application gateway"
    } else if lower.contains("/azurefirewalls/") {
        "Firewall"
    } else if lower.contains("/bastionhosts/") {
        "Bastion"
    } else {
        "Attached to"
    }
}

// ── Public IP ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PublicIpRow {
    pub base: ArmBase,
    pub address: Option<String>,
    pub allocation: Option<String>,
    pub version: Option<String>,
    pub sku: Option<String>,
    pub tier: Option<String>,
    pub dns_label: Option<String>,
    pub fqdn: Option<String>,
    pub idle_timeout: Option<i64>,
    pub zones: Vec<String>,
    pub ddos_protection: Option<String>,
    /// The IP configuration it is bound to (NIC, LB frontend, gateway…).
    pub ip_config_id: Option<String>,
    pub nat_gateway_id: Option<String>,
    pub prefix_id: Option<String>,
}

impl PublicIpRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PublicIpRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(PublicIpRow {
            address: json::str_at(v, &format!("{}/ipAddress", p)),
            allocation: json::str_at(v, &format!("{}/publicIPAllocationMethod", p)),
            version: json::str_at(v, &format!("{}/publicIPAddressVersion", p)),
            sku: json::str_at(v, "/sku/name"),
            tier: json::str_at(v, "/sku/tier"),
            dns_label: json::str_at(v, &format!("{}/dnsSettings/domainNameLabel", p)),
            fqdn: json::str_at(v, &format!("{}/dnsSettings/fqdn", p)),
            idle_timeout: json::int_at(v, &format!("{}/idleTimeoutInMinutes", p)),
            zones: json::strings_at(v, "/zones"),
            ddos_protection: json::str_at(v, &format!("{}/ddosSettings/protectionMode", p)),
            ip_config_id: json::arm_id(json::id_at(v, &format!("{}/ipConfiguration", p))),
            nat_gateway_id: json::arm_id(json::id_at(v, &format!("{}/natGateway", p))),
            prefix_id: json::arm_id(json::id_at(v, &format!("{}/publicIPPrefix", p))),
            base,
        })
    }

    /// What it is attached to: the owner of its IP configuration, else the
    /// NAT gateway using it.
    pub fn attached_to(&self) -> Option<String> {
        self.ip_config_id
            .as_deref()
            .and_then(owner_of)
            .or_else(|| self.nat_gateway_id.clone())
    }

    /// Unattached public IPs still bill, so the attachment is the state,
    /// the same shape as a NIC's.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = if self.ip_config_id.is_some() || self.nat_gateway_id.is_some() {
            (ResourceState::Running, "attached")
        } else {
            (ResourceState::Available, "unattached")
        };
        state_ladder(self.base.provisioning_state.as_deref(), Some(runtime))
    }
}

impl Resource for PublicIpRow {
    arm_row!("Public IP");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PUBLIC_IP_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.address.clone()),
            json::opt(self.fqdn.clone()),
            self.attached_to().as_deref().map(name_of_id).unwrap_or(""),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let sku = match (&self.sku, &self.tier) {
            (Some(s), Some(t)) => format!("{} · {}", s, t),
            (s, _) => json::opt(s.clone()),
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Address".into(), json::opt(self.address.clone())),
            ("Allocation".into(), json::opt(self.allocation.clone())),
            ("Version".into(), json::opt(self.version.clone())),
            ("SKU".into(), sku),
            (
                "Attached to".into(),
                self.attached_to()
                    .map(|o| format!("{} {}", kind_label(&o), name_of_id(&o)))
                    .unwrap_or_else(|| "-".into()),
            ),
            ("DNS label".into(), json::opt(self.dns_label.clone())),
            ("FQDN".into(), json::opt(self.fqdn.clone())),
            ("Idle timeout".into(), self.idle_timeout.map(|m| format!("{} min", m)).unwrap_or_else(|| "-".into())),
            ("Zones".into(), json::join(&self.zones)),
            ("DDoS protection".into(), json::opt(self.ddos_protection.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(owner) = self.ip_config_id.as_deref().and_then(owner_of) {
            v.push((format!("{} {}", kind_label(&owner), name_of_id(&owner)), owner));
        }
        if let Some(nat) = &self.nat_gateway_id {
            v.push((format!("NAT gateway {}", name_of_id(nat)), nat.clone()));
        }
        if let Some(prefix) = &self.prefix_id {
            v.push((format!("Prefix {}", name_of_id(prefix)), prefix.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network public-ip show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn public_ip_section_lines(r: &PublicIpRow, section: PublicIpDetailSection) -> Vec<(String, String)> {
    match section {
        PublicIpDetailSection::Overview => overview_rows(r),
        PublicIpDetailSection::Related => related_rows(r),
        PublicIpDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Load balancer ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Frontend {
    pub name: String,
    pub private_ip: Option<String>,
    pub allocation: Option<String>,
    pub subnet_id: Option<String>,
    pub public_ip_id: Option<String>,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BackendPool {
    pub name: String,
    /// NIC IP configurations in the pool (NIC-based pools).
    pub ip_config_ids: Vec<String>,
    /// Addresses in the pool (IP-based pools).
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LoadBalancerRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub tier: Option<String>,
    pub frontends: Vec<Frontend>,
    pub pools: Vec<BackendPool>,
    pub rules: Vec<Value>,
    pub probes: Vec<Value>,
    pub nat_rules: Vec<Value>,
    pub outbound_rules: Vec<Value>,
}

impl LoadBalancerRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<LoadBalancerRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let frontends = json::arr(v, &format!("{}/frontendIPConfigurations", p))
            .iter()
            .map(|f| Frontend {
                name: json::text(f, "/name"),
                private_ip: json::str_at(f, "/properties/privateIPAddress"),
                allocation: json::str_at(f, "/properties/privateIPAllocationMethod"),
                subnet_id: json::arm_id(json::id_at(f, "/properties/subnet")),
                public_ip_id: json::arm_id(json::id_at(f, "/properties/publicIPAddress")),
                zones: json::strings_at(f, "/zones"),
            })
            .collect();
        let pools = json::arr(v, &format!("{}/backendAddressPools", p))
            .iter()
            .map(|b| BackendPool {
                name: json::text(b, "/name"),
                ip_config_ids: json::ids_at(b, "/properties/backendIPConfigurations"),
                addresses: json::arr(b, "/properties/loadBalancerBackendAddresses")
                    .iter()
                    .filter_map(|a| json::str_at(a, "/properties/ipAddress"))
                    .collect(),
            })
            .collect();
        Some(LoadBalancerRow {
            sku: json::str_at(v, "/sku/name"),
            tier: json::str_at(v, "/sku/tier"),
            frontends,
            pools,
            rules: json::arr(v, &format!("{}/loadBalancingRules", p)),
            probes: json::arr(v, &format!("{}/probes", p)),
            nat_rules: json::arr(v, &format!("{}/inboundNatRules", p)),
            outbound_rules: json::arr(v, &format!("{}/outboundRules", p)),
            base,
        })
    }

    fn is_public(&self) -> bool {
        self.frontends.iter().any(|f| f.public_ip_id.is_some())
    }

    /// Every NIC behind any pool, deduplicated.
    fn backend_nics(&self) -> Vec<String> {
        let configs: Vec<String> = self.pools.iter().flat_map(|p| p.ip_config_ids.clone()).collect();
        owners(&configs)
    }
}

/// The name segment of a sub-resource reference, `-` when absent.
fn ref_name(v: &Value, ptr: &str) -> String {
    json::id_at(v, ptr).map(|id| name_of_id(&id).to_string()).unwrap_or_else(|| "-".into())
}

impl Resource for LoadBalancerRow {
    arm_row!("Load Balancer");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&LOAD_BALANCER_SECTIONS)
    }
    fn search_text(&self) -> String {
        let ips: Vec<String> = self.frontends.iter().filter_map(|f| f.private_ip.clone()).collect();
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            if self.is_public() { "public" } else { "internal" },
            ips.join(" "),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let sku = match (&self.sku, &self.tier) {
            (Some(s), Some(t)) => format!("{} · {}", s, t),
            (s, _) => json::opt(s.clone()),
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), sku),
            ("Type".into(), if self.is_public() { "public" } else { "internal" }.into()),
            ("Frontends".into(), self.frontends.len().to_string()),
            ("Backend pools".into(), self.pools.len().to_string()),
            ("Backend NICs".into(), self.backend_nics().len().to_string()),
            ("LB rules".into(), self.rules.len().to_string()),
            ("Probes".into(), self.probes.len().to_string()),
            ("Inbound NAT rules".into(), self.nat_rules.len().to_string()),
            ("Outbound rules".into(), self.outbound_rules.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for f in &self.frontends {
            if let Some(ip) = &f.public_ip_id {
                v.push((format!("Public IP {}", name_of_id(ip)), ip.clone()));
            }
            if let Some(s) = &f.subnet_id {
                v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
            }
        }
        for nic in self.backend_nics() {
            v.push((format!("NIC {}", name_of_id(&nic)), nic));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network lb show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn load_balancer_section_lines(r: &LoadBalancerRow, section: LoadBalancerDetailSection) -> Vec<(String, String)> {
    match section {
        LoadBalancerDetailSection::Overview => overview_rows(r),
        LoadBalancerDetailSection::Frontends => {
            let mut lines = Vec::new();
            if r.frontends.is_empty() {
                lines.push((String::new(), "No frontends".into()));
            }
            for f in &r.frontends {
                lines.push((String::new(), String::new()));
                lines.push((f.name.clone(), String::new()));
                match &f.public_ip_id {
                    Some(ip) => lines.push((format!("  Public IP · {}", name_of_id(ip)), ip.clone())),
                    None => {
                        lines.push((
                            "  Private IP".into(),
                            format!("{} ({})", json::opt(f.private_ip.clone()), json::opt(f.allocation.clone())),
                        ));
                        if let Some(s) = &f.subnet_id {
                            lines.push((format!("  Subnet · {}", name_of_id(s)), s.clone()));
                        }
                    }
                }
                if !f.zones.is_empty() {
                    lines.push(("  Zones".into(), json::join(&f.zones)));
                }
            }
            lines
        }
        LoadBalancerDetailSection::BackendPools => {
            let mut lines = Vec::new();
            if r.pools.is_empty() {
                lines.push((String::new(), "No backend pools".into()));
            }
            for pool in &r.pools {
                lines.push((String::new(), String::new()));
                lines.push((pool.name.clone(), String::new()));
                let nics = owners(&pool.ip_config_ids);
                if nics.is_empty() && pool.addresses.is_empty() {
                    lines.push((String::new(), "· empty".into()));
                }
                for nic in nics {
                    lines.push((format!("  NIC · {}", name_of_id(&nic)), nic));
                }
                if !pool.addresses.is_empty() {
                    lines.push(("  Addresses".into(), json::join(&pool.addresses)));
                }
            }
            lines
        }
        LoadBalancerDetailSection::Rules => rule_lines(r),
        LoadBalancerDetailSection::Related => related_rows(r),
        LoadBalancerDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// LB rules, probes, inbound NAT and outbound rules, each group headed.
fn rule_lines(r: &LoadBalancerRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let p = "/properties";
    lines.push(("Load-balancing rules".into(), String::new()));
    if r.rules.is_empty() {
        lines.push((String::new(), "· none".into()));
    }
    for rule in &r.rules {
        lines.push((
            format!("  {}", json::text(rule, "/name")),
            format!(
                "{} {} → {} · {} → {} · probe {}",
                json::text(rule, &format!("{}/protocol", p)),
                json::text(rule, &format!("{}/frontendPort", p)),
                json::text(rule, &format!("{}/backendPort", p)),
                ref_name(rule, &format!("{}/frontendIPConfiguration", p)),
                ref_name(rule, &format!("{}/backendAddressPool", p)),
                ref_name(rule, &format!("{}/probe", p)),
            ),
        ));
    }
    lines.push((String::new(), String::new()));
    lines.push(("Health probes".into(), String::new()));
    if r.probes.is_empty() {
        lines.push((String::new(), "· none".into()));
    }
    for probe in &r.probes {
        let path = json::str_at(probe, &format!("{}/requestPath", p))
            .map(|s| format!(" {}", s))
            .unwrap_or_default();
        lines.push((
            format!("  {}", json::text(probe, "/name")),
            format!(
                "{} {}{} · every {} s · threshold {}",
                json::text(probe, &format!("{}/protocol", p)),
                json::text(probe, &format!("{}/port", p)),
                path,
                json::text(probe, &format!("{}/intervalInSeconds", p)),
                json::str_at(probe, &format!("{}/probeThreshold", p))
                    .or_else(|| json::str_at(probe, &format!("{}/numberOfProbes", p)))
                    .unwrap_or_else(|| "-".into()),
            ),
        ));
    }
    if !r.nat_rules.is_empty() {
        lines.push((String::new(), String::new()));
        lines.push(("Inbound NAT rules".into(), String::new()));
        for rule in &r.nat_rules {
            let frontend_port = match (
                json::str_at(rule, &format!("{}/frontendPortRangeStart", p)),
                json::str_at(rule, &format!("{}/frontendPortRangeEnd", p)),
            ) {
                (Some(a), Some(b)) => format!("{}-{}", a, b),
                _ => json::text(rule, &format!("{}/frontendPort", p)),
            };
            lines.push((
                format!("  {}", json::text(rule, "/name")),
                format!(
                    "{} {} → {}",
                    json::text(rule, &format!("{}/protocol", p)),
                    frontend_port,
                    json::text(rule, &format!("{}/backendPort", p)),
                ),
            ));
        }
    }
    if !r.outbound_rules.is_empty() {
        lines.push((String::new(), String::new()));
        lines.push(("Outbound rules".into(), String::new()));
        for rule in &r.outbound_rules {
            lines.push((
                format!("  {}", json::text(rule, "/name")),
                format!(
                    "{} · pool {} · {} ports",
                    json::text(rule, &format!("{}/protocol", p)),
                    ref_name(rule, &format!("{}/backendAddressPool", p)),
                    json::text(rule, &format!("{}/allocatedOutboundPorts", p)),
                ),
            ));
        }
    }
    lines
}

// ── Route table ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Route {
    pub name: String,
    pub prefix: String,
    pub next_hop_type: String,
    pub next_hop_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RouteTableRow {
    pub base: ArmBase,
    pub routes: Vec<Route>,
    pub subnet_ids: Vec<String>,
    pub bgp_propagation_disabled: Option<bool>,
}

impl RouteTableRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<RouteTableRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(RouteTableRow {
            routes: json::arr(v, &format!("{}/routes", p))
                .iter()
                .map(|r| Route {
                    name: json::text(r, "/name"),
                    prefix: json::text(r, "/properties/addressPrefix"),
                    next_hop_type: json::text(r, "/properties/nextHopType"),
                    next_hop_ip: json::str_at(r, "/properties/nextHopIpAddress"),
                })
                .collect(),
            subnet_ids: json::ids_at(v, &format!("{}/subnets", p)),
            bgp_propagation_disabled: json::bool_at(v, &format!("{}/disableBgpRoutePropagation", p)),
            base,
        })
    }
}

impl Resource for RouteTableRow {
    arm_row!("Route Table");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ROUTE_TABLE_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        let bgp = match self.bgp_propagation_disabled {
            Some(true) => "disabled",
            Some(false) => "enabled",
            None => "-",
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Routes".into(), self.routes.len().to_string()),
            ("Subnets".into(), self.subnet_ids.len().to_string()),
            ("BGP route propagation".into(), bgp.into()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in &self.subnet_ids {
            v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network route-table show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn route_table_section_lines(r: &RouteTableRow, section: RouteTableDetailSection) -> Vec<(String, String)> {
    match section {
        RouteTableDetailSection::Overview => overview_rows(r),
        RouteTableDetailSection::Routes => {
            if r.routes.is_empty() {
                return vec![(String::new(), "No user routes (system routes apply)".into())];
            }
            r.routes
                .iter()
                .map(|rt| {
                    let hop = match &rt.next_hop_ip {
                        Some(ip) => format!("{} {}", rt.next_hop_type, ip),
                        None => rt.next_hop_type.clone(),
                    };
                    (rt.name.clone(), format!("{} → {}", rt.prefix, hop))
                })
                .collect()
        }
        RouteTableDetailSection::Related => related_rows(r),
        RouteTableDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── NAT gateway ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NatGatewayRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub idle_timeout: Option<i64>,
    pub zones: Vec<String>,
    pub public_ip_ids: Vec<String>,
    pub prefix_ids: Vec<String>,
    pub subnet_ids: Vec<String>,
}

impl NatGatewayRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<NatGatewayRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        // The v4 and v6 lists are separate arrays; nebaz shows them together.
        let both = |a: &str, b: &str| -> Vec<String> {
            let mut ids = json::ids_at(v, &format!("{}/{}", p, a));
            ids.extend(json::ids_at(v, &format!("{}/{}", p, b)));
            ids
        };
        Some(NatGatewayRow {
            sku: json::str_at(v, "/sku/name"),
            idle_timeout: json::int_at(v, &format!("{}/idleTimeoutInMinutes", p)),
            zones: json::strings_at(v, "/zones"),
            public_ip_ids: both("publicIpAddresses", "publicIpAddressesV6"),
            prefix_ids: both("publicIpPrefixes", "publicIpPrefixesV6"),
            subnet_ids: json::ids_at(v, &format!("{}/subnets", p)),
            base,
        })
    }
}

impl Resource for NatGatewayRow {
    arm_row!("NAT Gateway");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&NAT_GATEWAY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Idle timeout".into(), self.idle_timeout.map(|m| format!("{} min", m)).unwrap_or_else(|| "-".into())),
            ("Zones".into(), json::join(&self.zones)),
            ("Public IPs".into(), self.public_ip_ids.len().to_string()),
            ("Public IP prefixes".into(), self.prefix_ids.len().to_string()),
            ("Subnets".into(), self.subnet_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for ip in &self.public_ip_ids {
            v.push((format!("Public IP {}", name_of_id(ip)), ip.clone()));
        }
        for prefix in &self.prefix_ids {
            v.push((format!("Prefix {}", name_of_id(prefix)), prefix.clone()));
        }
        for s in &self.subnet_ids {
            v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network nat gateway show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn nat_gateway_section_lines(r: &NatGatewayRow, section: NatGatewayDetailSection) -> Vec<(String, String)> {
    match section {
        NatGatewayDetailSection::Overview => overview_rows(r),
        NatGatewayDetailSection::Related => related_rows(r),
        NatGatewayDetailSection::Tags => tag_rows(r.tags()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-net";

    fn id(t: &str) -> String {
        format!("{}/providers/Microsoft.Network/{}", RG, t)
    }

    #[test]
    fn owner_of_strips_the_child_configuration() {
        assert_eq!(owner_of(&id("networkInterfaces/nic-1/ipConfigurations/ipconfig1")), Some(id("networkInterfaces/nic-1")));
        assert_eq!(owner_of(&id("loadBalancers/lb/frontendIPConfigurations/fe")), Some(id("loadBalancers/lb")));
        // A top-level resource has no owner under a provider.
        assert_eq!(owner_of(&id("publicIPAddresses/ip")), None);
        assert_eq!(owner_of("/subscriptions/0000/resourceGroups/rg"), None);
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for desc in [&PUBLIC_IP_SECTIONS, &LOAD_BALANCER_SECTIONS, &ROUTE_TABLE_SECTIONS, &NAT_GATEWAY_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(labels[labels.len() - 2], "Related");
            assert_eq!(labels.last(), Some(&"Tags"));
        }
    }

    #[test]
    fn public_ip_state_is_its_attachment() {
        let mut v = serde_json::json!({
            "id": id("publicIPAddresses/web-pip"),
            "name": "web-pip",
            "location": "westeurope",
            "sku": {"name": "Standard", "tier": "Regional"},
            "zones": ["1", "2", "3"],
            "properties": {
                "provisioningState": "Succeeded",
                "ipAddress": "20.1.2.3",
                "publicIPAllocationMethod": "Static",
                "publicIPAddressVersion": "IPv4",
                "dnsSettings": {"domainNameLabel": "web", "fqdn": "web.westeurope.cloudapp.azure.com"},
                "ipConfiguration": {"id": id("networkInterfaces/web-1/ipConfigurations/ipconfig1")}
            }
        });
        let row = PublicIpRow::from_json(&v, None).unwrap();
        assert_eq!(row.state_label(), "attached");
        assert_eq!(row.state(), ResourceState::Running);
        assert!(row.details().iter().any(|(k, val)| k == "Attached to" && val == "NIC web-1"));
        assert!(row.details().iter().any(|(k, val)| k == "SKU" && val == "Standard · Regional"));
        assert!(row.related().iter().any(|(l, target)| l == "NIC web-1" && *target == id("networkInterfaces/web-1")));
        assert!(row.cli_command().unwrap().starts_with("az network public-ip show --ids "));

        v["properties"].as_object_mut().unwrap().remove("ipConfiguration");
        let orphan = PublicIpRow::from_json(&v, None).unwrap();
        assert_eq!(orphan.state_label(), "unattached");
        assert_eq!(orphan.state(), ResourceState::Available);

        v["properties"]["natGateway"] = serde_json::json!({"id": id("natGateways/nat-1")});
        let nat = PublicIpRow::from_json(&v, None).unwrap();
        assert_eq!(nat.state_label(), "attached");
        assert!(nat.related().iter().any(|(l, _)| l == "NAT gateway nat-1"));
    }

    fn lb_json() -> Value {
        let lb = id("loadBalancers/lb-web");
        serde_json::json!({
            "id": lb,
            "name": "lb-web",
            "location": "westeurope",
            "sku": {"name": "Standard", "tier": "Regional"},
            "properties": {
                "provisioningState": "Succeeded",
                "frontendIPConfigurations": [
                    {"id": format!("{}/frontendIPConfigurations/fe-public", lb), "name": "fe-public",
                     "properties": {"publicIPAddress": {"id": id("publicIPAddresses/lb-pip")}}},
                    {"id": format!("{}/frontendIPConfigurations/fe-internal", lb), "name": "fe-internal",
                     "properties": {"privateIPAddress": "10.0.1.10", "privateIPAllocationMethod": "Static",
                                    "subnet": {"id": id("virtualNetworks/v/subnets/app")}}}
                ],
                "backendAddressPools": [
                    {"name": "web", "properties": {"backendIPConfigurations": [
                        {"id": id("networkInterfaces/web-1/ipConfigurations/ipconfig1")},
                        {"id": id("networkInterfaces/web-2/ipConfigurations/ipconfig1")},
                        {"id": id("networkInterfaces/web-2/ipConfigurations/ipconfig2")}
                    ]}},
                    {"name": "empty", "properties": {}}
                ],
                "loadBalancingRules": [
                    {"name": "https", "properties": {"protocol": "Tcp", "frontendPort": 443, "backendPort": 8443,
                        "frontendIPConfiguration": {"id": format!("{}/frontendIPConfigurations/fe-public", lb)},
                        "backendAddressPool": {"id": format!("{}/backendAddressPools/web", lb)},
                        "probe": {"id": format!("{}/probes/hp", lb)}}}
                ],
                "probes": [{"name": "hp", "properties": {"protocol": "Http", "port": 8443, "requestPath": "/health",
                    "intervalInSeconds": 5, "probeThreshold": 2}}],
                "inboundNatRules": [{"name": "ssh", "properties": {"protocol": "Tcp", "frontendPortRangeStart": 50000,
                    "frontendPortRangeEnd": 50099, "backendPort": 22}}]
            }
        })
    }

    #[test]
    fn load_balancer_sections_read_frontends_pools_and_rules() {
        let row = LoadBalancerRow::from_json(&lb_json(), None).unwrap();
        assert!(row.details().iter().any(|(k, v)| k == "Type" && v == "public"));
        assert!(row.details().iter().any(|(k, v)| k == "Backend NICs" && v == "2"));

        let fe = load_balancer_section_lines(&row, LoadBalancerDetailSection::Frontends);
        assert!(fe.iter().any(|(k, v)| k == "  Public IP · lb-pip" && *v == id("publicIPAddresses/lb-pip")));
        assert!(fe.iter().any(|(k, v)| k == "  Private IP" && v == "10.0.1.10 (Static)"));

        let pools = load_balancer_section_lines(&row, LoadBalancerDetailSection::BackendPools);
        let nics: Vec<&str> = pools.iter().filter(|(k, _)| k.starts_with("  NIC · ")).map(|(k, _)| k.as_str()).collect();
        assert_eq!(nics, ["  NIC · web-1", "  NIC · web-2"], "two configs on web-2 are one NIC");
        assert!(pools.iter().any(|(_, v)| v == "· empty"));

        let rules = load_balancer_section_lines(&row, LoadBalancerDetailSection::Rules);
        assert!(rules.iter().any(|(k, v)| k == "  https" && v == "Tcp 443 → 8443 · fe-public → web · probe hp"));
        assert!(rules.iter().any(|(k, v)| k == "  hp" && v == "Http 8443 /health · every 5 s · threshold 2"));
        assert!(rules.iter().any(|(k, v)| k == "  ssh" && v == "Tcp 50000-50099 → 22"));
        assert!(!rules.iter().any(|(k, _)| k == "Outbound rules"), "absent groups are omitted");

        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Public IP lb-pip", "Subnet app", "NIC web-1", "NIC web-2"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
    }

    #[test]
    fn route_table_and_nat_gateway_rows() {
        let rt = RouteTableRow::from_json(
            &serde_json::json!({
                "id": id("routeTables/rt-hub"),
                "name": "rt-hub",
                "location": "westeurope",
                "properties": {
                    "disableBgpRoutePropagation": true,
                    "routes": [
                        {"name": "to-fw", "properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.0.4"}},
                        {"name": "local", "properties": {"addressPrefix": "10.1.0.0/16", "nextHopType": "VnetLocal"}}
                    ],
                    "subnets": [{"id": id("virtualNetworks/v/subnets/app")}]
                }
            }),
            None,
        )
        .unwrap();
        let routes = route_table_section_lines(&rt, RouteTableDetailSection::Routes);
        assert_eq!(routes[0], ("to-fw".to_string(), "0.0.0.0/0 → VirtualAppliance 10.0.0.4".to_string()));
        assert_eq!(routes[1].1, "10.1.0.0/16 → VnetLocal");
        assert!(rt.details().iter().any(|(k, v)| k == "BGP route propagation" && v == "disabled"));
        assert!(rt.related().iter().any(|(l, _)| l == "Subnet app"));
        assert!(rt.cli_command().unwrap().starts_with("az network route-table show --ids "));

        let nat = NatGatewayRow::from_json(
            &serde_json::json!({
                "id": id("natGateways/nat-1"),
                "name": "nat-1",
                "location": "westeurope",
                "sku": {"name": "Standard"},
                "properties": {
                    "idleTimeoutInMinutes": 4,
                    "publicIpAddresses": [{"id": id("publicIPAddresses/nat-pip")}],
                    "publicIpPrefixesV6": [{"id": id("publicIPPrefixes/v6")}],
                    "subnets": [{"id": id("virtualNetworks/v/subnets/app")}]
                }
            }),
            None,
        )
        .unwrap();
        let related: Vec<String> = nat.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Public IP nat-pip", "Prefix v6", "Subnet app"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
        assert!(nat.details().iter().any(|(k, v)| k == "Idle timeout" && v == "4 min"));
        assert!(nat.cli_command().unwrap().starts_with("az network nat gateway show --ids "));
    }
}
