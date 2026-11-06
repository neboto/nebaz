//! The Virtual WAN service (issue #158): the hub of most CAF landing
//! zones. Virtual WANs (`Microsoft.Network/virtualWans`), virtual hubs
//! (`virtualHubs`, Azure Route Servers among them: `kind` RouteServer),
//! the hub gateways (site-to-site `vpnGateways`, `expressRouteGateways`,
//! point-to-site `p2sVpnGateways`) and the VPN sites (`vpnSites`, the
//! branches). Its own tab beside Hybrid (SERVICES.md rule 35): six more
//! sub-tabs there would pass the digit keys, and a vWAN estate is
//! debugged hub first.
//!
//! **One subscription-wide list each.** A hub's VNet connections, its
//! route tables and its routing intent are lazy sections (one list per
//! hub, on entering the section). A gateway's connections are on its own
//! body: the site-to-site gateway's `connections[]` (with each link), the
//! ExpressRoute gateway's `expressRouteConnections[]`. A WAN's Hubs and a
//! VPN site's Connections are matched in the warm Hubs and VPN gateways
//! lists, loaded for the section when their sub-tab has not been opened.
//!
//! **Secrets never.** A connection's and a link connection's `sharedKey`,
//! an ExpressRoute connection's `authorizationKey`, a site's `siteKey` and
//! any RADIUS secret are stripped before a row keeps its JSON (Hybrid's
//! [`without_secrets`]); the `sharedKeys` reads are never sent. Effective,
//! inbound and outbound routes, BGP learned and advertised routes, P2S
//! connection health and the VPN configuration download are `POST`s: the
//! `C` catalogue copies the commands, nebaz never sends them.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::edge::top_level_of;
use crate::azure::services::governance::Warm;
use crate::azure::services::hybrid::{bandwidth, bytes, without_secrets};
use crate::azure::services::network::NETWORK_API_VERSION;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// Every Virtual WAN type is Microsoft.Network: the Network service's version.
pub const VWAN_API_VERSION: &str = NETWORK_API_VERSION;

const WANS_PATH: &str = "/providers/Microsoft.Network/virtualWans";
const HUBS_PATH: &str = "/providers/Microsoft.Network/virtualHubs";
const VPN_GATEWAYS_PATH: &str = "/providers/Microsoft.Network/vpnGateways";
const ER_GATEWAYS_PATH: &str = "/providers/Microsoft.Network/expressRouteGateways";
const P2S_GATEWAYS_PATH: &str = "/providers/Microsoft.Network/p2svpnGateways";
const VPN_SITES_PATH: &str = "/providers/Microsoft.Network/vpnSites";

crate::sections! {
    pub enum VirtualWanDetailSection,
    pub static VIRTUAL_WAN_SECTIONS = [
        Overview "Overview",
        Wan "WAN",
        Hubs "Hubs" => crate::app::App::trigger_vwan_hubs,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum VirtualHubDetailSection,
    pub static VIRTUAL_HUB_SECTIONS = [
        Overview "Overview",
        Hub "Hub",
        Gateways "Gateways",
        Connections "Connections" => crate::app::App::trigger_hub_connections,
        Routing "Routing" => crate::app::App::trigger_hub_routing,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_hub_connections,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum VwanVpnGatewayDetailSection,
    pub static VWAN_VPN_GATEWAY_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration",
        Connections "Connections",
        NatRules "NAT rules",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum VwanErGatewayDetailSection,
    pub static VWAN_ER_GATEWAY_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration",
        Connections "Connections",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum P2sGatewayDetailSection,
    pub static P2S_GATEWAY_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration",
        Clients "Clients",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum VpnSiteDetailSection,
    pub static VPN_SITE_SECTIONS = [
        Overview "Overview",
        Site "Site",
        Links "Links",
        Connections "Connections" => crate::app::App::trigger_vwan_vpn_gateways,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_vwan_vpn_gateways,
        Tags "Tags",
    ]
}

// ── Small shared readers ──────────────────────────────────────────────

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn push_unique(v: &mut Vec<(String, String)>, label: String, id: String) {
    if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&id)) {
        v.push((label, id));
    }
}

/// `{hub}/{child}`: a hub's child list.
pub fn hub_child_path(hub_id: &str, child: &str) -> String {
    format!("{}/{}", hub_id.trim_end_matches('/'), child)
}

/// The hub a VNet peering's remote VNet stands for: Virtual WAN connects
/// a VNet by peering it with the hub's managed VNet, named
/// `HV_{hub}_{guid}` in a Microsoft subscription nobody can read.
pub fn managed_hub_name(vnet_name: &str) -> Option<&str> {
    let rest = vnet_name.strip_prefix("HV_").or_else(|| vnet_name.strip_prefix("hv_"))?;
    // `_` then a 36-character GUID.
    let cut = rest.len().checked_sub(37)?;
    let (hub, guid) = rest.split_at(cut);
    let guid = guid.strip_prefix('_')?;
    let well_formed = guid.len() == 36 && guid.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    (well_formed && !hub.is_empty()).then_some(hub)
}

/// A count as words: `1 hub`, `3 hubs`.
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", n, if n == 1 { one } else { many })
}

/// A connection's routing configuration, the lines every hub connection
/// shape shares (VNet, site-to-site, ExpressRoute, P2S): the route table
/// it associates with and the tables and labels it propagates to.
fn routing_rows(v: &Value, indent: &str) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let rc = "/properties/routingConfiguration";
    if let Some(id) = json::arm_id(json::id_at(v, &format!("{}/associatedRouteTable", rc))) {
        lines.push((format!("{}Associated route table · {}", indent, name_of_id(&id)), id));
    }
    let mut to: Vec<String> = json::ids_at(v, &format!("{}/propagatedRouteTables/ids", rc))
        .iter()
        .map(|id| name_of_id(id).to_string())
        .collect();
    to.extend(json::strings_at(v, &format!("{}/propagatedRouteTables/labels", rc)).into_iter().map(|l| format!("label {}", l)));
    if !to.is_empty() {
        lines.push((format!("{}Propagates to", indent), to.join(", ")));
    }
    lines
}

/// A connection status with a flag when it is down.
fn status_word(s: Option<String>) -> String {
    match s {
        Some(s) if same(&s, "NotConnected") => format!("⚠ {}", s),
        other => json::opt(other),
    }
}

// ── Virtual WAN ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VirtualWanRow {
    pub base: ArmBase,
    /// `Basic` or `Standard` (`properties.type`).
    pub wan_type: Option<String>,
    pub allow_branch_to_branch: Option<bool>,
    pub allow_vnet_to_vnet: Option<bool>,
    pub disable_vpn_encryption: Option<bool>,
    pub office365_category: Option<String>,
    pub hub_ids: Vec<String>,
    pub site_ids: Vec<String>,
}

impl VirtualWanRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VirtualWanRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(VirtualWanRow {
            wan_type: json::str_at(v, &p("type")),
            allow_branch_to_branch: json::bool_at(v, &p("allowBranchToBranchTraffic")),
            allow_vnet_to_vnet: json::bool_at(v, &p("allowVnetToVnetTraffic")),
            disable_vpn_encryption: json::bool_at(v, &p("disableVpnEncryption")),
            office365_category: json::str_at(v, &p("office365LocalBreakoutCategory")),
            hub_ids: json::ids_at(v, &p("virtualHubs")),
            site_ids: json::ids_at(v, &p("vpnSites")),
            base,
        })
    }

    fn is_basic(&self) -> bool {
        self.wan_type.as_deref().is_some_and(|t| same(t, "basic"))
    }

    pub fn wan_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Type".into(), json::opt(self.wan_type.clone()))];
        if self.is_basic() {
            lines.push((
                String::new(),
                "· a Basic WAN has site-to-site VPN only: no ExpressRoute, point-to-site, VNet-to-VNet transit through the hub or hub-to-hub".into(),
            ));
        }
        lines.push(("Branch-to-branch".into(), json::yes_no(self.allow_branch_to_branch)));
        lines.push(("VNet-to-VNet".into(), json::yes_no(self.allow_vnet_to_vnet)));
        lines.push(("VPN encryption".into(), json::yes_no(self.disable_vpn_encryption.map(|d| !d))));
        lines.push(("Office 365 breakout".into(), json::opt(self.office365_category.clone())));
        lines.push(("Hubs".into(), self.hub_ids.len().to_string()));
        lines.push(("VPN sites".into(), self.site_ids.len().to_string()));
        lines
    }

    /// The WAN's hubs, from its own list of ids, filled in from the warm
    /// Hubs list (region, address prefix, routing state).
    pub fn hub_rows(&self, hubs: Warm) -> Vec<(String, String)> {
        if self.hub_ids.is_empty() {
            return vec![(String::new(), "No hubs".into())];
        }
        let warm = hubs.rows();
        let mut lines = Vec::new();
        for id in &self.hub_ids {
            let hub = warm.and_then(|w| {
                w.iter().filter_map(|r| r.as_any().downcast_ref::<VirtualHubRow>()).find(|h| same(&h.base.id, id))
            });
            match hub {
                Some(h) => {
                    lines.push((format!("Hub · {}", h.base.name), h.base.id.clone()));
                    lines.push(("  Region".into(), h.base.location.clone()));
                    lines.push(("  Address prefix".into(), json::opt(h.address_prefix.clone())));
                    lines.push(("  Routing state".into(), json::opt(h.routing_state.clone())));
                    lines.push(("  Secured".into(), h.secured_label()));
                }
                None => lines.push((format!("Hub · {}", name_of_id(id)), id.clone())),
            }
        }
        if warm.is_none() {
            lines.push((String::new(), String::new()));
            lines.extend(hubs.waiting("Hubs (@hub)"));
        }
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for h in &self.hub_ids {
            push_unique(&mut v, format!("Hub · {}", name_of_id(h)), h.clone());
        }
        for s in &self.site_ids {
            push_unique(&mut v, format!("VPN site · {}", name_of_id(s)), s.clone());
        }
        v
    }
}

impl Resource for VirtualWanRow {
    arm_row!("Virtual WAN");
    /// `Standard · 2 hubs · 3 VPN sites`.
    fn list_summary(&self) -> Option<String> {
        Some(format!(
            "{} · {} · {}",
            self.wan_type.as_deref().unwrap_or("-"),
            count(self.hub_ids.len(), "hub", "hubs"),
            count(self.site_ids.len(), "VPN site", "VPN sites")
        ))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VIRTUAL_WAN_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Type".into(), json::opt(self.wan_type.clone())),
            ("Hubs".into(), self.hub_ids.len().to_string()),
            ("VPN sites".into(), self.site_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        VirtualWanRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vwan show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Virtual hub ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VirtualHubRow {
    pub base: ArmBase,
    /// Top-level `kind`: empty for a WAN hub, `RouteServer` for an Azure
    /// Route Server (a hub with no WAN).
    pub kind: Option<String>,
    pub wan_id: Option<String>,
    pub address_prefix: Option<String>,
    pub sku: Option<String>,
    /// `None`, `Provisioned`, `Provisioning`, `Failed`: the hub router.
    pub routing_state: Option<String>,
    pub router_asn: Option<i64>,
    pub router_ips: Vec<String>,
    /// Routing infrastructure units; Azure's default is 2.
    pub router_min_capacity: Option<i64>,
    /// `ExpressRoute`, `VpnGateway`, `ASPath`.
    pub routing_preference: Option<String>,
    pub allow_branch_to_branch: Option<bool>,
    pub vpn_gateway_id: Option<String>,
    pub er_gateway_id: Option<String>,
    pub p2s_gateway_id: Option<String>,
    pub firewall_id: Option<String>,
    pub security_partner_id: Option<String>,
    pub security_provider: Option<String>,
}

impl VirtualHubRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VirtualHubRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let id = |k: &str| json::arm_id(json::id_at(v, &p(k)));
        Some(VirtualHubRow {
            kind: json::str_at(v, "/kind").filter(|k| !k.is_empty()),
            wan_id: id("virtualWan"),
            address_prefix: json::str_at(v, &p("addressPrefix")),
            sku: json::str_at(v, &p("sku")),
            routing_state: json::str_at(v, &p("routingState")),
            router_asn: json::int_at(v, &p("virtualRouterAsn")),
            router_ips: json::strings_at(v, &p("virtualRouterIps")),
            router_min_capacity: json::int_at(v, &p("virtualRouterAutoScaleConfiguration/minCapacity")),
            routing_preference: json::str_at(v, &p("hubRoutingPreference")),
            allow_branch_to_branch: json::bool_at(v, &p("allowBranchToBranchTraffic")),
            vpn_gateway_id: id("vpnGateway"),
            er_gateway_id: id("expressRouteGateway"),
            p2s_gateway_id: id("p2SVpnGateway"),
            firewall_id: id("azureFirewall"),
            security_partner_id: id("securityPartnerProvider"),
            security_provider: json::str_at(v, &p("securityProviderName")),
            base,
        })
    }

    pub fn is_route_server(&self) -> bool {
        self.kind.as_deref().is_some_and(|k| same(k, "RouteServer"))
    }

    /// Provisioning first, then the hub router: a hub whose router is not
    /// provisioned routes nothing.
    pub fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.routing_state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "provisioned" => ResourceState::Available,
                "failed" => ResourceState::Unavailable,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// `Azure Firewall afw-…`, `Zscaler (partner)`, or `no`.
    pub fn secured_label(&self) -> String {
        if let Some(fw) = &self.firewall_id {
            return format!("Azure Firewall {}", name_of_id(fw));
        }
        if let Some(p) = &self.security_provider {
            return format!("{} (security partner)", p);
        }
        "no".into()
    }

    /// The routing infrastructure units and what they carry, from Azure's
    /// sizing: 2 units (the default) carry 3 Gbps and 2,000 VMs across
    /// the hub's connected VNets, each unit above that 1 Gbps and 1,000 VMs.
    fn capacity_label(&self) -> String {
        let units = self.router_min_capacity.unwrap_or(2).max(2);
        let extra = units - 2;
        let default = if self.router_min_capacity.is_none() { " (the default)" } else { "" };
        format!("{} units{} · ≈{} Gbps, ≈{} VMs", units, default, 3 + extra, (2 + extra) * 1000)
    }

    pub fn hub_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.is_route_server() {
            lines.push(("Kind".into(), "Azure Route Server (a virtual hub with no WAN)".into()));
        } else if let Some(w) = &self.wan_id {
            lines.push((format!("WAN · {}", name_of_id(w)), w.clone()));
        }
        lines.push(("Address prefix".into(), json::opt(self.address_prefix.clone())));
        lines.push(("SKU".into(), json::opt(self.sku.clone())));
        lines.push(("Routing state".into(), json::opt(self.routing_state.clone())));
        if self.routing_state.as_deref().is_some_and(|s| same(s, "failed")) {
            lines.push((String::new(), "⚠ the hub router failed to provision: the hub routes nothing until it is reset".into()));
        }
        lines.push(("Router ASN".into(), json::num(self.router_asn)));
        lines.push(("Router IPs".into(), json::join(&self.router_ips)));
        lines.push(("Routing capacity".into(), self.capacity_label()));
        if !self.is_route_server() {
            lines.push(("Routing preference".into(), json::opt(self.routing_preference.clone())));
            lines.push(("Branch-to-branch".into(), json::yes_no(self.allow_branch_to_branch)));
            lines.push(("Secured".into(), self.secured_label()));
        }
        lines
    }

    fn gateway_ids(&self) -> Vec<(&'static str, &String)> {
        [
            ("VPN gateway", &self.vpn_gateway_id),
            ("ExpressRoute gateway", &self.er_gateway_id),
            ("P2S gateway", &self.p2s_gateway_id),
            ("Azure Firewall", &self.firewall_id),
            ("Security partner", &self.security_partner_id),
        ]
        .into_iter()
        .filter_map(|(label, id)| id.as_ref().map(|i| (label, i)))
        .collect()
    }

    pub fn gateway_rows(&self) -> Vec<(String, String)> {
        let found = self.gateway_ids();
        if found.is_empty() {
            let why = if self.is_route_server() { "a Route Server has none" } else { "No gateways or firewall in this hub" };
            return vec![(String::new(), why.into())];
        }
        found.into_iter().map(|(label, id)| (format!("{} · {}", label, name_of_id(id)), id.clone())).collect()
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(w) = &self.wan_id {
            push_unique(&mut v, format!("WAN · {}", name_of_id(w)), w.clone());
        }
        for (label, id) in self.gateway_ids() {
            push_unique(&mut v, format!("{} · {}", label, name_of_id(id)), id.clone());
        }
        v
    }
}

impl Resource for VirtualHubRow {
    arm_row!("Virtual hub");
    /// `10.100.0.0/23 · Standard · secured` or `Route Server · ASN 65515`.
    fn list_summary(&self) -> Option<String> {
        if self.is_route_server() {
            return Some(format!("Route Server · ASN {}", json::num(self.router_asn)));
        }
        let mut s = format!("{} · {}", self.address_prefix.as_deref().unwrap_or("-"), self.sku.as_deref().unwrap_or("-"));
        if self.firewall_id.is_some() || self.security_provider.is_some() {
            s.push_str(" · secured");
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VIRTUAL_HUB_SECTIONS)
    }
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            self.address_prefix.clone().unwrap_or_default(),
            self.kind.clone().unwrap_or_default(),
        ];
        parts.extend(self.router_ips.iter().cloned());
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("WAN".into(), self.wan_id.as_deref().map(|w| name_of_id(w).to_string()).unwrap_or_else(|| "-".into())),
            ("Address prefix".into(), json::opt(self.address_prefix.clone())),
            ("Routing state".into(), json::opt(self.routing_state.clone())),
            ("Secured".into(), self.secured_label()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        VirtualHubRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vhub show --ids {}", shell_quote(&self.base.id)))
    }
}

/// A hub's Connections section: each VNet it connects, with transit,
/// internet security, the routing configuration and static routes.
pub fn hub_connection_rows(lazy: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(lazy, "Connections", |items| {
        if items.is_empty() {
            return vec![(String::new(), "No VNet connections".into())];
        }
        let mut lines = Vec::new();
        for (i, c) in items.iter().enumerate() {
            if i > 0 {
                lines.push((String::new(), String::new()));
            }
            let q = |k: &str| format!("/properties/{}", k);
            match json::arm_id(json::id_at(c, &q("remoteVirtualNetwork"))) {
                Some(vnet) => lines.push((format!("{} · VNet {}", json::text(c, "/name"), name_of_id(&vnet)), vnet)),
                None => lines.push((json::text(c, "/name"), "-".into())),
            }
            lines.push(("  State".into(), json::text(c, &q("provisioningState")).to_lowercase()));
            lines.push(("  Internet security".into(), json::yes_no(json::bool_at(c, &q("enableInternetSecurity")))));
            lines.push(("  Hub-to-VNet transit".into(), json::yes_no(json::bool_at(c, &q("allowHubToRemoteVnetTransit")))));
            lines.push((
                "  VNet uses hub gateways".into(),
                json::yes_no(json::bool_at(c, &q("allowRemoteVnetToUseHubVnetGateways"))),
            ));
            lines.extend(routing_rows(c, "  "));
            for r in json::arr(c, &q("routingConfiguration/vnetRoutes/staticRoutes")) {
                lines.push((
                    format!("  Static route {}", json::text(&r, "/name")),
                    format!("{} → {}", list_or_dash(&r, "/addressPrefixes"), json::text(&r, "/nextHopIpAddress")),
                ));
            }
        }
        lines
    })
}

fn list_or_dash(v: &Value, ptr: &str) -> String {
    json::join(&json::strings_at(v, ptr))
}

/// A hub's Routing section: the routing intent (what a secured hub sends
/// through its firewall), then each route table with its routes.
pub fn hub_routing_rows(intent: Option<&Lazy<Vec<Value>>>, tables: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    let mut lines = vec![("━━ Routing intent".into(), String::new())];
    lines.extend(lazy_list_rows(intent, "Routing intent", |items| {
        let policies: Vec<Value> = items.iter().flat_map(|i| json::arr(i, "/properties/routingPolicies")).collect();
        if policies.is_empty() {
            return vec![(String::new(), "None: the hub routes by its route tables alone".into())];
        }
        policies
            .iter()
            .map(|p| {
                let what = format!("{} ({})", json::text(p, "/name"), list_or_dash(p, "/destinations"));
                match json::str_at(p, "/nextHop").filter(|h| h.starts_with("/subscriptions/")) {
                    Some(hop) => (format!("{} → {}", what, name_of_id(&hop)), hop),
                    None => (what, json::text(p, "/nextHop")),
                }
            })
            .collect()
    }));
    lines.push((String::new(), String::new()));
    lines.push(("━━ Route tables".into(), String::new()));
    lines.extend(lazy_list_rows(tables, "Route tables", |items| {
        if items.is_empty() {
            return vec![(String::new(), "No route tables".into())];
        }
        let mut out = Vec::new();
        for t in items {
            let q = |k: &str| format!("/properties/{}", k);
            let labels = json::strings_at(t, &q("labels"));
            let label = if labels.is_empty() { String::new() } else { format!(" · labels {}", labels.join(", ")) };
            out.push((format!("{}{}", json::text(t, "/name"), label), json::text(t, "/id")));
            let routes = json::arr(t, &q("routes"));
            if routes.is_empty() {
                out.push(("  Routes".into(), "none".into()));
            }
            for r in routes {
                let to = format!("  {} · {}", json::text(&r, "/name"), list_or_dash(&r, "/destinations"));
                match json::str_at(&r, "/nextHop").filter(|h| h.starts_with("/subscriptions/")) {
                    Some(hop) => out.push((format!("{} → {}", to, name_of_id(&hop)), hop)),
                    None => out.push((to, format!("→ {}", json::text(&r, "/nextHop")))),
                }
            }
            out.push((
                "  Associated · propagating".into(),
                format!(
                    "{} · {}",
                    count(json::arr(t, &q("associatedConnections")).len(), "connection", "connections"),
                    count(json::arr(t, &q("propagatingConnections")).len(), "connection", "connections")
                ),
            ));
        }
        out
    }));
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "· the hub's effective routes are a POST: C copies `az network vhub get-effective-routes`".into()));
    lines
}

/// The VNets a hub's loaded connections name, for its Related section.
fn connected_vnets(lazy: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    match lazy {
        Some(Lazy::Loaded(items)) => items
            .iter()
            .filter_map(|c| json::arm_id(json::id_at(c, "/properties/remoteVirtualNetwork")))
            .map(|v| (format!("Connected VNet · {}", name_of_id(&v)), v))
            .collect(),
        _ => Vec::new(),
    }
}

// ── Site-to-site VPN gateway ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VwanVpnGatewayRow {
    pub base: ArmBase,
    pub hub_id: Option<String>,
    pub scale_units: Option<i64>,
    pub bgp: Option<Value>,
    pub routing_preference_internet: Option<bool>,
    pub ip_configurations: Vec<Value>,
    pub nat_rules: Vec<Value>,
    /// `connections[]`: one per VPN site, each with its link connections.
    pub connections: Vec<Value>,
}

impl VwanVpnGatewayRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VwanVpnGatewayRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(VwanVpnGatewayRow {
            hub_id: json::arm_id(json::id_at(v, &p("virtualHub"))),
            scale_units: json::int_at(v, &p("vpnGatewayScaleUnit")),
            bgp: v.pointer(&p("bgpSettings")).filter(|b| b.is_object()).cloned(),
            routing_preference_internet: json::bool_at(v, &p("isRoutingPreferenceInternet")),
            ip_configurations: json::arr(v, &p("ipConfigurations")),
            nat_rules: json::arr(v, &p("natRules")),
            connections: json::arr(v, &p("connections")),
            base,
        })
    }

    /// The connections to `site_id`.
    pub fn connections_to(&self, site_id: &str) -> Vec<&Value> {
        self.connections
            .iter()
            .filter(|c| json::str_at(c, "/properties/remoteVpnSite/id").is_some_and(|s| same(&s, site_id)))
            .collect()
    }

    /// Connections whose status (or every link's) is NotConnected.
    pub fn down_count(&self) -> usize {
        self.connections.iter().filter(|c| connection_down(c)).count()
    }

    pub fn configuration_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![(
            "Scale units".into(),
            match self.scale_units {
                // 500 Mbps aggregate per scale unit (Azure's sizing).
                Some(n) => format!("{} · ≈{} aggregate", n, bandwidth(n * 500)),
                None => "-".into(),
            },
        )];
        lines.push(("Routing preference".into(), if self.routing_preference_internet == Some(true) { "Internet" } else { "Microsoft network" }.into()));
        if let Some(b) = &self.bgp {
            lines.push(("BGP ASN".into(), json::num(json::int_at(b, "/asn"))));
            lines.push(("BGP peering address".into(), json::text(b, "/bgpPeeringAddress")));
            for a in json::arr(b, "/bgpPeeringAddresses") {
                let config = json::str_at(&a, "/ipconfigurationId").map(|i| name_of_id(&i).to_string()).unwrap_or_else(|| "-".into());
                lines.push((format!("  {}", config), String::new()));
                lines.push(("    Default".into(), list_or_dash(&a, "/defaultBgpIpAddresses")));
                lines.push(("    Custom (APIPA)".into(), list_or_dash(&a, "/customBgpIpAddresses")));
                lines.push(("    Tunnel".into(), list_or_dash(&a, "/tunnelIpAddresses")));
            }
        }
        for c in &self.ip_configurations {
            lines.push((
                format!("Instance {}", json::text(c, "/id")),
                format!("public {} · private {}", json::text(c, "/publicIpAddress"), json::text(c, "/privateIpAddress")),
            ));
        }
        lines
    }

    pub fn connection_rows(&self) -> Vec<(String, String)> {
        if self.connections.is_empty() {
            return vec![(String::new(), "No site connections".into())];
        }
        let mut lines = Vec::new();
        for (i, c) in self.connections.iter().enumerate() {
            if i > 0 {
                lines.push((String::new(), String::new()));
            }
            lines.extend(site_connection_lines(c));
        }
        lines
    }

    pub fn nat_rule_rows(&self) -> Vec<(String, String)> {
        if self.nat_rules.is_empty() {
            return vec![(String::new(), "No NAT rules".into())];
        }
        let maps = |v: &Value, ptr: &str| -> String {
            json::join(&json::arr(v, ptr).iter().map(|m| json::text(m, "/addressSpace")).collect::<Vec<_>>())
        };
        self.nat_rules
            .iter()
            .map(|r| {
                let q = |k: &str| format!("/properties/{}", k);
                (
                    format!("{} · {} {}", json::text(r, "/name"), json::text(r, &q("type")), json::text(r, &q("mode"))),
                    format!("{} ↔ {}", maps(r, &q("internalMappings")), maps(r, &q("externalMappings"))),
                )
            })
            .collect()
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(h) = &self.hub_id {
            push_unique(&mut v, format!("Hub · {}", name_of_id(h)), h.clone());
        }
        for c in &self.connections {
            if let Some(s) = json::arm_id(json::id_at(c, "/properties/remoteVpnSite")) {
                push_unique(&mut v, format!("VPN site · {}", name_of_id(&s)), s);
            }
        }
        v
    }
}

/// A site connection down: its own status, or every link's when the
/// connection's own is not reported.
fn connection_down(c: &Value) -> bool {
    let own = json::str_at(c, "/properties/connectionStatus");
    if own.as_deref().is_some_and(|s| same(s, "NotConnected")) {
        return true;
    }
    let links = json::arr(c, "/properties/vpnLinkConnections");
    own.as_deref().is_none_or(|s| same(s, "Unknown"))
        && !links.is_empty()
        && links.iter().all(|l| json::str_at(l, "/properties/connectionStatus").is_some_and(|s| same(&s, "NotConnected")))
}

/// One site connection's lines: the site, status, protocol, BGP, then
/// each link with its own status and traffic.
fn site_connection_lines(c: &Value) -> Vec<(String, String)> {
    let q = |k: &str| format!("/properties/{}", k);
    let mut lines = Vec::new();
    match json::arm_id(json::id_at(c, &q("remoteVpnSite"))) {
        Some(site) => lines.push((format!("{} · site {}", json::text(c, "/name"), name_of_id(&site)), site)),
        None => lines.push((json::text(c, "/name"), "-".into())),
    }
    lines.push(("  Status".into(), status_word(json::str_at(c, &q("connectionStatus")))));
    lines.push(("  Internet security".into(), json::yes_no(json::bool_at(c, &q("enableInternetSecurity")))));
    lines.extend(routing_rows(c, "  "));
    for l in json::arr(c, &q("vpnLinkConnections")) {
        let lq = |k: &str| format!("/properties/{}", k);
        let link = json::arm_id(json::id_at(&l, &lq("vpnSiteLink"))).map(|id| name_of_id(&id).to_string()).unwrap_or_else(|| json::text(&l, "/name"));
        lines.push((format!("  Link {}", link), status_word(json::str_at(&l, &lq("connectionStatus")))));
        lines.push((
            "    Protocol · bandwidth".into(),
            format!(
                "{} · {}",
                json::text(&l, &lq("vpnConnectionProtocolType")),
                json::int_at(&l, &lq("connectionBandwidth")).map(bandwidth).unwrap_or_else(|| "-".into())
            ),
        ));
        lines.push(("    BGP".into(), json::yes_no(json::bool_at(&l, &lq("enableBgp")))));
        let policies = json::arr(&l, &lq("ipsecPolicies"));
        if let Some(p) = policies.first() {
            lines.push((
                "    IPsec policy".into(),
                format!(
                    "IKE {}/{} · IPsec {}/{} · {} · {}",
                    json::text(p, "/ikeEncryption"),
                    json::text(p, "/ikeIntegrity"),
                    json::text(p, "/ipsecEncryption"),
                    json::text(p, "/ipsecIntegrity"),
                    json::text(p, "/dhGroup"),
                    json::text(p, "/pfsGroup")
                ),
            ));
        }
        if let (Some(i), Some(e)) = (json::int_at(&l, &lq("ingressBytesTransferred")), json::int_at(&l, &lq("egressBytesTransferred"))) {
            lines.push(("    In · out".into(), format!("{} · {}", bytes(i), bytes(e))));
        }
    }
    lines
}

impl Resource for VwanVpnGatewayRow {
    arm_row!("Hub VPN gateway");
    /// `2 scale units · 3 connections · 1 down`.
    fn list_summary(&self) -> Option<String> {
        let mut s = format!(
            "{} · {}",
            count(self.scale_units.unwrap_or(0).max(0) as usize, "scale unit", "scale units"),
            count(self.connections.len(), "connection", "connections")
        );
        let down = self.down_count();
        if down > 0 {
            s.push_str(&format!(" · ⚠ {} down", down));
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VWAN_VPN_GATEWAY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Hub".into(), self.hub_id.as_deref().map(|h| name_of_id(h).to_string()).unwrap_or_else(|| "-".into())),
            ("Scale units".into(), json::num(self.scale_units)),
            ("Connections".into(), format!("{} ({} down)", self.connections.len(), self.down_count())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        VwanVpnGatewayRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vpn-gateway show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── ExpressRoute gateway ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VwanErGatewayRow {
    pub base: ArmBase,
    pub hub_id: Option<String>,
    pub min_scale_units: Option<i64>,
    pub max_scale_units: Option<i64>,
    pub allow_non_vwan: Option<bool>,
    pub connections: Vec<Value>,
}

impl VwanErGatewayRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VwanErGatewayRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(VwanErGatewayRow {
            hub_id: json::arm_id(json::id_at(v, &p("virtualHub"))),
            min_scale_units: json::int_at(v, &p("autoScaleConfiguration/bounds/min")),
            max_scale_units: json::int_at(v, &p("autoScaleConfiguration/bounds/max")),
            allow_non_vwan: json::bool_at(v, &p("allowNonVirtualWanTraffic")),
            connections: json::arr(v, &p("expressRouteConnections")),
            base,
        })
    }

    /// The circuit a connection's peering belongs to.
    fn circuit_of(c: &Value) -> Option<String> {
        json::arm_id(json::id_at(c, "/properties/expressRouteCircuitPeering")).and_then(|p| top_level_of(&p))
    }

    fn scale_label(&self) -> String {
        // 2 Gbps per scale unit (Azure's sizing).
        let gbps = |n: i64| format!("≈{} Gbps", n * 2);
        match (self.min_scale_units, self.max_scale_units) {
            (Some(lo), Some(hi)) if hi > lo => format!("{}–{} · {}–{}", lo, hi, gbps(lo), gbps(hi)),
            (Some(n), _) => format!("{} · {}", n, gbps(n)),
            _ => "-".into(),
        }
    }

    pub fn configuration_rows(&self) -> Vec<(String, String)> {
        vec![
            ("Scale units".into(), self.scale_label()),
            ("Traffic from non-vWAN VNets".into(), json::yes_no(self.allow_non_vwan)),
            ("Connections".into(), self.connections.len().to_string()),
        ]
    }

    pub fn connection_rows(&self) -> Vec<(String, String)> {
        if self.connections.is_empty() {
            return vec![(String::new(), "No circuit connections".into())];
        }
        let mut lines = Vec::new();
        for (i, c) in self.connections.iter().enumerate() {
            if i > 0 {
                lines.push((String::new(), String::new()));
            }
            let q = |k: &str| format!("/properties/{}", k);
            match Self::circuit_of(c) {
                Some(circuit) => lines.push((format!("{} · circuit {}", json::text(c, "/name"), name_of_id(&circuit)), circuit)),
                None => lines.push((json::text(c, "/name"), "-".into())),
            }
            if let Some(peering) = json::arm_id(json::id_at(c, &q("expressRouteCircuitPeering"))) {
                lines.push((format!("  Peering · {}", name_of_id(&peering)), peering));
            }
            lines.push(("  State".into(), json::text(c, &q("provisioningState")).to_lowercase()));
            lines.push(("  Routing weight".into(), json::num(json::int_at(c, &q("routingWeight")))));
            lines.push(("  Internet security".into(), json::yes_no(json::bool_at(c, &q("enableInternetSecurity")))));
            lines.push(("  FastPath".into(), json::yes_no(json::bool_at(c, &q("expressRouteGatewayBypass")))));
            lines.extend(routing_rows(c, "  "));
        }
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(h) = &self.hub_id {
            push_unique(&mut v, format!("Hub · {}", name_of_id(h)), h.clone());
        }
        for c in &self.connections {
            if let Some(circuit) = Self::circuit_of(c) {
                push_unique(&mut v, format!("ExpressRoute circuit · {}", name_of_id(&circuit)), circuit);
            }
        }
        v
    }
}

impl Resource for VwanErGatewayRow {
    arm_row!("Hub ExpressRoute gateway");
    /// `1 scale unit · 1 circuit`.
    fn list_summary(&self) -> Option<String> {
        Some(format!(
            "{} · {}",
            count(self.min_scale_units.unwrap_or(0).max(0) as usize, "scale unit", "scale units"),
            count(self.connections.len(), "circuit", "circuits")
        ))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VWAN_ER_GATEWAY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Hub".into(), self.hub_id.as_deref().map(|h| name_of_id(h).to_string()).unwrap_or_else(|| "-".into())),
            ("Scale units".into(), self.scale_label()),
            ("Connections".into(), self.connections.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        VwanErGatewayRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network express-route gateway show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Point-to-site gateway ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2sGatewayRow {
    pub base: ArmBase,
    pub hub_id: Option<String>,
    pub scale_units: Option<i64>,
    pub server_configuration_id: Option<String>,
    pub configurations: Vec<Value>,
    pub custom_dns: Vec<String>,
    pub routing_preference_internet: Option<bool>,
    /// `vpnClientConnectionHealth`: what the list body carries; the
    /// detailed health is a POST.
    pub health: Option<Value>,
}

impl P2sGatewayRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<P2sGatewayRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(P2sGatewayRow {
            hub_id: json::arm_id(json::id_at(v, &p("virtualHub"))),
            scale_units: json::int_at(v, &p("vpnGatewayScaleUnit")),
            server_configuration_id: json::arm_id(json::id_at(v, &p("vpnServerConfiguration"))),
            configurations: json::arr(v, &p("p2SConnectionConfigurations")),
            custom_dns: json::strings_at(v, &p("customDnsServers")),
            routing_preference_internet: json::bool_at(v, &p("isRoutingPreferenceInternet")),
            health: v.pointer(&p("vpnClientConnectionHealth")).filter(|h| h.is_object()).cloned(),
            base,
        })
    }

    pub fn client_count(&self) -> Option<i64> {
        self.health.as_ref().and_then(|h| json::int_at(h, "/vpnClientConnectionsCount"))
    }

    fn pools(&self) -> Vec<String> {
        self.configurations
            .iter()
            .flat_map(|c| json::strings_at(c, "/properties/vpnClientAddressPool/addressPrefixes"))
            .collect()
    }

    pub fn configuration_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![(
            "Scale units".into(),
            match self.scale_units {
                // 500 Mbps per scale unit (Azure's sizing).
                Some(n) => format!("{} · ≈{}", n, bandwidth(n * 500)),
                None => "-".into(),
            },
        )];
        if let Some(s) = &self.server_configuration_id {
            lines.push((format!("Server configuration · {}", name_of_id(s)), s.clone()));
        }
        lines.push(("Client address pools".into(), json::join(&self.pools())));
        lines.push(("Custom DNS".into(), json::join(&self.custom_dns)));
        lines.push(("Routing preference".into(), if self.routing_preference_internet == Some(true) { "Internet" } else { "Microsoft network" }.into()));
        for c in &self.configurations {
            lines.push((format!("Configuration {}", json::text(c, "/name")), String::new()));
            lines.push(("  Internet security".into(), json::yes_no(json::bool_at(c, "/properties/enableInternetSecurity"))));
            lines.extend(routing_rows(c, "  "));
        }
        lines
    }

    pub fn client_rows(&self) -> Vec<(String, String)> {
        let Some(h) = &self.health else {
            return vec![(String::new(), "No client health in the gateway's body".into())];
        };
        let mut lines = vec![
            ("Connected clients".into(), json::num(json::int_at(h, "/vpnClientConnectionsCount"))),
            ("Allocated addresses".into(), json::arr(h, "/allocatedIpAddresses").len().to_string()),
        ];
        if let (Some(i), Some(e)) = (json::int_at(h, "/totalIngressBytesTransferred"), json::int_at(h, "/totalEgressBytesTransferred")) {
            lines.push(("In · out".into(), format!("{} · {}", bytes(i), bytes(e))));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· per-user sessions are a POST (getP2sVpnConnectionHealthDetailed): nebaz never sends it".into()));
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(h) = &self.hub_id {
            push_unique(&mut v, format!("Hub · {}", name_of_id(h)), h.clone());
        }
        if let Some(s) = &self.server_configuration_id {
            push_unique(&mut v, format!("VPN server configuration · {}", name_of_id(s)), s.clone());
        }
        v
    }
}

impl Resource for P2sGatewayRow {
    arm_row!("Hub P2S gateway");
    /// `1 scale unit · 172.30.0.0/22 · 37 clients`.
    fn list_summary(&self) -> Option<String> {
        let mut s = format!("{} · {}", count(self.scale_units.unwrap_or(0).max(0) as usize, "scale unit", "scale units"), json::join(&self.pools()));
        if let Some(n) = self.client_count() {
            s.push_str(&format!(" · {}", count(n.max(0) as usize, "client", "clients")));
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&P2S_GATEWAY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Hub".into(), self.hub_id.as_deref().map(|h| name_of_id(h).to_string()).unwrap_or_else(|| "-".into())),
            ("Client pools".into(), json::join(&self.pools())),
            ("Connected clients".into(), json::num(self.client_count())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        P2sGatewayRow::related(self)
    }
    /// The name form: `p2s-vpn-gateway show` declares `--name` without an
    /// `id_part` (SERVICES.md rule 9).
    fn cli_command(&self) -> Option<String> {
        let rg = self.resource_group()?;
        let sub = crate::azure::resource::subscription_of(&self.base.id)?;
        Some(format!(
            "az network p2s-vpn-gateway show -g {} -n {} --subscription {}",
            shell_quote(rg),
            shell_quote(&self.base.name),
            sub
        ))
    }
}

// ── VPN site ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VpnSiteRow {
    pub base: ArmBase,
    pub wan_id: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub link_speed_mbps: Option<i64>,
    pub ip_address: Option<String>,
    pub address_prefixes: Vec<String>,
    pub bgp: Option<Value>,
    pub security_site: Option<bool>,
    pub links: Vec<Value>,
    pub o365: Option<Value>,
}

impl VpnSiteRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VpnSiteRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(VpnSiteRow {
            wan_id: json::arm_id(json::id_at(v, &p("virtualWan"))),
            vendor: json::str_at(v, &p("deviceProperties/deviceVendor")),
            model: json::str_at(v, &p("deviceProperties/deviceModel")),
            link_speed_mbps: json::int_at(v, &p("deviceProperties/linkSpeedInMbps")),
            ip_address: json::str_at(v, &p("ipAddress")),
            address_prefixes: json::strings_at(v, &p("addressSpace/addressPrefixes")),
            bgp: v.pointer(&p("bgpProperties")).filter(|b| b.is_object()).cloned(),
            security_site: json::bool_at(v, &p("isSecuritySite")),
            links: json::arr(v, &p("vpnSiteLinks")),
            o365: v.pointer(&p("o365Policy/breakOutCategories")).filter(|b| b.is_object()).cloned(),
            base,
        })
    }

    fn device(&self) -> String {
        match (&self.vendor, &self.model) {
            (Some(v), Some(m)) => format!("{} {}", v, m),
            (Some(v), None) => v.clone(),
            _ => "-".into(),
        }
    }

    pub fn site_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Device".into(), self.device()),
            ("Link speed".into(), self.link_speed_mbps.map(bandwidth).unwrap_or_else(|| "-".into())),
            ("Address space".into(), json::join(&self.address_prefixes)),
        ];
        if let Some(ip) = &self.ip_address {
            lines.push(("IP address".into(), ip.clone()));
        }
        if let Some(b) = &self.bgp {
            lines.push(("BGP ASN".into(), json::num(json::int_at(b, "/asn"))));
            lines.push(("BGP peering address".into(), json::text(b, "/bgpPeeringAddress")));
        }
        lines.push(("Security site".into(), json::yes_no(self.security_site)));
        if let Some(o) = &self.o365 {
            let on: Vec<String> =
                ["allow", "optimize", "default"].iter().filter(|k| json::bool_at(o, &format!("/{}", k)) == Some(true)).map(|k| k.to_string()).collect();
            lines.push(("Office 365 breakout".into(), json::join(&on)));
        }
        lines
    }

    pub fn link_rows(&self) -> Vec<(String, String)> {
        if self.links.is_empty() {
            return vec![(String::new(), "No links: a site before links (one IP on the site itself)".into())];
        }
        let mut lines = Vec::new();
        for l in &self.links {
            let q = |k: &str| format!("/properties/{}", k);
            let endpoint = json::str_at(l, &q("ipAddress")).or_else(|| json::str_at(l, &q("fqdn"))).unwrap_or_else(|| "-".into());
            lines.push((json::text(l, "/name"), endpoint));
            lines.push((
                "  Provider · speed".into(),
                format!(
                    "{} · {}",
                    json::text(l, &q("linkProperties/linkProviderName")),
                    json::int_at(l, &q("linkProperties/linkSpeedInMbps")).map(bandwidth).unwrap_or_else(|| "-".into())
                ),
            ));
            if json::int_at(l, &q("bgpProperties/asn")).is_some() {
                lines.push((
                    "  BGP".into(),
                    format!("ASN {} · {}", json::num(json::int_at(l, &q("bgpProperties/asn"))), json::text(l, &q("bgpProperties/bgpPeeringAddress"))),
                ));
            }
        }
        lines
    }

    /// The hub VPN gateways in the warm list that connect this site.
    fn gateways<'a>(&self, warm: &'a [Box<dyn Resource>]) -> Vec<&'a VwanVpnGatewayRow> {
        warm.iter()
            .filter_map(|r| r.as_any().downcast_ref::<VwanVpnGatewayRow>())
            .filter(|g| !g.connections_to(&self.base.id).is_empty())
            .collect()
    }

    pub fn connection_rows(&self, gateways: Warm) -> Vec<(String, String)> {
        let Some(warm) = gateways.rows() else {
            return gateways.waiting("VPN gateways (@hubvpn)");
        };
        let found = self.gateways(warm);
        if found.is_empty() {
            return vec![(String::new(), "No hub VPN gateway in this subscription connects this site".into())];
        }
        let mut lines = Vec::new();
        for g in found {
            lines.push((format!("Gateway · {}", g.base.name), g.base.id.clone()));
            if let Some(h) = &g.hub_id {
                lines.push((format!("  Hub · {}", name_of_id(h)), h.clone()));
            }
            for c in g.connections_to(&self.base.id) {
                lines.extend(site_connection_lines(c).into_iter().map(|(l, v)| (format!("  {}", l), v)));
            }
        }
        lines
    }

    pub fn related(&self, gateways: Warm) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(w) = &self.wan_id {
            push_unique(&mut v, format!("WAN · {}", name_of_id(w)), w.clone());
        }
        for g in gateways.rows().map(|w| self.gateways(w)).unwrap_or_default() {
            push_unique(&mut v, format!("Hub VPN gateway · {}", g.base.name), g.base.id.clone());
        }
        v
    }
}

impl Resource for VpnSiteRow {
    arm_row!("VPN site");
    /// `Cisco ISR4451 · 2 links · 192.168.40.0/24`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("{} · {} · {}", self.device(), count(self.links.len(), "link", "links"), json::join(&self.address_prefixes)))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VPN_SITE_SECTIONS)
    }
    fn search_text(&self) -> String {
        let mut parts = vec![self.base.id.clone(), self.base.name.clone(), self.device()];
        parts.extend(self.address_prefixes.iter().cloned());
        parts.extend(self.ip_address.iter().cloned());
        parts.extend(self.links.iter().filter_map(|l| json::str_at(l, "/properties/ipAddress")));
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("WAN".into(), self.wan_id.as_deref().map(|w| name_of_id(w).to_string()).unwrap_or_else(|| "-".into())),
            ("Device".into(), self.device()),
            ("Links".into(), self.links.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        VpnSiteRow::related(self, Warm::Cold)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vpn-site show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Section dispatch ──────────────────────────────────────────────────

/// What a Virtual WAN section reads beyond its row: the sibling lists
/// (warm or loaded for the section) and the selected hub's lazy reads.
pub struct VwanContext<'a> {
    pub hubs: Warm<'a>,
    pub vpn_gateways: Warm<'a>,
    pub hub_connections: Option<&'a Lazy<Vec<Value>>>,
    pub route_tables: Option<&'a Lazy<Vec<Value>>>,
    pub routing_intent: Option<&'a Lazy<Vec<Value>>>,
}

pub fn virtual_wan_section_lines(r: &dyn Resource, idx: usize, cx: &VwanContext) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    let app = crate::azure::services::rendered_by_app;
    if let Some(x) = any.downcast_ref::<VirtualWanRow>() {
        use VirtualWanDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Wan => x.wan_rows(),
            S::Hubs => x.hub_rows(cx.hubs),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, Vec::new()),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<VirtualHubRow>() {
        use VirtualHubDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Hub => x.hub_rows(),
            S::Gateways => x.gateway_rows(),
            S::Connections => hub_connection_rows(cx.hub_connections),
            S::Routing => hub_routing_rows(cx.routing_intent, cx.route_tables),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, connected_vnets(cx.hub_connections)),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<VwanVpnGatewayRow>() {
        use VwanVpnGatewayDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Configuration => x.configuration_rows(),
            S::Connections => x.connection_rows(),
            S::NatRules => x.nat_rule_rows(),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, Vec::new()),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<VwanErGatewayRow>() {
        use VwanErGatewayDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Configuration => x.configuration_rows(),
            S::Connections => x.connection_rows(),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, Vec::new()),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<P2sGatewayRow>() {
        use P2sGatewayDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Configuration => x.configuration_rows(),
            S::Clients => x.client_rows(),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, Vec::new()),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<VpnSiteRow>() {
        use VpnSiteDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Site => x.site_rows(),
            S::Links => x.link_rows(),
            S::Connections => x.connection_rows(cx.vpn_gateways),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(x, x.related(cx.vpn_gateways)),
            S::Tags => tag_rows(x.tags()),
        });
    }
    None
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct VirtualWanService {
    scope: Scope,
}

impl VirtualWanService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<T: Resource + 'static>(rows: Vec<T>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::VirtualHubs => Self::boxed(page.iter().filter_map(|v| VirtualHubRow::from_json(v, tenant)).collect()),
            JumpView::VwanVpnGateways => {
                Self::boxed(page.iter().filter_map(|v| VwanVpnGatewayRow::from_json(v, tenant)).collect())
            }
            JumpView::VwanErGateways => Self::boxed(page.iter().filter_map(|v| VwanErGatewayRow::from_json(v, tenant)).collect()),
            JumpView::P2sGateways => Self::boxed(page.iter().filter_map(|v| P2sGatewayRow::from_json(v, tenant)).collect()),
            JumpView::VpnSites => Self::boxed(page.iter().filter_map(|v| VpnSiteRow::from_json(v, tenant)).collect()),
            _ => Self::boxed(page.iter().filter_map(|v| VirtualWanRow::from_json(v, tenant)).collect()),
        }
    }

    /// The list path and the progress words of a sub-tab.
    fn list_of(view: JumpView) -> (&'static str, &'static str) {
        match view {
            JumpView::VirtualHubs => (HUBS_PATH, "Listing virtual hubs…"),
            JumpView::VwanVpnGateways => (VPN_GATEWAYS_PATH, "Listing hub VPN gateways…"),
            JumpView::VwanErGateways => (ER_GATEWAYS_PATH, "Listing hub ExpressRoute gateways…"),
            JumpView::P2sGateways => (P2S_GATEWAYS_PATH, "Listing hub point-to-site gateways…"),
            JumpView::VpnSites => (VPN_SITES_PATH, "Listing VPN sites…"),
            _ => (WANS_PATH, "Listing virtual WANs…"),
        }
    }
}

#[async_trait]
impl AzureService for VirtualWanService {
    fn service_type(&self) -> ServiceType {
        ServiceType::VirtualWan
    }

    fn name(&self) -> &str {
        "Virtual WAN"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, _) = Self::list_of(view);
        let page = self.scope.list(path, VWAN_API_VERSION).await?;
        Ok(Self::rows(view, &page, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let (path, message) = Self::list_of(view);
        let r = self
            .scope
            .stream(path, VWAN_API_VERSION, &[], service_type, message, &event_tx, |page| Self::rows(view, &page, tenant.as_deref()))
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, VWAN_API_VERSION).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::VirtualWans);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-vwan";

    fn id(path: &str) -> String {
        format!("{}/providers/Microsoft.Network/{}", RG, path)
    }

    fn texts(lines: &[(String, String)]) -> String {
        lines.iter().map(|(l, v)| format!("{} = {}\n", l, v)).collect()
    }

    fn hub_json() -> Value {
        json!({
            "id": id("virtualHubs/vhub-neu"), "name": "vhub-neu", "location": "northeurope", "kind": "",
            "properties": {
                "provisioningState": "Succeeded", "routingState": "Provisioned",
                "virtualWan": {"id": id("virtualWans/vwan")}, "addressPrefix": "10.100.0.0/23", "sku": "Standard",
                "virtualRouterAsn": 65515, "virtualRouterIps": ["10.100.0.68", "10.100.0.69"],
                "virtualRouterAutoScaleConfiguration": {"minCapacity": 4},
                "hubRoutingPreference": "ExpressRoute",
                "vpnGateway": {"id": id("vpnGateways/vpngw")}, "expressRouteGateway": {"id": id("expressRouteGateways/ergw")},
                "azureFirewall": {"id": id("azureFirewalls/afw-vhub")}
            }
        })
    }

    fn vpn_gateway_json(link_status: &str) -> Value {
        json!({
            "id": id("vpnGateways/vpngw"), "name": "vpngw", "location": "northeurope",
            "properties": {
                "provisioningState": "Succeeded", "virtualHub": {"id": id("virtualHubs/vhub-neu")}, "vpnGatewayScaleUnit": 2,
                "bgpSettings": {"asn": 65515, "bgpPeeringAddress": "10.100.0.12,10.100.0.13"},
                "connections": [{
                    "name": "conn-dublin",
                    "properties": {
                        "remoteVpnSite": {"id": id("vpnSites/vst-dublin")}, "connectionStatus": "Unknown",
                        "sharedKey": "never-shown",
                        "vpnLinkConnections": [{"name": "l1", "properties": {
                            "vpnSiteLink": {"id": id("vpnSites/vst-dublin/vpnSiteLinks/link-isp-a")},
                            "connectionStatus": link_status, "sharedKey": "never-shown-either",
                            "vpnConnectionProtocolType": "IKEv2", "connectionBandwidth": 100, "enableBgp": true
                        }}]
                    }
                }]
            }
        })
    }

    #[test]
    fn hub_parses_its_router_gateways_and_firewall() {
        let h = VirtualHubRow::from_json(&hub_json(), None).unwrap();
        assert_eq!(h.state(), ResourceState::Available);
        assert_eq!(h.list_summary().unwrap(), "10.100.0.0/23 · Standard · secured");
        let hub = texts(&h.hub_rows());
        assert!(hub.contains("Routing capacity = 4 units · ≈5 Gbps, ≈4000 VMs"), "{}", hub);
        assert!(hub.contains("Secured = Azure Firewall afw-vhub"), "{}", hub);
        let gw = texts(&h.gateway_rows());
        assert!(gw.contains("VPN gateway · vpngw = ") && gw.contains("ExpressRoute gateway · ergw"), "{}", gw);
        assert!(h.related().iter().any(|(l, _)| l == "WAN · vwan"));
    }

    #[test]
    fn a_failed_hub_router_is_unavailable_and_a_route_server_says_so() {
        let mut v = hub_json();
        v["properties"]["routingState"] = json!("Failed");
        let h = VirtualHubRow::from_json(&v, None).unwrap();
        assert_eq!(h.state(), ResourceState::Unavailable);
        assert!(texts(&h.hub_rows()).contains("⚠ the hub router failed"));
        let rs = VirtualHubRow::from_json(
            &json!({"id": id("virtualHubs/rs-hub"), "name": "rs-hub", "location": "westeurope", "kind": "RouteServer",
                    "properties": {"virtualRouterAsn": 65515, "routingState": "Provisioned"}}),
            None,
        )
        .unwrap();
        assert_eq!(rs.list_summary().unwrap(), "Route Server · ASN 65515");
        assert!(texts(&rs.gateway_rows()).contains("a Route Server has none"));
    }

    #[test]
    fn shared_keys_never_survive_and_a_down_link_shows() {
        let g = VwanVpnGatewayRow::from_json(&vpn_gateway_json("NotConnected"), None).unwrap();
        assert!(!g.base.raw.contains("never-shown"), "{}", g.base.raw);
        assert_eq!(g.down_count(), 1);
        assert!(g.list_summary().unwrap().ends_with("⚠ 1 down"));
        let conns = texts(&g.connection_rows());
        assert!(conns.contains("Link link-isp-a = ⚠ NotConnected"), "{}", conns);
        assert!(conns.contains("Protocol · bandwidth = IKEv2 · 100 Mbps"), "{}", conns);
        let up = VwanVpnGatewayRow::from_json(&vpn_gateway_json("Connected"), None).unwrap();
        assert_eq!(up.down_count(), 0);
    }

    #[test]
    fn a_site_finds_its_gateway_in_the_warm_list() {
        let site = VpnSiteRow::from_json(
            &json!({"id": id("vpnSites/vst-dublin"), "name": "vst-dublin", "location": "northeurope",
                    "properties": {"virtualWan": {"id": id("virtualWans/vwan")}, "siteKey": "never-shown",
                                   "deviceProperties": {"deviceVendor": "Cisco", "deviceModel": "ISR4451"},
                                   "addressSpace": {"addressPrefixes": ["192.168.40.0/24"]}}}),
            None,
        )
        .unwrap();
        assert!(!site.base.raw.contains("never-shown"));
        let warm: Vec<Box<dyn Resource>> = vec![Box::new(VwanVpnGatewayRow::from_json(&vpn_gateway_json("Connected"), None).unwrap())];
        let conns = texts(&site.connection_rows(Warm::Rows(&warm)));
        assert!(conns.contains("Gateway · vpngw") && conns.contains("Hub · vhub-neu"), "{}", conns);
        assert!(texts(&site.connection_rows(Warm::Cold)).contains("Open the VPN gateways (@hubvpn) sub-tab"));
        assert!(site.related(Warm::Rows(&warm)).iter().any(|(l, _)| l == "Hub VPN gateway · vpngw"));
    }

    #[test]
    fn an_er_gateway_links_the_circuit_and_drops_the_authorization_key() {
        let g = VwanErGatewayRow::from_json(
            &json!({"id": id("expressRouteGateways/ergw"), "name": "ergw", "location": "northeurope",
                    "properties": {"virtualHub": {"id": id("virtualHubs/vhub-neu")},
                                   "autoScaleConfiguration": {"bounds": {"min": 1, "max": 3}},
                                   "expressRouteConnections": [{"name": "erc-ams-conn", "properties": {
                                       "expressRouteCircuitPeering": {"id": format!("{}/peerings/AzurePrivatePeering", id("expressRouteCircuits/erc-ams"))},
                                       "authorizationKey": "never-shown", "routingWeight": 0}}]}}),
            None,
        )
        .unwrap();
        assert!(!g.base.raw.contains("never-shown"));
        assert!(texts(&g.configuration_rows()).contains("Scale units = 1–3 · ≈2 Gbps–≈6 Gbps"));
        assert!(g.related().iter().any(|(l, id)| l == "ExpressRoute circuit · erc-ams" && id.ends_with("expressRouteCircuits/erc-ams")));
    }

    #[test]
    fn routing_shows_the_intent_and_jumpable_next_hops() {
        let fw = id("azureFirewalls/afw-vhub");
        let intent = Lazy::Loaded(vec![json!({"name": "ri", "properties": {"routingPolicies": [
            {"name": "PrivateTraffic", "destinations": ["PrivateTraffic"], "nextHop": fw}]}})]);
        let tables = Lazy::Loaded(vec![json!({"name": "defaultRouteTable", "id": id("virtualHubs/vhub-neu/hubRouteTables/defaultRouteTable"),
            "properties": {"labels": ["default"], "routes": [{"name": "_policy_PrivateTraffic", "destinations": ["10.0.0.0/8"], "nextHop": fw}],
                           "associatedConnections": [{"id": "a"}], "propagatingConnections": []}})]);
        let lines = hub_routing_rows(Some(&intent), Some(&tables));
        assert!(lines.iter().any(|(l, v)| l == "PrivateTraffic (PrivateTraffic) → afw-vhub" && v == &fw), "{}", texts(&lines));
        assert!(lines.iter().any(|(l, v)| l == "  _policy_PrivateTraffic · 10.0.0.0/8 → afw-vhub" && v == &fw), "{}", texts(&lines));
        assert!(texts(&hub_routing_rows(Some(&Lazy::Loaded(vec![])), None)).contains("None: the hub routes by its route tables alone"));
    }

    #[test]
    fn a_hub_managed_vnet_name_names_its_hub() {
        assert_eq!(managed_hub_name("HV_vhub-neu-prod_3f2a1b4c-5d6e-7f80-91a2-b3c4d5e6f708"), Some("vhub-neu-prod"));
        assert_eq!(managed_hub_name("HV_my_hub_3f2a1b4c-5d6e-7f80-91a2-b3c4d5e6f708"), Some("my_hub"));
        assert_eq!(managed_hub_name("vnet-hub-prod"), None);
        assert_eq!(managed_hub_name("HV_short"), None);
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        for d in [&VIRTUAL_WAN_SECTIONS, &VIRTUAL_HUB_SECTIONS, &VWAN_VPN_GATEWAY_SECTIONS, &VWAN_ER_GATEWAY_SECTIONS, &P2S_GATEWAY_SECTIONS, &VPN_SITE_SECTIONS] {
            let labels: Vec<&str> = d.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels[0], "Overview");
            assert_eq!(&labels[labels.len() - 4..], &["Access", "Activity", "Related", "Tags"]);
            assert!(labels.len() <= 10, "digit keys: {labels:?}");
        }
    }
}
