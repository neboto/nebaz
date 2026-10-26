//! The Hybrid service (issue #135): how the estate reaches on-premises.
//! ExpressRoute circuits (`Microsoft.Network/expressRouteCircuits`),
//! virtual network gateways (ExpressRoute and VPN), their connections
//! (`Microsoft.Network/connections`: ExpressRoute, IPsec, VNet-to-VNet)
//! and local network gateways (the on-premises side of a VPN). Its own tab
//! rather than more Network sub-tabs, for the digit-key reason DNS and Edge
//! are (SERVICES.md rules 15, 26 and 27).
//!
//! **Lists by group.** Circuits have a subscription-wide list; gateways,
//! connections and local gateways do not (ARM lists them per resource
//! group only). Those three sub-tabs ask the generic resources list which
//! groups hold the type (`$filter=resourceType eq '…'`, one call) and then
//! list each of those groups (one call per group), streaming every page.
//! A group that fails beside others is a warning.
//!
//! Everything a section shows is on the list body: no lazy calls. A
//! circuit's, a gateway's or a local gateway's connections are matched in
//! the warm Connections list, never fetched.
//!
//! **Secrets never.** A circuit authorization's `authorizationKey`, a
//! Global Reach connection's `authorizationKey`, a connection's
//! `sharedKey` and `authorizationKey`, a peering's MD5 `sharedKey`, a
//! RADIUS secret, the circuit `activationKey` and P2S root certificate
//! data are stripped before a row keeps its JSON ([`without_secrets`]);
//! the circuit `serviceKey` is masked to its last four characters. The
//! connection `sharedkey` read is never sent (the guard refuses the
//! path). ARP and route tables, stats, BGP peer status, learned and
//! advertised routes and VPN diagnostics are POSTs or out of scope: the
//! `C` catalogue copies the commands, nebaz never sends them.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, Resource, ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::all_resources::RESOURCES_API_VERSION;
use crate::azure::services::edge::top_level_of;
use crate::azure::services::network::NETWORK_API_VERSION;
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_lines, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::{Event, LoadProgress};
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// Every hybrid type is Microsoft.Network: the Network service's version.
pub const HYBRID_API_VERSION: &str = NETWORK_API_VERSION;

const CIRCUITS_PATH: &str = "/providers/Microsoft.Network/expressRouteCircuits";
pub const GATEWAY_TYPE: &str = "Microsoft.Network/virtualNetworkGateways";
pub const CONNECTION_TYPE: &str = "Microsoft.Network/connections";
pub const LOCAL_GATEWAY_TYPE: &str = "Microsoft.Network/localNetworkGateways";

crate::sections! {
    pub enum CircuitDetailSection,
    pub static CIRCUIT_SECTIONS = [
        Overview "Overview",
        Provider "Provider",
        Peerings "Peerings",
        GlobalReach "Global Reach",
        Authorizations "Authorizations",
        Connections "Connections",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum GatewayDetailSection,
    pub static GATEWAY_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration",
        IpConfigurations "IP configurations",
        Bgp "BGP",
        PointToSite "Point-to-site",
        Connections "Connections",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ConnectionDetailSection,
    pub static CONNECTION_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration",
        Ipsec "IPsec",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum LocalGatewayDetailSection,
    pub static LOCAL_GATEWAY_SECTIONS = [
        Overview "Overview",
        OnPremises "On-premises",
        Connections "Connections",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Secrets out of the JSON ───────────────────────────────────────────

/// Fields that hold a key or secret material, at any depth: authorization
/// keys (circuit authorizations, Global Reach, a redeeming connection),
/// pre-shared and MD5 keys, RADIUS secrets, the circuit activation key,
/// and P2S root certificate data.
const SECRET_FIELDS: &[&str] = &["authorizationKey", "sharedKey", "radiusServerSecret", "activationKey", "publicCertData"];

/// The circuit field that is masked rather than removed: the provider
/// needs it to provision, the last characters identify it.
const MASKED_FIELDS: &[&str] = &["serviceKey"];

/// `****1a2b`: the last four characters, or nothing of a short value.
pub fn mask_key(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return "****".into();
    }
    format!("****{}", s.chars().skip(n - 4).collect::<String>())
}

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            for (k, val) in map.iter_mut() {
                if MASKED_FIELDS.iter().any(|m| m.eq_ignore_ascii_case(k)) {
                    if let Value::String(s) = val {
                        *s = mask_key(s);
                    }
                } else {
                    scrub(val);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every secret-shaped field removed and the service key
/// masked: what a row parses and keeps for `e`.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
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

/// `vnet/subnet` from a subnet id.
fn subnet_label(id: &str) -> String {
    let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
    match parts.iter().rposition(|p| p.eq_ignore_ascii_case("subnets")) {
        Some(i) if i >= 2 && i + 1 < parts.len() => format!("{}/{}", parts[i - 1], parts[i + 1]),
        _ => name_of_id(id).to_string(),
    }
}

/// `1 Gbps`, `500 Mbps`.
pub fn bandwidth(mbps: i64) -> String {
    if mbps >= 1000 && mbps % 1000 == 0 {
        format!("{} Gbps", mbps / 1000)
    } else {
        format!("{} Mbps", mbps)
    }
}

/// Bytes in binary units: `1.5 GiB`.
pub fn bytes(n: i64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", n)
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

/// Strings at `ptr`, or `-`.
fn list_at(v: &Value, ptr: &str) -> String {
    json::join(&json::strings_at(v, ptr))
}

/// The number at `ptr`, whether ARM sent it as a number or a string.
fn num_at(v: &Value, ptr: &str) -> Option<i64> {
    match v.pointer(ptr)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

// ── ExpressRoute circuit ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CircuitRow {
    pub base: ArmBase,
    pub sku_name: Option<String>,
    pub sku_tier: Option<String>,
    pub sku_family: Option<String>,
    pub provider: Option<String>,
    pub peering_location: Option<String>,
    pub bandwidth_mbps: Option<i64>,
    /// ExpressRoute Direct: the port and its bandwidth.
    pub port_id: Option<String>,
    pub bandwidth_gbps: Option<f64>,
    /// `circuitProvisioningState`: `Enabled` / `Disabled`.
    pub circuit_state: Option<String>,
    /// `serviceProviderProvisioningState`: `NotProvisioned`,
    /// `Provisioning`, `Provisioned`, `Deprovisioning`, `DeProvisioned`.
    pub provider_state: Option<String>,
    /// Already masked ([`mask_key`]).
    pub service_key: Option<String>,
    pub provider_notes: Option<String>,
    pub global_reach: Option<bool>,
    pub allow_classic: Option<bool>,
    pub peerings: Vec<Value>,
    pub authorizations: Vec<Value>,
}

impl CircuitRow {
    /// Parses a circuit with its keys stripped and the service key masked.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<CircuitRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(CircuitRow {
            sku_name: json::str_at(v, "/sku/name"),
            sku_tier: json::str_at(v, "/sku/tier"),
            sku_family: json::str_at(v, "/sku/family"),
            provider: json::str_at(v, &p("serviceProviderProperties/serviceProviderName")),
            peering_location: json::str_at(v, &p("serviceProviderProperties/peeringLocation")),
            bandwidth_mbps: num_at(v, &p("serviceProviderProperties/bandwidthInMbps")),
            port_id: json::arm_id(json::id_at(v, &p("expressRoutePort"))),
            bandwidth_gbps: v.pointer(&p("bandwidthInGbps")).and_then(Value::as_f64),
            circuit_state: json::str_at(v, &p("circuitProvisioningState")),
            provider_state: json::str_at(v, &p("serviceProviderProvisioningState")),
            service_key: json::str_at(v, &p("serviceKey")),
            provider_notes: json::str_at(v, &p("serviceProviderNotes")),
            global_reach: json::bool_at(v, &p("globalReachEnabled")),
            allow_classic: json::bool_at(v, &p("allowClassicOperations")),
            peerings: json::arr(v, &p("peerings")),
            authorizations: json::arr(v, &p("authorizations")),
            base,
        })
    }

    /// Provisioning first, then a disabled circuit, then where the
    /// provider is (a circuit bills from creation, provisioned or not).
    pub fn ladder(&self) -> (ResourceState, String) {
        let disabled = self.circuit_state.as_deref().is_some_and(|s| same(s, "disabled"));
        let runtime = if disabled {
            Some((ResourceState::Stopped, "disabled"))
        } else {
            self.provider_state.as_deref().map(|s| {
                let bucket = match s.to_lowercase().as_str() {
                    "provisioned" => ResourceState::Available,
                    "deprovisioning" => ResourceState::Deleting,
                    "deprovisioned" => ResourceState::Stopped,
                    _ => ResourceState::Pending,
                };
                (bucket, s)
            })
        };
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn bandwidth_label(&self) -> String {
        match (self.bandwidth_mbps, self.bandwidth_gbps) {
            (Some(m), _) => bandwidth(m),
            (None, Some(g)) => format!("{} Gbps (Direct)", g),
            _ => "-".into(),
        }
    }

    fn sku_label(&self) -> String {
        match (&self.sku_tier, &self.sku_family) {
            (Some(t), Some(f)) => format!("{} · {}", t, f),
            (Some(t), None) => t.clone(),
            _ => json::opt(self.sku_name.clone()),
        }
    }

    /// The peer circuit of every Global Reach connection, either side:
    /// `(this peering, peer circuit id, address prefix, status)`.
    pub fn global_reach_links(&self) -> Vec<(String, String, String, String)> {
        let mut out = Vec::new();
        for peering in &self.peerings {
            let pname = json::text(peering, "/name");
            for c in json::arr(peering, "/properties/connections")
                .into_iter()
                .chain(json::arr(peering, "/properties/peeredConnections"))
            {
                // Own peering on one side, the peer's on the other; the
                // peered side names this circuit as `expressRouteCircuitPeering`.
                let candidates = [
                    json::id_at(&c, "/properties/peerExpressRouteCircuitPeering"),
                    json::id_at(&c, "/properties/expressRouteCircuitPeering"),
                ];
                let peer = candidates
                    .into_iter()
                    .flatten()
                    .filter_map(|id| top_level_of(&id))
                    .find(|top| !same(top, &self.base.id));
                if let Some(peer) = peer {
                    out.push((
                        pname.clone(),
                        peer,
                        json::text(&c, "/properties/addressPrefix"),
                        json::text(&c, "/properties/circuitConnectionStatus"),
                    ));
                }
            }
        }
        out
    }

    pub fn provider_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Provider".into(), json::opt(self.provider.clone())),
            ("Peering location".into(), json::opt(self.peering_location.clone())),
            ("Bandwidth".into(), self.bandwidth_label()),
            ("SKU".into(), self.sku_label()),
        ];
        if let Some(port) = &self.port_id {
            lines.push((format!("ExpressRoute Direct port · {}", name_of_id(port)), port.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push(("Circuit state".into(), json::opt(self.circuit_state.clone())));
        lines.push(("Provider state".into(), json::opt(self.provider_state.clone())));
        let note = match self.provider_state.as_deref().map(str::to_lowercase).as_deref() {
            Some("notprovisioned") => Some("· the provider has not provisioned the circuit yet: give them the service key (it bills already)"),
            Some("provisioning") => Some("· the provider is provisioning the circuit"),
            Some("deprovisioning") | Some("deprovisioned") => {
                Some("· the provider has released the circuit; it bills until it is deleted")
            }
            _ => None,
        };
        if let Some(n) = note {
            lines.push((String::new(), n.into()));
        }
        lines.push(("Service key".into(), format!("{} (masked)", json::opt(self.service_key.clone()))));
        lines.push(("Provider notes".into(), json::opt(self.provider_notes.clone())));
        lines.push(("Global Reach".into(), json::yes_no(self.global_reach)));
        lines.push(("Classic operations".into(), json::yes_no(self.allow_classic)));
        lines
    }

    pub fn peering_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.peerings.is_empty() {
            lines.push((String::new(), "No peerings configured".into()));
            return lines;
        }
        for (i, p) in self.peerings.iter().enumerate() {
            if i > 0 {
                lines.push((String::new(), String::new()));
            }
            let q = |k: &str| format!("/properties/{}", k);
            lines.push((json::text(p, "/name"), format!("{} · {}", json::text(p, &q("peeringType")), json::text(p, &q("state")).to_lowercase())));
            lines.push(("  VLAN".into(), json::num(num_at(p, &q("vlanId")))));
            lines.push(("  Peer ASN".into(), json::num(num_at(p, &q("peerASN")))));
            lines.push(("  Azure ASN".into(), json::num(num_at(p, &q("azureASN")))));
            lines.push(("  Primary prefix".into(), json::text(p, &q("primaryPeerAddressPrefix"))));
            lines.push(("  Secondary prefix".into(), json::text(p, &q("secondaryPeerAddressPrefix"))));
            lines.push((
                "  Azure ports".into(),
                format!("{} · {}", json::text(p, &q("primaryAzurePort")), json::text(p, &q("secondaryAzurePort"))),
            ));
            if let Some(rf) = json::arm_id(json::id_at(p, &q("routeFilter"))) {
                lines.push((format!("  Route filter · {}", name_of_id(&rf)), rf));
            }
            if let Some(ms) = p.pointer(&q("microsoftPeeringConfig")).filter(|m| m.is_object()) {
                lines.push(("  Advertised prefixes".into(), list_at(ms, "/advertisedPublicPrefixes")));
                let state = json::text(ms, "/advertisedPublicPrefixesState");
                let flagged = if same(&state, "ValidationNeeded") {
                    format!("⚠ {}: the prefixes' ownership is not validated yet, so Microsoft does not accept them", state)
                } else {
                    state
                };
                lines.push(("  Prefix validation".into(), flagged));
                lines.push(("  Customer ASN".into(), json::num(num_at(ms, "/customerASN"))));
                lines.push(("  Routing registry".into(), json::text(ms, "/routingRegistryName")));
                lines.push(("  Advertised communities".into(), list_at(ms, "/advertisedCommunities")));
            }
            if let Some(v6) = p.pointer(&q("ipv6PeeringConfig")).filter(|m| m.is_object()) {
                lines.push((
                    "  IPv6".into(),
                    format!(
                        "{} · {} / {}",
                        json::text(v6, "/state").to_lowercase(),
                        json::text(v6, "/primaryPeerAddressPrefix"),
                        json::text(v6, "/secondaryPeerAddressPrefix")
                    ),
                ));
            }
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· ARP and route tables are POSTs and stats are left out: C copies the commands, nebaz never sends them".into()));
        lines
    }

    pub fn global_reach_rows(&self) -> Vec<(String, String)> {
        let links = self.global_reach_links();
        let mut lines = vec![("Global Reach".into(), json::yes_no(self.global_reach))];
        if links.is_empty() {
            lines.push((String::new(), "No Global Reach connections".into()));
        }
        for (peering, peer, prefix, status) in links {
            lines.push((format!("Peer circuit · {}", name_of_id(&peer)), peer));
            lines.push(("  Via".into(), peering));
            lines.push(("  Address prefix".into(), prefix));
            lines.push(("  Status".into(), status));
        }
        lines
    }

    /// Names and use status only: the key is stripped at parse.
    pub fn authorization_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.authorizations.is_empty() {
            lines.push((String::new(), "No authorizations".into()));
        }
        for a in &self.authorizations {
            lines.push((json::text(a, "/name"), json::text(a, "/properties/authorizationUseStatus")));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· an authorization's key is never read or shown".into()));
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(port) = &self.port_id {
            push_unique(&mut v, format!("ExpressRoute port · {}", name_of_id(port)), port.clone());
        }
        for p in &self.peerings {
            if let Some(rf) = json::arm_id(json::id_at(p, "/properties/routeFilter")) {
                push_unique(&mut v, format!("Route filter · {}", name_of_id(&rf)), rf);
            }
        }
        for (_, peer, _, _) in self.global_reach_links() {
            push_unique(&mut v, format!("Global Reach peer · {}", name_of_id(&peer)), peer);
        }
        v
    }
}

impl Resource for CircuitRow {
    arm_row!("ExpressRoute circuit");
    /// `Equinix · Amsterdam · 1 Gbps`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([
            self.provider.clone(),
            self.peering_location.clone(),
            Some(self.bandwidth_label()).filter(|b| b != "-"),
        ])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CIRCUIT_SECTIONS)
    }
    /// Peering prefixes and ASNs are searchable.
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            json::opt(self.provider.clone()),
            json::opt(self.peering_location.clone()),
        ];
        for p in &self.peerings {
            for k in ["primaryPeerAddressPrefix", "secondaryPeerAddressPrefix"] {
                parts.push(json::text(p, &format!("/properties/{}", k)));
            }
            parts.push(json::num(num_at(p, "/properties/peerASN")));
        }
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        let types: Vec<String> = self.peerings.iter().map(|p| json::text(p, "/properties/peeringType")).collect();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Circuit state".into(), json::opt(self.circuit_state.clone())),
            ("Provider state".into(), json::opt(self.provider_state.clone())),
            ("Provider".into(), json::opt(self.provider.clone())),
            ("Peering location".into(), json::opt(self.peering_location.clone())),
            ("Bandwidth".into(), self.bandwidth_label()),
            ("SKU".into(), self.sku_label()),
            ("Peerings".into(), json::join(&types)),
            ("Global Reach".into(), json::yes_no(self.global_reach)),
            ("Authorizations".into(), self.authorizations.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        CircuitRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network express-route show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Virtual network gateway ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayRow {
    pub base: ArmBase,
    /// `Vpn`, `ExpressRoute`, `LocalGateway`.
    pub gateway_type: Option<String>,
    /// `RouteBased` / `PolicyBased`.
    pub vpn_type: Option<String>,
    pub sku_name: Option<String>,
    pub sku_tier: Option<String>,
    pub generation: Option<String>,
    pub active_active: Option<bool>,
    pub enable_bgp: Option<bool>,
    pub admin_state: Option<String>,
    pub ip_configurations: Vec<Value>,
    pub bgp: Option<Value>,
    pub vpn_client: Option<Value>,
    pub custom_routes: Vec<String>,
    pub private_ip: Option<bool>,
    pub allow_remote_vnet: Option<bool>,
    pub allow_vwan: Option<bool>,
}

impl GatewayRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<GatewayRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(GatewayRow {
            gateway_type: json::str_at(v, &p("gatewayType")),
            vpn_type: json::str_at(v, &p("vpnType")),
            sku_name: json::str_at(v, &p("sku/name")),
            sku_tier: json::str_at(v, &p("sku/tier")),
            generation: json::str_at(v, &p("vpnGatewayGeneration")),
            active_active: json::bool_at(v, &p("activeActive")),
            enable_bgp: json::bool_at(v, &p("enableBgp")),
            admin_state: json::str_at(v, &p("adminState")),
            ip_configurations: json::arr(v, &p("ipConfigurations")),
            bgp: v.pointer(&p("bgpSettings")).filter(|b| b.is_object()).cloned(),
            vpn_client: v.pointer(&p("vpnClientConfiguration")).filter(|b| b.is_object()).cloned(),
            custom_routes: json::strings_at(v, &p("customRoutes/addressPrefixes")),
            private_ip: json::bool_at(v, &p("enablePrivateIpAddress")),
            allow_remote_vnet: json::bool_at(v, &p("allowRemoteVnetTraffic")),
            allow_vwan: json::bool_at(v, &p("allowVirtualWanTraffic")),
            base,
        })
    }

    pub fn ladder(&self) -> (ResourceState, String) {
        let runtime = self
            .admin_state
            .as_deref()
            .filter(|s| same(s, "disabled"))
            .map(|s| (ResourceState::Stopped, s));
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    pub fn is_expressroute(&self) -> bool {
        self.gateway_type.as_deref().is_some_and(|t| same(t, "expressroute"))
    }

    fn sku(&self) -> &str {
        self.sku_name.as_deref().unwrap_or("-")
    }

    /// Zone redundancy from the SKU: an `…AZ` SKU, or ErGwScale.
    pub fn zone_redundancy(&self) -> String {
        let sku = self.sku();
        if sku.to_uppercase().ends_with("AZ") {
            format!("yes ({} is an AZ SKU)", sku)
        } else if same(sku, "ErGwScale") {
            "yes (ErGwScale)".into()
        } else if sku == "-" {
            "-".into()
        } else {
            format!("no ({} is not an AZ SKU)", sku)
        }
    }

    /// The gateway's subnet (GatewaySubnet), from its IP configurations.
    pub fn subnet_id(&self) -> Option<String> {
        self.ip_configurations.iter().find_map(|c| json::arm_id(json::id_at(c, "/properties/subnet")))
    }

    pub fn vnet_id(&self) -> Option<String> {
        self.subnet_id().and_then(|s| top_level_of(&s))
    }

    pub fn public_ip_ids(&self) -> Vec<String> {
        self.ip_configurations
            .iter()
            .filter_map(|c| json::arm_id(json::id_at(c, "/properties/publicIPAddress")))
            .collect()
    }

    fn bgp_asn(&self) -> Option<i64> {
        self.bgp.as_ref().and_then(|b| num_at(b, "/asn"))
    }

    pub fn configuration_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Gateway type".into(), json::opt(self.gateway_type.clone())),
            ("SKU".into(), format!("{} · tier {}", self.sku(), json::opt(self.sku_tier.clone()))),
            ("Zone redundancy".into(), self.zone_redundancy()),
            ("Active-active".into(), json::yes_no(self.active_active)),
        ];
        if !self.is_expressroute() {
            lines.push(("VPN type".into(), json::opt(self.vpn_type.clone())));
            lines.push(("Generation".into(), json::opt(self.generation.clone())));
            lines.push(("Private IP".into(), json::yes_no(self.private_ip)));
        } else {
            lines.push(("FastPath".into(), "set per connection (the Connections section)".into()));
            lines.push(("Remote VNet traffic".into(), json::yes_no(self.allow_remote_vnet)));
            lines.push(("Virtual WAN traffic".into(), json::yes_no(self.allow_vwan)));
        }
        lines.push(("BGP".into(), json::yes_no(self.enable_bgp)));
        lines.push(("Admin state".into(), json::opt(self.admin_state.clone())));
        if !self.custom_routes.is_empty() {
            lines.push(("Custom routes".into(), json::join(&self.custom_routes)));
        }
        lines
    }

    pub fn ip_configuration_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.ip_configurations.is_empty() {
            lines.push((String::new(), "No IP configurations".into()));
        }
        for c in &self.ip_configurations {
            lines.push((
                json::text(c, "/name"),
                format!(
                    "{} {}",
                    json::text(c, "/properties/privateIPAllocationMethod").to_lowercase(),
                    json::str_at(c, "/properties/privateIPAddress").unwrap_or_default()
                )
                .trim()
                .to_string(),
            ));
            if let Some(s) = json::arm_id(json::id_at(c, "/properties/subnet")) {
                lines.push((format!("  Subnet · {}", subnet_label(&s)), s));
            }
            if let Some(pip) = json::arm_id(json::id_at(c, "/properties/publicIPAddress")) {
                lines.push((format!("  Public IP · {}", name_of_id(&pip)), pip));
            }
        }
        if let Some(s) = self.subnet_id() {
            if !name_of_id(&s).eq_ignore_ascii_case("GatewaySubnet") {
                lines.push((String::new(), format!("⚠ the gateway's subnet is {}: Azure requires it to be named GatewaySubnet", name_of_id(&s))));
            }
        }
        lines
    }

    pub fn bgp_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("BGP".into(), json::yes_no(self.enable_bgp))];
        let Some(b) = &self.bgp else {
            lines.push((String::new(), "No BGP settings".into()));
            return lines;
        };
        lines.push(("ASN".into(), json::num(self.bgp_asn())));
        lines.push(("Peer weight".into(), json::num(num_at(b, "/peerWeight"))));
        lines.push(("Peering address".into(), json::text(b, "/bgpPeeringAddress")));
        for a in json::arr(b, "/bgpPeeringAddresses") {
            let config = json::str_at(&a, "/ipconfigurationId").map(|i| name_of_id(&i).to_string()).unwrap_or_else(|| "-".into());
            lines.push((format!("  {}", config), String::new()));
            lines.push(("    Default".into(), list_at(&a, "/defaultBgpIpAddresses")));
            lines.push(("    Custom (APIPA)".into(), list_at(&a, "/customBgpIpAddresses")));
            lines.push(("    Tunnel".into(), list_at(&a, "/tunnelIpAddresses")));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· BGP peer status and learned / advertised routes are POSTs: C copies the commands".into()));
        lines
    }

    pub fn point_to_site_rows(&self) -> Vec<(String, String)> {
        let Some(c) = &self.vpn_client else {
            let why = if self.is_expressroute() { "an ExpressRoute gateway has none" } else { "not configured" };
            return vec![("Point-to-site".into(), why.into())];
        };
        let mut lines = vec![
            ("Address pool".into(), list_at(c, "/vpnClientAddressPool/addressPrefixes")),
            ("Tunnel types".into(), list_at(c, "/vpnClientProtocols")),
            ("Authentication".into(), list_at(c, "/vpnAuthenticationTypes")),
        ];
        if json::str_at(c, "/aadTenant").is_some() {
            lines.push(("Entra tenant".into(), json::text(c, "/aadTenant")));
            lines.push(("Entra audience".into(), json::text(c, "/aadAudience")));
            lines.push(("Entra issuer".into(), json::text(c, "/aadIssuer")));
        }
        let mut radius: Vec<String> = json::str_at(c, "/radiusServerAddress").into_iter().collect();
        radius.extend(json::arr(c, "/radiusServers").iter().filter_map(|r| json::str_at(r, "/radiusServerAddress")));
        if !radius.is_empty() {
            lines.push(("RADIUS servers".into(), format!("{} (secrets never shown)", radius.join(", "))));
        }
        let roots: Vec<String> = json::arr(c, "/vpnClientRootCertificates").iter().map(|r| json::text(r, "/name")).collect();
        lines.push(("Root certificates".into(), json::join(&roots)));
        lines.push(("Revoked certificates".into(), json::arr(c, "/vpnClientRevokedCertificates").len().to_string()));
        let policies = json::arr(c, "/vpnClientIpsecPolicies");
        if !policies.is_empty() {
            lines.push(("Custom IPsec policies".into(), policies.len().to_string()));
        }
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(vnet) = self.vnet_id() {
            push_unique(&mut v, format!("VNet · {}", name_of_id(&vnet)), vnet);
        }
        if let Some(s) = self.subnet_id() {
            push_unique(&mut v, format!("Subnet · {}", subnet_label(&s)), s);
        }
        for pip in self.public_ip_ids() {
            push_unique(&mut v, format!("Public IP · {}", name_of_id(&pip)), pip);
        }
        v
    }
}

impl Resource for GatewayRow {
    arm_row!("Virtual network gateway");
    /// `ExpressRoute · ErGw1AZ`, `Vpn · VpnGw2AZ · active-active · ASN 65515`.
    fn list_summary(&self) -> Option<String> {
        let mut s = format!("{} · {}", self.gateway_type.as_deref().unwrap_or("-"), self.sku());
        if self.active_active == Some(true) {
            s.push_str(" · active-active");
        }
        if self.enable_bgp == Some(true) {
            if let Some(asn) = self.bgp_asn() {
                s.push_str(&format!(" · ASN {}", asn));
            }
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
        Some(&GATEWAY_SECTIONS)
    }
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            self.gateway_type.clone().unwrap_or_default(),
            self.sku().to_string(),
        ];
        if let Some(b) = &self.bgp {
            parts.push(json::text(b, "/bgpPeeringAddress"));
            parts.push(json::num(num_at(b, "/asn")));
        }
        for c in &self.ip_configurations {
            parts.extend(json::str_at(c, "/properties/privateIPAddress"));
        }
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Gateway type".into(), json::opt(self.gateway_type.clone())),
            ("SKU".into(), self.sku().to_string()),
            ("Zone redundancy".into(), self.zone_redundancy()),
            ("Active-active".into(), json::yes_no(self.active_active)),
            ("BGP".into(), json::yes_no(self.enable_bgp)),
            ("ASN".into(), json::num(self.bgp_asn())),
            ("VNet".into(), self.vnet_id().map(|v| name_of_id(&v).to_string()).unwrap_or_else(|| "-".into())),
            ("Public IPs".into(), self.public_ip_ids().len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        GatewayRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vnet-gateway show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Connection ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConnectionRow {
    pub base: ArmBase,
    /// `ExpressRoute`, `IPsec`, `Vnet2Vnet`, `VPNClient`.
    pub connection_type: Option<String>,
    /// `Connected`, `Connecting`, `NotConnected`, `Unknown`.
    pub status: Option<String>,
    /// This side: the virtual network gateway.
    pub gateway_id: Option<String>,
    /// The other side: a VNet-to-VNet peer gateway.
    pub peer_gateway_id: Option<String>,
    /// The other side of an IPsec connection.
    pub local_gateway_id: Option<String>,
    /// The other side of an ExpressRoute connection: the circuit (or
    /// its peering; normalized to the circuit).
    pub circuit_id: Option<String>,
    pub protocol: Option<String>,
    pub routing_weight: Option<i64>,
    pub ingress_bytes: Option<i64>,
    pub egress_bytes: Option<i64>,
    pub enable_bgp: Option<bool>,
    pub fast_path: Option<bool>,
    pub private_link_fast_path: Option<bool>,
    pub policy_selectors: Option<bool>,
    pub dpd_timeout: Option<i64>,
    pub mode: Option<String>,
    pub auth_type: Option<String>,
    pub ipsec_policies: Vec<Value>,
    pub traffic_selectors: Vec<Value>,
    pub tunnels: Vec<Value>,
}

impl ConnectionRow {
    /// Parses a connection with its shared key and authorization key
    /// stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ConnectionRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let id = |k: &str| json::arm_id(json::id_at(v, &p(k)));
        Some(ConnectionRow {
            connection_type: json::str_at(v, &p("connectionType")),
            status: json::str_at(v, &p("connectionStatus")),
            gateway_id: id("virtualNetworkGateway1"),
            peer_gateway_id: id("virtualNetworkGateway2"),
            local_gateway_id: id("localNetworkGateway2"),
            circuit_id: id("peer").map(|c| top_level_of(&c).unwrap_or(c)),
            protocol: json::str_at(v, &p("connectionProtocol")),
            routing_weight: num_at(v, &p("routingWeight")),
            ingress_bytes: num_at(v, &p("ingressBytesTransferred")),
            egress_bytes: num_at(v, &p("egressBytesTransferred")),
            enable_bgp: json::bool_at(v, &p("enableBgp")),
            fast_path: json::bool_at(v, &p("expressRouteGatewayBypass")),
            private_link_fast_path: json::bool_at(v, &p("enablePrivateLinkFastPath")),
            policy_selectors: json::bool_at(v, &p("usePolicyBasedTrafficSelectors")),
            dpd_timeout: num_at(v, &p("dpdTimeoutSeconds")),
            mode: json::str_at(v, &p("connectionMode")),
            auth_type: json::str_at(v, &p("authenticationType")),
            ipsec_policies: json::arr(v, &p("ipsecPolicies")),
            traffic_selectors: json::arr(v, &p("trafficSelectorPolicies")),
            tunnels: json::arr(v, &p("tunnelConnectionStatus")),
            base,
        })
    }

    pub fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "connected" => ResourceState::Available,
                "notconnected" => ResourceState::Unavailable,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    pub fn is_expressroute(&self) -> bool {
        self.connection_type.as_deref().is_some_and(|t| same(t, "expressroute"))
    }

    /// The far end: the circuit, the local gateway or the peer gateway.
    pub fn other_side(&self) -> Option<&str> {
        self.circuit_id
            .as_deref()
            .or(self.local_gateway_id.as_deref())
            .or(self.peer_gateway_id.as_deref())
    }

    /// Whether this connection touches `id` (a gateway on either side, a
    /// local gateway, a circuit).
    pub fn uses(&self, id: &str) -> bool {
        [&self.gateway_id, &self.peer_gateway_id, &self.local_gateway_id, &self.circuit_id]
            .into_iter()
            .flatten()
            .any(|x| same(x, id))
    }

    fn type_label(&self) -> &str {
        self.connection_type.as_deref().unwrap_or("-")
    }

    pub fn configuration_rows(&self) -> Vec<(String, String)> {
        let status = json::opt(self.status.clone());
        let status = if self.status.as_deref().is_some_and(|s| same(s, "notconnected")) {
            format!("⚠ {}: the tunnel or circuit link is down", status)
        } else {
            status
        };
        let mut lines = vec![
            ("Type".into(), self.type_label().to_string()),
            ("Status".into(), status),
            ("Routing weight".into(), json::num(self.routing_weight)),
            ("Ingress".into(), self.ingress_bytes.map(bytes).unwrap_or_else(|| "-".into())),
            ("Egress".into(), self.egress_bytes.map(bytes).unwrap_or_else(|| "-".into())),
        ];
        if self.is_expressroute() {
            lines.push(("FastPath".into(), json::yes_no(self.fast_path)));
            lines.push(("Private Link FastPath".into(), json::yes_no(self.private_link_fast_path)));
        } else {
            lines.push(("Protocol".into(), json::opt(self.protocol.clone())));
            lines.push(("BGP".into(), json::yes_no(self.enable_bgp)));
            lines.push(("Policy-based selectors".into(), json::yes_no(self.policy_selectors)));
            lines.push(("DPD timeout".into(), self.dpd_timeout.map(|s| format!("{} s", s)).unwrap_or_else(|| "-".into())));
            lines.push(("Mode".into(), json::opt(self.mode.clone())));
            lines.push((
                "Authentication".into(),
                format!("{} (a pre-shared key is never read)", self.auth_type.clone().unwrap_or_else(|| "PSK".into())),
            ));
        }
        for t in &self.tunnels {
            lines.push((
                format!("  Tunnel {}", json::text(t, "/tunnel")),
                format!(
                    "{} · in {} · out {} · since {}",
                    json::text(t, "/connectionStatus"),
                    num_at(t, "/ingressBytesTransferred").map(bytes).unwrap_or_else(|| "-".into()),
                    num_at(t, "/egressBytesTransferred").map(bytes).unwrap_or_else(|| "-".into()),
                    json::time(json::str_at(t, "/lastConnectionEstablishedUtcTime"))
                ),
            ));
        }
        lines
    }

    pub fn ipsec_rows(&self) -> Vec<(String, String)> {
        if self.is_expressroute() {
            return vec![(String::new(), "An ExpressRoute connection has no IPsec settings".into())];
        }
        let mut lines = Vec::new();
        if self.ipsec_policies.is_empty() {
            lines.push(("IPsec policy".into(), "default (Azure's proposals)".into()));
        }
        for (i, p) in self.ipsec_policies.iter().enumerate() {
            lines.push((format!("Policy {}", i + 1), String::new()));
            lines.push((
                "  IKE".into(),
                format!("{} · {} · {}", json::text(p, "/ikeEncryption"), json::text(p, "/ikeIntegrity"), json::text(p, "/dhGroup")),
            ));
            lines.push((
                "  IPsec".into(),
                format!("{} · {} · {}", json::text(p, "/ipsecEncryption"), json::text(p, "/ipsecIntegrity"), json::text(p, "/pfsGroup")),
            ));
            lines.push((
                "  SA lifetime".into(),
                format!("{} s · {} KB", json::num(num_at(p, "/saLifeTimeSeconds")), json::num(num_at(p, "/saDataSizeKilobytes"))),
            ));
        }
        for t in &self.traffic_selectors {
            lines.push((
                "Traffic selector".into(),
                format!("{} ↔ {}", list_at(t, "/localAddressRanges"), list_at(t, "/remoteAddressRanges")),
            ));
        }
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(g) = &self.gateway_id {
            push_unique(&mut v, format!("VNet gateway · {}", name_of_id(g)), g.clone());
        }
        if let Some(c) = &self.circuit_id {
            push_unique(&mut v, format!("ExpressRoute circuit · {}", name_of_id(c)), c.clone());
        }
        if let Some(l) = &self.local_gateway_id {
            push_unique(&mut v, format!("Local network gateway · {}", name_of_id(l)), l.clone());
        }
        if let Some(g) = &self.peer_gateway_id {
            push_unique(&mut v, format!("Peer VNet gateway · {}", name_of_id(g)), g.clone());
        }
        v
    }
}

impl Resource for ConnectionRow {
    arm_row!("Gateway connection");
    /// `ExpressRoute → erc-contoso-ams`.
    fn list_summary(&self) -> Option<String> {
        Some(match self.other_side() {
            Some(o) => format!("{} → {}", self.type_label(), name_of_id(o)),
            None => self.type_label().to_string(),
        })
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CONNECTION_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        let name = |id: &Option<String>| id.as_deref().map(|i| name_of_id(i).to_string()).unwrap_or_else(|| "-".into());
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Type".into(), self.type_label().to_string()),
            ("Status".into(), json::opt(self.status.clone())),
            ("Gateway".into(), name(&self.gateway_id)),
            (
                "Other side".into(),
                self.other_side().map(|o| name_of_id(o).to_string()).unwrap_or_else(|| "-".into()),
            ),
            ("Routing weight".into(), json::num(self.routing_weight)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        ConnectionRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network vpn-connection show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Local network gateway ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LocalGatewayRow {
    pub base: ArmBase,
    pub address_space: Vec<String>,
    pub gateway_ip: Option<String>,
    pub fqdn: Option<String>,
    pub bgp: Option<Value>,
}

impl LocalGatewayRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<LocalGatewayRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        Some(LocalGatewayRow {
            address_space: json::strings_at(v, "/properties/localNetworkAddressSpace/addressPrefixes"),
            gateway_ip: json::str_at(v, "/properties/gatewayIpAddress"),
            fqdn: json::str_at(v, "/properties/fqdn"),
            bgp: v.pointer("/properties/bgpSettings").filter(|b| b.is_object()).cloned(),
            base,
        })
    }

    fn endpoint(&self) -> String {
        self.gateway_ip.clone().or_else(|| self.fqdn.clone()).unwrap_or_else(|| "-".into())
    }

    pub fn on_premises_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Gateway IP".into(), json::opt(self.gateway_ip.clone())),
            ("FQDN".into(), json::opt(self.fqdn.clone())),
            ("Address space".into(), json::join(&self.address_space)),
        ];
        match &self.bgp {
            Some(b) => {
                lines.push(("BGP ASN".into(), json::num(num_at(b, "/asn"))));
                lines.push(("BGP peer address".into(), json::text(b, "/bgpPeeringAddress")));
                lines.push(("Peer weight".into(), json::num(num_at(b, "/peerWeight"))));
            }
            None => lines.push(("BGP".into(), "no (static routes: the address space above)".into())),
        }
        lines
    }
}

impl Resource for LocalGatewayRow {
    arm_row!("Local network gateway");
    /// `203.0.113.24 · 192.168.0.0/16 +1`.
    fn list_summary(&self) -> Option<String> {
        let space = match self.address_space.as_slice() {
            [] => None,
            [one] => Some(one.clone()),
            [first, rest @ ..] => Some(format!("{} +{}", first, rest.len())),
        };
        crate::azure::resource::summary_of([Some(self.endpoint()), space])
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&LOCAL_GATEWAY_SECTIONS)
    }
    /// The on-premises address space and endpoint are searchable.
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            self.endpoint(),
        ];
        parts.extend(self.address_space.iter().cloned());
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Endpoint".into(), self.endpoint()),
            ("Address space".into(), json::join(&self.address_space)),
            ("BGP ASN".into(), json::num(self.bgp.as_ref().and_then(|b| num_at(b, "/asn")))),
        ]
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network local-gateway show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Connections matched in the warm list ──────────────────────────────

/// The connections in the warm Connections list that touch `id`.
pub fn connections_using<'a>(warm: &'a [Box<dyn Resource>], id: &str) -> Vec<&'a ConnectionRow> {
    warm.iter()
        .filter_map(|r| r.as_any().downcast_ref::<ConnectionRow>())
        .filter(|c| c.uses(id))
        .collect()
}

/// The Connections section of a circuit, gateway or local gateway: each
/// connection touching `id` from the warm list, jumpable. `None` is a
/// cold list.
pub fn connection_rows(id: &str, warm: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    let Some(warm) = warm else {
        return vec![(String::new(), "· the Connections list is not loaded: open Hybrid › Connections (@cn) to match them".into())];
    };
    let found = connections_using(warm, id);
    if found.is_empty() {
        return vec![(String::new(), "No connections in this subscription's Connections list".into())];
    }
    let mut lines = Vec::new();
    for c in found {
        lines.push((format!("Connection · {}", c.base.name), c.base.id.clone()));
        lines.push(("  Type".into(), c.type_label().to_string()));
        lines.push(("  Status".into(), json::opt(c.status.clone())));
        // The far end from this row's point of view.
        let far = [&c.gateway_id, &c.circuit_id, &c.local_gateway_id, &c.peer_gateway_id]
            .into_iter()
            .flatten()
            .find(|x| !same(x, id));
        if let Some(far) = far {
            lines.push((format!("  Other end · {}", name_of_id(far)), far.clone()));
        }
        if c.is_expressroute() {
            lines.push(("  FastPath".into(), json::yes_no(c.fast_path)));
        }
    }
    lines
}

/// The links the warm Connections list adds to a Related section.
fn connection_links(id: &str, warm: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    warm.map(|w| {
        connections_using(w, id)
            .into_iter()
            .map(|c| (format!("Connection · {}", c.base.name), c.base.id.clone()))
            .collect()
    })
    .unwrap_or_default()
}

fn related_with_connections(mut rel: Vec<(String, String)>, id: &str, warm: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    for (label, cid) in connection_links(id, warm) {
        push_unique(&mut rel, label, cid);
    }
    related_lines(rel)
}

pub fn circuit_section_lines(
    r: &CircuitRow,
    section: CircuitDetailSection,
    connections: Option<&[Box<dyn Resource>]>,
) -> Vec<(String, String)> {
    match section {
        CircuitDetailSection::Overview => overview_rows(r),
        CircuitDetailSection::Provider => r.provider_rows(),
        CircuitDetailSection::Peerings => r.peering_rows(),
        CircuitDetailSection::GlobalReach => r.global_reach_rows(),
        CircuitDetailSection::Authorizations => r.authorization_rows(),
        CircuitDetailSection::Connections => connection_rows(r.id(), connections),
        CircuitDetailSection::Access => crate::azure::services::rendered_by_app(),
        CircuitDetailSection::Activity => crate::azure::services::rendered_by_app(),
        CircuitDetailSection::Related => related_with_connections(r.related(), r.id(), connections),
        CircuitDetailSection::Tags => tag_rows(r.tags()),
    }
}

pub fn gateway_section_lines(
    r: &GatewayRow,
    section: GatewayDetailSection,
    connections: Option<&[Box<dyn Resource>]>,
) -> Vec<(String, String)> {
    match section {
        GatewayDetailSection::Overview => overview_rows(r),
        GatewayDetailSection::Configuration => r.configuration_rows(),
        GatewayDetailSection::IpConfigurations => r.ip_configuration_rows(),
        GatewayDetailSection::Bgp => r.bgp_rows(),
        GatewayDetailSection::PointToSite => r.point_to_site_rows(),
        GatewayDetailSection::Connections => connection_rows(r.id(), connections),
        GatewayDetailSection::Access => crate::azure::services::rendered_by_app(),
        GatewayDetailSection::Activity => crate::azure::services::rendered_by_app(),
        GatewayDetailSection::Related => related_with_connections(r.related(), r.id(), connections),
        GatewayDetailSection::Tags => tag_rows(r.tags()),
    }
}

pub fn connection_section_lines(r: &ConnectionRow, section: ConnectionDetailSection) -> Vec<(String, String)> {
    match section {
        ConnectionDetailSection::Overview => overview_rows(r),
        ConnectionDetailSection::Configuration => r.configuration_rows(),
        ConnectionDetailSection::Ipsec => r.ipsec_rows(),
        ConnectionDetailSection::Access => crate::azure::services::rendered_by_app(),
        ConnectionDetailSection::Activity => crate::azure::services::rendered_by_app(),
        ConnectionDetailSection::Related => related_lines(r.related()),
        ConnectionDetailSection::Tags => tag_rows(r.tags()),
    }
}

pub fn local_gateway_section_lines(
    r: &LocalGatewayRow,
    section: LocalGatewayDetailSection,
    connections: Option<&[Box<dyn Resource>]>,
) -> Vec<(String, String)> {
    match section {
        LocalGatewayDetailSection::Overview => overview_rows(r),
        LocalGatewayDetailSection::OnPremises => r.on_premises_rows(),
        LocalGatewayDetailSection::Connections => connection_rows(r.id(), connections),
        LocalGatewayDetailSection::Access => crate::azure::services::rendered_by_app(),
        LocalGatewayDetailSection::Activity => crate::azure::services::rendered_by_app(),
        LocalGatewayDetailSection::Related => related_with_connections(r.related(), r.id(), connections),
        LocalGatewayDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

/// The resource groups an `$filter=resourceType eq …` answer names, each
/// once (case-insensitively), in first-seen order.
pub fn groups_of(items: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in items {
        if let Some(rg) = json::str_at(v, "/id").as_deref().and_then(resource_group_of) {
            if !out.iter().any(|g| same(g, rg)) {
                out.push(rg.to_string());
            }
        }
    }
    out
}

pub struct HybridService {
    scope: Scope,
}

impl HybridService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<T: Resource + 'static>(rows: Vec<T>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::VnetGateways => Self::boxed(page.iter().filter_map(|v| GatewayRow::from_json(v, tenant)).collect()),
            JumpView::GatewayConnections => {
                Self::boxed(page.iter().filter_map(|v| ConnectionRow::from_json(v, tenant)).collect())
            }
            JumpView::LocalGateways => Self::boxed(page.iter().filter_map(|v| LocalGatewayRow::from_json(v, tenant)).collect()),
            _ => Self::boxed(page.iter().filter_map(|v| CircuitRow::from_json(v, tenant)).collect()),
        }
    }

    /// The ARM type a per-group sub-tab lists; `None` for circuits (one
    /// subscription-wide list).
    fn per_group_type(view: JumpView) -> Option<(&'static str, &'static str)> {
        match view {
            JumpView::VnetGateways => Some((GATEWAY_TYPE, "virtual network gateways")),
            JumpView::GatewayConnections => Some((CONNECTION_TYPE, "connections")),
            JumpView::LocalGateways => Some((LOCAL_GATEWAY_TYPE, "local network gateways")),
            _ => None,
        }
    }

    /// The groups holding `arm_type`: one generic resources call.
    async fn groups_with(&self, arm_type: &str) -> Result<Vec<String>> {
        let filter = format!("resourceType eq '{}'", arm_type);
        let items = self
            .scope
            .list_query("/resources", RESOURCES_API_VERSION, &[("$filter", filter.as_str())])
            .await?;
        Ok(groups_of(&items))
    }

    fn group_suffix(rg: &str, arm_type: &str) -> String {
        format!("/resourceGroups/{}/providers/{}", rg, arm_type)
    }
}

#[async_trait]
impl AzureService for HybridService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Hybrid
    }

    fn name(&self) -> &str {
        "Hybrid"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        let Some((arm_type, _)) = Self::per_group_type(view) else {
            let page = self.scope.list(CIRCUITS_PATH, HYBRID_API_VERSION).await?;
            return Ok(Self::rows(view, &page, tenant));
        };
        let groups = self.groups_with(arm_type).await?;
        let mut out = Vec::new();
        let mut first_err = None;
        for rg in &groups {
            match self.scope.list(&Self::group_suffix(rg, arm_type), HYBRID_API_VERSION).await {
                Ok(page) => out.extend(Self::rows(view, &page, tenant)),
                Err(e) => first_err = first_err.or(Some(e)),
            }
        }
        match first_err {
            Some(e) if out.is_empty() => Err(e),
            _ => Ok(out),
        }
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let Some((arm_type, what)) = Self::per_group_type(view) else {
            let r = self
                .scope
                .stream(CIRCUITS_PATH, HYBRID_API_VERSION, &[], service_type, "Listing ExpressRoute circuits…", &event_tx, |page| {
                    Self::rows(view, &page, tenant.as_deref())
                })
                .await;
            return finish_stream(service_type, r, &event_tx);
        };
        let _ = event_tx.send(Event::ResourcesPartiallyLoaded {
            service: service_type,
            resources: Vec::new(),
            progress: LoadProgress {
                loaded_count: 0,
                total_count: None,
                status_message: Some(format!("Finding the resource groups with {}…", what)),
            },
        });
        let groups = match self.groups_with(arm_type).await {
            Ok(g) => g,
            Err(e) => return finish_stream(service_type, Err(e), &event_tx),
        };
        let mut total = 0usize;
        let mut failures = Vec::new();
        for rg in &groups {
            let label = format!("Listing {} in {}…", what, rg);
            let r = self
                .scope
                .stream(&Self::group_suffix(rg, arm_type), HYBRID_API_VERSION, &[], service_type, &label, &event_tx, |page| {
                    Self::rows(view, &page, tenant.as_deref())
                })
                .await;
            match r {
                Ok(n) => total += n,
                Err(e) => failures.push((rg.clone(), e)),
            }
        }
        // A group that fails beside one that streamed is a warning; only
        // every group failing is the list's error.
        if !groups.is_empty() && failures.len() == groups.len() {
            return finish_stream(service_type, Err(failures.remove(0).1), &event_tx);
        }
        for (rg, e) in failures {
            let _ = event_tx.send(Event::ResourceLoadWarning { service: service_type, warning: format!("{}: {}", rg, e) });
        }
        finish_stream(service_type, Ok(total), &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, HYBRID_API_VERSION).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::ExpressRouteCircuits);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-hub";

    fn id(path: &str) -> String {
        format!("{}/providers/Microsoft.Network/{}", RG, path)
    }

    fn circuit_json() -> Value {
        json!({
            "id": id("expressRouteCircuits/erc-ams"),
            "name": "erc-ams",
            "location": "westeurope",
            "sku": {"name": "Premium_MeteredData", "tier": "Premium", "family": "MeteredData"},
            "properties": {
                "provisioningState": "Succeeded",
                "circuitProvisioningState": "Enabled",
                "serviceProviderProvisioningState": "Provisioned",
                "serviceKey": "0a1b2c3d-1111-2222-3333-444455556666",
                "activationKey": "fixture-activation",
                "serviceProviderProperties": {"serviceProviderName": "Equinix", "peeringLocation": "Amsterdam", "bandwidthInMbps": 1000},
                "globalReachEnabled": true,
                "authorizations": [
                    {"name": "auth-spoke", "properties": {"authorizationKey": "fixture-auth-key", "authorizationUseStatus": "InUse"}}
                ],
                "peerings": [{
                    "name": "AzurePrivatePeering",
                    "id": id("expressRouteCircuits/erc-ams/peerings/AzurePrivatePeering"),
                    "properties": {
                        "peeringType": "AzurePrivatePeering", "state": "Enabled", "azureASN": 12076, "peerASN": 65010,
                        "primaryPeerAddressPrefix": "172.16.0.0/30", "secondaryPeerAddressPrefix": "172.16.0.4/30",
                        "vlanId": 100, "sharedKey": "fixture-md5",
                        "connections": [{"name": "gr-sin", "properties": {
                            "expressRouteCircuitPeering": {"id": id("expressRouteCircuits/erc-ams/peerings/AzurePrivatePeering")},
                            "peerExpressRouteCircuitPeering": {"id": "/subscriptions/1111/resourceGroups/rg-asia/providers/Microsoft.Network/expressRouteCircuits/erc-sin/peerings/AzurePrivatePeering"},
                            "addressPrefix": "10.255.0.0/29", "authorizationKey": "fixture-gr-key", "circuitConnectionStatus": "Connected"}}]
                    }
                }, {
                    "name": "MicrosoftPeering",
                    "properties": {"peeringType": "MicrosoftPeering", "state": "Enabled", "vlanId": 200, "peerASN": 65020,
                        "microsoftPeeringConfig": {"advertisedPublicPrefixes": ["203.0.113.0/28"], "advertisedPublicPrefixesState": "ValidationNeeded"}}
                }]
            }
        })
    }

    fn gateway_json(name: &str, kind: &str, sku: &str) -> Value {
        json!({
            "id": id(&format!("virtualNetworkGateways/{name}")),
            "name": name,
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "gatewayType": kind, "vpnType": "RouteBased", "vpnGatewayGeneration": "Generation2",
                "sku": {"name": sku, "tier": sku},
                "activeActive": true, "enableBgp": true,
                "ipConfigurations": [{"name": "default", "properties": {
                    "privateIPAllocationMethod": "Dynamic",
                    "subnet": {"id": id("virtualNetworks/vnet-hub/subnets/GatewaySubnet")},
                    "publicIPAddress": {"id": id(&format!("publicIPAddresses/pip-{name}"))}}}],
                "bgpSettings": {"asn": 65515, "bgpPeeringAddress": "10.10.255.4,10.10.255.5", "peerWeight": 0,
                    "bgpPeeringAddresses": [{"ipconfigurationId": id(&format!("virtualNetworkGateways/{name}/ipConfigurations/default")),
                        "defaultBgpIpAddresses": ["10.10.255.4"], "customBgpIpAddresses": [], "tunnelIpAddresses": ["20.1.2.3"]}]},
                "vpnClientConfiguration": {"vpnClientAddressPool": {"addressPrefixes": ["172.31.0.0/24"]},
                    "vpnClientProtocols": ["OpenVPN"], "vpnAuthenticationTypes": ["AAD"],
                    "radiusServerSecret": "fixture-radius",
                    "vpnClientRootCertificates": [{"name": "root-1", "properties": {"publicCertData": "fixture-cert"}}]}
            }
        })
    }

    fn connection_json(name: &str, kind: &str, status: &str) -> Value {
        let mut props = json!({
            "provisioningState": "Succeeded",
            "connectionType": kind,
            "connectionStatus": status,
            "virtualNetworkGateway1": {"id": id("virtualNetworkGateways/vgw-er")},
            "routingWeight": 10,
            "ingressBytesTransferred": 1_610_612_736_i64,
            "egressBytesTransferred": 512,
            "sharedKey": "fixture-psk",
            "authorizationKey": "fixture-redeem"
        });
        if kind == "ExpressRoute" {
            props["peer"] = json!({"id": id("expressRouteCircuits/erc-ams")});
            props["expressRouteGatewayBypass"] = json!(true);
        } else {
            props["localNetworkGateway2"] = json!({"id": id("localNetworkGateways/lgw-office")});
            props["ipsecPolicies"] = json!([{"ikeEncryption": "AES256", "ikeIntegrity": "SHA256", "dhGroup": "DHGroup14",
                "ipsecEncryption": "GCMAES256", "ipsecIntegrity": "GCMAES256", "pfsGroup": "PFS2048",
                "saLifeTimeSeconds": 27000, "saDataSizeKilobytes": 102400000}]);
        }
        json!({"id": id(&format!("connections/{name}")), "name": name, "location": "westeurope", "properties": props})
    }

    fn texts(lines: &[(String, String)]) -> String {
        lines.iter().map(|(a, b)| format!("{a} {b}\n")).collect()
    }

    #[test]
    fn secrets_are_stripped_and_the_service_key_masked() {
        let c = CircuitRow::from_json(&circuit_json(), None).unwrap();
        let raw = c.raw_content().unwrap();
        for (i, needle) in ["fixture-auth-key", "fixture-md5", "fixture-gr-key", "fixture-activation", "444455556666"].iter().enumerate() {
            assert!(!raw.contains(needle), "fixture value {i} left in the circuit JSON");
        }
        assert!(raw.contains("****6666"));
        assert_eq!(c.service_key.as_deref(), Some("****6666"));
        let conn = ConnectionRow::from_json(&connection_json("cn", "IPsec", "Connected"), None).unwrap();
        let raw = conn.raw_content().unwrap();
        assert!(!raw.contains("fixture-psk") && !raw.contains("fixture-redeem"));
        let g = GatewayRow::from_json(&gateway_json("vgw-vpn", "Vpn", "VpnGw2AZ"), None).unwrap();
        let raw = g.raw_content().unwrap();
        assert!(!raw.contains("fixture-radius") && !raw.contains("fixture-cert"));
        assert_eq!(mask_key("short"), "****");
    }

    #[test]
    fn circuit_parses_provider_peerings_and_global_reach() {
        let c = CircuitRow::from_json(&circuit_json(), None).unwrap();
        assert_eq!(c.list_summary().as_deref(), Some("Equinix · Amsterdam · 1 Gbps"));
        assert_eq!(c.ladder(), (ResourceState::Available, "provisioned".into()));
        let peerings = texts(&c.peering_rows());
        assert!(peerings.contains("VLAN 100") && peerings.contains("172.16.0.4/30") && peerings.contains("65010"));
        assert!(peerings.contains("⚠ ValidationNeeded"));
        let links = c.global_reach_links();
        assert_eq!(links.len(), 1);
        assert!(links[0].1.ends_with("/expressRouteCircuits/erc-sin"));
        assert!(c.related().iter().any(|(l, _)| l == "Global Reach peer · erc-sin"));
        let auth = texts(&c.authorization_rows());
        assert!(auth.contains("auth-spoke InUse"));
    }

    #[test]
    fn circuit_state_follows_the_provider() {
        let mut v = circuit_json();
        v["properties"]["serviceProviderProvisioningState"] = json!("NotProvisioned");
        let c = CircuitRow::from_json(&v, None).unwrap();
        assert_eq!(c.ladder(), (ResourceState::Pending, "notprovisioned".into()));
        v["properties"]["circuitProvisioningState"] = json!("Disabled");
        assert_eq!(CircuitRow::from_json(&v, None).unwrap().ladder().0, ResourceState::Stopped);
        v["properties"]["provisioningState"] = json!("Updating");
        assert_eq!(CircuitRow::from_json(&v, None).unwrap().ladder(), (ResourceState::Pending, "updating".into()));
    }

    #[test]
    fn gateway_parses_sku_bgp_and_links() {
        let g = GatewayRow::from_json(&gateway_json("vgw-vpn", "Vpn", "VpnGw2AZ"), None).unwrap();
        assert_eq!(g.list_summary().as_deref(), Some("Vpn · VpnGw2AZ · active-active · ASN 65515"));
        assert!(g.zone_redundancy().starts_with("yes"));
        assert_eq!(g.vnet_id(), Some(id("virtualNetworks/vnet-hub")));
        let rel = g.related();
        assert!(rel.iter().any(|(l, _)| l == "Subnet · vnet-hub/GatewaySubnet"));
        assert!(rel.iter().any(|(l, _)| l == "Public IP · pip-vgw-vpn"));
        assert!(texts(&g.bgp_rows()).contains("20.1.2.3"));
        let p2s = texts(&g.point_to_site_rows());
        assert!(p2s.contains("172.31.0.0/24") && p2s.contains("root-1"));
        assert_eq!(g.ladder().1, "");
        let er = GatewayRow::from_json(&gateway_json("vgw-er", "ExpressRoute", "Standard"), None).unwrap();
        assert!(er.zone_redundancy().starts_with("no"));
        assert!(!texts(&er.ip_configuration_rows()).contains('⚠'));
    }

    #[test]
    fn connection_status_drives_the_state() {
        let ok = ConnectionRow::from_json(&connection_json("cn-er", "ExpressRoute", "Connected"), None).unwrap();
        assert_eq!(ok.ladder(), (ResourceState::Available, "connected".into()));
        assert_eq!(ok.circuit_id, Some(id("expressRouteCircuits/erc-ams")));
        assert_eq!(ok.list_summary().as_deref(), Some("ExpressRoute → erc-ams"));
        assert!(texts(&ok.configuration_rows()).contains("Ingress 1.5 GiB"));
        let down = ConnectionRow::from_json(&connection_json("cn-vpn", "IPsec", "NotConnected"), None).unwrap();
        assert_eq!(down.ladder(), (ResourceState::Unavailable, "notconnected".into()));
        assert!(texts(&down.configuration_rows()).contains("⚠ NotConnected"));
        assert!(texts(&down.ipsec_rows()).contains("GCMAES256"));
        let unknown = ConnectionRow::from_json(&connection_json("cn-x", "IPsec", "Unknown"), None).unwrap();
        assert_eq!(unknown.ladder().0, ResourceState::Pending);
        let rel = down.related();
        assert!(rel.iter().any(|(l, _)| l == "Local network gateway · lgw-office"));
        assert!(rel.iter().any(|(l, _)| l == "VNet gateway · vgw-er"));
    }

    #[test]
    fn warm_connections_feed_the_circuit_gateway_and_local_gateway() {
        let warm: Vec<Box<dyn Resource>> = vec![
            Box::new(ConnectionRow::from_json(&connection_json("cn-er", "ExpressRoute", "Connected"), None).unwrap()),
            Box::new(ConnectionRow::from_json(&connection_json("cn-vpn", "IPsec", "NotConnected"), None).unwrap()),
        ];
        let circuit = id("expressRouteCircuits/erc-ams");
        let rows = texts(&connection_rows(&circuit, Some(&warm)));
        assert!(rows.contains("Connection · cn-er") && !rows.contains("cn-vpn"));
        assert!(rows.contains("Other end · vgw-er"));
        let gw = texts(&connection_rows(&id("virtualNetworkGateways/vgw-er"), Some(&warm)));
        assert!(gw.contains("cn-er") && gw.contains("cn-vpn"));
        let lgw = texts(&connection_rows(&id("localNetworkGateways/lgw-office"), Some(&warm)));
        assert!(lgw.contains("cn-vpn") && !lgw.contains("cn-er"));
        assert!(texts(&connection_rows(&circuit, None)).contains("not loaded"));
        let c = CircuitRow::from_json(&circuit_json(), None).unwrap();
        let rel = circuit_section_lines(&c, CircuitDetailSection::Related, Some(&warm));
        assert!(rel.iter().any(|(l, _)| l == "Connection · cn-er"));
    }

    #[test]
    fn local_gateway_parses_its_address_space() {
        let v = json!({"id": id("localNetworkGateways/lgw-office"), "name": "lgw-office", "location": "westeurope",
            "properties": {"provisioningState": "Succeeded", "gatewayIpAddress": "203.0.113.24",
                "localNetworkAddressSpace": {"addressPrefixes": ["192.168.0.0/16", "10.200.0.0/16"]},
                "bgpSettings": {"asn": 65050, "bgpPeeringAddress": "192.168.255.1"}}});
        let l = LocalGatewayRow::from_json(&v, None).unwrap();
        assert_eq!(l.list_summary().as_deref(), Some("203.0.113.24 · 192.168.0.0/16 +1"));
        assert!(texts(&l.on_premises_rows()).contains("BGP ASN 65050"));
        assert!(l.search_text().contains("10.200.0.0/16"));
    }

    #[test]
    fn groups_are_distinct_case_insensitively() {
        let items = vec![
            json!({"id": "/subscriptions/0/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworkGateways/a"}),
            json!({"id": "/subscriptions/0/resourceGroups/RG-HUB/providers/Microsoft.Network/virtualNetworkGateways/b"}),
            json!({"id": "/subscriptions/0/resourceGroups/rg-dr/providers/Microsoft.Network/virtualNetworkGateways/c"}),
        ];
        assert_eq!(groups_of(&items), vec!["rg-hub".to_string(), "rg-dr".to_string()]);
        assert_eq!(
            HybridService::group_suffix("rg-hub", GATEWAY_TYPE),
            "/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworkGateways"
        );
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        for d in [&CIRCUIT_SECTIONS, &GATEWAY_SECTIONS, &CONNECTION_SECTIONS, &LOCAL_GATEWAY_SECTIONS] {
            let labels: Vec<&str> = d.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels[0], "Overview");
            assert_eq!(&labels[labels.len() - 4..], &["Access", "Activity", "Related", "Tags"]);
            assert!(labels.len() <= 10, "digit keys: {labels:?}");
        }
    }
}
