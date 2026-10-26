//! Private Link services (#143), an Edge sub-tab (`@pls`): the provider
//! side of Private Link. A service sits behind a Standard internal load
//! balancer's frontend(s) and NATs each consumer's traffic through its own
//! IP configurations in a subnet; consumers reach it through a private
//! endpoint in their own VNet (any subscription, any tenant), which the
//! service lists as a private endpoint connection. Front Door Premium
//! origins reach a service the same way (`edge.rs`'s Private Link target
//! jumps here, as does a private endpoint's target).
//!
//! One subscription-wide list (`Microsoft.Network/privateLinkServices`),
//! every section from the list body. Load balancer frontends and consumer
//! endpoints are matched in the warm lists (never a call): a frontend's
//! private IP and subnet from the warm load balancers, a consumer endpoint
//! jumps only when the warm private endpoints list has it (it is often in
//! another subscription or tenant, so it is text otherwise).

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::services::edge::top_level_of;
use crate::azure::services::network_edge::LoadBalancerRow;
use crate::azure::services::network_private::PrivateEndpointRow;
use crate::azure::services::{arm_row, json, overview_rows, related_lines, tag_rows, ArmBase};
use serde_json::Value;

pub const PRIVATE_LINK_SERVICES_PATH: &str = "/providers/Microsoft.Network/privateLinkServices";

crate::sections! {
    pub enum PrivateLinkServiceDetailSection,
    pub static PRIVATE_LINK_SERVICE_SECTIONS = [
        Overview "Overview",
        Frontend "Frontend",
        Visibility "Visibility",
        Connections "Connections",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

/// One NAT IP configuration: the source address consumers' traffic is
/// translated to.
#[derive(Debug, Clone)]
pub struct NatIpConfig {
    pub name: String,
    pub private_ip: Option<String>,
    pub allocation: Option<String>,
    pub version: Option<String>,
    pub primary: Option<bool>,
    pub subnet_id: Option<String>,
}

/// One consumer's private endpoint connection.
#[derive(Debug, Clone)]
pub struct PlsConnection {
    pub name: String,
    pub endpoint_id: Option<String>,
    pub endpoint_location: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub actions_required: Option<String>,
    pub link_identifier: Option<String>,
}

impl PlsConnection {
    pub fn is_approved(&self) -> bool {
        self.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("approved"))
    }
}

#[derive(Debug, Clone)]
pub struct PrivateLinkServiceRow {
    pub base: ArmBase,
    pub alias: Option<String>,
    /// The load balancer frontend IP configuration ids.
    pub frontend_ids: Vec<String>,
    pub nat_ips: Vec<NatIpConfig>,
    pub nic_ids: Vec<String>,
    pub visibility: Vec<String>,
    pub auto_approval: Vec<String>,
    pub fqdns: Vec<String>,
    pub proxy_protocol: Option<bool>,
    pub destination_ip: Option<String>,
    pub access_mode: Option<String>,
    pub connections: Vec<PlsConnection>,
}

impl PrivateLinkServiceRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PrivateLinkServiceRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |s: &str| format!("/properties/{}", s);
        Some(PrivateLinkServiceRow {
            alias: json::str_at(v, &p("alias")),
            frontend_ids: json::ids_at(v, &p("loadBalancerFrontendIpConfigurations")),
            nat_ips: json::arr(v, &p("ipConfigurations"))
                .iter()
                .map(|c| NatIpConfig {
                    name: json::text(c, "/name"),
                    private_ip: json::str_at(c, "/properties/privateIPAddress"),
                    allocation: json::str_at(c, "/properties/privateIPAllocationMethod"),
                    version: json::str_at(c, "/properties/privateIPAddressVersion"),
                    primary: json::bool_at(c, "/properties/primary"),
                    subnet_id: json::arm_id(json::id_at(c, "/properties/subnet")),
                })
                .collect(),
            nic_ids: json::ids_at(v, &p("networkInterfaces")),
            visibility: json::strings_at(v, &p("visibility/subscriptions")),
            auto_approval: json::strings_at(v, &p("autoApproval/subscriptions")),
            fqdns: json::strings_at(v, &p("fqdns")),
            proxy_protocol: json::bool_at(v, &p("enableProxyProtocol")),
            destination_ip: json::str_at(v, &p("destinationIPAddress")),
            access_mode: json::str_at(v, &p("accessMode")),
            connections: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .map(|c| PlsConnection {
                    name: json::text(c, "/name"),
                    endpoint_id: json::arm_id(json::id_at(c, "/properties/privateEndpoint")),
                    endpoint_location: json::str_at(c, "/properties/privateEndpointLocation"),
                    status: json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    description: json::str_at(c, "/properties/privateLinkServiceConnectionState/description"),
                    actions_required: json::str_at(c, "/properties/privateLinkServiceConnectionState/actionsRequired"),
                    link_identifier: json::str_at(c, "/properties/linkIdentifier"),
                })
                .collect(),
            base,
        })
    }

    /// The load balancers behind the frontends, each once.
    pub fn load_balancer_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for f in &self.frontend_ids {
            if let Some(lb) = top_level_of(f) {
                if !out.iter().any(|x| x.eq_ignore_ascii_case(&lb)) {
                    out.push(lb);
                }
            }
        }
        out
    }

    fn nat_subnets(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in self.nat_ips.iter().filter_map(|c| c.subnet_id.clone()) {
            if !out.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
                out.push(s);
            }
        }
        out
    }

    fn pending(&self) -> usize {
        self.connections.iter().filter(|c| !c.is_approved()).count()
    }

    fn visibility_label(&self) -> String {
        subscriptions_label(&self.visibility, "only this subscription (and those with RBAC on it)")
    }

    fn auto_approval_label(&self) -> String {
        subscriptions_label(&self.auto_approval, "none: every connection waits for approval")
    }

    pub fn frontend_rows(&self, lbs: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.frontend_ids.is_empty() {
            match &self.destination_ip {
                Some(ip) => lines.push(("Destination IP".into(), format!("{} (direct connect, no load balancer)", ip))),
                None => lines.push((String::new(), "No load balancer frontend".into())),
            }
        }
        for f in &self.frontend_ids {
            let lb = top_level_of(f).unwrap_or_else(|| f.clone());
            lines.push((format!("Load balancer · {} / {}", name_of_id(&lb), name_of_id(f)), lb.clone()));
            let warm = lbs.and_then(|l| {
                l.iter()
                    .filter_map(|r| r.as_any().downcast_ref::<LoadBalancerRow>())
                    .find(|r| r.base.id.eq_ignore_ascii_case(&lb))
            });
            match (lbs, warm) {
                (None, _) => lines.push((String::new(), "  · load @lb for the frontend's address".into())),
                (Some(_), None) => lines.push((String::new(), "  · not in this subscription's load balancers".into())),
                (Some(_), Some(row)) => {
                    let fe = row.frontends.iter().find(|x| x.name.eq_ignore_ascii_case(name_of_id(f)));
                    match fe {
                        Some(fe) => {
                            lines.push(("  Private IP".into(), json::opt(fe.private_ip.clone())));
                            if let Some(s) = &fe.subnet_id {
                                lines.push((format!("  Subnet · {}", subnet_label(s)), s.clone()));
                            }
                            if fe.public_ip_id.is_some() {
                                lines.push(("  ⚠".into(), "a public frontend: Private Link needs an internal one".into()));
                            }
                        }
                        None => lines.push((String::new(), "  · frontend not found on the load balancer".into())),
                    }
                }
            }
        }
        lines.push((String::new(), String::new()));
        lines.push(("NAT IP configurations".into(), self.nat_ips.len().to_string()));
        for c in &self.nat_ips {
            let primary = if c.primary == Some(true) { " (primary)" } else { "" };
            lines.push((
                format!("  {}{}", c.name, primary),
                format!(
                    "{} · {}{}",
                    json::opt(c.private_ip.clone()),
                    json::opt(c.allocation.clone()),
                    c.version.as_deref().map(|v| format!(" · {}", v)).unwrap_or_default()
                ),
            ));
            if let Some(s) = &c.subnet_id {
                lines.push((format!("    Subnet · {}", subnet_label(s)), s.clone()));
            }
        }
        lines.push((
            "Proxy protocol".into(),
            match self.proxy_protocol {
                Some(true) => "on (the backend must parse the PROXY v2 header for the consumer's link id)".into(),
                Some(false) => "off".into(),
                None => "-".into(),
            },
        ));
        for n in &self.nic_ids {
            lines.push((format!("NIC · {}", name_of_id(n)), n.clone()));
        }
        lines
    }

    pub fn visibility_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Alias".into(), json::opt(self.alias.clone())),
            (String::new(), "· consumers connect by this alias (or the id); it is text, not a resource".into()),
            ("Visibility".into(), self.visibility_label()),
        ];
        for s in self.visibility.iter().filter(|s| s.as_str() != "*") {
            lines.push(("  ".into(), s.clone()));
        }
        lines.push(("Auto-approval".into(), self.auto_approval_label()));
        for s in &self.auto_approval {
            lines.push(("  ".into(), s.clone()));
        }
        if let Some(m) = &self.access_mode {
            lines.push(("Access mode".into(), m.clone()));
        }
        lines.push(("FQDNs".into(), json::join(&self.fqdns)));
        lines
    }

    pub fn connection_rows(&self, endpoints: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
        if self.connections.is_empty() {
            return vec![(String::new(), "No private endpoint connections".into())];
        }
        let mut lines = Vec::new();
        for c in &self.connections {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((c.name.clone(), String::new()));
            if let Some(pe) = &c.endpoint_id {
                let warm = endpoints.is_some_and(|l| {
                    l.iter().any(|r| r.as_any().is::<PrivateEndpointRow>() && r.id().eq_ignore_ascii_case(pe))
                });
                if warm {
                    lines.push((format!("  Consumer endpoint · {}", name_of_id(pe)), pe.clone()));
                } else {
                    // Often another subscription or tenant: text, not a jump.
                    let why = if endpoints.is_some() { "not in this subscription's private endpoints" } else { "load @pe to match it" };
                    lines.push(("  Consumer endpoint".into(), format!("{} ({}): {}", name_of_id(pe), why, pe.trim_start_matches('/'))));
                }
            }
            if let Some(l) = &c.endpoint_location {
                lines.push(("  Endpoint location".into(), l.clone()));
            }
            let status = json::opt(c.status.clone());
            lines.push((
                "  Status".into(),
                if c.is_approved() { status } else { format!("⚠ {} (traffic flows only once approved)", status) },
            ));
            if let Some(d) = c.description.as_ref().filter(|d| !d.is_empty()) {
                lines.push(("  Description".into(), d.clone()));
            }
            if let Some(a) = c.actions_required.as_ref().filter(|a| !a.is_empty() && !a.eq_ignore_ascii_case("none")) {
                lines.push(("  Actions required".into(), a.clone()));
            }
            if let Some(id) = &c.link_identifier {
                lines.push(("  Link id".into(), id.clone()));
            }
        }
        lines
    }

    /// Related plus each consumer endpoint the warm list has.
    pub fn related_with(&self, endpoints: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
        let mut rel = self.related();
        for c in &self.connections {
            let Some(pe) = &c.endpoint_id else { continue };
            let warm = endpoints.is_some_and(|l| l.iter().any(|r| r.id().eq_ignore_ascii_case(pe)));
            if warm && !rel.iter().any(|(_, x)| x.eq_ignore_ascii_case(pe)) {
                rel.push((format!("Consumer endpoint {}", name_of_id(pe)), pe.clone()));
            }
        }
        related_lines(rel)
    }
}

/// `vnet/subnet`.
fn subnet_label(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    match parts.iter().rposition(|p| p.eq_ignore_ascii_case("subnets")) {
        Some(i) if i >= 1 && i + 1 < parts.len() => format!("{}/{}", parts[i - 1], parts[i + 1]),
        _ => name_of_id(id).to_string(),
    }
}

fn subscriptions_label(subs: &[String], none: &str) -> String {
    match subs {
        [] => none.into(),
        [one] if one == "*" => "anyone with the alias (*)".into(),
        [_] => "1 subscription".into(),
        many => format!("{} subscriptions", many.len()),
    }
}

impl Resource for PrivateLinkServiceRow {
    arm_row!("Private Link service");
    /// `lb-x · 2 connections · 1 pending`.
    fn list_summary(&self) -> Option<String> {
        let lbs: Vec<String> = self.load_balancer_ids().iter().map(|l| name_of_id(l).to_string()).collect();
        let n = self.connections.len();
        crate::azure::resource::summary_of([
            (!lbs.is_empty()).then(|| lbs.join(", ")),
            Some(if n == 1 { "1 connection".to_string() } else { format!("{} connections", n) }),
            (self.pending() > 0).then(|| format!("{} not approved", self.pending())),
        ])
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PRIVATE_LINK_SERVICE_SECTIONS)
    }
    /// The alias and NAT IPs are searchable.
    fn search_text(&self) -> String {
        let mut parts = vec![
            self.base.id.clone(),
            self.base.name.clone(),
            self.resource_group().unwrap_or("").to_string(),
            self.alias.clone().unwrap_or_default(),
        ];
        parts.extend(self.nat_ips.iter().filter_map(|c| c.private_ip.clone()));
        parts.extend(self.fqdns.iter().cloned());
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        let lbs: Vec<String> = self.load_balancer_ids().iter().map(|l| name_of_id(l).to_string()).collect();
        let nat: Vec<String> = self.nat_ips.iter().filter_map(|c| c.private_ip.clone()).collect();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Alias".into(), json::opt(self.alias.clone())),
            ("Load balancer".into(), json::join(&lbs)),
            ("NAT IPs".into(), json::join(&nat)),
            ("Visibility".into(), self.visibility_label()),
            ("Auto-approval".into(), self.auto_approval_label()),
            ("Proxy protocol".into(), json::yes_no(self.proxy_protocol)),
            ("Connections".into(), format!("{} ({} not approved)", self.connections.len(), self.pending())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for lb in self.load_balancer_ids() {
            v.push((format!("Load balancer {}", name_of_id(&lb)), lb));
        }
        for s in self.nat_subnets() {
            v.push((format!("NAT subnet {}", subnet_label(&s)), s));
        }
        for n in &self.nic_ids {
            v.push((format!("NIC {}", name_of_id(n)), n.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network private-link-service show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn private_link_service_section_lines(
    r: &PrivateLinkServiceRow,
    section: PrivateLinkServiceDetailSection,
    lbs: Option<&[Box<dyn Resource>]>,
    endpoints: Option<&[Box<dyn Resource>]>,
) -> Vec<(String, String)> {
    match section {
        PrivateLinkServiceDetailSection::Overview => overview_rows(r),
        PrivateLinkServiceDetailSection::Frontend => r.frontend_rows(lbs),
        PrivateLinkServiceDetailSection::Visibility => r.visibility_rows(),
        PrivateLinkServiceDetailSection::Connections => r.connection_rows(endpoints),
        PrivateLinkServiceDetailSection::Access => crate::azure::services::rendered_by_app(),
        PrivateLinkServiceDetailSection::Activity => crate::azure::services::rendered_by_app(),
        PrivateLinkServiceDetailSection::Related => r.related_with(endpoints),
        PrivateLinkServiceDetailSection::Tags => tag_rows(r.tags()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-hub/providers/Microsoft.Network";

    fn pls_json() -> Value {
        json!({
            "id": format!("{}/privateLinkServices/pls-orders", RG),
            "name": "pls-orders",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "alias": "pls-orders.0f1e2d3c-aaaa-bbbb-cccc-000000000000.westeurope.azure.privatelinkservice",
                "loadBalancerFrontendIpConfigurations": [{"id": format!("{}/loadBalancers/lb-pls/frontendIPConfigurations/fe-pls", RG)}],
                "ipConfigurations": [{"name": "nat-1", "properties": {"privateIPAddress": "10.10.15.10",
                    "privateIPAllocationMethod": "Static", "primary": true, "privateIPAddressVersion": "IPv4",
                    "subnet": {"id": format!("{}/virtualNetworks/vnet-hub/subnets/snet-pls", RG)}}}],
                "visibility": {"subscriptions": ["1111", "2222"]},
                "autoApproval": {"subscriptions": ["1111"]},
                "enableProxyProtocol": false,
                "privateEndpointConnections": [
                    {"name": "pe-a.conn", "properties": {"privateEndpoint": {"id": "/subscriptions/1111/resourceGroups/rg-a/providers/Microsoft.Network/privateEndpoints/pe-a"},
                        "privateLinkServiceConnectionState": {"status": "Approved", "description": "Auto-approved"}}},
                    {"name": "pe-b.conn", "properties": {"privateEndpoint": {"id": "/subscriptions/3333/resourceGroups/rg-b/providers/Microsoft.Network/privateEndpoints/pe-b"},
                        "privateLinkServiceConnectionState": {"status": "Pending", "description": "please approve"}}}
                ]
            }
        })
    }

    #[test]
    fn a_private_link_service_parses_and_flags_unapproved_connections() {
        let r = PrivateLinkServiceRow::from_json(&pls_json(), None).unwrap();
        assert_eq!(r.load_balancer_ids(), vec![format!("{}/loadBalancers/lb-pls", RG)]);
        assert_eq!(r.list_summary().as_deref(), Some("lb-pls · 2 connections · 1 not approved"));
        let lines = r.connection_rows(None);
        assert!(lines.iter().any(|(k, v)| k == "  Status" && v.starts_with("⚠ Pending")));
        assert!(lines.iter().any(|(k, v)| k == "  Status" && v == "Approved"));
        // A cold endpoint list: the consumer is text, never a jump.
        assert!(lines.iter().all(|(_, v)| !v.starts_with("/subscriptions/")));
        let rel = r.related();
        assert!(rel.iter().any(|(k, _)| k == "NAT subnet vnet-hub/snet-pls"));
    }

    #[test]
    fn section_labels_follow_the_convention() {
        let labels: Vec<&str> = PRIVATE_LINK_SERVICE_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Frontend", "Visibility", "Connections", "Access", "Activity", "Related", "Tags"]);
    }
}
