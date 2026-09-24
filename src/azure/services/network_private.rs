//! The Network service's private-networking types (issue #8): private
//! endpoints and private DNS zones, each one subscription-wide list and a
//! sub-tab of Network. Key Vault and Foundry already list private
//! endpoint ids in Related; with `for_arm_id` routing them they jump.
//!
//! An endpoint's target (`privateLinkServiceId`) is the reverse link:
//! Enter on it lands on the vault, account or storage account it fronts
//! when nebaz browses that type. A zone's records and VNet links are
//! per-zone lists, so they are lazy sections.
//!
//! Private DNS zones have `location: global`; `Location::admits` lets
//! global rows through every location filter.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::services::{arm_row, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase};
use crate::lazy::Lazy;
use serde_json::Value;

pub const PRIVATE_ENDPOINTS_PATH: &str = "/providers/Microsoft.Network/privateEndpoints";
pub const PRIVATE_DNS_ZONES_PATH: &str = "/providers/Microsoft.Network/privateDnsZones";
/// Private DNS is its own spec with its own versions (checked against
/// azure-rest-api-specs, 2026-09-24); the rest of Network is on
/// `NETWORK_API_VERSION`.
pub const PRIVATE_DNS_API_VERSION: &str = "2024-06-01";

crate::sections! {
    pub enum PrivateEndpointDetailSection,
    pub static PRIVATE_ENDPOINT_SECTIONS = [
        Overview "Overview",
        Connection "Connection",
        Dns "DNS",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum PrivateDnsZoneDetailSection,
    pub static PRIVATE_DNS_ZONE_SECTIONS = [
        Overview "Overview",
        Records "Records" => crate::app::App::trigger_dns_records,
        VnetLinks "VNet links" => crate::app::App::trigger_dns_vnet_links,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Private endpoint ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivateLinkConnection {
    pub name: String,
    /// The resource the endpoint fronts.
    pub target_id: Option<String>,
    pub group_ids: Vec<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    /// From `manualPrivateLinkServiceConnections`: the target's owner had
    /// to approve it.
    pub manual: bool,
}

#[derive(Debug, Clone)]
pub struct PrivateEndpointRow {
    pub base: ArmBase,
    pub subnet_id: Option<String>,
    pub nic_ids: Vec<String>,
    pub connections: Vec<PrivateLinkConnection>,
    /// `(fqdn, ip addresses)`.
    pub dns_configs: Vec<(String, Vec<String>)>,
}

impl PrivateEndpointRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PrivateEndpointRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let connection = |c: &Value, manual: bool| PrivateLinkConnection {
            name: json::text(c, "/name"),
            target_id: json::arm_id(json::str_at(c, "/properties/privateLinkServiceId")),
            group_ids: json::strings_at(c, "/properties/groupIds"),
            status: json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
            description: json::str_at(c, "/properties/privateLinkServiceConnectionState/description"),
            manual,
        };
        let mut connections: Vec<PrivateLinkConnection> = json::arr(v, &format!("{}/privateLinkServiceConnections", p))
            .iter()
            .map(|c| connection(c, false))
            .collect();
        connections.extend(
            json::arr(v, &format!("{}/manualPrivateLinkServiceConnections", p))
                .iter()
                .map(|c| connection(c, true)),
        );
        Some(PrivateEndpointRow {
            subnet_id: json::arm_id(json::id_at(v, &format!("{}/subnet", p))),
            nic_ids: json::ids_at(v, &format!("{}/networkInterfaces", p)),
            connections,
            dns_configs: json::arr(v, &format!("{}/customDnsConfigs", p))
                .iter()
                .map(|d| (json::text(d, "/fqdn"), json::strings_at(d, "/ipAddresses")))
                .collect(),
            base,
        })
    }

    /// The first connection's status is the endpoint's runtime state: an
    /// endpoint has one connection in practice.
    fn ladder(&self) -> (ResourceState, String) {
        let status = self.connections.iter().find_map(|c| c.status.clone());
        let runtime = status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "approved" => ResourceState::Available,
                "pending" => ResourceState::Pending,
                "rejected" | "disconnected" => ResourceState::Unavailable,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn targets(&self) -> Vec<&str> {
        self.connections.iter().filter_map(|c| c.target_id.as_deref()).collect()
    }
}

impl Resource for PrivateEndpointRow {
    arm_row!("Private Endpoint");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PRIVATE_ENDPOINT_SECTIONS)
    }
    /// The target's name is searchable: `/kv-prod` finds the vault's
    /// endpoints.
    fn search_text(&self) -> String {
        let targets: Vec<&str> = self.targets().into_iter().map(name_of_id).collect();
        let fqdns: Vec<&str> = self.dns_configs.iter().map(|(f, _)| f.as_str()).collect();
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            targets.join(" "),
            fqdns.join(" "),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let first = self.connections.first();
        let ips: Vec<String> = self.dns_configs.iter().flat_map(|(_, ips)| ips.clone()).collect();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            (
                "Target".into(),
                first.and_then(|c| c.target_id.as_deref()).map(name_of_id).unwrap_or("-").to_string(),
            ),
            ("Sub-resource".into(), first.map(|c| json::join(&c.group_ids)).unwrap_or_else(|| "-".into())),
            ("Status".into(), json::opt(first.and_then(|c| c.status.clone()))),
            ("Subnet".into(), self.subnet_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("Private IPs".into(), json::join(&ips)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for t in self.targets() {
            v.push((format!("Target {}", name_of_id(t)), t.to_string()));
        }
        if let Some(s) = &self.subnet_id {
            v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
        }
        for n in &self.nic_ids {
            v.push((format!("NIC {}", name_of_id(n)), n.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network private-endpoint show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn private_endpoint_section_lines(
    r: &PrivateEndpointRow,
    section: PrivateEndpointDetailSection,
) -> Vec<(String, String)> {
    match section {
        PrivateEndpointDetailSection::Overview => overview_rows(r),
        PrivateEndpointDetailSection::Connection => {
            let mut lines = Vec::new();
            if r.connections.is_empty() {
                lines.push((String::new(), "No connections".into()));
            }
            for c in &r.connections {
                lines.push((String::new(), String::new()));
                lines.push((c.name.clone(), String::new()));
                if let Some(t) = &c.target_id {
                    lines.push((format!("  Target · {}", name_of_id(t)), t.clone()));
                }
                lines.push(("  Sub-resource".into(), json::join(&c.group_ids)));
                lines.push(("  Status".into(), json::opt(c.status.clone())));
                if let Some(d) = c.description.as_ref().filter(|d| !d.is_empty()) {
                    lines.push(("  Description".into(), d.clone()));
                }
                lines.push((
                    "  Approval".into(),
                    if c.manual { "manual (the target's owner approves)" } else { "automatic" }.into(),
                ));
            }
            lines
        }
        PrivateEndpointDetailSection::Dns => {
            if r.dns_configs.is_empty() {
                return vec![
                    (String::new(), "No custom DNS configs".into()),
                    (String::new(), "· names resolve through a private DNS zone group on the endpoint".into()),
                ];
            }
            r.dns_configs
                .iter()
                .map(|(fqdn, ips)| (fqdn.clone(), json::join(ips)))
                .collect()
        }
        PrivateEndpointDetailSection::Related => related_rows(r),
        PrivateEndpointDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Private DNS zone ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivateDnsZoneRow {
    pub base: ArmBase,
    pub record_sets: Option<i64>,
    pub max_record_sets: Option<i64>,
    pub vnet_links: Option<i64>,
    pub registration_links: Option<i64>,
}

impl PrivateDnsZoneRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PrivateDnsZoneRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(PrivateDnsZoneRow {
            record_sets: json::int_at(v, &format!("{}/numberOfRecordSets", p)),
            max_record_sets: json::int_at(v, &format!("{}/maxNumberOfRecordSets", p)),
            vnet_links: json::int_at(v, &format!("{}/numberOfVirtualNetworkLinks", p)),
            registration_links: json::int_at(v, &format!("{}/numberOfVirtualNetworkLinksWithRegistration", p)),
            base,
        })
    }

    /// `-g {rg} -z {zone} --subscription {sub}`, what the zone's child
    /// list commands take.
    fn zone_args(&self) -> Option<String> {
        Some(format!(
            "-g {} -z {} --subscription {}",
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(&self.base.name),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for PrivateDnsZoneRow {
    arm_row!("Private DNS Zone");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PRIVATE_DNS_ZONE_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        let records = match (self.record_sets, self.max_record_sets) {
            (Some(n), Some(max)) => format!("{} of {}", n, max),
            (n, _) => json::num(n),
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Record sets".into(), records),
            ("VNet links".into(), json::num(self.vnet_links)),
            ("  with auto-registration".into(), json::num(self.registration_links)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network private-dns zone show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn private_dns_zone_section_lines(
    r: &PrivateDnsZoneRow,
    section: PrivateDnsZoneDetailSection,
    records: Option<&Lazy<Vec<Value>>>,
    links: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        PrivateDnsZoneDetailSection::Overview => overview_rows(r),
        PrivateDnsZoneDetailSection::Records => lazy_list_rows(records, "Records", |items| record_rows(items, r)),
        PrivateDnsZoneDetailSection::VnetLinks => lazy_list_rows(links, "VNet links", |items| vnet_link_rows(items, r)),
        PrivateDnsZoneDetailSection::Related => {
            let mut lines = related_rows(r);
            lines.push((String::new(), "· linked VNets are in the VNet links section".into()));
            lines
        }
        PrivateDnsZoneDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// A record set's values, whatever its type.
fn record_values(rs: &Value) -> Vec<String> {
    let p = "/properties";
    let pick = |arr: &str, field: &str| -> Vec<String> {
        json::arr(rs, &format!("{}/{}", p, arr))
            .iter()
            .filter_map(|r| json::str_at(r, &format!("/{}", field)))
            .collect()
    };
    let mut values = pick("aRecords", "ipv4Address");
    values.extend(pick("aaaaRecords", "ipv6Address"));
    values.extend(json::str_at(rs, &format!("{}/cnameRecord/cname", p)));
    values.extend(pick("ptrRecords", "ptrdname"));
    for mx in json::arr(rs, &format!("{}/mxRecords", p)) {
        values.push(format!("{} {}", json::text(&mx, "/preference"), json::text(&mx, "/exchange")));
    }
    for srv in json::arr(rs, &format!("{}/srvRecords", p)) {
        values.push(format!(
            "{} {} {} {}",
            json::text(&srv, "/priority"),
            json::text(&srv, "/weight"),
            json::text(&srv, "/port"),
            json::text(&srv, "/target")
        ));
    }
    for txt in json::arr(rs, &format!("{}/txtRecords", p)) {
        values.push(json::strings_at(&txt, "/value").join(""));
    }
    if let Some(host) = json::str_at(rs, &format!("{}/soaRecord/host", p)) {
        values.push(format!("{} {}", host, json::text(rs, &format!("{}/soaRecord/email", p))));
    }
    values
}

/// The Records section body from the zone's `ALL` record-set list.
pub fn record_rows(items: &[Value], r: &PrivateDnsZoneRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No record sets".into()));
    }
    for rs in items {
        // `Microsoft.Network/privateDnsZones/A` → `A`.
        let kind = json::text(rs, "/type").rsplit('/').next().unwrap_or("-").to_uppercase();
        let auto = if json::bool_at(rs, "/properties/isAutoRegistered") == Some(true) {
            " · auto-registered"
        } else {
            ""
        };
        lines.push((
            json::text(rs, "/name"),
            format!(
                "{} {} s → {}{}",
                kind,
                json::text(rs, "/properties/ttl"),
                json::join(&record_values(rs)),
                auto
            ),
        ));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az network private-dns record-set list {}", r.zone_args().unwrap_or_default()),
    ));
    lines
}

/// The VNet links section body: each linked VNet's id is the value, so
/// Enter jumps to it.
pub fn vnet_link_rows(items: &[Value], r: &PrivateDnsZoneRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No VNet links: nothing resolves this zone".into()));
    }
    for link in items {
        let p = "/properties";
        let vnet = json::arm_id(json::id_at(link, &format!("{}/virtualNetwork", p)));
        lines.push((String::new(), String::new()));
        match &vnet {
            Some(id) => lines.push((format!("{} · {}", json::text(link, "/name"), name_of_id(id)), id.clone())),
            None => lines.push((json::text(link, "/name"), String::new())),
        }
        lines.push((
            "  Auto-registration".into(),
            json::yes_no(json::bool_at(link, &format!("{}/registrationEnabled", p))),
        ));
        lines.push(("  State".into(), json::text(link, &format!("{}/virtualNetworkLinkState", p))));
        if let Some(policy) = json::str_at(link, &format!("{}/resolutionPolicy", p)) {
            lines.push(("  Resolution policy".into(), policy));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az network private-dns link vnet list {}", r.zone_args().unwrap_or_default()),
    ));
    lines
}

/// The ARM path of a zone's child list (`ALL` record sets,
/// `virtualNetworkLinks`).
pub fn zone_child_path(zone_id: &str, child: &str) -> String {
    format!("{}/{}", zone_id.trim_end_matches('/'), child)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-net";

    fn pe_json(status: &str, manual: bool) -> Value {
        let conn = serde_json::json!([{
            "name": "kv-conn",
            "properties": {
                "privateLinkServiceId": "/subscriptions/0000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-prod",
                "groupIds": ["vault"],
                "privateLinkServiceConnectionState": {"status": status, "description": "Auto-Approved"}
            }
        }]);
        let (auto, man) = if manual { (serde_json::json!([]), conn) } else { (conn, serde_json::json!([])) };
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-kv", RG),
            "name": "pe-kv",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "subnet": {"id": format!("{}/providers/Microsoft.Network/virtualNetworks/v/subnets/pe", RG)},
                "networkInterfaces": [{"id": format!("{}/providers/Microsoft.Network/networkInterfaces/pe-kv.nic.1", RG)}],
                "privateLinkServiceConnections": auto,
                "manualPrivateLinkServiceConnections": man,
                "customDnsConfigs": [{"fqdn": "kv-prod.privatelink.example", "ipAddresses": ["10.0.5.4"]}]
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for desc in [&PRIVATE_ENDPOINT_SECTIONS, &PRIVATE_DNS_ZONE_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(labels[labels.len() - 2], "Related");
            assert_eq!(labels.last(), Some(&"Tags"));
        }
    }

    #[test]
    fn private_endpoint_state_is_its_connection_status_and_the_target_jumps() {
        let row = PrivateEndpointRow::from_json(&pe_json("Approved", false), None).unwrap();
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "approved");
        assert!(row.search_text().contains("kv-prod"), "the target's name is searchable");
        let target = row.related().into_iter().find(|(l, _)| l == "Target kv-prod").unwrap().1;
        assert_eq!(
            crate::azure::service::JumpView::for_arm_id(&target),
            Some(crate::azure::service::JumpView::KeyVaults)
        );
        assert!(row.related().iter().any(|(l, _)| l == "Subnet pe"));
        assert!(row.details().iter().any(|(k, v)| k == "Private IPs" && v == "10.0.5.4"));
        let dns = private_endpoint_section_lines(&row, PrivateEndpointDetailSection::Dns);
        assert_eq!(dns[0], ("kv-prod.privatelink.example".to_string(), "10.0.5.4".to_string()));
        assert!(row.cli_command().unwrap().starts_with("az network private-endpoint show --ids "));

        let pending = PrivateEndpointRow::from_json(&pe_json("Pending", true), None).unwrap();
        assert_eq!(pending.state(), ResourceState::Pending);
        let conn = private_endpoint_section_lines(&pending, PrivateEndpointDetailSection::Connection);
        assert!(conn.iter().any(|(k, v)| k == "  Approval" && v.starts_with("manual")));
        let rejected = PrivateEndpointRow::from_json(&pe_json("Rejected", false), None).unwrap();
        assert_eq!(rejected.state(), ResourceState::Unavailable);
    }

    #[test]
    fn dns_zone_records_and_links_render_with_their_read_commands() {
        let zone = PrivateDnsZoneRow::from_json(
            &serde_json::json!({
                "id": format!("{}/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net", RG),
                "name": "privatelink.vaultcore.azure.net",
                "location": "global",
                "properties": {"numberOfRecordSets": 3, "maxNumberOfRecordSets": 25000,
                    "numberOfVirtualNetworkLinks": 1, "numberOfVirtualNetworkLinksWithRegistration": 0}
            }),
            None,
        )
        .unwrap();
        assert_eq!(zone.location(), Some("global"));
        assert!(zone.details().iter().any(|(k, v)| k == "Record sets" && v == "3 of 25000"));

        let records = vec![
            serde_json::json!({"name": "kv-prod", "type": "Microsoft.Network/privateDnsZones/A",
                "properties": {"ttl": 10, "aRecords": [{"ipv4Address": "10.0.5.4"}]}}),
            serde_json::json!({"name": "vm1", "type": "Microsoft.Network/privateDnsZones/A",
                "properties": {"ttl": 10, "isAutoRegistered": true, "aRecords": [{"ipv4Address": "10.0.1.4"}]}}),
            serde_json::json!({"name": "www", "type": "Microsoft.Network/privateDnsZones/CNAME",
                "properties": {"ttl": 3600, "cnameRecord": {"cname": "kv-prod.privatelink.vaultcore.azure.net"}}}),
        ];
        let lines = private_dns_zone_section_lines(&zone, PrivateDnsZoneDetailSection::Records, Some(&Lazy::Loaded(records)), None);
        assert_eq!(lines[0], ("kv-prod".to_string(), "A 10 s → 10.0.5.4".to_string()));
        assert_eq!(lines[1].1, "A 10 s → 10.0.1.4 · auto-registered");
        assert_eq!(lines[2].1, "CNAME 3600 s → kv-prod.privatelink.vaultcore.azure.net");
        assert_eq!(
            lines.last().unwrap().1,
            "az network private-dns record-set list -g rg-net -z privatelink.vaultcore.azure.net --subscription 0000"
        );

        let links = vec![serde_json::json!({
            "name": "hub-link",
            "properties": {"virtualNetwork": {"id": format!("{}/providers/Microsoft.Network/virtualNetworks/hub", RG)},
                "registrationEnabled": false, "virtualNetworkLinkState": "Completed"}
        })];
        let lines = private_dns_zone_section_lines(&zone, PrivateDnsZoneDetailSection::VnetLinks, None, Some(&Lazy::Loaded(links)));
        let (label, target) = lines.iter().find(|(k, _)| k.starts_with("hub-link")).unwrap();
        assert_eq!(label, "hub-link · hub");
        assert_eq!(
            crate::azure::service::JumpView::for_arm_id(target),
            Some(crate::azure::service::JumpView::VirtualNetworks)
        );
        assert!(lines.last().unwrap().1.starts_with("az network private-dns link vnet list -g rg-net"));
        assert_eq!(
            zone_child_path(&zone.base.id, "ALL"),
            format!("{}/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net/ALL", RG)
        );
    }
}
