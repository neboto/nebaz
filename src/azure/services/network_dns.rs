//! The DNS tab (issue #37): Private DNS zones (rows in
//! `network_private.rs`), public DNS zones, the DNS Private Resolver, its
//! forwarding rulesets and DNS security policies, each one
//! subscription-wide list and a sub-tab. All Microsoft.Network, but their
//! own tab: thirteen Network sub-tabs left the last three without a digit
//! key, and DNS is debugged as one workflow (zone → resolver → ruleset →
//! VNet link). Public zones and the resolver are two specs of their own,
//! neither on `NETWORK_API_VERSION` nor on Private DNS's.
//!
//! A zone's record sets, a ruleset's forwarding rules and a policy's
//! security rules are per-parent lists: lazy sections. What links these
//! types to each other and to VNets (a resolver's endpoints and their
//! subnets, which rulesets use which outbound endpoint, which VNets a
//! ruleset, policy or private zone is linked to) lives in child lists that
//! no list body carries, and the reverse direction ("what points at this
//! VNet") has only `POST` lookups (`listDnsResolvers`,
//! `listDnsForwardingRulesets`), which nebaz never sends. So one lazy
//! **DNS topology** per subscription gathers those child lists once
//! ([`fetch_dns_topology`]); the resolver, ruleset and policy sections and
//! the VNet and subnet Related sections all read it.
//!
//! Zone name servers (`*.azure-dns.*`) are DNS, not HTTP: shown as text,
//! never resolved. nebaz makes no DNS queries of its own.

use crate::azure::arm::ArmClient;
use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::network_private::{PrivateDnsZoneRow, PRIVATE_DNS_API_VERSION, PRIVATE_DNS_ZONES_PATH};
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_lines, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;

pub const DNS_ZONES_PATH: &str = "/providers/Microsoft.Network/dnszones";
pub const DNS_RESOLVERS_PATH: &str = "/providers/Microsoft.Network/dnsResolvers";
pub const DNS_FORWARDING_RULESETS_PATH: &str = "/providers/Microsoft.Network/dnsForwardingRulesets";
pub const DNS_RESOLVER_POLICIES_PATH: &str = "/providers/Microsoft.Network/dnsResolverPolicies";
/// Public DNS's newest stable version (azure-rest-api-specs, 2026-10-23);
/// DNSSEC is only in the previews, so it is not shown.
pub const DNS_API_VERSION: &str = "2018-05-01";
/// The resolver spec's newest stable version, which also carries DNS
/// security policies (azure-rest-api-specs, 2026-10-23).
pub const DNS_RESOLVER_API_VERSION: &str = "2025-05-01";
/// A zone's Records section stops paging here, as Activity does.
pub const DNS_RECORDS_MAX: usize = 1000;
/// The topology lists the children of at most this many resolvers,
/// rulesets, policies and private zones each.
pub const TOPOLOGY_MAX_PARENTS: usize = 100;
/// TXT values (domain verification, DKIM) are cut here in the list.
const TXT_MAX: usize = 60;

crate::sections! {
    pub enum DnsZoneDetailSection,
    pub static DNS_ZONE_SECTIONS = [
        Overview "Overview",
        Records "Records" => crate::app::App::trigger_public_dns_records,
        Delegation "Delegation",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_public_dns_records,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum DnsResolverDetailSection,
    pub static DNS_RESOLVER_SECTIONS = [
        Overview "Overview",
        Endpoints "Endpoints" => crate::app::App::trigger_dns_topology,
        Rulesets "Rulesets" => crate::app::App::trigger_dns_topology,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_dns_topology,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum DnsRulesetDetailSection,
    pub static DNS_RULESET_SECTIONS = [
        Overview "Overview",
        Rules "Rules" => crate::app::App::trigger_dns_forwarding_rules,
        VnetLinks "VNet links" => crate::app::App::trigger_dns_topology,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_dns_topology,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum DnsPolicyDetailSection,
    pub static DNS_POLICY_SECTIONS = [
        Overview "Overview",
        Rules "Rules" => crate::app::App::trigger_dns_security_rules,
        VnetLinks "VNet links" => crate::app::App::trigger_dns_topology,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_dns_topology,
        Tags "Tags",
    ]
}

/// ARM ids compare case-insensitively (`dnszones` vs `dnsZones`).
fn same_id(a: &str, b: &str) -> bool {
    a.trim_end_matches('/').eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// The resolver an endpoint id belongs to: everything before
/// `/inboundEndpoints/` or `/outboundEndpoints/`.
pub fn resolver_of_endpoint(endpoint_id: &str) -> Option<String> {
    let lower = endpoint_id.to_ascii_lowercase();
    ["/outboundendpoints/", "/inboundendpoints/"]
        .iter()
        .find_map(|seg| lower.find(seg))
        .map(|i| endpoint_id[..i].to_string())
}

/// `{flag} {name} -g {rg} --subscription {sub}`, what the child list
/// commands take.
fn parent_args(id: &str, flag: &str) -> String {
    format!(
        "{} {} -g {} --subscription {}",
        flag,
        shell_quote(name_of_id(id)),
        shell_quote(resource_group_of(id).unwrap_or("-")),
        shell_quote(subscription_of(id).unwrap_or("-"))
    )
}

/// The Overview of a resolver-spec type: its copied commands are in the
/// `dns-resolver` CLI extension, not the core CLI.
fn extension_overview(r: &dyn Resource) -> Vec<(String, String)> {
    let mut lines = overview_rows(r);
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "· the copied commands need the dns-resolver CLI extension".into()));
    lines
}

fn read_command(cmd: String) -> Vec<(String, String)> {
    vec![(String::new(), String::new()), ("Read command".into(), cmd)]
}

// ── The DNS topology (one per subscription) ───────────────────────────

/// One inbound IP configuration, or an outbound endpoint's subnet.
#[derive(Debug, Clone)]
pub struct EndpointIp {
    pub subnet_id: Option<String>,
    pub private_ip: Option<String>,
    pub allocation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsEndpoint {
    pub id: String,
    pub name: String,
    pub inbound: bool,
    pub ips: Vec<EndpointIp>,
    pub provisioning_state: Option<String>,
}

impl DnsEndpoint {
    pub fn from_json(v: &Value, inbound: bool) -> Option<DnsEndpoint> {
        let id = json::str_at(v, "/id")?;
        let ips = if inbound {
            json::arr(v, "/properties/ipConfigurations")
                .iter()
                .map(|c| EndpointIp {
                    subnet_id: json::arm_id(json::id_at(c, "/subnet")),
                    private_ip: json::str_at(c, "/privateIpAddress"),
                    allocation: json::str_at(c, "/privateIpAllocationMethod"),
                })
                .collect()
        } else {
            vec![EndpointIp {
                subnet_id: json::arm_id(json::id_at(v, "/properties/subnet")),
                private_ip: None,
                allocation: None,
            }]
        };
        Some(DnsEndpoint {
            name: json::str_at(v, "/name").unwrap_or_else(|| name_of_id(&id).to_string()),
            inbound,
            ips,
            provisioning_state: json::str_at(v, "/properties/provisioningState"),
            id,
        })
    }

    fn subnets(&self) -> impl Iterator<Item = &str> {
        self.ips.iter().filter_map(|ip| ip.subnet_id.as_deref())
    }

    fn direction(&self) -> &'static str {
        if self.inbound { "inbound" } else { "outbound" }
    }
}

#[derive(Debug, Clone)]
pub struct ResolverNode {
    pub id: String,
    pub name: String,
    pub vnet_id: Option<String>,
    pub endpoints: Vec<DnsEndpoint>,
}

/// One VNet link of a ruleset, a security policy or a private zone.
#[derive(Debug, Clone)]
pub struct VnetLink {
    pub name: String,
    pub vnet_id: Option<String>,
    /// `(label, value)` lines under the link: state, auto-registration,
    /// metadata.
    pub detail: Vec<(String, String)>,
}

impl VnetLink {
    pub fn from_json(v: &Value) -> VnetLink {
        let p = "/properties";
        let mut detail = Vec::new();
        if let Some(reg) = json::bool_at(v, &format!("{}/registrationEnabled", p)) {
            detail.push(("  Auto-registration".into(), json::yes_no(Some(reg))));
        }
        if let Some(s) = json::str_at(v, &format!("{}/virtualNetworkLinkState", p)) {
            detail.push(("  State".into(), s));
        }
        if let Some(s) = json::str_at(v, &format!("{}/provisioningState", p)).filter(|s| s != "Succeeded") {
            detail.push(("  Provisioning".into(), s));
        }
        if let Some(meta) = v.pointer(&format!("{}/metadata", p)).and_then(|m| m.as_object()) {
            let mut kv: Vec<String> = meta
                .iter()
                .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or("")))
                .collect();
            kv.sort();
            if !kv.is_empty() {
                detail.push(("  Metadata".into(), kv.join(", ")));
            }
        }
        VnetLink {
            name: json::text(v, "/name"),
            vnet_id: json::arm_id(json::id_at(v, &format!("{}/virtualNetwork", p))),
            detail,
        }
    }
}

/// A ruleset, a security policy or a private zone: what it is linked to.
#[derive(Debug, Clone)]
pub struct LinkedParent {
    pub id: String,
    pub name: String,
    /// A ruleset's outbound endpoints; empty for the others.
    pub outbound_endpoint_ids: Vec<String>,
    pub links: Vec<VnetLink>,
}

impl LinkedParent {
    fn links_to(&self, vnet_id: &str) -> Vec<&VnetLink> {
        self.links
            .iter()
            .filter(|l| l.vnet_id.as_deref().is_some_and(|v| same_id(v, vnet_id)))
            .collect()
    }
}

/// Every DNS link in one subscription: resolvers with their endpoints,
/// rulesets, security policies and private zones with their VNet links.
#[derive(Debug, Clone, Default)]
pub struct DnsTopology {
    pub resolvers: Vec<ResolverNode>,
    pub rulesets: Vec<LinkedParent>,
    pub policies: Vec<LinkedParent>,
    pub private_zones: Vec<LinkedParent>,
    /// A child list that failed: the rest still renders.
    pub warnings: Vec<String>,
    /// Which parent lists were cut at `TOPOLOGY_MAX_PARENTS`.
    pub truncated: Vec<&'static str>,
}

impl DnsTopology {
    pub fn resolver(&self, id: &str) -> Option<&ResolverNode> {
        self.resolvers.iter().find(|r| same_id(&r.id, id))
    }

    pub fn ruleset(&self, id: &str) -> Option<&LinkedParent> {
        self.rulesets.iter().find(|r| same_id(&r.id, id))
    }

    pub fn policy(&self, id: &str) -> Option<&LinkedParent> {
        self.policies.iter().find(|r| same_id(&r.id, id))
    }

    fn endpoint(&self, id: &str) -> Option<&DnsEndpoint> {
        self.resolvers.iter().flat_map(|r| &r.endpoints).find(|e| same_id(&e.id, id))
    }

    /// The rulesets that forward through one of the resolver's outbound
    /// endpoints, with that endpoint.
    fn rulesets_of_resolver(&self, resolver_id: &str) -> Vec<(&LinkedParent, &str)> {
        let mut v = Vec::new();
        for rs in &self.rulesets {
            for ep in &rs.outbound_endpoint_ids {
                if resolver_of_endpoint(ep).is_some_and(|r| same_id(&r, resolver_id)) {
                    v.push((rs, ep.as_str()));
                }
            }
        }
        v
    }

    /// The footer every topology-derived body ends with: where the data
    /// came from, and what is missing from it.
    fn notes(&self) -> Vec<(String, String)> {
        let mut lines = vec![(
            String::new(),
            "· from the subscription's resolver, ruleset, policy and private zone lists, read once per session".into(),
        )];
        for t in &self.truncated {
            lines.push((String::new(), format!("· only the first {} {} are followed", TOPOLOGY_MAX_PARENTS, t)));
        }
        for w in &self.warnings {
            lines.push((String::new(), format!("⚠ {}", w)));
        }
        lines
    }
}

/// Gather a subscription's DNS links (`sub` is `/subscriptions/{id}`):
/// the resolver list and each resolver's inbound and outbound endpoints,
/// the ruleset, policy and private zone lists and each one's VNet links.
/// All `GET`s; `4 + 2·resolvers + rulesets + policies + zones` calls. Only
/// the resolver list failing fails the whole; any other list becomes a
/// warning.
pub async fn fetch_dns_topology(arm: Arc<ArmClient>, sub: String) -> std::result::Result<DnsTopology, String> {
    let mut t = DnsTopology::default();
    let resolvers = arm
        .list(&format!("{}{}", sub, DNS_RESOLVERS_PATH), DNS_RESOLVER_API_VERSION)
        .await
        .map_err(|e| e.to_string())?;
    if resolvers.len() > TOPOLOGY_MAX_PARENTS {
        t.truncated.push("resolvers");
    }
    for v in resolvers.iter().take(TOPOLOGY_MAX_PARENTS) {
        let Some(id) = json::str_at(v, "/id") else { continue };
        let mut endpoints = Vec::new();
        for (child, inbound) in [("inboundEndpoints", true), ("outboundEndpoints", false)] {
            match arm.list(&format!("{}/{}", id, child), DNS_RESOLVER_API_VERSION).await {
                Ok(items) => endpoints.extend(items.iter().filter_map(|e| DnsEndpoint::from_json(e, inbound))),
                Err(e) => t.warnings.push(format!("{} of {}: {}", child, name_of_id(&id), e)),
            }
        }
        t.resolvers.push(ResolverNode {
            name: json::str_at(v, "/name").unwrap_or_else(|| name_of_id(&id).to_string()),
            vnet_id: json::arm_id(json::id_at(v, "/properties/virtualNetwork")),
            endpoints,
            id,
        });
    }
    let parents: [(&str, &'static str, &'static str, &'static str); 3] = [
        (DNS_FORWARDING_RULESETS_PATH, DNS_RESOLVER_API_VERSION, "virtualNetworkLinks", "rulesets"),
        (DNS_RESOLVER_POLICIES_PATH, DNS_RESOLVER_API_VERSION, "virtualNetworkLinks", "security policies"),
        (PRIVATE_DNS_ZONES_PATH, PRIVATE_DNS_API_VERSION, "virtualNetworkLinks", "private DNS zones"),
    ];
    for (i, (path, api_version, child, what)) in parents.into_iter().enumerate() {
        let list = match arm.list(&format!("{}{}", sub, path), api_version).await {
            Ok(list) => list,
            Err(e) => {
                t.warnings.push(format!("{}: {}", what, e));
                continue;
            }
        };
        if list.len() > TOPOLOGY_MAX_PARENTS {
            t.truncated.push(what);
        }
        for v in list.iter().take(TOPOLOGY_MAX_PARENTS) {
            let Some(id) = json::str_at(v, "/id") else { continue };
            let links = match arm.list(&format!("{}/{}", id, child), api_version).await {
                Ok(items) => items.iter().map(VnetLink::from_json).collect(),
                Err(e) => {
                    t.warnings.push(format!("VNet links of {}: {}", name_of_id(&id), e));
                    Vec::new()
                }
            };
            let parent = LinkedParent {
                name: json::str_at(v, "/name").unwrap_or_else(|| name_of_id(&id).to_string()),
                outbound_endpoint_ids: json::ids_at(v, "/properties/dnsResolverOutboundEndpoints"),
                links,
                id,
            };
            match i {
                0 => t.rulesets.push(parent),
                1 => t.policies.push(parent),
                _ => t.private_zones.push(parent),
            }
        }
    }
    Ok(t)
}

/// A topology-backed section: the three lazy arms, with `render` on the
/// loaded topology.
fn with_topology(
    topo: Option<&Lazy<DnsTopology>>,
    render: impl FnOnce(&DnsTopology) -> Vec<(String, String)>,
) -> Vec<(String, String)> {
    match topo {
        None | Some(Lazy::Loading) => vec![("DNS links".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => crate::azure::services::error_rows(e),
        Some(Lazy::Loaded(t)) => render(t),
    }
}

/// The DNS lines a VNet's Related section gains: the resolvers in it and
/// the rulesets, security policies and private zones linked to it.
pub fn vnet_dns_related(topo: Option<&Lazy<DnsTopology>>, vnet_id: &str) -> Vec<(String, String)> {
    let lines = with_topology(topo, |t| {
        let mut lines = Vec::new();
        for r in t.resolvers.iter().filter(|r| r.vnet_id.as_deref().is_some_and(|v| same_id(v, vnet_id))) {
            lines.push((format!("DNS resolver {}", r.name), r.id.clone()));
        }
        for (what, parents) in [
            ("Forwarding ruleset", &t.rulesets),
            ("DNS security policy", &t.policies),
            ("Private DNS zone", &t.private_zones),
        ] {
            for p in parents {
                for link in p.links_to(vnet_id) {
                    let reg = if link.detail.iter().any(|(k, v)| k == "  Auto-registration" && v == "yes") {
                        " · auto-registration"
                    } else {
                        ""
                    };
                    lines.push((format!("{} {}{}", what, p.name, reg), p.id.clone()));
                }
            }
        }
        if lines.is_empty() {
            lines.push((String::new(), "· no DNS resolver, ruleset, policy or private zone points here".into()));
        }
        lines.extend(t.warnings.iter().map(|w| (String::new(), format!("⚠ {}", w))));
        lines
    });
    let mut out = vec![(String::new(), String::new())];
    out.extend(lines);
    out
}

/// The DNS lines a subnet's Related section gains: the resolver endpoints
/// placed in it.
pub fn subnet_dns_related(topo: Option<&Lazy<DnsTopology>>, subnet_id: &str) -> Vec<(String, String)> {
    let Some(Lazy::Loaded(t)) = topo else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for r in &t.resolvers {
        for e in &r.endpoints {
            if e.subnets().any(|s| same_id(s, subnet_id)) {
                lines.push((format!("DNS resolver {} · {} endpoint {}", r.name, e.direction(), e.name), r.id.clone()));
            }
        }
    }
    if !lines.is_empty() {
        lines.insert(0, (String::new(), String::new()));
    }
    lines
}

// ── Public DNS zone ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsZoneRow {
    pub base: ArmBase,
    pub record_sets: Option<i64>,
    pub max_record_sets: Option<i64>,
    pub max_records_per_set: Option<i64>,
    pub name_servers: Vec<String>,
    pub zone_type: Option<String>,
    /// Legacy private zones (`zoneType: Private`) carry their VNets here.
    pub registration_vnets: Vec<String>,
    pub resolution_vnets: Vec<String>,
}

impl DnsZoneRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<DnsZoneRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(DnsZoneRow {
            record_sets: json::int_at(v, &format!("{}/numberOfRecordSets", p)),
            max_record_sets: json::int_at(v, &format!("{}/maxNumberOfRecordSets", p)),
            max_records_per_set: json::int_at(v, &format!("{}/maxNumberOfRecordsPerRecordSet", p)),
            name_servers: json::strings_at(v, &format!("{}/nameServers", p)),
            zone_type: json::str_at(v, &format!("{}/zoneType", p)),
            registration_vnets: json::ids_at(v, &format!("{}/registrationVirtualNetworks", p)),
            resolution_vnets: json::ids_at(v, &format!("{}/resolutionVirtualNetworks", p)),
            base,
        })
    }
}

/// `1 record set` / `12 record sets`, shared with private DNS zones.
pub(crate) fn record_sets_label(n: i64) -> String {
    if n == 1 {
        "1 record set".to_string()
    } else {
        format!("{n} record sets")
    }
}

impl Resource for DnsZoneRow {
    arm_row!("DNS Zone");
    /// How many record sets, and `private` for a legacy private zone.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([
            self.record_sets.map(record_sets_label),
            self.zone_type
                .as_deref()
                .filter(|t| t.eq_ignore_ascii_case("private"))
                .map(|_| "private".to_string()),
        ])
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&DNS_ZONE_SECTIONS)
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
            ("Zone type".into(), json::opt(self.zone_type.clone())),
            ("Record sets".into(), records),
            ("Records per set (max)".into(), json::num(self.max_records_per_set)),
            ("Name servers".into(), self.name_servers.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for n in &self.registration_vnets {
            v.push((format!("Registration VNet {}", name_of_id(n)), n.clone()));
        }
        for n in &self.resolution_vnets {
            v.push((format!("Resolution VNet {}", name_of_id(n)), n.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network dns zone show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn dns_zone_section_lines(
    r: &DnsZoneRow,
    section: DnsZoneDetailSection,
    records: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        DnsZoneDetailSection::Overview => overview_rows(r),
        DnsZoneDetailSection::Records => lazy_list_rows(records, "Records", |items| public_record_rows(items, r)),
        DnsZoneDetailSection::Delegation => {
            let mut lines: Vec<(String, String)> =
                r.name_servers.iter().map(|ns| ("Name server".into(), ns.clone())).collect();
            if lines.is_empty() {
                lines.push((String::new(), "No name servers (a legacy private zone has none)".into()));
            }
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· the parent zone or registrar delegates here with NS records for these".into()));
            lines.push((String::new(), "· shown as text; nebaz never resolves a name".into()));
            lines
        }
        DnsZoneDetailSection::Access => crate::azure::services::rendered_by_app(),
        DnsZoneDetailSection::Activity => crate::azure::services::rendered_by_app(),
        DnsZoneDetailSection::Related => {
            let mut rel = r.related();
            if let Some(Lazy::Loaded(items)) = records {
                for t in alias_targets(items) {
                    if !rel.iter().any(|(_, id)| same_id(id, &t)) {
                        rel.push((format!("Alias target {}", name_of_id(&t)), t));
                    }
                }
            }
            let mut lines = related_lines(rel);
            if !matches!(records, Some(Lazy::Loaded(_))) {
                lines.push((String::new(), "· alias targets appear once Records has loaded".into()));
            }
            lines
        }
        DnsZoneDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The resources alias record sets point at, in record order.
fn alias_targets(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|rs| json::arm_id(json::id_at(rs, "/properties/targetResource")))
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

/// A public record set's values, whatever its type. Public DNS spells
/// its arrays `ARecords`, `MXRecords`… (Private DNS: `aRecords`).
fn public_record_values(rs: &Value) -> Vec<String> {
    let p = "/properties";
    let pick = |arr: &str, field: &str| -> Vec<String> {
        json::arr(rs, &format!("{}/{}", p, arr))
            .iter()
            .filter_map(|r| json::str_at(r, &format!("/{}", field)))
            .collect()
    };
    let mut values = pick("ARecords", "ipv4Address");
    values.extend(pick("AAAARecords", "ipv6Address"));
    values.extend(json::str_at(rs, &format!("{}/CNAMERecord/cname", p)));
    values.extend(pick("NSRecords", "nsdname"));
    values.extend(pick("PTRRecords", "ptrdname"));
    for mx in json::arr(rs, &format!("{}/MXRecords", p)) {
        values.push(format!("{} {}", json::text(&mx, "/preference"), json::text(&mx, "/exchange")));
    }
    for srv in json::arr(rs, &format!("{}/SRVRecords", p)) {
        values.push(format!(
            "{} {} {} {}",
            json::text(&srv, "/priority"),
            json::text(&srv, "/weight"),
            json::text(&srv, "/port"),
            json::text(&srv, "/target")
        ));
    }
    for txt in json::arr(rs, &format!("{}/TXTRecords", p)) {
        values.push(truncate(&json::strings_at(&txt, "/value").join(""), TXT_MAX));
    }
    for caa in json::arr(rs, &format!("{}/caaRecords", p)) {
        values.push(format!(
            "{} {} {}",
            json::text(&caa, "/flags"),
            json::text(&caa, "/tag"),
            json::text(&caa, "/value")
        ));
    }
    if let Some(host) = json::str_at(rs, &format!("{}/SOARecord/host", p)) {
        values.push(format!("{} {}", host, json::text(rs, &format!("{}/SOARecord/email", p))));
    }
    values
}

/// The Records section body from the zone's `all` record-set list. An
/// alias record set's target is its own line, so Enter jumps to it.
pub fn public_record_rows(items: &[Value], r: &DnsZoneRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No record sets".into()));
    }
    for rs in items {
        // `Microsoft.Network/dnszones/A` → `A`.
        let kind = json::text(rs, "/type").rsplit('/').next().unwrap_or("-").to_uppercase();
        let target = json::arm_id(json::id_at(rs, "/properties/targetResource"));
        let values = match &target {
            Some(t) => format!("alias → {}", name_of_id(t)),
            None => json::join(&public_record_values(rs)),
        };
        lines.push((
            json::text(rs, "/name"),
            format!("{} {} s → {}", kind, json::text(rs, "/properties/TTL"), values),
        ));
        if let Some(t) = target {
            lines.push((format!("  alias target · {}", name_of_id(&t)), t));
        }
    }
    if items.len() >= DNS_RECORDS_MAX {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("· the first {} record sets; the rest are not fetched", DNS_RECORDS_MAX)));
    }
    lines.extend(read_command(format!(
        "az network dns record-set list {}",
        parent_args(&r.base.id, "-z")
    )));
    lines
}

/// The ARM path of a DNS parent's child list (`{zone}/all`,
/// `{ruleset}/forwardingRules`, `{policy}/dnsSecurityRules`).
pub fn dns_child_path(id: &str, child: &str) -> String {
    format!("{}/{}", id.trim_end_matches('/'), child)
}

// ── DNS Private Resolver ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsResolverRow {
    pub base: ArmBase,
    pub vnet_id: Option<String>,
    pub resolver_state: Option<String>,
}

impl DnsResolverRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<DnsResolverRow> {
        let base = ArmBase::from_json(v, tenant)?;
        Some(DnsResolverRow {
            vnet_id: json::arm_id(json::id_at(v, "/properties/virtualNetwork")),
            resolver_state: json::str_at(v, "/properties/dnsResolverState"),
            base,
        })
    }

    /// `dnsResolverState`: `Connected` or `Disconnected`.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.resolver_state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "connected" => ResourceState::Available,
                "disconnected" => ResourceState::Unavailable,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for DnsResolverRow {
    arm_row!("DNS Resolver");
    /// The VNet it serves (its state is the state column already).
    fn list_summary(&self) -> Option<String> {
        self.vnet_id
            .as_deref()
            .map(|id| format!("vnet {}", crate::azure::resource::name_of_id(id)))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&DNS_RESOLVER_SECTIONS)
    }
    /// The VNet's name is searchable: `/vnet-hub` finds its resolver.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.vnet_id.as_deref().map(name_of_id).unwrap_or("")
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Resolver state".into(), json::opt(self.resolver_state.clone())),
            ("Virtual network".into(), self.vnet_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(n) = &self.vnet_id {
            v.push((format!("Virtual network {}", name_of_id(n)), n.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az dns-resolver show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn dns_resolver_section_lines(
    r: &DnsResolverRow,
    section: DnsResolverDetailSection,
    topo: Option<&Lazy<DnsTopology>>,
) -> Vec<(String, String)> {
    match section {
        DnsResolverDetailSection::Overview => extension_overview(r),
        DnsResolverDetailSection::Endpoints => with_topology(topo, |t| {
            let mut lines = Vec::new();
            match t.resolver(&r.base.id) {
                None => lines.push((String::new(), "Not in the subscription's resolver list (read once per session)".into())),
                Some(node) if node.endpoints.is_empty() => lines.push((String::new(), "No endpoints".into())),
                Some(node) => {
                    for e in &node.endpoints {
                        lines.push((String::new(), String::new()));
                        let ip = e.ips.iter().filter_map(|i| i.private_ip.clone()).collect::<Vec<_>>();
                        let head = if e.inbound { json::join(&ip) } else { "forwards queries out".into() };
                        lines.push((format!("{} · {}", e.name, e.direction()), head));
                        for ip in &e.ips {
                            if let Some(s) = &ip.subnet_id {
                                lines.push((format!("  Subnet · {}", name_of_id(s)), s.clone()));
                            }
                            if let Some(a) = &ip.allocation {
                                lines.push(("  Allocation".into(), a.clone()));
                            }
                        }
                        if let Some(p) = e.provisioning_state.as_ref().filter(|p| *p != "Succeeded") {
                            lines.push(("  Provisioning".into(), p.clone()));
                        }
                    }
                }
            }
            lines.push((String::new(), String::new()));
            lines.extend(t.notes());
            let args = parent_args(&r.base.id, "--dns-resolver-name");
            lines.extend(read_command(format!("az dns-resolver inbound-endpoint list {}", args)));
            lines.push(("".into(), format!("az dns-resolver outbound-endpoint list {}", args)));
            lines
        }),
        DnsResolverDetailSection::Rulesets => with_topology(topo, |t| {
            let mut lines: Vec<(String, String)> = t
                .rulesets_of_resolver(&r.base.id)
                .into_iter()
                .map(|(rs, ep)| (format!("{} · via {}", rs.name, name_of_id(ep)), rs.id.clone()))
                .collect();
            if lines.is_empty() {
                lines.push((String::new(), "No ruleset uses this resolver's outbound endpoints".into()));
            }
            lines.push((String::new(), String::new()));
            lines.extend(t.notes());
            lines
        }),
        DnsResolverDetailSection::Access => crate::azure::services::rendered_by_app(),
        DnsResolverDetailSection::Activity => crate::azure::services::rendered_by_app(),
        DnsResolverDetailSection::Related => {
            let mut rel = r.related();
            let mut tail = Vec::new();
            match topo {
                Some(Lazy::Loaded(t)) => {
                    if let Some(node) = t.resolver(&r.base.id) {
                        for e in &node.endpoints {
                            for s in e.subnets() {
                                rel.push((format!("Subnet {} · {} endpoint {}", name_of_id(s), e.direction(), e.name), s.to_string()));
                            }
                        }
                    }
                    for (rs, _) in t.rulesets_of_resolver(&r.base.id) {
                        if !rel.iter().any(|(_, id)| same_id(id, &rs.id)) {
                            rel.push((format!("Ruleset {}", rs.name), rs.id.clone()));
                        }
                    }
                    tail.extend(t.warnings.iter().map(|w| (String::new(), format!("⚠ {}", w))));
                }
                Some(Lazy::Error(e)) => tail.push((String::new(), format!("⚠ endpoints and rulesets: {}", e))),
                _ => tail.push((String::new(), "· endpoint subnets and rulesets: loading…".into())),
            }
            let mut lines = related_lines(rel);
            lines.extend(tail);
            lines
        }
        DnsResolverDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── DNS forwarding ruleset ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsRulesetRow {
    pub base: ArmBase,
    pub outbound_endpoint_ids: Vec<String>,
}

impl DnsRulesetRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<DnsRulesetRow> {
        let base = ArmBase::from_json(v, tenant)?;
        Some(DnsRulesetRow {
            outbound_endpoint_ids: json::ids_at(v, "/properties/dnsResolverOutboundEndpoints"),
            base,
        })
    }

    /// The resolvers that own the ruleset's outbound endpoints, deduplicated.
    fn resolver_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for r in self.outbound_endpoint_ids.iter().filter_map(|e| resolver_of_endpoint(e)) {
            if !v.iter().any(|x| same_id(x, &r)) {
                v.push(r);
            }
        }
        v
    }
}

impl Resource for DnsRulesetRow {
    arm_row!("DNS Forwarding Ruleset");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&DNS_RULESET_SECTIONS)
    }
    /// The resolver's name is searchable: `/dnspr-hub` finds its rulesets.
    fn search_text(&self) -> String {
        let resolvers: Vec<String> = self.resolver_ids().iter().map(|r| name_of_id(r).to_string()).collect();
        format!(
            "{} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            resolvers.join(" ")
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let endpoints: Vec<String> = self.outbound_endpoint_ids.iter().map(|e| name_of_id(e).to_string()).collect();
        let resolvers: Vec<String> = self.resolver_ids().iter().map(|r| name_of_id(r).to_string()).collect();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Outbound endpoints".into(), json::join(&endpoints)),
            ("Resolvers".into(), json::join(&resolvers)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for r in self.resolver_ids() {
            v.push((format!("Resolver {}", name_of_id(&r)), r));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az dns-resolver forwarding-ruleset show --ids {}", shell_quote(&self.base.id)))
    }
}

/// A ruleset's or policy's VNet links body, from the topology.
fn vnet_link_lines(
    topo: Option<&Lazy<DnsTopology>>,
    find: impl FnOnce(&DnsTopology) -> Option<&LinkedParent>,
    read: String,
) -> Vec<(String, String)> {
    with_topology(topo, |t| {
        let mut lines = Vec::new();
        match find(t) {
            Some(p) if !p.links.is_empty() => {
                for link in &p.links {
                    lines.push((String::new(), String::new()));
                    match &link.vnet_id {
                        Some(id) => lines.push((format!("{} · {}", link.name, name_of_id(id)), id.clone())),
                        None => lines.push((link.name.clone(), String::new())),
                    }
                    lines.extend(link.detail.iter().cloned());
                }
            }
            Some(_) => lines.push((String::new(), "No VNet links: no VNet uses it".into())),
            None => lines.push((String::new(), "Not in the subscription's list (read once per session)".into())),
        }
        lines.push((String::new(), String::new()));
        lines.extend(t.notes());
        lines.extend(read_command(read));
        lines
    })
}

type Lines = Vec<(String, String)>;

/// The linked VNets as Related lines, and the notes to put after the
/// hint (the topology's loading state or warnings).
fn linked_vnet_related(
    topo: Option<&Lazy<DnsTopology>>,
    find: impl FnOnce(&DnsTopology) -> Option<&LinkedParent>,
) -> (Lines, Lines) {
    match topo {
        Some(Lazy::Loaded(t)) => {
            let rel = find(t)
                .map(|p| {
                    p.links
                        .iter()
                        .filter_map(|l| l.vnet_id.as_ref())
                        .map(|v| (format!("Linked VNet {}", name_of_id(v)), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            (rel, t.warnings.iter().map(|w| (String::new(), format!("⚠ {}", w))).collect())
        }
        Some(Lazy::Error(e)) => (Vec::new(), vec![(String::new(), format!("⚠ VNet links: {}", e))]),
        _ => (Vec::new(), vec![(String::new(), "· linked VNets: loading…".into())]),
    }
}

pub fn dns_ruleset_section_lines(
    r: &DnsRulesetRow,
    section: DnsRulesetDetailSection,
    rules: Option<&Lazy<Vec<Value>>>,
    topo: Option<&Lazy<DnsTopology>>,
) -> Vec<(String, String)> {
    match section {
        DnsRulesetDetailSection::Overview => extension_overview(r),
        DnsRulesetDetailSection::Rules => lazy_list_rows(rules, "Rules", |items| forwarding_rule_rows(items, r)),
        DnsRulesetDetailSection::VnetLinks => vnet_link_lines(
            topo,
            |t| t.ruleset(&r.base.id),
            format!("az dns-resolver vnet-link list {}", parent_args(&r.base.id, "--ruleset-name")),
        ),
        DnsRulesetDetailSection::Access => crate::azure::services::rendered_by_app(),
        DnsRulesetDetailSection::Activity => crate::azure::services::rendered_by_app(),
        DnsRulesetDetailSection::Related => {
            let mut rel = r.related();
            if let Some(Lazy::Loaded(t)) = topo {
                for ep in &r.outbound_endpoint_ids {
                    for s in t.endpoint(ep).into_iter().flat_map(|e| e.subnets()) {
                        rel.push((format!("Subnet {} · outbound endpoint {}", name_of_id(s), name_of_id(ep)), s.to_string()));
                    }
                }
                for rid in r.resolver_ids() {
                    if let Some(v) = t.resolver(&rid).and_then(|n| n.vnet_id.as_ref()) {
                        rel.push((format!("Resolver VNet {}", name_of_id(v)), v.clone()));
                    }
                }
            }
            let (links, tail) = linked_vnet_related(topo, |t| t.ruleset(&r.base.id));
            rel.extend(links);
            let mut lines = related_lines(rel);
            lines.extend(tail);
            lines
        }
        DnsRulesetDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Rules section body: each forwarded domain, its target DNS servers
/// and whether the rule is on.
pub fn forwarding_rule_rows(items: &[Value], r: &DnsRulesetRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No forwarding rules: queries resolve through Azure DNS".into()));
    }
    for rule in items {
        let p = "/properties";
        let targets: Vec<String> = json::arr(rule, &format!("{}/targetDnsServers", p))
            .iter()
            .map(|t| format!("{}:{}", json::text(t, "/ipAddress"), json::str_at(t, "/port").unwrap_or_else(|| "53".into())))
            .collect();
        let state = json::str_at(rule, &format!("{}/forwardingRuleState", p)).unwrap_or_else(|| "-".into());
        lines.push((
            json::text(rule, &format!("{}/domainName", p)),
            format!("→ {} · {}", json::join(&targets), state.to_lowercase()),
        ));
    }
    lines.extend(read_command(format!(
        "az dns-resolver forwarding-rule list {}",
        parent_args(&r.base.id, "--ruleset-name")
    )));
    lines
}

// ── DNS security policy ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsPolicyRow {
    pub base: ArmBase,
}

impl DnsPolicyRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<DnsPolicyRow> {
        Some(DnsPolicyRow { base: ArmBase::from_json(v, tenant)? })
    }
}

impl Resource for DnsPolicyRow {
    arm_row!("DNS Security Policy");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&DNS_POLICY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
        ]
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az dns-resolver policy show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn dns_policy_section_lines(
    r: &DnsPolicyRow,
    section: DnsPolicyDetailSection,
    rules: Option<&Lazy<Vec<Value>>>,
    topo: Option<&Lazy<DnsTopology>>,
) -> Vec<(String, String)> {
    match section {
        DnsPolicyDetailSection::Overview => extension_overview(r),
        DnsPolicyDetailSection::Rules => lazy_list_rows(rules, "Rules", |items| security_rule_rows(items, r)),
        DnsPolicyDetailSection::VnetLinks => vnet_link_lines(
            topo,
            |t| t.policy(&r.base.id),
            format!("az dns-resolver policy vnet-link list {}", parent_args(&r.base.id, "--policy-name")),
        ),
        DnsPolicyDetailSection::Access => crate::azure::services::rendered_by_app(),
        DnsPolicyDetailSection::Activity => crate::azure::services::rendered_by_app(),
        DnsPolicyDetailSection::Related => {
            let mut rel = r.related();
            let (links, tail) = linked_vnet_related(topo, |t| t.policy(&r.base.id));
            rel.extend(links);
            let mut lines = related_lines(rel);
            lines.extend(tail);
            lines
        }
        DnsPolicyDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Rules section body: security rules by priority, each with its
/// action and the domain lists it matches (Enter on one opens it in All
/// resources).
pub fn security_rule_rows(items: &[Value], r: &DnsPolicyRow) -> Vec<(String, String)> {
    let p = "/properties";
    let mut rules: Vec<&Value> = items.iter().collect();
    rules.sort_by_key(|rule| json::int_at(rule, &format!("{}/priority", p)).unwrap_or(i64::MAX));
    let mut lines = Vec::new();
    if rules.is_empty() {
        lines.push((String::new(), "No security rules".into()));
    }
    for rule in rules {
        lines.push((String::new(), String::new()));
        lines.push((
            format!("{} · {}", json::text(rule, &format!("{}/priority", p)), json::text(rule, "/name")),
            format!(
                "{} · {}",
                json::text(rule, &format!("{}/action/actionType", p)).to_lowercase(),
                json::text(rule, &format!("{}/dnsSecurityRuleState", p)).to_lowercase()
            ),
        ));
        for list in json::ids_at(rule, &format!("{}/dnsResolverDomainLists", p)) {
            lines.push((format!("  Domain list · {}", name_of_id(&list)), list));
        }
    }
    lines.extend(read_command(format!(
        "az dns-resolver policy dns-security-rule list {}",
        parent_args(&r.base.id, "--policy-name")
    )));
    lines
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct DnsService {
    scope: Scope,
}

impl DnsService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// Every DNS sub-tab is one plain list: path, api-version (three
    /// specs) and the loading label.
    fn list(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::DnsZones => (DNS_ZONES_PATH, DNS_API_VERSION, "Listing DNS zones…"),
            JumpView::DnsResolvers => (DNS_RESOLVERS_PATH, DNS_RESOLVER_API_VERSION, "Listing DNS resolvers…"),
            JumpView::DnsForwardingRulesets => {
                (DNS_FORWARDING_RULESETS_PATH, DNS_RESOLVER_API_VERSION, "Listing DNS forwarding rulesets…")
            }
            JumpView::DnsResolverPolicies => {
                (DNS_RESOLVER_POLICIES_PATH, DNS_RESOLVER_API_VERSION, "Listing DNS security policies…")
            }
            _ => (PRIVATE_DNS_ZONES_PATH, PRIVATE_DNS_API_VERSION, "Listing private DNS zones…"),
        }
    }

    /// One page of a sub-tab, parsed by that sub-tab's row type.
    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        fn boxed<R: Resource + 'static>(rows: impl Iterator<Item = R>) -> Vec<Box<dyn Resource>> {
            rows.map(|r| Box::new(r) as Box<dyn Resource>).collect()
        }
        match view {
            JumpView::DnsZones => boxed(page.iter().filter_map(|v| DnsZoneRow::from_json(v, tenant))),
            JumpView::DnsResolvers => boxed(page.iter().filter_map(|v| DnsResolverRow::from_json(v, tenant))),
            JumpView::DnsForwardingRulesets => boxed(page.iter().filter_map(|v| DnsRulesetRow::from_json(v, tenant))),
            JumpView::DnsResolverPolicies => boxed(page.iter().filter_map(|v| DnsPolicyRow::from_json(v, tenant))),
            _ => boxed(page.iter().filter_map(|v| PrivateDnsZoneRow::from_json(v, tenant))),
        }
    }
}

#[async_trait]
impl AzureService for DnsService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Dns
    }

    fn name(&self) -> &str {
        "DNS"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, api_version, _) = Self::list(view);
        Ok(Self::rows(view, &self.scope.list(path, api_version).await?, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let (path, api_version, label) = Self::list(view);
        let r = self
            .scope
            .stream(path, api_version, &[], service_type, label, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let not_found = || Error::ResourceNotFound(id.to_string());
        let view = JumpView::for_arm_id(id).filter(|v| v.service() == ServiceType::Dns).ok_or_else(not_found)?;
        let (_, api_version, _) = Self::list(view);
        let v = self.scope.get(id, api_version).await?;
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant()).pop().ok_or_else(not_found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::service::JumpView;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-dns";

    fn id(t: &str) -> String {
        format!("{}/providers/Microsoft.Network/{}", RG, t)
    }

    fn topology() -> DnsTopology {
        let resolver = id("dnsResolvers/dnspr-hub");
        DnsTopology {
            resolvers: vec![ResolverNode {
                id: resolver.clone(),
                name: "dnspr-hub".into(),
                vnet_id: Some(id("virtualNetworks/vnet-hub")),
                endpoints: vec![
                    DnsEndpoint::from_json(
                        &serde_json::json!({
                            "id": format!("{}/inboundEndpoints/in", resolver), "name": "in",
                            "properties": {"ipConfigurations": [{"subnet": {"id": id("virtualNetworks/vnet-hub/subnets/dns-in")},
                                "privateIpAddress": "10.0.0.4", "privateIpAllocationMethod": "Dynamic"}],
                                "provisioningState": "Succeeded"}
                        }),
                        true,
                    )
                    .unwrap(),
                    DnsEndpoint::from_json(
                        &serde_json::json!({
                            "id": format!("{}/outboundEndpoints/out", resolver), "name": "out",
                            "properties": {"subnet": {"id": id("virtualNetworks/vnet-hub/subnets/dns-out")}}
                        }),
                        false,
                    )
                    .unwrap(),
                ],
            }],
            rulesets: vec![LinkedParent {
                id: id("dnsForwardingRulesets/rs-onprem"),
                name: "rs-onprem".into(),
                outbound_endpoint_ids: vec![format!("{}/outboundEndpoints/out", resolver)],
                links: vec![VnetLink::from_json(&serde_json::json!({
                    "name": "spoke-link",
                    "properties": {"virtualNetwork": {"id": id("virtualNetworks/vnet-aca")}, "metadata": {"env": "prod"}}
                }))],
            }],
            policies: Vec::new(),
            private_zones: vec![LinkedParent {
                id: id("privateDnsZones/privatelink.example"),
                name: "privatelink.example".into(),
                outbound_endpoint_ids: Vec::new(),
                links: vec![VnetLink::from_json(&serde_json::json!({
                    "name": "aca", "properties": {"virtualNetwork": {"id": id("virtualnetworks/VNET-ACA")},
                        "registrationEnabled": false, "virtualNetworkLinkState": "Completed"}
                }))],
            }],
            warnings: Vec::new(),
            truncated: Vec::new(),
        }
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for desc in [&DNS_ZONE_SECTIONS, &DNS_RESOLVER_SECTIONS, &DNS_RULESET_SECTIONS, &DNS_POLICY_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(labels[labels.len() - 4], "Access");
            assert_eq!(labels[labels.len() - 3], "Activity");
            assert_eq!(labels[labels.len() - 2], "Related");
            assert_eq!(labels.last(), Some(&"Tags"));
        }
    }

    #[test]
    fn public_zone_records_render_values_aliases_and_long_txt() {
        let zone = DnsZoneRow::from_json(
            &serde_json::json!({
                "id": id("dnszones/example.com"), "name": "example.com", "location": "global",
                "properties": {"numberOfRecordSets": 4, "maxNumberOfRecordSets": 10000, "zoneType": "Public",
                    "nameServers": ["ns1-01.azure-dns.com.", "ns2-01.azure-dns.net."]}
            }),
            None,
        )
        .unwrap();
        assert_eq!(zone.location(), Some("global"));
        assert_eq!(zone.list_summary().as_deref(), Some("4 record sets"));
        assert_eq!(zone.state(), ResourceState::stateless());
        assert!(zone.details().iter().any(|(k, v)| k == "Record sets" && v == "4 of 10000"));
        assert!(zone.cli_command().unwrap().starts_with("az network dns zone show --ids "));
        let delegation = dns_zone_section_lines(&zone, DnsZoneDetailSection::Delegation, None);
        assert_eq!(delegation[0], ("Name server".to_string(), "ns1-01.azure-dns.com.".to_string()));

        let pip = id("publicIPAddresses/pip-web");
        let records = vec![
            serde_json::json!({"name": "www", "type": "Microsoft.Network/dnszones/A",
                "properties": {"TTL": 300, "ARecords": [{"ipv4Address": "20.1.2.3"}]}}),
            serde_json::json!({"name": "@", "type": "Microsoft.Network/dnszones/A",
                "properties": {"TTL": 60, "targetResource": {"id": pip}}}),
            serde_json::json!({"name": "@", "type": "Microsoft.Network/dnszones/TXT",
                "properties": {"TTL": 3600, "TXTRecords": [{"value": ["v=DKIM1; k=rsa; p=", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"]}]}}),
            serde_json::json!({"name": "@", "type": "Microsoft.Network/dnszones/MX",
                "properties": {"TTL": 3600, "MXRecords": [{"preference": 10, "exchange": "mail.example.com"}]}}),
        ];
        let lines = dns_zone_section_lines(&zone, DnsZoneDetailSection::Records, Some(&Lazy::Loaded(records.clone())));
        assert_eq!(lines[0], ("www".to_string(), "A 300 s → 20.1.2.3".to_string()));
        assert_eq!(lines[1].1, "A 60 s → alias → pip-web");
        assert_eq!(lines[2], ("  alias target · pip-web".to_string(), pip.clone()));
        assert_eq!(JumpView::for_arm_id(&lines[2].1), Some(JumpView::PublicIps));
        assert!(lines[3].1.starts_with("TXT 3600 s → v=DKIM1"));
        assert!(lines[3].1.ends_with('…') && lines[3].1.chars().count() < 80, "{}", lines[3].1);
        assert_eq!(lines[4].1, "MX 3600 s → 10 mail.example.com");
        assert_eq!(
            lines.last().unwrap().1,
            "az network dns record-set list -z example.com -g rg-dns --subscription 0000"
        );
        let related = dns_zone_section_lines(&zone, DnsZoneDetailSection::Related, Some(&Lazy::Loaded(records)));
        assert!(related.iter().any(|(k, v)| k == "Alias target pip-web" && *v == pip));
        assert_eq!(dns_child_path(&zone.base.id, "all"), format!("{}/all", id("dnszones/example.com")));
    }

    #[test]
    fn resolver_endpoints_rulesets_and_related_come_from_the_topology() {
        let row = DnsResolverRow::from_json(
            &serde_json::json!({
                "id": id("dnsResolvers/dnspr-hub"), "name": "dnspr-hub", "location": "westeurope",
                "properties": {"virtualNetwork": {"id": id("virtualNetworks/vnet-hub")},
                    "dnsResolverState": "Connected", "provisioningState": "Succeeded"}
            }),
            None,
        )
        .unwrap();
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "connected");
        assert_eq!(row.list_summary().as_deref(), Some("vnet vnet-hub"));
        assert!(row.search_text().contains("vnet-hub"));
        assert_eq!(row.cli_command().unwrap(), format!("az dns-resolver show --ids {}", row.base.id));
        let topo = Lazy::Loaded(topology());

        let endpoints = dns_resolver_section_lines(&row, DnsResolverDetailSection::Endpoints, Some(&topo));
        assert!(endpoints.iter().any(|(k, v)| k == "in · inbound" && v == "10.0.0.4"));
        let subnet = endpoints.iter().find(|(k, _)| k == "  Subnet · dns-in").unwrap();
        assert_eq!(JumpView::for_arm_id(&subnet.1), Some(JumpView::Subnets));
        assert!(endpoints.iter().any(|(_, v)| v.starts_with("az dns-resolver outbound-endpoint list --dns-resolver-name dnspr-hub")));

        let rulesets = dns_resolver_section_lines(&row, DnsResolverDetailSection::Rulesets, Some(&topo));
        assert_eq!(rulesets[0], ("rs-onprem · via out".to_string(), id("dnsForwardingRulesets/rs-onprem")));

        let related = dns_resolver_section_lines(&row, DnsResolverDetailSection::Related, Some(&topo));
        for label in ["Virtual network vnet-hub", "Subnet dns-in · inbound endpoint in", "Subnet dns-out · outbound endpoint out", "Ruleset rs-onprem"] {
            assert!(related.iter().any(|(k, _)| k == label), "{label}: {related:?}");
        }
        let loading = dns_resolver_section_lines(&row, DnsResolverDetailSection::Endpoints, Some(&Lazy::Loading));
        assert_eq!(loading[0].1, "Loading…");
    }

    #[test]
    fn ruleset_rules_links_and_related_reach_the_resolver_and_vnets() {
        let row = DnsRulesetRow::from_json(
            &serde_json::json!({
                "id": id("dnsForwardingRulesets/rs-onprem"), "name": "rs-onprem", "location": "westeurope",
                "properties": {"provisioningState": "Succeeded", "dnsResolverOutboundEndpoints": [
                    {"id": id("dnsResolvers/dnspr-hub/outboundEndpoints/out")}]}
            }),
            None,
        )
        .unwrap();
        let resolver = row.related().into_iter().find(|(l, _)| l == "Resolver dnspr-hub").unwrap().1;
        assert_eq!(JumpView::for_arm_id(&resolver), Some(JumpView::DnsResolvers));
        assert!(row.cli_command().unwrap().starts_with("az dns-resolver forwarding-ruleset show --ids "));

        let rules = vec![serde_json::json!({"name": "corp", "properties": {"domainName": "corp.contoso.com.",
            "targetDnsServers": [{"ipAddress": "10.10.0.4", "port": 53}, {"ipAddress": "10.10.0.5"}],
            "forwardingRuleState": "Enabled"}})];
        let lines = dns_ruleset_section_lines(&row, DnsRulesetDetailSection::Rules, Some(&Lazy::Loaded(rules)), None);
        assert_eq!(lines[0], ("corp.contoso.com.".to_string(), "→ 10.10.0.4:53, 10.10.0.5:53 · enabled".to_string()));
        assert!(lines.last().unwrap().1.starts_with("az dns-resolver forwarding-rule list --ruleset-name rs-onprem -g rg-dns"));

        let topo = Lazy::Loaded(topology());
        let links = dns_ruleset_section_lines(&row, DnsRulesetDetailSection::VnetLinks, None, Some(&topo));
        let (_, vnet) = links.iter().find(|(k, _)| k == "spoke-link · vnet-aca").unwrap();
        assert_eq!(JumpView::for_arm_id(vnet), Some(JumpView::VirtualNetworks));
        assert!(links.iter().any(|(k, v)| k == "  Metadata" && v == "env=prod"));

        let related = dns_ruleset_section_lines(&row, DnsRulesetDetailSection::Related, None, Some(&topo));
        for label in ["Resolver dnspr-hub", "Subnet dns-out · outbound endpoint out", "Resolver VNet vnet-hub", "Linked VNet vnet-aca"] {
            assert!(related.iter().any(|(k, _)| k == label), "{label}: {related:?}");
        }
    }

    #[test]
    fn vnet_and_subnet_related_list_what_points_at_them() {
        let topo = Lazy::Loaded(topology());
        let hub = id("virtualNetworks/vnet-hub");
        let lines = vnet_dns_related(Some(&topo), &hub);
        assert!(lines.iter().any(|(k, _)| k == "DNS resolver dnspr-hub"));
        // The zone's link spells the id in another case: still a match.
        let aca = vnet_dns_related(Some(&topo), &id("virtualNetworks/vnet-aca"));
        assert!(aca.iter().any(|(k, _)| k == "Forwarding ruleset rs-onprem"));
        assert!(aca.iter().any(|(k, _)| k == "Private DNS zone privatelink.example"));
        let none = vnet_dns_related(Some(&topo), &id("virtualNetworks/other"));
        assert!(none.iter().any(|(_, v)| v.starts_with("· no DNS resolver")));
        assert!(vnet_dns_related(None, &hub).iter().any(|(_, v)| v == "Loading…"));

        let subnet = subnet_dns_related(Some(&topo), &id("virtualNetworks/vnet-hub/subnets/dns-in"));
        assert!(subnet.iter().any(|(k, _)| k == "DNS resolver dnspr-hub · inbound endpoint in"));
        assert!(subnet_dns_related(None, "x").is_empty());
    }

    #[test]
    fn policy_rules_sort_by_priority_and_domain_lists_land_in_all_resources() {
        let row = DnsPolicyRow::from_json(
            &serde_json::json!({"id": id("dnsResolverPolicies/pol"), "name": "pol", "location": "westeurope",
                "properties": {"provisioningState": "Succeeded"}}),
            None,
        )
        .unwrap();
        assert!(row.cli_command().unwrap().starts_with("az dns-resolver policy show --ids "));
        let list = id("dnsResolverDomainLists/blocked");
        let rules = vec![
            serde_json::json!({"name": "allow", "properties": {"priority": 200, "action": {"actionType": "Allow"},
                "dnsResolverDomainLists": [], "dnsSecurityRuleState": "Enabled"}}),
            serde_json::json!({"name": "block", "properties": {"priority": 100, "action": {"actionType": "Block"},
                "dnsResolverDomainLists": [{"id": list}], "dnsSecurityRuleState": "Enabled"}}),
        ];
        let lines = dns_policy_section_lines(&row, DnsPolicyDetailSection::Rules, Some(&Lazy::Loaded(rules)), None);
        assert_eq!(lines[1], ("100 · block".to_string(), "block · enabled".to_string()));
        assert_eq!(lines[2], ("  Domain list · blocked".to_string(), list.clone()));
        assert_eq!(JumpView::landing_for_arm_id(&list), Some(JumpView::AllResources));
        assert!(lines.last().unwrap().1.starts_with("az dns-resolver policy dns-security-rule list --policy-name pol"));
    }

    #[test]
    fn endpoint_ids_name_their_resolver() {
        assert_eq!(
            resolver_of_endpoint(&id("dnsResolvers/r/OUTBOUNDENDPOINTS/o")),
            Some(id("dnsResolvers/r"))
        );
        assert_eq!(resolver_of_endpoint(&id("dnsResolvers/r")), None);
    }
}
