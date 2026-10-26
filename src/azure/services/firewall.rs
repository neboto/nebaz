//! The Firewall service (issue #136): the hub's security layer. Azure
//! Firewalls (`Microsoft.Network/azureFirewalls`), firewall policies
//! (`firewallPolicies`, their rule collection groups lazy), IP groups
//! (`ipGroups`), and Palo Alto Networks Cloud NGFW
//! (`PaloAltoNetworks.Cloudngfw/firewalls`) with its local rulestacks
//! (`localRulestacks`, rules and objects lazy). Five subscription-wide
//! lists; its own tab (SERVICES.md rule 27 says why).
//!
//! **What a UDR points at** is the first thing each firewall shows: an
//! Azure Firewall's private IP, a Cloud NGFW's `ipOfTrustSubnetForUdr`.
//! [`udr_next_hops`] returns those addresses for any row, and
//! [`firewall_for_next_hop`] finds the warm firewall a route's next hop
//! names, so a route table can say which firewall its traffic goes through
//! without a call.
//!
//! **Never**: a Cloud NGFW's Panorama registration string (`configString`)
//! or VM auth key (`vmAuthKey`), stripped before the row keeps its JSON.
//! Every read is a `GET`: the rulestack's `listFirewalls`, `listAppIds`,
//! `listSecurityServices`, the firewall's `getGlobalRulestack`,
//! `getLogProfile` and `getSupportInfo`, and an Azure Firewall's
//! `learnedIPPrefixes`, are `POST`s nebaz never sends. Global rulestacks
//! are tenant-scoped (`/providers/PaloAltoNetworks.Cloudngfw/globalRulestacks`,
//! no subscription in the path), outside a subscription `Reader`: a
//! firewall that uses one names it as text.

use crate::azure::resource::{
    name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::network::NETWORK_API_VERSION;
use crate::azure::services::network_edge::RouteTableRow;
use crate::azure::services::{arm_row, error_rows, finish_stream, json, overview_rows, related_lines, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::{Lazy, LazyMap};
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// Azure Firewall, firewall policies and IP groups are Network types: the
/// Network service's version.
pub const AZFW_API_VERSION: &str = NETWORK_API_VERSION;
/// `PaloAltoNetworks.Cloudngfw` (azure-rest-api-specs, checked
/// 2026-10-26): the version the `palo-alto-networks` CLI extension pins.
/// `2026-06-01` is newer but landed in the specs six weeks ago.
pub const NGFW_API_VERSION: &str = "2025-10-08";

const AZURE_FIREWALLS_PATH: &str = "/providers/Microsoft.Network/azureFirewalls";
const FIREWALL_POLICIES_PATH: &str = "/providers/Microsoft.Network/firewallPolicies";
const IP_GROUPS_PATH: &str = "/providers/Microsoft.Network/ipGroups";
const NGFWS_PATH: &str = "/providers/PaloAltoNetworks.Cloudngfw/firewalls";
const RULESTACKS_PATH: &str = "/providers/PaloAltoNetworks.Cloudngfw/localRulestacks";

crate::sections! {
    pub enum AzureFirewallDetailSection,
    pub static AZURE_FIREWALL_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Policy "Policy",
        Rules "Rules" => crate::app::App::trigger_firewall_rules,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum FirewallPolicyDetailSection,
    pub static FIREWALL_POLICY_SECTIONS = [
        Overview "Overview",
        Settings "Settings",
        RuleCollectionGroups "Rule collection groups" => crate::app::App::trigger_firewall_rules,
        Hierarchy "Hierarchy",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum IpGroupDetailSection,
    pub static IP_GROUP_SECTIONS = [
        Overview "Overview",
        Addresses "Addresses",
        UsedBy "Used by",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum CloudNgfwDetailSection,
    pub static CLOUD_NGFW_SECTIONS = [
        Overview "Overview",
        Network "Network",
        FrontEnd "Front end",
        Rules "Rules" => crate::app::App::trigger_firewall_rules,
        Management "Management",
        Status "Status" => crate::app::App::trigger_ngfw_status,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum RulestackDetailSection,
    pub static RULESTACK_SECTIONS = [
        Overview "Overview",
        Rules "Rules" => crate::app::App::trigger_firewall_rules,
        Objects "Objects" => crate::app::App::trigger_rulestack_objects,
        SecurityServices "Security services",
        Firewalls "Firewalls",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Secrets out of the JSON ───────────────────────────────────────────

/// A Cloud NGFW's Panorama registration string (it carries the auth key)
/// and the VM auth key itself.
const SECRET_FIELDS: &[&str] = &["configString", "vmAuthKey"];

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            map.values_mut().for_each(scrub);
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with the Panorama secrets removed, at any depth.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

// ── Small shared readers ──────────────────────────────────────────────

fn push_unique(v: &mut Vec<(String, String)>, label: String, id: String) {
    if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&id)) {
        v.push((label, id));
    }
}

fn same_id(a: &str, b: &str) -> bool {
    a.trim_end_matches('/').eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// `vnet/subnet` from a subnet id.
fn subnet_label(id: &str) -> String {
    let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
    match parts.iter().rposition(|p| p.eq_ignore_ascii_case("subnets")) {
        Some(i) if i >= 2 && i + 1 < parts.len() => format!("{}/{}", parts[i - 1], parts[i + 1]),
        _ => name_of_id(id).to_string(),
    }
}

/// The VNet id of a subnet id.
fn vnet_of_subnet(id: &str) -> Option<String> {
    let lower = id.to_lowercase();
    let at = lower.rfind("/subnets/")?;
    Some(id[..at].to_string())
}

/// The `{"…": {"id": "…"}}` ids of an array, ARM ids only.
fn arm_ids(v: &Value, ptr: &str) -> Vec<String> {
    json::ids_at(v, ptr).into_iter().filter(|i| i.starts_with("/subscriptions/")).collect()
}

/// Strings of an array at `ptr`, `-` joined by `, ` when empty.
fn list_text(v: &Value, ptr: &str) -> String {
    json::join(&json::strings_at(v, ptr))
}

/// A Cloud NGFW `BooleanEnum` (`TRUE` / `FALSE`).
fn bool_enum(v: &Value, ptr: &str) -> bool {
    json::str_at(v, ptr).is_some_and(|s| s.eq_ignore_ascii_case("true"))
}

/// The rows of one type in a warm list.
fn rows_of<'a, T: 'static>(list: Option<&'a [Box<dyn Resource>]>) -> impl Iterator<Item = &'a T> + 'a {
    list.unwrap_or_default().iter().filter_map(|r| r.as_any().downcast_ref::<T>())
}

/// The lazy-map key for a policy's or rulestack's rules: the id
/// lowercased, so a reference spelled differently from the row's own id
/// finds the same read.
pub fn rules_key(id: &str) -> String {
    id.trim_end_matches('/').to_lowercase()
}

/// `{policy}/ruleCollectionGroups`.
pub fn rule_collection_groups_path(policy_id: &str) -> String {
    format!("{}/ruleCollectionGroups", policy_id.trim_end_matches('/'))
}

/// `{rulestack}/{child}`: `localRules`, `prefixlists`, `fqdnlists`.
pub fn rulestack_child_path(rulestack_id: &str, child: &str) -> String {
    format!("{}/{}", rulestack_id.trim_end_matches('/'), child)
}

/// `{firewall}/statuses/default`.
pub fn ngfw_status_path(firewall_id: &str) -> String {
    format!("{}/statuses/default", firewall_id.trim_end_matches('/'))
}

/// The warm Firewall-tab lists of one subscription a section reads. `None`
/// is a list not loaded this session.
#[derive(Default, Clone, Copy)]
pub struct FirewallLists<'a> {
    pub firewalls: Option<&'a [Box<dyn Resource>]>,
    pub policies: Option<&'a [Box<dyn Resource>]>,
    pub ip_groups: Option<&'a [Box<dyn Resource>]>,
    pub ngfws: Option<&'a [Box<dyn Resource>]>,
    pub rulestacks: Option<&'a [Box<dyn Resource>]>,
    /// The warm Network route tables, for "routed here".
    pub route_tables: Option<&'a [Box<dyn Resource>]>,
}

impl<'a> FirewallLists<'a> {
    fn policy(&self, id: &str) -> Option<&'a FirewallPolicyRow> {
        rows_of::<FirewallPolicyRow>(self.policies).find(|p| same_id(&p.base.id, id))
    }

    fn ip_group(&self, id: &str) -> Option<&'a IpGroupRow> {
        rows_of::<IpGroupRow>(self.ip_groups).find(|g| same_id(&g.base.id, id))
    }

    fn rulestack(&self, id: &str) -> Option<&'a RulestackRow> {
        rows_of::<RulestackRow>(self.rulestacks).find(|r| same_id(&r.base.id, id))
    }
}

/// The lazy reads the sections render: rule collection groups by policy,
/// local rules, prefix lists and FQDN lists by rulestack, each keyed by
/// [`rules_key`]; a Cloud NGFW's status by its id.
#[derive(Clone, Copy)]
pub struct FirewallLazy<'a> {
    pub rule_collection_groups: &'a LazyMap<Vec<Value>>,
    pub ngfw_rules: &'a LazyMap<Vec<Value>>,
    pub prefix_lists: &'a LazyMap<Vec<Value>>,
    pub fqdn_lists: &'a LazyMap<Vec<Value>>,
    pub ngfw_status: &'a LazyMap<Value>,
}

// ── UDR next hops ─────────────────────────────────────────────────────

/// The addresses a spoke's user-defined route sends traffic to when this
/// firewall is its next hop: an Azure Firewall's private IP (or its
/// virtual hub private IP), a Cloud NGFW's `ipOfTrustSubnetForUdr`. Empty
/// for any other row. Pure: what the list body carries.
pub fn udr_next_hops(r: &dyn Resource) -> Vec<String> {
    let any = r.as_any();
    if let Some(f) = any.downcast_ref::<AzureFirewallRow>() {
        return f.private_ips();
    }
    if let Some(n) = any.downcast_ref::<CloudNgfwRow>() {
        return n.udr_ip().into_iter().collect();
    }
    Vec::new()
}

/// The warm route tables' routes whose next hop is one of `next_hops`,
/// as jumpable lines (each table, then the subnets it is associated with):
/// what sends traffic through this firewall. No call.
pub fn routes_to(next_hops: &[String], route_tables: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    let Some(tables) = route_tables else {
        return vec![(String::new(), "· load @rt to see which route tables send traffic here".into())];
    };
    let mut lines = Vec::new();
    for t in rows_of::<RouteTableRow>(Some(tables)) {
        let routes: Vec<String> = t
            .routes
            .iter()
            .filter(|r| r.next_hop_ip.as_deref().is_some_and(|ip| next_hops.iter().any(|h| h == ip.trim())))
            .map(|r| format!("{} {}", r.name, r.prefix))
            .collect();
        if routes.is_empty() {
            continue;
        }
        lines.push((format!("Route table {} ({})", t.base.name, routes.join(", ")), t.base.id.clone()));
        for s in &t.subnet_ids {
            lines.push((format!("  subnet {}", subnet_label(s)), s.clone()));
        }
    }
    if lines.is_empty() {
        lines.push((String::new(), "No loaded route table sends traffic here".into()));
    }
    lines
}

/// The firewall among `lists` (the warm Firewalls and Cloud NGFW lists)
/// whose UDR next hop is `ip`: what a route's `nextHopIpAddress` points
/// at. No call.
// The route-table side of the match: a follow-up names the firewall a
// route's next hop is (Network · Routes).
#[allow(dead_code)]
pub fn firewall_for_next_hop<'a>(ip: &str, lists: &[&'a [Box<dyn Resource>]]) -> Option<&'a dyn Resource> {
    let ip = ip.trim();
    if ip.is_empty() {
        return None;
    }
    lists
        .iter()
        .flat_map(|l| l.iter())
        .find(|r| udr_next_hops(r.as_ref()).iter().any(|h| h == ip))
        .map(|r| r.as_ref())
}

// ── Rule rendering (policies, classic collections) ────────────────────

/// One side of a rule: addresses, FQDNs, IP group names.
fn side(v: &Value, addrs: &str, fqdns: Option<&str>, ip_groups: &str) -> String {
    let mut parts = json::strings_at(v, addrs);
    if let Some(f) = fqdns {
        parts.extend(json::strings_at(v, f));
    }
    parts.extend(json::strings_at(v, ip_groups).iter().map(|g| format!("ipg:{}", name_of_id(g))));
    if parts.is_empty() {
        "*".into()
    } else {
        parts.join(", ")
    }
}

/// `TCP, UDP`, or an application rule's `Https:443, Http:80`.
fn protocols(v: &Value) -> String {
    let mut out = json::strings_at(v, "/ipProtocols");
    for p in json::arr(v, "/protocols") {
        match &p {
            Value::String(s) => out.push(s.clone()),
            _ => {
                let t = json::text(&p, "/protocolType");
                match json::str_at(&p, "/port") {
                    Some(port) => out.push(format!("{}:{}", t, port)),
                    None => out.push(t),
                }
            }
        }
    }
    if out.is_empty() {
        "any".into()
    } else {
        out.join(", ")
    }
}

/// The kind of a rule: the policy's `ruleType`, else the classic
/// collection's kind.
fn rule_kind(rule: &Value, classic: &str) -> String {
    json::str_at(rule, "/ruleType").unwrap_or_else(|| classic.to_string())
}

/// One rule as a line: what it matches, in the order a reader checks.
fn rule_summary(rule: &Value, kind: &str) -> String {
    let src = side(rule, "/sourceAddresses", None, "/sourceIpGroups");
    let ports = json::strings_at(rule, "/destinationPorts");
    let ports = if ports.is_empty() { String::new() } else { format!(" :{}", ports.join(",")) };
    let k = kind.to_lowercase();
    if k.contains("application") {
        let mut targets = json::strings_at(rule, "/targetFqdns");
        targets.extend(json::strings_at(rule, "/fqdnTags").iter().map(|t| format!("tag:{}", t)));
        targets.extend(json::strings_at(rule, "/targetUrls").iter().map(|u| format!("url:{}", u)));
        targets.extend(json::strings_at(rule, "/webCategories").iter().map(|c| format!("category:{}", c)));
        targets.extend(json::strings_at(rule, "/destinationAddresses"));
        let tls = if json::bool_at(rule, "/terminateTLS") == Some(true) { " · TLS inspected" } else { "" };
        format!(
            "{} · {} → {}{}",
            protocols(rule),
            src,
            if targets.is_empty() { "*".into() } else { targets.join(", ") },
            tls
        )
    } else if k.contains("nat") {
        let dst = side(rule, "/destinationAddresses", None, "/destinationIpGroups");
        let to = json::str_at(rule, "/translatedAddress")
            .or_else(|| json::str_at(rule, "/translatedFqdn"))
            .unwrap_or_else(|| "-".into());
        let to_port = json::str_at(rule, "/translatedPort").map(|p| format!(":{}", p)).unwrap_or_default();
        format!("{} · {} → {}{} ⇒ {}{}", protocols(rule), src, dst, ports, to, to_port)
    } else {
        let dst = side(rule, "/destinationAddresses", Some("/destinationFqdns"), "/destinationIpGroups");
        format!("{} · {} → {}{}", protocols(rule), src, dst, ports)
    }
}

/// The IP groups a rule names, as jumpable lines under it.
fn ip_group_lines(rule: &Value, indent: &str, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ptr, side) in [("/sourceIpGroups", "source"), ("/destinationIpGroups", "destination")] {
        for g in json::strings_at(rule, ptr) {
            let count = lists
                .ip_group(&g)
                .map(|row| format!(" ({} addresses)", row.addresses.len()))
                .unwrap_or_default();
            out.push((format!("{}{} IP group {}{}", indent, side, name_of_id(&g), count), g));
        }
    }
    out
}

/// A rule collection group (or a list of them) sorted by priority, then
/// name: the order Azure evaluates them in within one rule type.
fn by_priority(items: &[Value], ptr: &str) -> Vec<Value> {
    let mut items = items.to_vec();
    items.sort_by(|a, b| {
        let pa = json::int_at(a, ptr).unwrap_or(i64::MAX);
        let pb = json::int_at(b, ptr).unwrap_or(i64::MAX);
        pa.cmp(&pb).then_with(|| json::text(a, "/name").to_lowercase().cmp(&json::text(b, "/name").to_lowercase()))
    });
    items
}

/// A collection's kind and action: `DNAT`, `Allow`, `Deny`.
fn collection_kind(c: &Value) -> String {
    match json::str_at(c, "/ruleCollectionType").as_deref() {
        Some(t) if t.to_lowercase().contains("nat") => "DNAT".into(),
        Some(_) => "Filter".into(),
        None => "-".into(),
    }
}

/// Every group of a policy's rule collection groups, by priority, each
/// collection by priority, each rule in the collection's order.
pub fn rule_collection_group_rows(groups: &[Value], lists: &FirewallLists<'_>, inherited_from: Option<&str>) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let tag = inherited_from.map(|b| format!(" (inherited from {})", b)).unwrap_or_default();
    for g in by_priority(groups, "/properties/priority") {
        let collections = json::arr(&g, "/properties/ruleCollections");
        lines.push((
            format!("Group {}{}", json::text(&g, "/name"), tag),
            format!("priority {} · {} collections", json::text(&g, "/properties/priority"), collections.len()),
        ));
        for c in by_priority(&collections, "/priority") {
            let rules = json::arr(&c, "/rules");
            lines.push((
                format!("  Collection {}", json::text(&c, "/name")),
                format!(
                    "{} · {} · priority {} · {} rules",
                    collection_kind(&c),
                    json::text(&c, "/action/type"),
                    json::text(&c, "/priority"),
                    rules.len()
                ),
            ));
            for r in &rules {
                let kind = rule_kind(r, "-");
                lines.push((format!("    {} {}", kind.trim_end_matches("Rule"), json::text(r, "/name")), rule_summary(r, &kind)));
                lines.extend(ip_group_lines(r, "      ", lists));
            }
        }
    }
    lines
}

/// The note every rules section closes with: how Azure orders what it
/// just listed.
fn processing_note() -> (String, String) {
    (
        String::new(),
        "· Azure applies DNAT rules first, then network, then application rules; within each, by group then collection priority (100 first). A base policy's groups come before the policy's own.".into(),
    )
}

/// A policy's rules with its base's first: the base's groups once they
/// have loaded, `Loading…` while they read.
fn policy_rules_rows(
    policy_id: &str,
    base_id: Option<&str>,
    lazy: &FirewallLazy<'_>,
    lists: &FirewallLists<'_>,
) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if let Some(base) = base_id {
        match lazy.rule_collection_groups.get(&rules_key(base)) {
            None | Some(Lazy::Loading) => lines.push((format!("Base policy {}", name_of_id(base)), "Loading…".into())),
            Some(Lazy::Error(e)) => lines.push((format!("Base policy {}", name_of_id(base)), format!("⚠ {}", e))),
            Some(Lazy::Loaded(groups)) => lines.extend(rule_collection_group_rows(groups, lists, Some(name_of_id(base)))),
        }
    }
    match lazy.rule_collection_groups.get(&rules_key(policy_id)) {
        None | Some(Lazy::Loading) => lines.push(("Rule collection groups".into(), "Loading…".into())),
        Some(Lazy::Error(e)) => lines.extend(error_rows(e)),
        Some(Lazy::Loaded(groups)) if groups.is_empty() && base_id.is_none() => {
            lines.push((String::new(), "No rule collection groups: the policy allows nothing (deny by default)".into()))
        }
        Some(Lazy::Loaded(groups)) => lines.extend(rule_collection_group_rows(groups, lists, None)),
    }
    lines.push((String::new(), String::new()));
    lines.push(processing_note());
    lines
}

// ── Azure Firewall ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AzureFirewallRow {
    pub base: ArmBase,
    /// `AZFW_VNet` or `AZFW_Hub`.
    pub sku_name: Option<String>,
    /// `Basic`, `Standard`, `Premium`.
    pub sku_tier: Option<String>,
    pub threat_intel_mode: Option<String>,
    pub policy_id: Option<String>,
    pub virtual_hub_id: Option<String>,
    pub ip_configs: Vec<Value>,
    pub management_ip_config: Option<Value>,
    pub hub_ip_addresses: Option<Value>,
    pub zones: Vec<String>,
    /// `additionalProperties`: `Network.DNS.EnableProxy`, …
    pub additional: Vec<(String, String)>,
    pub ip_group_ids: Vec<String>,
    pub network_collections: Vec<Value>,
    pub application_collections: Vec<Value>,
    pub nat_collections: Vec<Value>,
    pub autoscale: Option<(Option<i64>, Option<i64>)>,
}

impl AzureFirewallRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AzureFirewallRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let mut additional: Vec<(String, String)> = v
            .pointer("/properties/additionalProperties")
            .and_then(|m| m.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect())
            .unwrap_or_default();
        additional.sort();
        Some(AzureFirewallRow {
            sku_name: json::str_at(v, &p("sku/name")),
            sku_tier: json::str_at(v, &p("sku/tier")),
            threat_intel_mode: json::str_at(v, &p("threatIntelMode")),
            policy_id: json::arm_id(json::id_at(v, &p("firewallPolicy"))),
            virtual_hub_id: json::arm_id(json::id_at(v, &p("virtualHub"))),
            ip_configs: json::arr(v, &p("ipConfigurations")),
            management_ip_config: v.pointer("/properties/managementIpConfiguration").filter(|m| m.is_object()).cloned(),
            hub_ip_addresses: v.pointer("/properties/hubIPAddresses").filter(|m| m.is_object()).cloned(),
            zones: json::strings_at(v, "/zones"),
            additional,
            ip_group_ids: arm_ids(v, &p("ipGroups")),
            network_collections: json::arr(v, &p("networkRuleCollections")),
            application_collections: json::arr(v, &p("applicationRuleCollections")),
            nat_collections: json::arr(v, &p("natRuleCollections")),
            autoscale: v
                .pointer("/properties/autoscaleConfiguration")
                .filter(|a| a.is_object())
                .map(|a| (json::int_at(a, "/minCapacity"), json::int_at(a, "/maxCapacity"))),
            base,
        })
    }

    fn tier(&self) -> &str {
        self.sku_tier.as_deref().unwrap_or("-")
    }

    fn is_hub(&self) -> bool {
        self.sku_name.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("AZFW_Hub")) || self.virtual_hub_id.is_some()
    }

    /// The private IPs a UDR points at: each IP configuration's, then the
    /// virtual hub's.
    pub fn private_ips(&self) -> Vec<String> {
        let mut ips: Vec<String> = self
            .ip_configs
            .iter()
            .filter_map(|c| json::str_at(c, "/properties/privateIPAddress"))
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(h) = self.hub_ip_addresses.as_ref().and_then(|h| json::str_at(h, "/privateIPAddress")) {
            if !ips.contains(&h) {
                ips.push(h);
            }
        }
        ips
    }

    /// The firewall's own subnets (`AzureFirewallSubnet`).
    fn subnet_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for c in &self.ip_configs {
            if let Some(s) = json::arm_id(json::id_at(c, "/properties/subnet")) {
                if !v.iter().any(|e| same_id(e, &s)) {
                    v.push(s);
                }
            }
        }
        v
    }

    fn public_ip_ids(&self) -> Vec<String> {
        self.ip_configs
            .iter()
            .filter_map(|c| json::arm_id(json::id_at(c, "/properties/publicIPAddress")))
            .collect()
    }

    fn additional(&self, key: &str) -> Option<&str> {
        self.additional.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }

    fn classic_rule_count(&self) -> usize {
        [&self.network_collections, &self.application_collections, &self.nat_collections]
            .iter()
            .flat_map(|c| c.iter())
            .map(|c| json::arr(c, "/properties/rules").len())
            .sum()
    }

    /// A deallocated firewall keeps no IP configuration (VNet) or hub
    /// addresses (vWAN): ARM's only sign it is stopped.
    fn ladder(&self) -> (ResourceState, String) {
        let allocated = if self.is_hub() { self.hub_ip_addresses.is_some() } else { !self.ip_configs.is_empty() };
        let runtime = if allocated { (ResourceState::Running, "allocated") } else { (ResourceState::Stopped, "deallocated") };
        state_ladder(self.base.provisioning_state.as_deref(), Some(runtime))
    }

    fn network_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        let ips = udr_next_hops(self);
        lines.push((
            "UDR next hop (private IP)".into(),
            if ips.is_empty() { "- (deallocated: no IP configuration)".into() } else { ips.join(", ") },
        ));
        lines.push((String::new(), "· spoke route tables send 0.0.0.0/0 (or a prefix) to this address as a virtual appliance".into()));
        lines.push((String::new(), String::new()));
        for s in self.subnet_ids() {
            if let Some(vnet) = vnet_of_subnet(&s) {
                lines.push((format!("VNet {}", name_of_id(&vnet)), vnet));
            }
            lines.push((format!("Subnet {}", subnet_label(&s)), s));
        }
        if let Some(h) = &self.virtual_hub_id {
            lines.push((format!("Virtual hub {}", name_of_id(h)), h.clone()));
        }
        for c in &self.ip_configs {
            let name = json::text(c, "/name");
            let private = json::str_at(c, "/properties/privateIPAddress").map(|p| format!(" · private {}", p)).unwrap_or_default();
            match json::arm_id(json::id_at(c, "/properties/publicIPAddress")) {
                Some(pip) => lines.push((format!("IP config {}{} · public IP {}", name, private, name_of_id(&pip)), pip)),
                None => lines.push((format!("IP config {}", name), private.trim_start_matches(" · ").to_string())),
            }
        }
        if let Some(h) = &self.hub_ip_addresses {
            let public: Vec<String> = json::arr(h, "/publicIPs/addresses").iter().filter_map(|a| json::str_at(a, "/address")).collect();
            lines.push(("Hub public IPs".into(), json::join(&public)));
            lines.push(("Hub public IP count".into(), json::text(h, "/publicIPs/count")));
        }
        lines.push((String::new(), String::new()));
        match &self.management_ip_config {
            Some(m) => {
                lines.push(("Forced tunnelling".into(), "on (a management IP configuration carries the control traffic)".into()));
                if let Some(s) = json::arm_id(json::id_at(m, "/properties/subnet")) {
                    lines.push((format!("Management subnet {}", subnet_label(&s)), s));
                }
                if let Some(pip) = json::arm_id(json::id_at(m, "/properties/publicIPAddress")) {
                    lines.push((format!("Management public IP {}", name_of_id(&pip)), pip));
                }
            }
            None => lines.push(("Management IP configuration".into(), "- (no forced tunnelling)".into())),
        }
        lines.push(("Zones".into(), json::join(&self.zones)));
        lines.push((String::new(), String::new()));
        lines.push(("Routed here".into(), String::new()));
        lines.extend(routes_to(&ips, lists.route_tables));
        lines
    }

    /// Policy: the governing settings, from the warm policy when it is
    /// loaded; the classic settings without one.
    fn policy_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        match &self.policy_id {
            Some(pid) => {
                lines.push((format!("Firewall policy {}", name_of_id(pid)), pid.clone()));
                match lists.policy(pid) {
                    Some(p) => {
                        lines.push(("Policy tier".into(), json::opt(p.tier.clone())));
                        lines.push(("Threat intelligence".into(), json::opt(p.threat_intel_mode.clone())));
                        lines.push(("IDPS".into(), p.idps_mode()));
                        lines.push(("TLS inspection".into(), p.tls_label()));
                        lines.push(("DNS proxy".into(), p.dns_proxy_label()));
                        if let Some(b) = &p.base_policy_id {
                            lines.push((format!("Base policy {}", name_of_id(b)), b.clone()));
                        }
                        if !self.sku_tier.as_deref().unwrap_or("").eq_ignore_ascii_case(p.tier.as_deref().unwrap_or("")) {
                            lines.push((
                                String::new(),
                                format!("⚠ the firewall is {} and the policy {}: the tiers must match", self.tier(), json::opt(p.tier.clone())),
                            ));
                        }
                    }
                    None => lines.push((String::new(), "· the policy's settings show once @fwp is loaded".into())),
                }
            }
            None => {
                lines.push(("Firewall policy".into(), "- (classic rules: the rules and settings live on the firewall)".into()));
                lines.push(("Threat intelligence".into(), json::opt(self.threat_intel_mode.clone())));
                lines.push((
                    "DNS proxy".into(),
                    match self.additional("Network.DNS.EnableProxy") {
                        Some(v) if v.eq_ignore_ascii_case("true") => "on".into(),
                        Some(_) => "off".into(),
                        None => "off".into(),
                    },
                ));
                if let Some(servers) = self.additional("Network.DNS.Servers") {
                    lines.push(("DNS servers".into(), servers.to_string()));
                }
                if let Some(snat) = self.additional("Network.SNAT.PrivateRanges") {
                    lines.push(("SNAT private ranges".into(), snat.to_string()));
                }
            }
        }
        for g in &self.ip_group_ids {
            lines.push((format!("IP group {}", name_of_id(g)), g.clone()));
        }
        let rest: Vec<&(String, String)> = self
            .additional
            .iter()
            .filter(|(k, _)| !["network.dns.enableproxy", "network.dns.servers", "network.snat.privateranges"].contains(&k.to_lowercase().as_str()))
            .collect();
        if !rest.is_empty() {
            lines.push((String::new(), String::new()));
            for (k, v) in rest {
                lines.push((k.clone(), v.clone()));
            }
        }
        lines
    }

    fn classic_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        let mut lines = vec![(String::new(), "Classic rule collections (no firewall policy)".into())];
        for (collections, kind) in [
            (&self.nat_collections, "NatRule"),
            (&self.network_collections, "NetworkRule"),
            (&self.application_collections, "ApplicationRule"),
        ] {
            for c in by_priority(collections, "/properties/priority") {
                let rules = json::arr(&c, "/properties/rules");
                lines.push((
                    format!("Collection {}", json::text(&c, "/name")),
                    format!(
                        "{} · {} · priority {} · {} rules",
                        kind.trim_end_matches("Rule"),
                        json::text(&c, "/properties/action/type"),
                        json::text(&c, "/properties/priority"),
                        rules.len()
                    ),
                ));
                for r in &rules {
                    lines.push((format!("  {}", json::text(r, "/name")), rule_summary(r, kind)));
                    lines.extend(ip_group_lines(r, "    ", lists));
                }
            }
        }
        if lines.len() == 1 {
            lines.push((String::new(), "No rules: the firewall denies everything".into()));
        }
        lines.push((String::new(), String::new()));
        lines.push(processing_note());
        lines
    }

    /// The policy and its base, as the rules section reads them.
    pub fn rule_sources(&self, lists: &FirewallLists<'_>) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(p) = &self.policy_id {
            v.push(p.clone());
            if let Some(b) = lists.policy(p).and_then(|p| p.base_policy_id.clone()) {
                v.push(b);
            }
        }
        v
    }

    fn rules_rows(&self, lazy: &FirewallLazy<'_>, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        match &self.policy_id {
            None => self.classic_rows(lists),
            Some(pid) => {
                let base = lists.policy(pid).and_then(|p| p.base_policy_id.clone());
                let mut lines = vec![(format!("From policy {}", name_of_id(pid)), pid.clone())];
                if lists.policy(pid).is_none() {
                    lines.push((String::new(), "· load @fwp to include a base policy's groups (they come first)".into()));
                }
                lines.extend(policy_rules_rows(pid, base.as_deref(), lazy, lists));
                lines
            }
        }
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(p) = &self.policy_id {
            push_unique(&mut v, format!("Firewall policy {}", name_of_id(p)), p.clone());
        }
        for s in self.subnet_ids() {
            if let Some(vnet) = vnet_of_subnet(&s) {
                push_unique(&mut v, format!("VNet {}", name_of_id(&vnet)), vnet);
            }
            push_unique(&mut v, format!("Subnet {}", subnet_label(&s)), s);
        }
        if let Some(h) = &self.virtual_hub_id {
            push_unique(&mut v, format!("Virtual hub {}", name_of_id(h)), h.clone());
        }
        for pip in self.public_ip_ids() {
            push_unique(&mut v, format!("Public IP {}", name_of_id(&pip)), pip);
        }
        if let Some(m) = &self.management_ip_config {
            if let Some(s) = json::arm_id(json::id_at(m, "/properties/subnet")) {
                push_unique(&mut v, format!("Management subnet {}", subnet_label(&s)), s);
            }
            if let Some(pip) = json::arm_id(json::id_at(m, "/properties/publicIPAddress")) {
                push_unique(&mut v, format!("Management public IP {}", name_of_id(&pip)), pip);
            }
        }
        for g in &self.ip_group_ids {
            push_unique(&mut v, format!("IP group {}", name_of_id(g)), g.clone());
        }
        v
    }
}

impl Resource for AzureFirewallRow {
    arm_row!("Azure Firewall");
    /// `Premium · 10.10.9.4 · policy fwp-hub-prod`: the next hop first.
    fn list_summary(&self) -> Option<String> {
        let ips = self.private_ips();
        let ip = if ips.is_empty() { "no IP".to_string() } else { ips.join(", ") };
        let rules = match &self.policy_id {
            Some(p) => format!("policy {}", name_of_id(p)),
            None => format!("{} classic rules", self.classic_rule_count()),
        };
        Some(format!("{} · {} · {}", self.tier(), ip, rules))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&AZURE_FIREWALL_SECTIONS)
    }
    /// Its private IPs are searchable: `@* 10.10.9.4` finds the firewall a
    /// route points at.
    fn search_text(&self) -> String {
        let mut parts = vec![self.base.id.clone(), self.base.name.clone(), self.tier().to_string()];
        parts.extend(self.private_ips());
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        let ips = self.private_ips();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("UDR next hop (private IP)".into(), json::join(&ips)),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), format!("{} · {}", json::opt(self.sku_name.clone()), self.tier())),
            (
                "Firewall policy".into(),
                self.policy_id.as_deref().map(|p| name_of_id(p).to_string()).unwrap_or_else(|| "- (classic rules)".into()),
            ),
            ("Threat intelligence".into(), json::opt(self.threat_intel_mode.clone())),
            ("Public IPs".into(), self.public_ip_ids().len().to_string()),
            ("Forced tunnelling".into(), json::yes_no(Some(self.management_ip_config.is_some()))),
            ("Zones".into(), json::join(&self.zones)),
            (
                "Autoscale".into(),
                match self.autoscale {
                    Some((min, max)) => format!("{}–{}", json::num(min), json::num(max)),
                    None => "-".into(),
                },
            ),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        AzureFirewallRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network firewall show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn azure_firewall_section_lines(
    r: &AzureFirewallRow,
    section: AzureFirewallDetailSection,
    lists: &FirewallLists<'_>,
    lazy: &FirewallLazy<'_>,
) -> Vec<(String, String)> {
    match section {
        AzureFirewallDetailSection::Overview => overview_rows(r),
        AzureFirewallDetailSection::Network => r.network_rows(lists),
        AzureFirewallDetailSection::Policy => r.policy_rows(lists),
        AzureFirewallDetailSection::Rules => r.rules_rows(lazy, lists),
        AzureFirewallDetailSection::Access => crate::azure::services::rendered_by_app(),
        AzureFirewallDetailSection::Activity => crate::azure::services::rendered_by_app(),
        AzureFirewallDetailSection::Related => related_lines(r.related()),
        AzureFirewallDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Firewall policy ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FirewallPolicyRow {
    pub base: ArmBase,
    pub tier: Option<String>,
    pub threat_intel_mode: Option<String>,
    pub base_policy_id: Option<String>,
    pub child_policy_ids: Vec<String>,
    pub firewall_ids: Vec<String>,
    pub rule_collection_group_ids: Vec<String>,
    pub threat_intel_allowlist: Option<Value>,
    pub intrusion_detection: Option<Value>,
    pub transport_security: Option<Value>,
    pub dns: Option<Value>,
    pub snat: Option<Value>,
    pub explicit_proxy: Option<Value>,
    pub sql: Option<Value>,
    pub insights: Option<Value>,
    pub identity_ids: Vec<String>,
}

impl FirewallPolicyRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<FirewallPolicyRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let obj = |k: &str| v.pointer(&p(k)).filter(|o| o.is_object()).cloned();
        Some(FirewallPolicyRow {
            tier: json::str_at(v, &p("sku/tier")),
            threat_intel_mode: json::str_at(v, &p("threatIntelMode")),
            base_policy_id: json::arm_id(json::id_at(v, &p("basePolicy"))),
            child_policy_ids: arm_ids(v, &p("childPolicies")),
            firewall_ids: arm_ids(v, &p("firewalls")),
            rule_collection_group_ids: arm_ids(v, &p("ruleCollectionGroups")),
            threat_intel_allowlist: obj("threatIntelWhitelist"),
            intrusion_detection: obj("intrusionDetection"),
            transport_security: obj("transportSecurity"),
            dns: obj("dnsSettings"),
            snat: obj("snat"),
            explicit_proxy: obj("explicitProxy"),
            sql: obj("sql"),
            insights: obj("insights"),
            identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    fn idps_mode(&self) -> String {
        match self.intrusion_detection.as_ref().and_then(|i| json::str_at(i, "/mode")) {
            Some(m) => m,
            None if self.tier.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("premium")) => "Off".into(),
            None => "- (Premium only)".into(),
        }
    }

    fn tls_label(&self) -> String {
        match self.transport_security.as_ref().and_then(|t| json::str_at(t, "/certificateAuthority/name")) {
            Some(n) => format!("on (CA {})", n),
            None => "off".into(),
        }
    }

    fn dns_proxy_label(&self) -> String {
        match self.dns.as_ref().and_then(|d| json::bool_at(d, "/enableProxy")) {
            Some(true) => "on".into(),
            _ => "off".into(),
        }
    }

    fn settings_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Tier".into(), json::opt(self.tier.clone())),
            ("Threat intelligence".into(), json::opt(self.threat_intel_mode.clone())),
        ];
        if let Some(a) = &self.threat_intel_allowlist {
            lines.push(("  Allow-list IPs".into(), list_text(a, "/ipAddresses")));
            lines.push(("  Allow-list FQDNs".into(), list_text(a, "/fqdns")));
        }
        lines.push((String::new(), String::new()));
        lines.push(("IDPS".into(), self.idps_mode()));
        if let Some(i) = &self.intrusion_detection {
            lines.push(("  Profile".into(), json::text(i, "/profile")));
            let overrides = json::arr(i, "/configuration/signatureOverrides");
            lines.push(("  Signature overrides".into(), overrides.len().to_string()));
            for o in overrides.iter().take(20) {
                lines.push((format!("    {}", json::text(o, "/id")), json::text(o, "/mode")));
            }
            for b in json::arr(i, "/configuration/bypassTrafficSettings") {
                lines.push((
                    format!("  Bypass {}", json::text(&b, "/name")),
                    format!(
                        "{} · {} → {} :{}",
                        json::text(&b, "/protocol"),
                        list_text(&b, "/sourceAddresses"),
                        list_text(&b, "/destinationAddresses"),
                        list_text(&b, "/destinationPorts")
                    ),
                ));
            }
            lines.push(("  Private ranges".into(), list_text(i, "/configuration/privateRanges")));
        }
        lines.push((String::new(), String::new()));
        lines.push(("TLS inspection".into(), self.tls_label()));
        if let Some(t) = &self.transport_security {
            // A Key Vault secret URL, shown as text and never requested.
            lines.push(("  CA certificate (Key Vault secret)".into(), json::text(t, "/certificateAuthority/keyVaultSecretId")));
            for i in &self.identity_ids {
                lines.push((format!("  Reading identity {}", name_of_id(i)), i.clone()));
            }
        }
        lines.push((String::new(), String::new()));
        lines.push(("DNS proxy".into(), self.dns_proxy_label()));
        match &self.dns {
            Some(d) => {
                let servers = json::strings_at(d, "/servers");
                lines.push(("DNS servers".into(), if servers.is_empty() { "Azure DNS (168.63.129.16)".into() } else { servers.join(", ") }));
                lines.push(("Proxy required for network rules".into(), json::yes_no(json::bool_at(d, "/requireProxyForNetworkRules"))));
            }
            None => lines.push(("DNS servers".into(), "Azure DNS (168.63.129.16)".into())),
        }
        lines.push((String::new(), String::new()));
        match &self.snat {
            Some(s) => {
                let ranges = json::strings_at(s, "/privateRanges");
                lines.push(("SNAT private ranges".into(), if ranges.is_empty() { "IANA RFC 1918 (default)".into() } else { ranges.join(", ") }));
                lines.push(("SNAT auto-learn".into(), json::text(s, "/autoLearnPrivateRanges")));
            }
            None => lines.push(("SNAT private ranges".into(), "IANA RFC 1918 (default)".into())),
        }
        if let Some(e) = &self.explicit_proxy {
            lines.push((
                "Explicit proxy".into(),
                format!(
                    "{} · HTTP {} · HTTPS {} · PAC {}",
                    json::yes_no(json::bool_at(e, "/enableExplicitProxy")),
                    json::text(e, "/httpPort"),
                    json::text(e, "/httpsPort"),
                    json::yes_no(json::bool_at(e, "/enablePacFile"))
                ),
            ));
        }
        if let Some(s) = &self.sql {
            lines.push(("SQL redirect".into(), json::yes_no(json::bool_at(s, "/allowSqlRedirect"))));
        }
        if let Some(i) = &self.insights {
            lines.push((
                "Policy analytics".into(),
                format!("{} · {} days", json::yes_no(json::bool_at(i, "/isEnabled")), json::text(i, "/retentionDays")),
            ));
            if let Some(w) = json::arm_id(json::id_at(i, "/logAnalyticsResources/defaultWorkspaceId")) {
                lines.push((format!("  Workspace {}", name_of_id(&w)), w));
            }
        }
        lines
    }

    /// The policies that name this one as their base: the body's list and
    /// the warm list's.
    fn child_policies(&self, lists: &FirewallLists<'_>) -> Vec<String> {
        let mut v = self.child_policy_ids.clone();
        for p in rows_of::<FirewallPolicyRow>(lists.policies) {
            if p.base_policy_id.as_deref().is_some_and(|b| same_id(b, &self.base.id)) && !v.iter().any(|e| same_id(e, &p.base.id)) {
                v.push(p.base.id.clone());
            }
        }
        v
    }

    /// The firewalls using it: the body's list and the warm list's.
    fn firewalls(&self, lists: &FirewallLists<'_>) -> Vec<String> {
        let mut v = self.firewall_ids.clone();
        for f in rows_of::<AzureFirewallRow>(lists.firewalls) {
            if f.policy_id.as_deref().is_some_and(|p| same_id(p, &self.base.id)) && !v.iter().any(|e| same_id(e, &f.base.id)) {
                v.push(f.base.id.clone());
            }
        }
        v
    }

    fn hierarchy_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        match &self.base_policy_id {
            Some(b) => {
                lines.push((format!("Base policy {}", name_of_id(b)), b.clone()));
                lines.push((String::new(), "· its rule collection groups are processed before this policy's own".into()));
            }
            None => lines.push(("Base policy".into(), "-".into())),
        }
        lines.push((String::new(), String::new()));
        let children = self.child_policies(lists);
        if children.is_empty() {
            lines.push(("Child policies".into(), "-".into()));
        }
        for c in children {
            lines.push((format!("Child policy {}", name_of_id(&c)), c));
        }
        lines.push((String::new(), String::new()));
        let firewalls = self.firewalls(lists);
        if firewalls.is_empty() {
            lines.push(("Firewalls".into(), "- (no firewall uses it)".into()));
        }
        for f in firewalls {
            let ip = rows_of::<AzureFirewallRow>(lists.firewalls)
                .find(|r| same_id(&r.base.id, &f))
                .map(|r| format!(" · {}", json::join(&r.private_ips())))
                .unwrap_or_default();
            lines.push((format!("Firewall {}{}", name_of_id(&f), ip), f));
        }
        if lists.firewalls.is_none() {
            lines.push((String::new(), "· matched against the policy body only; load @fw to match the warm firewalls too".into()));
        }
        lines
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(b) = &self.base_policy_id {
            push_unique(&mut v, format!("Base policy {}", name_of_id(b)), b.clone());
        }
        for c in &self.child_policy_ids {
            push_unique(&mut v, format!("Child policy {}", name_of_id(c)), c.clone());
        }
        for f in &self.firewall_ids {
            push_unique(&mut v, format!("Firewall {}", name_of_id(f)), f.clone());
        }
        for i in &self.identity_ids {
            push_unique(&mut v, format!("Identity {}", name_of_id(i)), i.clone());
        }
        if let Some(w) = self.insights.as_ref().and_then(|i| json::arm_id(json::id_at(i, "/logAnalyticsResources/defaultWorkspaceId"))) {
            push_unique(&mut v, format!("Workspace {}", name_of_id(&w)), w);
        }
        v
    }
}

impl Resource for FirewallPolicyRow {
    arm_row!("Firewall policy");
    /// `Premium · threat intel Deny · IDPS Alert · base fwp-base`.
    fn list_summary(&self) -> Option<String> {
        let mut s = format!(
            "{} · threat intel {} · IDPS {}",
            json::opt(self.tier.clone()),
            json::opt(self.threat_intel_mode.clone()),
            self.idps_mode()
        );
        if let Some(b) = &self.base_policy_id {
            s.push_str(&format!(" · base {}", name_of_id(b)));
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
        Some(&FIREWALL_POLICY_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Tier".into(), json::opt(self.tier.clone())),
            ("Threat intelligence".into(), json::opt(self.threat_intel_mode.clone())),
            ("IDPS".into(), self.idps_mode()),
            ("TLS inspection".into(), self.tls_label()),
            ("DNS proxy".into(), self.dns_proxy_label()),
            (
                "Base policy".into(),
                self.base_policy_id.as_deref().map(|b| name_of_id(b).to_string()).unwrap_or_else(|| "-".into()),
            ),
            ("Rule collection groups".into(), self.rule_collection_group_ids.len().to_string()),
            ("Child policies".into(), self.child_policy_ids.len().to_string()),
            ("Firewalls".into(), self.firewall_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        FirewallPolicyRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network firewall policy show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn firewall_policy_section_lines(
    r: &FirewallPolicyRow,
    section: FirewallPolicyDetailSection,
    lists: &FirewallLists<'_>,
    lazy: &FirewallLazy<'_>,
) -> Vec<(String, String)> {
    match section {
        FirewallPolicyDetailSection::Overview => overview_rows(r),
        FirewallPolicyDetailSection::Settings => r.settings_rows(),
        FirewallPolicyDetailSection::RuleCollectionGroups => {
            policy_rules_rows(&r.base.id, r.base_policy_id.as_deref(), lazy, lists)
        }
        FirewallPolicyDetailSection::Hierarchy => r.hierarchy_rows(lists),
        FirewallPolicyDetailSection::Access => crate::azure::services::rendered_by_app(),
        FirewallPolicyDetailSection::Activity => crate::azure::services::rendered_by_app(),
        FirewallPolicyDetailSection::Related => {
            let mut rel = r.related();
            for c in r.child_policies(lists) {
                push_unique(&mut rel, format!("Child policy {}", name_of_id(&c)), c);
            }
            for f in r.firewalls(lists) {
                push_unique(&mut rel, format!("Firewall {}", name_of_id(&f)), f);
            }
            related_lines(rel)
        }
        FirewallPolicyDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── IP group ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpGroupRow {
    pub base: ArmBase,
    pub addresses: Vec<String>,
    pub firewall_ids: Vec<String>,
    pub policy_ids: Vec<String>,
}

impl IpGroupRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<IpGroupRow> {
        let base = ArmBase::from_json(v, tenant)?;
        Some(IpGroupRow {
            addresses: json::strings_at(v, "/properties/ipAddresses"),
            firewall_ids: arm_ids(v, "/properties/firewalls"),
            policy_ids: arm_ids(v, "/properties/firewallPolicies"),
            base,
        })
    }

    fn used_by_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        for f in &self.firewall_ids {
            lines.push((format!("Firewall {}", name_of_id(f)), f.clone()));
        }
        for p in &self.policy_ids {
            lines.push((format!("Firewall policy {}", name_of_id(p)), p.clone()));
        }
        if lines.is_empty() {
            lines.push((String::new(), "Not used by a firewall or firewall policy".into()));
        }
        lines
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for (label, id) in self.used_by_rows() {
            if id.starts_with("/subscriptions/") {
                push_unique(&mut v, label, id);
            }
        }
        v
    }
}

impl Resource for IpGroupRow {
    arm_row!("IP group");
    /// `3 addresses · used by 2`.
    fn list_summary(&self) -> Option<String> {
        let used = self.firewall_ids.len() + self.policy_ids.len();
        Some(if used == 0 {
            format!("{} addresses · not used", self.addresses.len())
        } else {
            format!("{} addresses · used by {}", self.addresses.len(), used)
        })
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&IP_GROUP_SECTIONS)
    }
    /// Its addresses are searchable.
    fn search_text(&self) -> String {
        let mut parts = vec![self.base.id.clone(), self.base.name.clone()];
        parts.extend(self.addresses.iter().cloned());
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Addresses".into(), self.addresses.len().to_string()),
            ("Firewalls".into(), self.firewall_ids.len().to_string()),
            ("Firewall policies".into(), self.policy_ids.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        IpGroupRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network ip-group show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn ip_group_section_lines(r: &IpGroupRow, section: IpGroupDetailSection) -> Vec<(String, String)> {
    match section {
        IpGroupDetailSection::Overview => overview_rows(r),
        IpGroupDetailSection::Addresses => {
            if r.addresses.is_empty() {
                vec![(String::new(), "No addresses".into())]
            } else {
                r.addresses.iter().map(|a| (String::new(), a.clone())).collect()
            }
        }
        IpGroupDetailSection::UsedBy => r.used_by_rows(),
        IpGroupDetailSection::Access => crate::azure::services::rendered_by_app(),
        IpGroupDetailSection::Activity => crate::azure::services::rendered_by_app(),
        IpGroupDetailSection::Related => related_lines(r.related()),
        IpGroupDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Cloud NGFW ────────────────────────────────────────────────────────

/// How a Cloud NGFW's rules are managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgfwManagement {
    LocalRulestack,
    /// A tenant-scoped global rulestack: not readable at subscription scope.
    GlobalRulestack,
    Panorama,
    StrataCloudManager,
    None,
}

#[derive(Debug, Clone)]
pub struct CloudNgfwRow {
    pub base: ArmBase,
    /// `VNET` or `VWAN`.
    pub network_type: Option<String>,
    pub vnet: Option<Value>,
    pub vwan: Option<Value>,
    pub public_ips: Vec<Value>,
    pub egress_nat: Option<String>,
    pub egress_nat_ips: Vec<Value>,
    pub trusted_ranges: Vec<String>,
    pub private_snat_destinations: Vec<String>,
    pub panorama_managed: bool,
    pub scm_managed: bool,
    /// `panoramaConfig` without `configString` and `vmAuthKey`.
    pub panorama: Option<Value>,
    pub scm: Option<Value>,
    pub rulestack: Option<Value>,
    pub dns: Option<Value>,
    pub front_end: Vec<Value>,
    pub plan: Option<Value>,
    pub marketplace: Option<Value>,
    pub identity_ids: Vec<String>,
}

impl CloudNgfwRow {
    /// Parses a firewall with the Panorama secrets stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<CloudNgfwRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let obj = |k: &str| v.pointer(&p(k)).filter(|o| o.is_object()).cloned();
        Some(CloudNgfwRow {
            network_type: json::str_at(v, &p("networkProfile/networkType")),
            vnet: obj("networkProfile/vnetConfiguration"),
            vwan: obj("networkProfile/vwanConfiguration"),
            public_ips: json::arr(v, &p("networkProfile/publicIps")),
            egress_nat: json::str_at(v, &p("networkProfile/enableEgressNat")),
            egress_nat_ips: json::arr(v, &p("networkProfile/egressNatIp")),
            trusted_ranges: json::strings_at(v, &p("networkProfile/trustedRanges")),
            private_snat_destinations: json::strings_at(v, &p("networkProfile/privateSourceNatRulesDestination")),
            panorama_managed: bool_enum(v, &p("isPanoramaManaged")),
            scm_managed: bool_enum(v, &p("isStrataCloudManaged")),
            panorama: obj("panoramaConfig"),
            scm: obj("strataCloudManagerConfig"),
            rulestack: obj("associatedRulestack"),
            dns: obj("dnsSettings"),
            front_end: json::arr(v, &p("frontEndSettings")),
            plan: obj("planData"),
            marketplace: obj("marketplaceDetails"),
            identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    fn is_vwan(&self) -> bool {
        self.network_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("vwan"))
    }

    /// The VNet or vWAN configuration, whichever the type uses.
    fn net(&self) -> Option<&Value> {
        if self.is_vwan() {
            self.vwan.as_ref()
        } else {
            self.vnet.as_ref()
        }
        .or(self.vnet.as_ref())
        .or(self.vwan.as_ref())
    }

    /// `ipOfTrustSubnetForUdr`: what a spoke's UDR points at.
    pub fn udr_ip(&self) -> Option<String> {
        self.net().and_then(|n| json::str_at(n, "/ipOfTrustSubnetForUdr/address")).filter(|s| !s.is_empty())
    }

    /// The associated rulestack's ARM id.
    pub fn rulestack_id(&self) -> Option<String> {
        self.rulestack.as_ref().and_then(|r| json::str_at(r, "/resourceId")).filter(|s| !s.is_empty())
    }

    pub fn management(&self) -> NgfwManagement {
        if self.panorama_managed {
            return NgfwManagement::Panorama;
        }
        if self.scm_managed {
            return NgfwManagement::StrataCloudManager;
        }
        match self.rulestack_id() {
            Some(id) if id.to_lowercase().contains("/globalrulestacks/") => NgfwManagement::GlobalRulestack,
            Some(_) => NgfwManagement::LocalRulestack,
            None => NgfwManagement::None,
        }
    }

    fn management_label(&self) -> String {
        match self.management() {
            NgfwManagement::LocalRulestack => format!("local rulestack {}", self.rulestack_id().as_deref().map(name_of_id).unwrap_or("-")),
            NgfwManagement::GlobalRulestack => format!("global rulestack {}", self.rulestack_id().as_deref().map(name_of_id).unwrap_or("-")),
            NgfwManagement::Panorama => "Panorama".into(),
            NgfwManagement::StrataCloudManager => "Strata Cloud Manager".into(),
            NgfwManagement::None => "no rulestack".into(),
        }
    }

    fn marketplace_status(&self) -> Option<String> {
        self.marketplace.as_ref().and_then(|m| json::str_at(m, "/marketplaceSubscriptionStatus"))
    }

    /// Provisioning first, then the Marketplace subscription: a suspended
    /// or unsubscribed offer stops the firewall.
    fn ladder(&self) -> (ResourceState, String) {
        let status = self.marketplace_status();
        let runtime = status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "subscribed" => ResourceState::Available,
                "suspended" => ResourceState::Stopped,
                "unsubscribed" => ResourceState::Unavailable,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn address_line(label: &str, a: &Value) -> (String, String) {
        let addr = json::text(a, "/address");
        match json::arm_id(json::str_at(a, "/resourceId")) {
            Some(id) => (format!("{} {} ({})", label, addr, name_of_id(&id)), id),
            None => (label.to_string(), addr),
        }
    }

    fn space_line(label: &str, s: Option<&Value>) -> Option<(String, String)> {
        let s = s?;
        let space = json::text(s, "/addressSpace");
        Some(match json::arm_id(json::str_at(s, "/resourceId")) {
            Some(id) => (format!("{} {} ({})", label, subnet_or_name(&id), space), id),
            None => (label.to_string(), space),
        })
    }

    fn network_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        let mut lines = vec![(
            "UDR next hop (trust IP)".into(),
            self.udr_ip().unwrap_or_else(|| "-".into()),
        )];
        lines.push((String::new(), "· spoke route tables send 0.0.0.0/0 (or a prefix) to this address as a virtual appliance".into()));
        lines.push((String::new(), String::new()));
        lines.push(("Network type".into(), json::opt(self.network_type.clone())));
        if let Some(n) = self.net() {
            lines.extend(Self::space_line("VNet", n.get("vnet")));
            lines.extend(Self::space_line("Virtual hub", n.get("vHub")));
            lines.extend(Self::space_line("Trust subnet", n.get("trustSubnet")));
            lines.extend(Self::space_line("Untrust subnet", n.get("unTrustSubnet")));
            if let Some(nva) = json::arm_id(json::str_at(n, "/networkVirtualApplianceId")) {
                lines.push((format!("Network virtual appliance {}", name_of_id(&nva)), nva));
            }
        }
        lines.push((String::new(), String::new()));
        if self.public_ips.is_empty() {
            lines.push(("Public IPs".into(), "-".into()));
        }
        for a in &self.public_ips {
            lines.push(Self::address_line("Public IP", a));
        }
        lines.push(("Egress NAT".into(), json::opt(self.egress_nat.clone()).to_lowercase()));
        for a in &self.egress_nat_ips {
            lines.push(Self::address_line("Egress NAT IP", a));
        }
        lines.push(("Trusted ranges".into(), json::join(&self.trusted_ranges)));
        lines.push(("Private SNAT destinations".into(), json::join(&self.private_snat_destinations)));
        lines.push((String::new(), String::new()));
        match &self.dns {
            Some(d) => {
                lines.push(("DNS proxy".into(), json::text(d, "/enableDnsProxy").to_lowercase()));
                lines.push(("DNS type".into(), json::text(d, "/enabledDnsType").to_lowercase()));
                let servers: Vec<String> = json::arr(d, "/dnsServers").iter().filter_map(|s| json::str_at(s, "/address")).collect();
                lines.push(("DNS servers".into(), if servers.is_empty() { "Azure DNS".into() } else { servers.join(", ") }));
            }
            None => lines.push(("DNS".into(), "-".into())),
        }
        lines.push((String::new(), String::new()));
        lines.push(("Routed here".into(), String::new()));
        lines.extend(routes_to(&udr_next_hops(self), lists.route_tables));
        lines
    }

    fn front_end_rows(&self) -> Vec<(String, String)> {
        if self.front_end.is_empty() {
            return vec![(String::new(), "No front-end (DNAT) settings".into())];
        }
        let mut lines = Vec::new();
        for f in &self.front_end {
            lines.push((
                format!("{} ({})", json::text(f, "/name"), json::text(f, "/protocol")),
                format!(
                    "{}:{} → {}:{}",
                    json::text(f, "/frontendConfiguration/address/address"),
                    json::text(f, "/frontendConfiguration/port"),
                    json::text(f, "/backendConfiguration/address/address"),
                    json::text(f, "/backendConfiguration/port"),
                ),
            ));
            if let Some(pip) = json::arm_id(json::str_at(f, "/frontendConfiguration/address/resourceId")) {
                lines.push((format!("  front end {}", name_of_id(&pip)), pip));
            }
        }
        lines
    }

    fn management_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        let mut lines = vec![("Rules managed by".into(), self.management_label())];
        match self.management() {
            NgfwManagement::LocalRulestack => {
                if let Some(id) = self.rulestack_id() {
                    let mode = lists.rulestack(&id).map(|r| format!(" · default mode {}", json::opt(r.default_mode.clone()))).unwrap_or_default();
                    lines.push((format!("Local rulestack {}{}", name_of_id(&id), mode), id));
                }
            }
            NgfwManagement::GlobalRulestack => {
                lines.push((
                    "Global rulestack".into(),
                    format!("{} (tenant-scoped: outside a subscription Reader, not read)", self.rulestack_id().unwrap_or_default()),
                ));
            }
            NgfwManagement::Panorama => {
                if let Some(p) = &self.panorama {
                    lines.push(("Panorama server".into(), json::text(p, "/panoramaServer")));
                    if let Some(s2) = json::str_at(p, "/panoramaServer2") {
                        lines.push(("Panorama server 2".into(), s2));
                    }
                    lines.push(("Device group".into(), json::text(p, "/dgName")));
                    lines.push(("Template stack".into(), json::text(p, "/tplName")));
                    lines.push(("Log collector group".into(), json::text(p, "/cgName")));
                    lines.push(("Host name".into(), json::text(p, "/hostName")));
                }
                lines.push((String::new(), "· the registration string and VM auth key are never shown".into()));
            }
            NgfwManagement::StrataCloudManager => {
                lines.push(("Cloud manager".into(), self.scm.as_ref().map(|s| json::text(s, "/cloudManagerName")).unwrap_or_else(|| "-".into())));
            }
            NgfwManagement::None => {}
        }
        lines.push((String::new(), String::new()));
        match &self.marketplace {
            Some(m) => {
                lines.push(("Marketplace status".into(), json::text(m, "/marketplaceSubscriptionStatus")));
                lines.push(("Offer".into(), format!("{} · {}", json::text(m, "/publisherId"), json::text(m, "/offerId"))));
                lines.push(("Marketplace subscription".into(), json::text(m, "/marketplaceSubscriptionId")));
            }
            None => lines.push(("Marketplace".into(), "-".into())),
        }
        match &self.plan {
            Some(p) => {
                lines.push(("Plan".into(), json::text(p, "/planId")));
                lines.push(("Billing cycle".into(), json::text(p, "/billingCycle").to_lowercase()));
                lines.push(("Usage type".into(), json::text(p, "/usageType").to_lowercase()));
                lines.push(("Effective".into(), json::time(json::str_at(p, "/effectiveDate"))));
            }
            None => lines.push(("Plan".into(), "-".into())),
        }
        lines
    }

    fn rules_rows(&self, lazy: &FirewallLazy<'_>) -> Vec<(String, String)> {
        match self.management() {
            NgfwManagement::Panorama => {
                let dg = self.panorama.as_ref().map(|p| json::text(p, "/dgName")).unwrap_or_else(|| "-".into());
                vec![
                    ("Managed by Panorama".into(), format!("device group {}", dg)),
                    (String::new(), "· the security rules live in Panorama, not in ARM: open the device group there".into()),
                ]
            }
            NgfwManagement::StrataCloudManager => vec![
                ("Managed by Strata Cloud Manager".into(), self.scm.as_ref().map(|s| json::text(s, "/cloudManagerName")).unwrap_or_else(|| "-".into())),
                (String::new(), "· the security rules live in Strata Cloud Manager, not in ARM".into()),
            ],
            NgfwManagement::GlobalRulestack => vec![
                ("Global rulestack".into(), self.rulestack_id().unwrap_or_default()),
                (String::new(), "· a tenant-scoped rulestack: its rules are outside a subscription Reader and are not read".into()),
            ],
            NgfwManagement::None => vec![(String::new(), "No rulestack associated".into())],
            NgfwManagement::LocalRulestack => {
                let id = self.rulestack_id().unwrap_or_default();
                let mut lines = vec![(format!("From local rulestack {}", name_of_id(&id)), id.clone())];
                lines.extend(local_rules_rows(lazy.ngfw_rules.get(&rules_key(&id))));
                lines
            }
        }
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let (NgfwManagement::LocalRulestack, Some(id)) = (self.management(), self.rulestack_id()) {
            push_unique(&mut v, format!("Local rulestack {}", name_of_id(&id)), id);
        }
        if let Some(n) = self.net() {
            for (label, key) in [("VNet", "vnet"), ("Virtual hub", "vHub"), ("Trust subnet", "trustSubnet"), ("Untrust subnet", "unTrustSubnet")] {
                if let Some(id) = n.get(key).and_then(|s| json::arm_id(json::str_at(s, "/resourceId"))) {
                    push_unique(&mut v, format!("{} {}", label, subnet_or_name(&id)), id);
                }
            }
        }
        for a in self.public_ips.iter().chain(self.egress_nat_ips.iter()) {
            if let Some(id) = json::arm_id(json::str_at(a, "/resourceId")) {
                push_unique(&mut v, format!("Public IP {}", name_of_id(&id)), id);
            }
        }
        for i in &self.identity_ids {
            push_unique(&mut v, format!("Identity {}", name_of_id(i)), i.clone());
        }
        v
    }
}

/// `vnet/subnet` for a subnet id, else the name.
fn subnet_or_name(id: &str) -> String {
    if id.to_lowercase().contains("/subnets/") {
        subnet_label(id)
    } else {
        name_of_id(id).to_string()
    }
}

impl Resource for CloudNgfwRow {
    arm_row!("Cloud NGFW");
    /// `VNET · UDR 10.10.9.68 · local rulestack lrs-hub-prod`.
    fn list_summary(&self) -> Option<String> {
        Some(format!(
            "{} · UDR {} · {}",
            json::opt(self.network_type.clone()),
            self.udr_ip().unwrap_or_else(|| "-".into()),
            self.management_label()
        ))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CLOUD_NGFW_SECTIONS)
    }
    fn search_text(&self) -> String {
        let mut parts = vec![self.base.id.clone(), self.base.name.clone(), "palo alto cloud ngfw".to_string()];
        parts.extend(self.udr_ip());
        parts.extend(self.public_ips.iter().filter_map(|a| json::str_at(a, "/address")));
        parts.join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("UDR next hop (trust IP)".into(), self.udr_ip().unwrap_or_else(|| "-".into())),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Marketplace status".into(), json::opt(self.marketplace_status())),
            ("Network type".into(), json::opt(self.network_type.clone())),
            ("Rules managed by".into(), self.management_label()),
            ("Public IPs".into(), self.public_ips.len().to_string()),
            ("Egress NAT".into(), json::opt(self.egress_nat.clone()).to_lowercase()),
            ("Front-end (DNAT) settings".into(), self.front_end.len().to_string()),
            ("Plan".into(), self.plan.as_ref().map(|p| json::text(p, "/planId")).unwrap_or_else(|| "-".into())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        CloudNgfwRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az palo-alto cloudngfw firewall show --ids {}", shell_quote(&self.base.id)))
    }
}

/// `statuses/default`: health, Panorama connection.
fn status_rows(status: Option<&Lazy<Value>>) -> Vec<(String, String)> {
    match status {
        None | Some(Lazy::Loading) => vec![("Status".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => error_rows(e),
        Some(Lazy::Loaded(s)) => {
            let mut lines = vec![
                ("Health".into(), json::text(s, "/properties/healthStatus")),
                ("Reason".into(), json::text(s, "/properties/healthReason")),
                ("Panorama managed".into(), json::text(s, "/properties/isPanoramaManaged").to_lowercase()),
            ];
            if s.pointer("/properties/panoramaStatus").is_some() {
                lines.push(("Panorama server".into(), json::text(s, "/properties/panoramaStatus/panoramaServerStatus")));
                lines.push(("Panorama server 2".into(), json::text(s, "/properties/panoramaStatus/panoramaServer2Status")));
            }
            if let Some(f) = json::str_at(s, "/properties/strataCloudManagerInfo/folderName") {
                lines.push(("Strata Cloud Manager folder".into(), f));
            }
            if let Some(h) = &json::str_at(s, "/properties/healthStatus") {
                if !h.eq_ignore_ascii_case("green") {
                    lines.push((String::new(), format!("⚠ health {}", h)));
                }
            }
            lines
        }
    }
}

pub fn cloud_ngfw_section_lines(
    r: &CloudNgfwRow,
    section: CloudNgfwDetailSection,
    lists: &FirewallLists<'_>,
    lazy: &FirewallLazy<'_>,
) -> Vec<(String, String)> {
    match section {
        CloudNgfwDetailSection::Overview => overview_rows(r),
        CloudNgfwDetailSection::Network => r.network_rows(lists),
        CloudNgfwDetailSection::FrontEnd => r.front_end_rows(),
        CloudNgfwDetailSection::Rules => r.rules_rows(lazy),
        CloudNgfwDetailSection::Management => r.management_rows(lists),
        CloudNgfwDetailSection::Status => status_rows(lazy.ngfw_status.get(&r.base.id)),
        CloudNgfwDetailSection::Access => crate::azure::services::rendered_by_app(),
        CloudNgfwDetailSection::Activity => crate::azure::services::rendered_by_app(),
        CloudNgfwDetailSection::Related => related_lines(r.related()),
        CloudNgfwDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Local rulestack ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RulestackRow {
    pub base: ArmBase,
    pub scope: Option<String>,
    pub default_mode: Option<String>,
    pub description: Option<String>,
    pub min_app_id_version: Option<String>,
    pub security_services: Option<Value>,
    pub associated_subscriptions: Vec<String>,
}

impl RulestackRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<RulestackRow> {
        let v = &without_secrets(v);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(RulestackRow {
            scope: json::str_at(v, &p("scope")),
            default_mode: json::str_at(v, &p("defaultMode")),
            description: json::str_at(v, &p("description")),
            min_app_id_version: json::str_at(v, &p("minAppIdVersion")),
            security_services: v.pointer(&p("securityServices")).filter(|o| o.is_object()).cloned(),
            associated_subscriptions: json::strings_at(v, &p("associatedSubscriptions")),
            base,
        })
    }

    fn security_rows(&self) -> Vec<(String, String)> {
        let Some(s) = &self.security_services else {
            return vec![(String::new(), "No security services profiles".into())];
        };
        let mut lines = Vec::new();
        for (label, key) in [
            ("Vulnerability protection", "vulnerabilityProfile"),
            ("Anti-spyware", "antiSpywareProfile"),
            ("Antivirus", "antiVirusProfile"),
            ("URL filtering", "urlFilteringProfile"),
            ("File blocking", "fileBlockingProfile"),
            ("DNS security", "dnsSubscription"),
            ("Outbound trust certificate", "outboundTrustCertificate"),
            ("Outbound untrust certificate", "outboundUnTrustCertificate"),
        ] {
            lines.push((label.into(), json::text(s, &format!("/{}", key))));
        }
        lines
    }

    /// The warm Cloud NGFWs whose associated rulestack is this one.
    fn firewalls<'a>(&self, lists: &FirewallLists<'a>) -> Vec<&'a CloudNgfwRow> {
        rows_of::<CloudNgfwRow>(lists.ngfws)
            .filter(|f| f.rulestack_id().is_some_and(|r| same_id(&r, &self.base.id)))
            .collect()
    }

    fn firewall_rows(&self, lists: &FirewallLists<'_>) -> Vec<(String, String)> {
        if lists.ngfws.is_none() {
            return vec![(String::new(), "· load @ngfw to see which firewalls use it (the rulestack's own firewall list is a POST nebaz never sends)".into())];
        }
        let fws = self.firewalls(lists);
        if fws.is_empty() {
            return vec![(String::new(), "No loaded Cloud NGFW uses it".into())];
        }
        fws.iter()
            .map(|f| (format!("Firewall {} · UDR {}", f.base.name, f.udr_ip().unwrap_or_else(|| "-".into())), f.base.id.clone()))
            .collect()
    }
}

impl Resource for RulestackRow {
    arm_row!("Cloud NGFW rulestack");
    /// `LOCAL · IPS`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("{} · {}", json::opt(self.scope.clone()), json::opt(self.default_mode.clone())))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&RULESTACK_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Scope".into(), json::opt(self.scope.clone())),
            ("Default mode".into(), json::opt(self.default_mode.clone())),
            ("Min App-ID version".into(), json::opt(self.min_app_id_version.clone())),
            ("Description".into(), json::opt(self.description.clone())),
            ("Associated subscriptions".into(), json::join(&self.associated_subscriptions)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az palo-alto cloudngfw local-rulestack show --ids {}", shell_quote(&self.base.id)))
    }
}

/// One local rule as a line.
fn local_rule_summary(r: &Value) -> String {
    let p = |k: &str| format!("/properties/{}", k);
    let addr = |side: &str| {
        let mut parts = json::strings_at(r, &p(&format!("{}/cidrs", side)));
        parts.extend(json::strings_at(r, &p(&format!("{}/prefixLists", side))).iter().map(|l| format!("prefix:{}", l)));
        parts.extend(json::strings_at(r, &p(&format!("{}/fqdnLists", side))).iter().map(|l| format!("fqdn:{}", l)));
        parts.extend(json::strings_at(r, &p(&format!("{}/countries", side))).iter().map(|c| format!("country:{}", c)));
        parts.extend(json::strings_at(r, &p(&format!("{}/feeds", side))).iter().map(|f| format!("feed:{}", f)));
        if parts.is_empty() {
            "any".to_string()
        } else {
            parts.join(", ")
        }
    };
    let neg = |k: &str| if bool_enum(r, &p(k)) { "not " } else { "" };
    let mut ports = json::strings_at(r, &p("protocolPortList"));
    if ports.is_empty() {
        ports.extend(json::str_at(r, &p("protocol")));
    }
    let apps = json::strings_at(r, &p("applications"));
    let mut s = format!(
        "{} · {}{} → {}{} · apps {} · {}",
        json::text(r, &p("actionType")),
        neg("negateSource"),
        addr("source"),
        neg("negateDestination"),
        addr("destination"),
        if apps.is_empty() { "any".into() } else { apps.join(", ") },
        if ports.is_empty() { "application-default".into() } else { ports.join(", ") },
    );
    let urls = json::strings_at(r, &p("category/urlCustom"));
    if !urls.is_empty() {
        s.push_str(&format!(" · url {}", urls.join(", ")));
    }
    if let Some(d) = json::str_at(r, &p("decryptionRuleType")).filter(|d| !d.eq_ignore_ascii_case("none")) {
        s.push_str(&format!(" · decrypt {}", d));
    }
    if json::str_at(r, &p("enableLogging")).is_some_and(|l| l.eq_ignore_ascii_case("disabled")) {
        s.push_str(" · no logging");
    }
    s
}

/// A rulestack's local rules by priority (lowest first, what the firewall
/// evaluates first); a disabled rule says so.
pub fn local_rules_rows(rules: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    match rules {
        None | Some(Lazy::Loading) => vec![("Rules".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => error_rows(e),
        Some(Lazy::Loaded(rules)) if rules.is_empty() => {
            vec![(String::new(), "No local rules: the rulestack's default policy applies".into())]
        }
        Some(Lazy::Loaded(rules)) => {
            let mut lines: Vec<(String, String)> = by_priority(rules, "/properties/priority")
                .iter()
                .map(|r| {
                    let disabled = json::str_at(r, "/properties/ruleState").is_some_and(|s| s.eq_ignore_ascii_case("disabled"));
                    (
                        format!(
                            "{} {}{}",
                            json::text(r, "/properties/priority"),
                            json::str_at(r, "/properties/ruleName").unwrap_or_else(|| json::text(r, "/name")),
                            if disabled { " (disabled)" } else { "" }
                        ),
                        local_rule_summary(r),
                    )
                })
                .collect();
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· evaluated by priority, lowest first; the first match decides".into()));
            lines
        }
    }
}

/// Prefix lists and FQDN lists: the objects rules name.
fn objects_rows(prefixes: Option<&Lazy<Vec<Value>>>, fqdns: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    for (what, lazy, ptr) in [("Prefix lists", prefixes, "/properties/prefixList"), ("FQDN lists", fqdns, "/properties/fqdnList")] {
        match lazy {
            None | Some(Lazy::Loading) => lines.push((what.into(), "Loading…".into())),
            Some(Lazy::Error(e)) => lines.push((what.into(), format!("⚠ {}", e))),
            Some(Lazy::Loaded(items)) if items.is_empty() => lines.push((what.into(), "none".into())),
            Some(Lazy::Loaded(items)) => {
                lines.push((what.into(), items.len().to_string()));
                for i in items {
                    lines.push((format!("  {}", json::text(i, "/name")), list_text(i, ptr)));
                }
            }
        }
    }
    lines
}

pub fn rulestack_section_lines(
    r: &RulestackRow,
    section: RulestackDetailSection,
    lists: &FirewallLists<'_>,
    lazy: &FirewallLazy<'_>,
) -> Vec<(String, String)> {
    let key = rules_key(&r.base.id);
    match section {
        RulestackDetailSection::Overview => overview_rows(r),
        RulestackDetailSection::Rules => local_rules_rows(lazy.ngfw_rules.get(&key)),
        RulestackDetailSection::Objects => objects_rows(lazy.prefix_lists.get(&key), lazy.fqdn_lists.get(&key)),
        RulestackDetailSection::SecurityServices => r.security_rows(),
        RulestackDetailSection::Firewalls => r.firewall_rows(lists),
        RulestackDetailSection::Access => crate::azure::services::rendered_by_app(),
        RulestackDetailSection::Activity => crate::azure::services::rendered_by_app(),
        RulestackDetailSection::Related => {
            let mut rel = r.related();
            for f in r.firewalls(lists) {
                push_unique(&mut rel, format!("Firewall {}", f.base.name), f.base.id.clone());
            }
            related_lines(rel)
        }
        RulestackDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct FirewallService {
    scope: Scope,
}

impl FirewallService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<T: Resource + 'static>(rows: Vec<T>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::FirewallPolicies => Self::boxed(page.iter().filter_map(|v| FirewallPolicyRow::from_json(v, tenant)).collect()),
            JumpView::IpGroups => Self::boxed(page.iter().filter_map(|v| IpGroupRow::from_json(v, tenant)).collect()),
            JumpView::CloudNgfws => Self::boxed(page.iter().filter_map(|v| CloudNgfwRow::from_json(v, tenant)).collect()),
            JumpView::NgfwRulestacks => Self::boxed(page.iter().filter_map(|v| RulestackRow::from_json(v, tenant)).collect()),
            _ => Self::boxed(page.iter().filter_map(|v| AzureFirewallRow::from_json(v, tenant)).collect()),
        }
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::FirewallPolicies => (FIREWALL_POLICIES_PATH, AZFW_API_VERSION, "Listing firewall policies…"),
            JumpView::IpGroups => (IP_GROUPS_PATH, AZFW_API_VERSION, "Listing IP groups…"),
            JumpView::CloudNgfws => (NGFWS_PATH, NGFW_API_VERSION, "Listing Cloud NGFW firewalls…"),
            JumpView::NgfwRulestacks => (RULESTACKS_PATH, NGFW_API_VERSION, "Listing local rulestacks…"),
            _ => (AZURE_FIREWALLS_PATH, AZFW_API_VERSION, "Listing Azure Firewalls…"),
        }
    }

    pub fn api_version_for(id: &str) -> &'static str {
        if id.to_lowercase().contains("/paloaltonetworks.cloudngfw/") {
            NGFW_API_VERSION
        } else {
            AZFW_API_VERSION
        }
    }
}

#[async_trait]
impl AzureService for FirewallService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Firewall
    }

    fn name(&self) -> &str {
        "Firewall"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, _) = Self::list_of(view);
        let page = self.scope.list(path, version).await?;
        Ok(Self::rows(view, &page, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let (path, version, label) = Self::list_of(view);
        let r = self
            .scope
            .stream(path, version, &[], service_type, label, &event_tx, |page| Self::rows(view, &page, tenant.as_deref()))
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, Self::api_version_for(id)).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::AzureFirewalls);
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
        format!("{}/providers/{}", RG, path)
    }

    fn has(lines: &[(String, String)], k: &str, v: &str) -> bool {
        lines.iter().any(|(a, b)| a.contains(k) && b.contains(v))
    }

    fn azfw_json() -> Value {
        json!({
            "id": id("Microsoft.Network/azureFirewalls/afw-hub"),
            "name": "afw-hub",
            "location": "westeurope",
            "zones": ["1", "2", "3"],
            "properties": {
                "provisioningState": "Succeeded",
                "sku": {"name": "AZFW_VNet", "tier": "Premium"},
                "threatIntelMode": "Alert",
                "firewallPolicy": {"id": id("Microsoft.Network/firewallPolicies/fwp-child")},
                "ipConfigurations": [{"name": "ipc", "properties": {
                    "privateIPAddress": "10.10.9.4",
                    "subnet": {"id": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/AzureFirewallSubnet")},
                    "publicIPAddress": {"id": id("Microsoft.Network/publicIPAddresses/pip-afw")}}}],
                "managementIpConfiguration": {"name": "mgmt", "properties": {
                    "subnet": {"id": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/AzureFirewallManagementSubnet")},
                    "publicIPAddress": {"id": id("Microsoft.Network/publicIPAddresses/pip-afw-mgmt")}}},
                "additionalProperties": {"Network.DNS.EnableProxy": "true"}
            }
        })
    }

    fn policy_json(name: &str, base: Option<&str>) -> Value {
        let mut v = json!({
            "id": id(&format!("Microsoft.Network/firewallPolicies/{}", name)),
            "name": name,
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "sku": {"tier": "Premium"},
                "threatIntelMode": "Deny",
                "intrusionDetection": {"mode": "Alert", "configuration": {"signatureOverrides": [{"id": "2024897", "mode": "Deny"}]}},
                "dnsSettings": {"enableProxy": true, "servers": []},
                "firewalls": [{"id": id("Microsoft.Network/azureFirewalls/afw-hub")}]
            }
        });
        if let Some(b) = base {
            v["properties"]["basePolicy"] = json!({"id": id(&format!("Microsoft.Network/firewallPolicies/{}", b))});
        }
        v
    }

    fn groups() -> Vec<Value> {
        vec![
            json!({"name": "rcg-app", "properties": {"priority": 300, "ruleCollections": [
                {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "app-allow", "priority": 100,
                 "action": {"type": "Allow"}, "rules": [
                    {"ruleType": "ApplicationRule", "name": "allow-ms", "sourceIpGroups": [id("Microsoft.Network/ipGroups/ipg-spokes")],
                     "protocols": [{"protocolType": "Https", "port": 443}], "targetFqdns": ["*.microsoft.com"], "terminateTLS": true}]}]}}),
            json!({"name": "rcg-net", "properties": {"priority": 200, "ruleCollections": [
                {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "net-deny", "priority": 500,
                 "action": {"type": "Deny"}, "rules": [{"ruleType": "NetworkRule", "name": "deny-all", "ipProtocols": ["Any"],
                    "sourceAddresses": ["*"], "destinationAddresses": ["*"], "destinationPorts": ["*"]}]},
                {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "net-allow", "priority": 100,
                 "action": {"type": "Allow"}, "rules": [{"ruleType": "NetworkRule", "name": "dns", "ipProtocols": ["UDP"],
                    "sourceAddresses": ["10.0.0.0/8"], "destinationAddresses": ["168.63.129.16"], "destinationPorts": ["53"]}]},
                {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": "dnat", "priority": 50,
                 "action": {"type": "DNAT"}, "rules": [{"ruleType": "NatRule", "name": "rdp", "ipProtocols": ["TCP"],
                    "sourceAddresses": ["203.0.113.24"], "destinationAddresses": ["20.0.0.1"], "destinationPorts": ["3389"],
                    "translatedAddress": "10.20.0.4", "translatedPort": "3389"}]}
            ]}}),
        ]
    }

    fn ngfw_json() -> Value {
        json!({
            "id": id("PaloAltoNetworks.Cloudngfw/firewalls/ngfw-hub"),
            "name": "ngfw-hub",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "isPanoramaManaged": "FALSE",
                "panoramaConfig": {"configString": "fixture-registration", "vmAuthKey": "fixture-auth-key", "dgName": "dg"},
                "networkProfile": {
                    "networkType": "VNET",
                    "vnetConfiguration": {
                        "vnet": {"resourceId": id("Microsoft.Network/virtualNetworks/vnet-hub"), "addressSpace": "10.10.0.0/16"},
                        "trustSubnet": {"resourceId": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/snet-trust"), "addressSpace": "10.10.11.0/26"},
                        "unTrustSubnet": {"resourceId": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/snet-untrust"), "addressSpace": "10.10.11.64/26"},
                        "ipOfTrustSubnetForUdr": {"address": "10.10.11.4"}
                    },
                    "publicIps": [{"address": "20.1.2.3", "resourceId": id("Microsoft.Network/publicIPAddresses/pip-ngfw")}],
                    "enableEgressNat": "ENABLED",
                    "egressNatIp": [{"address": "20.1.2.3", "resourceId": id("Microsoft.Network/publicIPAddresses/pip-ngfw")}]
                },
                "associatedRulestack": {"resourceId": id("PaloAltoNetworks.Cloudngfw/localRulestacks/lrs-hub"), "location": "westeurope"},
                "dnsSettings": {"enableDnsProxy": "ENABLED", "enabledDnsType": "AZURE"},
                "frontEndSettings": [{"name": "rdp", "protocol": "TCP",
                    "frontendConfiguration": {"port": "3389", "address": {"address": "20.1.2.3", "resourceId": id("Microsoft.Network/publicIPAddresses/pip-ngfw")}},
                    "backendConfiguration": {"port": "3389", "address": {"address": "10.20.0.4"}}}],
                "planData": {"billingCycle": "MONTHLY", "planId": "panw-cngfw-payg", "usageType": "PAYG"},
                "marketplaceDetails": {"offerId": "pan_swfw_cloud_ngfw", "publisherId": "paloaltonetworks", "marketplaceSubscriptionStatus": "Subscribed"}
            }
        })
    }

    type Maps = (LazyMap<Vec<Value>>, LazyMap<Vec<Value>>, LazyMap<Vec<Value>>, LazyMap<Vec<Value>>, LazyMap<Value>);

    fn lazy_maps() -> Maps {
        Default::default()
    }

    #[test]
    fn section_labels_put_overview_first_and_access_activity_related_tags_last() {
        for desc in [&AZURE_FIREWALL_SECTIONS, &FIREWALL_POLICY_SECTIONS, &IP_GROUP_SECTIONS, &CLOUD_NGFW_SECTIONS, &RULESTACK_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(&labels[labels.len() - 4..], ["Access", "Activity", "Related", "Tags"]);
            assert!(labels.len() <= 10, "digit keys reach ten sections");
        }
    }

    #[test]
    fn an_azure_firewall_shows_its_private_ip_first_and_its_state() {
        let f = AzureFirewallRow::from_json(&azfw_json(), None).unwrap();
        assert_eq!(f.private_ips(), vec!["10.10.9.4"]);
        assert_eq!(f.list_summary().unwrap(), "Premium · 10.10.9.4 · policy fwp-child");
        assert_eq!(f.details()[1], ("UDR next hop (private IP)".into(), "10.10.9.4".into()));
        assert_eq!(f.state(), ResourceState::Running);
        assert_eq!(f.state_label(), "allocated");
        let net = f.network_rows(&FirewallLists::default());
        assert_eq!(net[0].1, "10.10.9.4");
        assert!(has(&net, "Subnet vnet-hub/AzureFirewallSubnet", "/subnets/AzureFirewallSubnet"));
        assert!(has(&net, "Management public IP pip-afw-mgmt", "pip-afw-mgmt"));
        let rel = f.related();
        assert!(rel.iter().any(|(l, _)| l == "Firewall policy fwp-child"));
        assert!(rel.iter().any(|(l, _)| l == "VNet vnet-hub"));
        assert!(f.cli_command().unwrap().starts_with("az network firewall show --ids "));
        // Deallocated: no IP configuration.
        let mut v = azfw_json();
        v["properties"]["ipConfigurations"] = json!([]);
        let d = AzureFirewallRow::from_json(&v, None).unwrap();
        assert_eq!((d.state(), d.state_label()), (ResourceState::Stopped, "deallocated".into()));
        v["properties"]["provisioningState"] = json!("Updating");
        assert_eq!(AzureFirewallRow::from_json(&v, None).unwrap().state_label(), "updating");
    }

    #[test]
    fn classic_rules_render_when_there_is_no_policy() {
        let mut v = azfw_json();
        v["properties"].as_object_mut().unwrap().remove("firewallPolicy");
        v["properties"]["networkRuleCollections"] = json!([{"name": "net", "properties": {"priority": 100, "action": {"type": "Allow"},
            "rules": [{"name": "dns", "protocols": ["UDP"], "sourceAddresses": ["10.0.0.0/8"], "destinationAddresses": ["168.63.129.16"], "destinationPorts": ["53"]}]}}]);
        let f = AzureFirewallRow::from_json(&v, None).unwrap();
        assert_eq!(f.list_summary().unwrap(), "Premium · 10.10.9.4 · 1 classic rules");
        let (rcg, rules, pl, fl, st) = lazy_maps();
        let lazy = FirewallLazy { rule_collection_groups: &rcg, ngfw_rules: &rules, prefix_lists: &pl, fqdn_lists: &fl, ngfw_status: &st };
        let lines = azure_firewall_section_lines(&f, AzureFirewallDetailSection::Rules, &FirewallLists::default(), &lazy);
        assert!(has(&lines, "Collection net", "Network · Allow · priority 100 · 1 rules"));
        assert!(has(&lines, "dns", "UDP · 10.0.0.0/8 → 168.63.129.16 :53"));
        let pol = azure_firewall_section_lines(&f, AzureFirewallDetailSection::Policy, &FirewallLists::default(), &lazy);
        assert!(has(&pol, "DNS proxy", "on"));
    }

    #[test]
    fn rule_collection_groups_render_in_priority_order_with_ip_groups_jumpable() {
        let lines = rule_collection_group_rows(&groups(), &FirewallLists::default(), None);
        let order: Vec<&str> = lines.iter().map(|(k, _)| k.trim()).filter(|k| k.starts_with("Group") || k.starts_with("Collection")).collect();
        assert_eq!(
            order,
            ["Group rcg-net", "Collection dnat", "Collection net-allow", "Collection net-deny", "Group rcg-app", "Collection app-allow"]
        );
        assert!(has(&lines, "Nat rdp", "TCP · 203.0.113.24 → 20.0.0.1 :3389 ⇒ 10.20.0.4:3389"));
        assert!(has(&lines, "Collection dnat", "DNAT · DNAT · priority 50"));
        assert!(has(&lines, "Application allow-ms", "Https:443 · ipg:ipg-spokes → *.microsoft.com · TLS inspected"));
        assert!(has(&lines, "source IP group ipg-spokes", "/ipGroups/ipg-spokes"));
    }

    #[test]
    fn a_policy_reads_its_base_first_and_names_the_firewalls_using_it() {
        let child = FirewallPolicyRow::from_json(&policy_json("fwp-child", Some("fwp-base")), None).unwrap();
        assert_eq!(child.list_summary().unwrap(), "Premium · threat intel Deny · IDPS Alert · base fwp-base");
        let mut rcg = LazyMap::default();
        rcg.apply(rules_key(child.base_policy_id.as_deref().unwrap()), Ok(vec![groups()[0].clone()]));
        rcg.apply(rules_key(&child.base.id), Ok(vec![groups()[1].clone()]));
        let (_, rules, pl, fl, st) = lazy_maps();
        let lazy = FirewallLazy { rule_collection_groups: &rcg, ngfw_rules: &rules, prefix_lists: &pl, fqdn_lists: &fl, ngfw_status: &st };
        let lines = firewall_policy_section_lines(&child, FirewallPolicyDetailSection::RuleCollectionGroups, &FirewallLists::default(), &lazy);
        let base_at = lines.iter().position(|(k, _)| k == "Group rcg-app (inherited from fwp-base)").unwrap();
        let own_at = lines.iter().position(|(k, _)| k == "Group rcg-net").unwrap();
        assert!(base_at < own_at, "{lines:#?}");
        let fw: Vec<Box<dyn Resource>> = vec![Box::new(AzureFirewallRow::from_json(&azfw_json(), None).unwrap())];
        let lists = FirewallLists { firewalls: Some(&fw), ..Default::default() };
        let h = firewall_policy_section_lines(&child, FirewallPolicyDetailSection::Hierarchy, &lists, &lazy);
        assert!(has(&h, "Base policy fwp-base", "/firewallPolicies/fwp-base"));
        assert!(has(&h, "Firewall afw-hub · 10.10.9.4", "/azureFirewalls/afw-hub"));
        let s = child.settings_rows();
        assert!(has(&s, "IDPS", "Alert"));
        assert!(has(&s, "2024897", "Deny"));
        assert!(has(&s, "DNS servers", "Azure DNS"));
        // Still loading: a Loading… line, never "No rules".
        let empty = LazyMap::default();
        let lazy = FirewallLazy { rule_collection_groups: &empty, ..lazy };
        let lines = firewall_policy_section_lines(&child, FirewallPolicyDetailSection::RuleCollectionGroups, &FirewallLists::default(), &lazy);
        assert!(lines.iter().any(|(_, v)| v == "Loading…"));
    }

    #[test]
    fn an_ip_group_lists_addresses_and_users() {
        let g = IpGroupRow::from_json(
            &json!({"id": id("Microsoft.Network/ipGroups/ipg-spokes"), "name": "ipg-spokes", "location": "westeurope",
                "properties": {"provisioningState": "Succeeded", "ipAddresses": ["10.20.0.0/16", "10.30.0.0/16"],
                    "firewallPolicies": [{"id": id("Microsoft.Network/firewallPolicies/fwp-child")}]}}),
            None,
        )
        .unwrap();
        assert_eq!(g.list_summary().unwrap(), "2 addresses · used by 1");
        assert_eq!(g.state(), ResourceState::stateless());
        assert!(has(&ip_group_section_lines(&g, IpGroupDetailSection::UsedBy), "Firewall policy fwp-child", "fwp-child"));
        assert!(g.search_text().contains("10.30.0.0/16"));
    }

    #[test]
    fn a_cloud_ngfw_shows_its_trust_ip_and_never_its_panorama_secrets() {
        let n = CloudNgfwRow::from_json(&ngfw_json(), None).unwrap();
        assert_eq!(n.udr_ip().as_deref(), Some("10.10.11.4"));
        assert_eq!(n.list_summary().unwrap(), "VNET · UDR 10.10.11.4 · local rulestack lrs-hub");
        assert_eq!((n.state(), n.state_label()), (ResourceState::Available, "subscribed".into()));
        assert_eq!(n.management(), NgfwManagement::LocalRulestack);
        let raw = n.raw_content().unwrap();
        assert!(!raw.contains("fixture-registration") && !raw.contains("fixture-auth-key"), "{raw}");
        let net = n.network_rows(&FirewallLists::default());
        assert_eq!(net[0], ("UDR next hop (trust IP)".into(), "10.10.11.4".into()));
        assert!(has(&net, "Trust subnet vnet-hub/snet-trust (10.10.11.0/26)", "/subnets/snet-trust"));
        assert!(has(&net, "Public IP 20.1.2.3 (pip-ngfw)", "pip-ngfw"));
        assert!(has(&n.front_end_rows(), "rdp (TCP)", "20.1.2.3:3389 → 10.20.0.4:3389"));
        let rel = n.related();
        assert!(rel.iter().any(|(l, _)| l == "Local rulestack lrs-hub"));
        assert!(rel.iter().any(|(l, _)| l == "Untrust subnet vnet-hub/snet-untrust"));
        let m = n.management_rows(&FirewallLists::default());
        assert!(has(&m, "Billing cycle", "monthly"));
        // Rules from the rulestack's lazy read, by priority.
        let (rcg, mut rules, pl, fl, st) = lazy_maps();
        rules.apply(
            rules_key(&n.rulestack_id().unwrap()),
            Ok(vec![
                json!({"name": "200", "properties": {"priority": 200, "ruleName": "deny-all", "actionType": "DenySilent"}}),
                json!({"name": "100", "properties": {"priority": 100, "ruleName": "allow-web", "actionType": "Allow",
                    "source": {"cidrs": ["10.20.0.0/16"]}, "destination": {"fqdnLists": ["fqdn-ms"]},
                    "applications": ["ssl", "web-browsing"], "protocolPortList": ["TCP:443"]}}),
            ]),
        );
        let lazy = FirewallLazy { rule_collection_groups: &rcg, ngfw_rules: &rules, prefix_lists: &pl, fqdn_lists: &fl, ngfw_status: &st };
        let lines = cloud_ngfw_section_lines(&n, CloudNgfwDetailSection::Rules, &FirewallLists::default(), &lazy);
        assert_eq!(lines[1].0, "100 allow-web");
        assert_eq!(lines[1].1, "Allow · 10.20.0.0/16 → fqdn:fqdn-ms · apps ssl, web-browsing · TCP:443");
        assert_eq!(lines[2].0, "200 deny-all");
    }

    #[test]
    fn a_panorama_managed_ngfw_says_where_its_rules_are() {
        let mut v = ngfw_json();
        v["properties"]["isPanoramaManaged"] = json!("TRUE");
        let n = CloudNgfwRow::from_json(&v, None).unwrap();
        assert_eq!(n.management(), NgfwManagement::Panorama);
        let (rcg, rules, pl, fl, st) = lazy_maps();
        let lazy = FirewallLazy { rule_collection_groups: &rcg, ngfw_rules: &rules, prefix_lists: &pl, fqdn_lists: &fl, ngfw_status: &st };
        let lines = cloud_ngfw_section_lines(&n, CloudNgfwDetailSection::Rules, &FirewallLists::default(), &lazy);
        assert!(has(&lines, "Managed by Panorama", "device group dg"));
        assert!(!lines.iter().any(|(_, v)| v == "Loading…"));
        let m = n.management_rows(&FirewallLists::default());
        assert!(m.iter().all(|(_, v)| !v.contains("fixture")));
        // A suspended Marketplace subscription stops it.
        v["properties"]["marketplaceDetails"]["marketplaceSubscriptionStatus"] = json!("Suspended");
        assert_eq!(CloudNgfwRow::from_json(&v, None).unwrap().state(), ResourceState::Stopped);
    }

    #[test]
    fn udr_next_hops_match_a_route_to_its_firewall() {
        let fws: Vec<Box<dyn Resource>> = vec![Box::new(AzureFirewallRow::from_json(&azfw_json(), None).unwrap())];
        let ngfws: Vec<Box<dyn Resource>> = vec![Box::new(CloudNgfwRow::from_json(&ngfw_json(), None).unwrap())];
        assert_eq!(udr_next_hops(fws[0].as_ref()), vec!["10.10.9.4"]);
        assert_eq!(udr_next_hops(ngfws[0].as_ref()), vec!["10.10.11.4"]);
        assert_eq!(firewall_for_next_hop("10.10.11.4", &[&fws, &ngfws]).map(|r| r.name()), Some("ngfw-hub"));
        assert_eq!(firewall_for_next_hop(" 10.10.9.4", &[&fws, &ngfws]).map(|r| r.name()), Some("afw-hub"));
        assert!(firewall_for_next_hop("10.0.0.1", &[&fws, &ngfws]).is_none());
        let g = IpGroupRow::from_json(&json!({"id": id("Microsoft.Network/ipGroups/g"), "name": "g"}), None).unwrap();
        assert!(udr_next_hops(&g).is_empty());
        // The reverse: which warm route tables send traffic here.
        let rts: Vec<Box<dyn Resource>> = vec![Box::new(
            RouteTableRow::from_json(
                &json!({"id": id("Microsoft.Network/routeTables/rt-spoke"), "name": "rt-spoke", "location": "westeurope",
                    "properties": {"routes": [{"name": "default", "properties": {"addressPrefix": "0.0.0.0/0",
                        "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.10.11.4"}}],
                        "subnets": [{"id": id("Microsoft.Network/virtualNetworks/vnet-spoke/subnets/snet-app")}]}}),
                None,
            )
            .unwrap(),
        )];
        let lines = routes_to(&udr_next_hops(ngfws[0].as_ref()), Some(&rts));
        assert!(has(&lines, "Route table rt-spoke (default 0.0.0.0/0)", "/routeTables/rt-spoke"));
        assert!(has(&lines, "subnet vnet-spoke/snet-app", "/subnets/snet-app"));
        assert!(has(&routes_to(&udr_next_hops(fws[0].as_ref()), Some(&rts)), "", "No loaded route table"));
        assert!(has(&routes_to(&[], None), "", "load @rt"));
    }

    #[test]
    fn a_rulestack_lists_objects_and_the_warm_firewalls_using_it() {
        let rs = RulestackRow::from_json(
            &json!({"id": id("PaloAltoNetworks.Cloudngfw/localRulestacks/lrs-hub"), "name": "lrs-hub", "location": "westeurope",
                "properties": {"provisioningState": "Succeeded", "scope": "LOCAL", "defaultMode": "IPS",
                    "securityServices": {"vulnerabilityProfile": "BestPractice", "urlFilteringProfile": "BestPractice"}}}),
            None,
        )
        .unwrap();
        assert_eq!(rs.list_summary().unwrap(), "LOCAL · IPS");
        assert!(has(&rs.security_rows(), "URL filtering", "BestPractice"));
        let ngfws: Vec<Box<dyn Resource>> = vec![Box::new(CloudNgfwRow::from_json(&ngfw_json(), None).unwrap())];
        let lists = FirewallLists { ngfws: Some(&ngfws), ..Default::default() };
        assert!(has(&rs.firewall_rows(&lists), "Firewall ngfw-hub · UDR 10.10.11.4", "ngfw-hub"));
        let (rcg, rules, mut pl, fl, st) = lazy_maps();
        pl.apply(rules_key(&rs.base.id), Ok(vec![json!({"name": "pl-spokes", "properties": {"prefixList": ["10.20.0.0/16"]}})]));
        let lazy = FirewallLazy { rule_collection_groups: &rcg, ngfw_rules: &rules, prefix_lists: &pl, fqdn_lists: &fl, ngfw_status: &st };
        let o = rulestack_section_lines(&rs, RulestackDetailSection::Objects, &lists, &lazy);
        assert!(has(&o, "pl-spokes", "10.20.0.0/16"));
        assert!(has(&o, "FQDN lists", "Loading…"));
    }

    #[test]
    fn ngfw_status_renders_health_and_panorama() {
        let mut st = LazyMap::default();
        st.apply("x".into(), Ok(json!({"properties": {"healthStatus": "YELLOW", "healthReason": "upgrading", "isPanoramaManaged": "TRUE",
            "panoramaStatus": {"panoramaServerStatus": "UP", "panoramaServer2Status": "DOWN"}}})));
        let lines = status_rows(st.get("x"));
        assert!(has(&lines, "Panorama server 2", "DOWN"));
        assert!(lines.iter().any(|(_, v)| v == "⚠ health YELLOW"));
    }
}
