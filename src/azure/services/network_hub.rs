//! The rest of a hub VNet in the Network tab (#137): Bastion hosts and
//! DDoS protection plans, one subscription-wide list each (sub-tabs of
//! Network; `NetworkService` dispatches here), and the **next-hop
//! resolver**: a route whose next hop is `VirtualAppliance` names only an
//! IP, which [`NextHops`] matches against the warm NICs, load balancers,
//! Azure Firewalls and Cloud NGFWs (an NVA such as a VM-Series pair behind
//! an internal LB with HA ports, or the hub's firewall, is the common
//! shape). Matching reads rows already loaded: no call.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::services::compute::{NicRow, VmRow};
use crate::azure::services::firewall::{udr_next_hops, AzureFirewallRow, CloudNgfwRow};
use crate::azure::services::network::{parent_of, SubnetRow};
use crate::azure::services::network_edge::{LoadBalancerRow, Route, RouteTableRow};
use crate::azure::services::{arm_row, json, overview_rows, related_rows, tag_rows, ArmBase};
use serde_json::Value;
use std::collections::HashMap;

pub const BASTION_HOSTS_PATH: &str = "/providers/Microsoft.Network/bastionHosts";
pub const DDOS_PLANS_PATH: &str = "/providers/Microsoft.Network/ddosProtectionPlans";

crate::sections! {
    pub enum BastionDetailSection,
    pub static BASTION_SECTIONS = [
        Overview "Overview",
        Features "Features",
        Network "Network",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum DdosPlanDetailSection,
    pub static DDOS_PLAN_SECTIONS = [
        Overview "Overview",
        Protected "Protected",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Bastion host ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BastionIpConfig {
    pub name: String,
    pub subnet_id: Option<String>,
    pub public_ip_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BastionRow {
    pub base: ArmBase,
    /// `Developer`, `Basic`, `Standard` or `Premium`.
    pub sku: Option<String>,
    pub scale_units: Option<i64>,
    pub dns_name: Option<String>,
    pub zones: Vec<String>,
    pub ip_configs: Vec<BastionIpConfig>,
    /// The Developer SKU names its VNet directly (it has no subnet).
    pub vnet_ref: Option<String>,
    /// The Developer SKU's allowed source prefixes.
    pub acl_prefixes: Vec<String>,
    pub disable_copy_paste: Option<bool>,
    pub file_copy: Option<bool>,
    pub ip_connect: Option<bool>,
    pub shareable_link: Option<bool>,
    pub tunneling: Option<bool>,
    pub kerberos: Option<bool>,
    pub session_recording: Option<bool>,
    pub private_only: Option<bool>,
}

impl BastionRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<BastionRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let flag = |name: &str| json::bool_at(v, &format!("{}/{}", p, name));
        Some(BastionRow {
            sku: json::str_at(v, "/sku/name"),
            scale_units: json::int_at(v, &format!("{}/scaleUnits", p)),
            dns_name: json::str_at(v, &format!("{}/dnsName", p)),
            zones: json::strings_at(v, "/zones"),
            ip_configs: json::arr(v, &format!("{}/ipConfigurations", p))
                .iter()
                .map(|c| BastionIpConfig {
                    name: json::text(c, "/name"),
                    subnet_id: json::arm_id(json::id_at(c, "/properties/subnet")),
                    public_ip_id: json::arm_id(json::id_at(c, "/properties/publicIPAddress")),
                })
                .collect(),
            vnet_ref: json::arm_id(json::id_at(v, &format!("{}/virtualNetwork", p))),
            acl_prefixes: json::arr(v, &format!("{}/networkAcls/ipRules", p))
                .iter()
                .filter_map(|r| json::str_at(r, "/addressPrefix"))
                .collect(),
            disable_copy_paste: flag("disableCopyPaste"),
            file_copy: flag("enableFileCopy"),
            ip_connect: flag("enableIpConnect"),
            shareable_link: flag("enableShareableLink"),
            tunneling: flag("enableTunneling"),
            kerberos: flag("enableKerberos"),
            session_recording: flag("enableSessionRecording"),
            private_only: flag("enablePrivateOnlyBastion"),
            base,
        })
    }

    /// The VNet it serves: the Developer SKU's `virtualNetwork`, else the
    /// parent of its `AzureBastionSubnet`.
    pub fn vnet_id(&self) -> Option<String> {
        self.vnet_ref.clone().or_else(|| {
            self.ip_configs
                .iter()
                .find_map(|c| c.subnet_id.as_deref())
                .and_then(|s| parent_of(s, "subnets"))
                .map(|(id, _)| id)
        })
    }

    /// `(feature, on)` in the portal's order; copy-paste is on unless
    /// disabled, every other flag off unless set.
    pub fn features(&self) -> Vec<(&'static str, bool)> {
        let on = |b: Option<bool>| b == Some(true);
        vec![
            ("Copy and paste", self.disable_copy_paste != Some(true)),
            ("Native client (tunneling)", on(self.tunneling)),
            ("IP-based connection", on(self.ip_connect)),
            ("Shareable link", on(self.shareable_link)),
            ("File copy", on(self.file_copy)),
            ("Kerberos", on(self.kerberos)),
            ("Session recording", on(self.session_recording)),
            ("Private-only", on(self.private_only)),
        ]
    }
}

impl Resource for BastionRow {
    arm_row!("Bastion");
    /// The SKU and scale units: what it can do and what it costs.
    fn list_summary(&self) -> Option<String> {
        match (&self.sku, self.scale_units) {
            (Some(s), Some(1)) => Some(format!("{s} · 1 unit")),
            (Some(s), Some(u)) => Some(format!("{s} · {u} units")),
            (s, _) => s.clone(),
        }
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&BASTION_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.sku.clone()),
            self.vnet_id().as_deref().map(name_of_id).unwrap_or(""),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let enabled: Vec<String> = self.features().into_iter().filter(|(_, on)| *on).map(|(f, _)| f.to_string()).collect();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Scale units".into(), json::num(self.scale_units)),
            ("Virtual network".into(), self.vnet_id().as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("DNS name".into(), json::opt(self.dns_name.clone())),
            ("Zones".into(), json::join(&self.zones)),
            ("Features".into(), json::join(&enabled)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(vnet) = self.vnet_id() {
            v.push((format!("Virtual network {}", name_of_id(&vnet)), vnet));
        }
        for c in &self.ip_configs {
            if let Some(s) = &c.subnet_id {
                v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
            }
            if let Some(ip) = &c.public_ip_id {
                v.push((format!("Public IP {}", name_of_id(ip)), ip.clone()));
            }
        }
        v
    }
    /// The `bastion` CLI extension; `bastion_name` has `id_part='name'`.
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network bastion show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn bastion_section_lines(r: &BastionRow, section: BastionDetailSection) -> Vec<(String, String)> {
    match section {
        BastionDetailSection::Overview => overview_rows(r),
        BastionDetailSection::Features => {
            let mut lines: Vec<(String, String)> = r
                .features()
                .into_iter()
                .map(|(f, on)| (f.to_string(), if on { "on" } else { "off" }.to_string()))
                .collect();
            lines.push((String::new(), String::new()));
            lines.push((
                String::new(),
                match r.sku.as_deref().map(str::to_lowercase).as_deref() {
                    Some("developer") => "· Developer: shared infrastructure, portal connections only, no features".into(),
                    Some("basic") => "· Basic: no native client, IP connect, shareable link or scaling (Standard and up)".into(),
                    Some("standard") => "· Session recording and private-only need Premium".into(),
                    _ => "· Native client, IP connect, shareable link and scaling need Standard; recording and private-only Premium".into(),
                },
            ));
            lines
        }
        BastionDetailSection::Network => {
            let mut lines = Vec::new();
            if let Some(vnet) = r.vnet_id() {
                lines.push((format!("Virtual network · {}", name_of_id(&vnet)), vnet));
            }
            for c in &r.ip_configs {
                lines.push((String::new(), String::new()));
                lines.push((c.name.clone(), String::new()));
                match &c.subnet_id {
                    Some(s) => lines.push((format!("  Subnet · {}", name_of_id(s)), s.clone())),
                    None => lines.push(("  Subnet".into(), "-".into())),
                }
                match &c.public_ip_id {
                    Some(ip) => lines.push((format!("  Public IP · {}", name_of_id(ip)), ip.clone())),
                    None => lines.push(("  Public IP".into(), "none (private-only)".into())),
                }
            }
            if !r.acl_prefixes.is_empty() {
                lines.push((String::new(), String::new()));
                lines.push(("Allowed sources".into(), json::join(&r.acl_prefixes)));
            }
            if lines.is_empty() {
                lines.push((String::new(), "No IP configurations".into()));
            }
            lines
        }
        BastionDetailSection::Access => crate::azure::services::rendered_by_app(),
        BastionDetailSection::Activity => crate::azure::services::rendered_by_app(),
        BastionDetailSection::Related => related_rows(r),
        BastionDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── DDoS protection plan ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DdosPlanRow {
    pub base: ArmBase,
    pub vnet_ids: Vec<String>,
    pub public_ip_ids: Vec<String>,
    pub guid: Option<String>,
}

impl DdosPlanRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<DdosPlanRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(DdosPlanRow {
            vnet_ids: json::ids_at(v, &format!("{}/virtualNetworks", p)),
            public_ip_ids: json::ids_at(v, &format!("{}/publicIPAddresses", p)),
            guid: json::str_at(v, &format!("{}/resourceGuid", p)),
            base,
        })
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

impl Resource for DdosPlanRow {
    arm_row!("DDoS Protection Plan");
    /// How much it covers.
    fn list_summary(&self) -> Option<String> {
        let mut s = count(self.vnet_ids.len(), "VNet", "VNets");
        if !self.public_ip_ids.is_empty() {
            s.push_str(&format!(" · {}", count(self.public_ip_ids.len(), "public IP", "public IPs")));
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
        Some(&DDOS_PLAN_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Virtual networks".into(), self.vnet_ids.len().to_string()),
            ("Public IPs (IP protection)".into(), self.public_ip_ids.len().to_string()),
            ("GUID".into(), json::opt(self.guid.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for id in &self.vnet_ids {
            v.push((format!("Protected VNet {}", name_of_id(id)), id.clone()));
        }
        for id in &self.public_ip_ids {
            v.push((format!("Public IP {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network ddos-protection show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn ddos_plan_section_lines(r: &DdosPlanRow, section: DdosPlanDetailSection) -> Vec<(String, String)> {
    match section {
        DdosPlanDetailSection::Overview => overview_rows(r),
        DdosPlanDetailSection::Protected => {
            let mut lines: Vec<(String, String)> = r
                .vnet_ids
                .iter()
                .map(|id| (format!("VNet · {}", name_of_id(id)), id.clone()))
                .chain(r.public_ip_ids.iter().map(|id| (format!("Public IP · {}", name_of_id(id)), id.clone())))
                .collect();
            if lines.is_empty() {
                lines.push((String::new(), "Covers no VNet (the plan still bills)".into()));
            }
            lines
        }
        DdosPlanDetailSection::Access => crate::azure::services::rendered_by_app(),
        DdosPlanDetailSection::Activity => crate::azure::services::rendered_by_app(),
        DdosPlanDetailSection::Related => related_rows(r),
        DdosPlanDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Next hops over the warm lists ─────────────────────────────────────

/// The warm lists a `VirtualAppliance` next-hop IP is matched against.
/// `None` is a list not loaded this session (or past its TTL). The VMs
/// only name what a NIC is attached to (its marketplace appliance kind);
/// they are not a source of their own.
#[derive(Default, Clone, Copy)]
pub struct NextHopLists<'a> {
    pub nics: Option<&'a [Box<dyn Resource>]>,
    pub load_balancers: Option<&'a [Box<dyn Resource>]>,
    pub vms: Option<&'a [Box<dyn Resource>]>,
    /// Azure Firewalls: each one's private IP (or virtual hub private IP).
    pub firewalls: Option<&'a [Box<dyn Resource>]>,
    /// Cloud NGFWs: each one's `ipOfTrustSubnetForUdr`.
    pub ngfws: Option<&'a [Box<dyn Resource>]>,
    // A new source is one field here and one row in
    // `NextHops::from_lists`'s `sources`.
}

/// What a next-hop IP is: the line's label and the ARM id ⏎ jumps to,
/// and a warning when the target would drop forwarded traffic.
#[derive(Debug, Clone, PartialEq)]
pub struct NextHop {
    pub label: String,
    pub id: String,
    pub warning: Option<String>,
}

/// Indexes one warm row into `ip → NextHop`, given the VM kinds.
type Indexer = fn(&dyn Resource, &VmKinds, &mut HashMap<String, NextHop>);

/// One next-hop source: its warm list, routing prefix, what a miss calls
/// it, and how its rows index.
type Source<'a> = (Option<&'a [Box<dyn Resource>]>, &'static str, &'static str, Indexer);

/// VM id (lowercased) → its marketplace appliance label, from the warm VMs.
type VmKinds = HashMap<String, String>;

/// Private IPs the warm lists know, each to what owns it. Built from rows
/// already loaded: no call.
#[derive(Debug, Default, Clone)]
pub struct NextHops {
    by_ip: HashMap<String, NextHop>,
    /// What a miss was compared with, for the miss line ("NIC", "load
    /// balancer").
    pub searched: Vec<&'static str>,
    /// The routing prefixes of the source lists that were not warm.
    pub cold: Vec<&'static str>,
}

impl NextHops {
    pub fn from_lists(l: NextHopLists<'_>) -> NextHops {
        let mut kinds = VmKinds::new();
        for r in l.vms.unwrap_or_default() {
            if let Some(vm) = r.as_any().downcast_ref::<VmRow>() {
                if let Some(p) = &vm.plan {
                    kinds.insert(vm.base.id.to_lowercase(), p.label());
                }
            }
        }
        // One row per source: its list, its routing prefix, what a miss
        // names it, and how its rows index.
        let sources: [Source<'_>; 4] = [
            (l.nics, "@nic", "NIC", index_nic),
            (l.load_balancers, "@lb", "load balancer", index_load_balancer),
            (l.firewalls, "@fw", "Azure Firewall", index_firewall),
            (l.ngfws, "@ngfw", "Cloud NGFW", index_firewall),
        ];
        let mut t = NextHops::default();
        for (list, prefix, what, index) in sources {
            t.searched.push(what);
            match list {
                None => t.cold.push(prefix),
                Some(rows) => {
                    for r in rows {
                        index(r.as_ref(), &kinds, &mut t.by_ip);
                    }
                }
            }
        }
        t
    }

    pub fn resolve(&self, ip: &str) -> Option<&NextHop> {
        self.by_ip.get(ip.trim())
    }

    /// The text for an IP no warm list knows.
    pub fn miss(&self, ip: &str) -> String {
        if self.cold.is_empty() {
            format!("{} is not a {} in the warm lists", ip, either(&self.searched))
        } else {
            format!("{} not matched; not loaded: {} (open them to match more)", ip, self.cold.join(" "))
        }
    }

    /// The lines under one route: `→ target` (jumps) and its warning, or
    /// the miss. Nothing for a route that is not `VirtualAppliance`.
    pub fn route_lines(&self, route: &Route, indent: &str) -> Vec<(String, String)> {
        let Some(ip) = route.next_hop_ip.as_deref().filter(|_| is_appliance(route)) else {
            return Vec::new();
        };
        match self.resolve(ip) {
            Some(hop) => {
                let mut lines = vec![(format!("{}→ {}", indent, hop.label), hop.id.clone())];
                if let Some(w) = &hop.warning {
                    lines.push((format!("{}  ", indent), w.clone()));
                }
                lines
            }
            None => vec![(format!("{}→", indent), self.miss(ip))],
        }
    }

    /// Every resolved appliance hop of a route table, for Related.
    pub fn links(&self, rt: &RouteTableRow) -> Vec<(String, String)> {
        rt.routes
            .iter()
            .filter(|r| is_appliance(r))
            .filter_map(|r| {
                let hop = self.resolve(r.next_hop_ip.as_deref()?)?;
                Some((format!("Next hop {} → {}", r.prefix, hop.label), hop.id.clone()))
            })
            .collect()
    }
}

/// A subnet's appliance next hops, for its Related: its route table read
/// from the warm route tables list, each `VirtualAppliance` route resolved.
/// Nothing when the subnet has no route table.
pub fn subnet_next_hop_lines(
    subnet: &SubnetRow,
    route_tables: Option<&[Box<dyn Resource>]>,
    hops: &NextHops,
) -> Vec<(String, String)> {
    let Some(rt_id) = &subnet.route_table_id else {
        return Vec::new();
    };
    let Some(rt) = route_tables
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r.as_any().downcast_ref::<RouteTableRow>())
        .find(|rt| rt.base.id.eq_ignore_ascii_case(rt_id))
    else {
        let note = match route_tables {
            None => format!("route table {} not loaded (open @rt to resolve its appliance hops)", name_of_id(rt_id)),
            Some(_) => format!("route table {} is not in the warm list", name_of_id(rt_id)),
        };
        return vec![("Next hops".into(), note)];
    };
    rt.routes
        .iter()
        .filter(|r| is_appliance(r))
        .filter_map(|r| {
            let ip = r.next_hop_ip.as_deref()?;
            Some(match hops.resolve(ip) {
                Some(hop) => (format!("Next hop {} → {}", r.prefix, hop.label), hop.id.clone()),
                None => (format!("Next hop {}", r.prefix), hops.miss(ip)),
            })
        })
        .collect()
}

/// `a`, `a or b`, `a, b or c`.
fn either(words: &[&str]) -> String {
    match words.split_last() {
        None => String::new(),
        Some((last, [])) => last.to_string(),
        Some((last, rest)) => format!("{} or {}", rest.join(", "), last),
    }
}

fn is_appliance(route: &Route) -> bool {
    route.next_hop_type.eq_ignore_ascii_case("VirtualAppliance")
}

/// A NIC's private IPs: the VM it is attached to (with its appliance kind
/// when the VM list is warm), else the NIC itself. A NIC without IP
/// forwarding drops what it is not addressed to: the classic NVA miss.
fn index_nic(r: &dyn Resource, kinds: &VmKinds, map: &mut HashMap<String, NextHop>) {
    let Some(nic) = r.as_any().downcast_ref::<NicRow>() else {
        return;
    };
    let (label, id) = match &nic.vm_id {
        Some(vm) => {
            let kind = kinds.get(&vm.to_lowercase()).map(|k| format!(" ({k})")).unwrap_or_default();
            (format!("VM {}{} · NIC {}", name_of_id(vm), kind, nic.base.name), vm.clone())
        }
        None => (format!("NIC {} (not attached to a VM)", nic.base.name), nic.base.id.clone()),
    };
    let warning = (nic.ip_forwarding != Some(true))
        .then(|| format!("⚠ IP forwarding is off on NIC {}: it drops traffic not addressed to it", nic.base.name));
    for ip in nic.ip_configs.iter().filter_map(|c| c.private_ip.as_deref()) {
        map.entry(ip.to_string()).or_insert_with(|| NextHop { label: label.clone(), id: id.clone(), warning: warning.clone() });
    }
}

/// A load balancer's private frontends; HA ports (an `All` rule on port
/// 0, what an NVA pair sits behind) is named.
fn index_load_balancer(r: &dyn Resource, _: &VmKinds, map: &mut HashMap<String, NextHop>) {
    let Some(lb) = r.as_any().downcast_ref::<LoadBalancerRow>() else {
        return;
    };
    for fe in &lb.frontends {
        let Some(ip) = fe.private_ip.as_deref() else {
            continue;
        };
        let ha = lb.rules.iter().any(|rule| {
            let p = "/properties";
            json::str_at(rule, &format!("{}/protocol", p)).is_some_and(|s| s.eq_ignore_ascii_case("All"))
                && json::int_at(rule, &format!("{}/frontendPort", p)) == Some(0)
                && json::id_at(rule, &format!("{}/frontendIPConfiguration", p))
                    .is_some_and(|id| name_of_id(&id).eq_ignore_ascii_case(&fe.name))
        });
        let label = format!(
            "Load balancer {} · frontend {}{}",
            lb.base.name,
            fe.name,
            if ha { " · HA ports" } else { "" }
        );
        map.entry(ip.to_string()).or_insert_with(|| NextHop { label, id: lb.base.id.clone(), warning: None });
    }
}

/// A firewall's UDR next hops ([`udr_next_hops`]): an Azure Firewall's
/// private IP, a Cloud NGFW's trust IP. A firewall forwards by design, so
/// there is no warning.
fn index_firewall(r: &dyn Resource, _: &VmKinds, map: &mut HashMap<String, NextHop>) {
    let any = r.as_any();
    let label = if let Some(f) = any.downcast_ref::<AzureFirewallRow>() {
        format!("Azure Firewall {}", f.base.name)
    } else if let Some(n) = any.downcast_ref::<CloudNgfwRow>() {
        format!("Cloud NGFW {} · trust IP", n.base.name)
    } else {
        return;
    };
    for ip in udr_next_hops(r) {
        map.entry(ip).or_insert_with(|| NextHop { label: label.clone(), id: r.id().to_string(), warning: None });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-hub";

    fn id(t: &str) -> String {
        format!("{}/providers/{}", RG, t)
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for desc in [&BASTION_SECTIONS, &DDOS_PLAN_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(labels[labels.len() - 3..], ["Activity", "Related", "Tags"]);
        }
    }

    #[test]
    fn bastion_reads_sku_features_and_its_subnet_vnet() {
        let v = serde_json::json!({
            "id": id("Microsoft.Network/bastionHosts/bas-hub"),
            "name": "bas-hub",
            "location": "westeurope",
            "sku": {"name": "Standard"},
            "properties": {
                "provisioningState": "Succeeded",
                "scaleUnits": 3,
                "dnsName": "bst-1234.bastion.azure.com",
                "enableTunneling": true,
                "enableIpConnect": true,
                "disableCopyPaste": false,
                "ipConfigurations": [{"name": "IpConf", "properties": {
                    "subnet": {"id": id("Microsoft.Network/virtualNetworks/vnet-hub/subnets/AzureBastionSubnet")},
                    "publicIPAddress": {"id": id("Microsoft.Network/publicIPAddresses/pip-bas")}}}]
            }
        });
        let row = BastionRow::from_json(&v, None).unwrap();
        assert_eq!(row.list_summary().as_deref(), Some("Standard · 3 units"));
        assert_eq!(row.vnet_id(), Some(id("Microsoft.Network/virtualNetworks/vnet-hub")));
        assert!(row.details().iter().any(|(k, v)| k == "Features" && v == "Copy and paste, Native client (tunneling), IP-based connection"));
        let f = bastion_section_lines(&row, BastionDetailSection::Features);
        assert!(f.iter().any(|(k, v)| k == "Shareable link" && v == "off"));
        let net = bastion_section_lines(&row, BastionDetailSection::Network);
        assert!(net.iter().any(|(k, v)| k == "Virtual network · vnet-hub" && v.ends_with("/virtualNetworks/vnet-hub")));
        assert!(net.iter().any(|(k, v)| k == "  Subnet · AzureBastionSubnet" && v.ends_with("/subnets/AzureBastionSubnet")));
        assert!(net.iter().any(|(k, _)| k == "  Public IP · pip-bas"));
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Virtual network vnet-hub", "Subnet AzureBastionSubnet", "Public IP pip-bas"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
        assert!(row.cli_command().unwrap().starts_with("az network bastion show --ids "));

        // The Developer SKU names its VNet and has no subnet.
        let dev = BastionRow::from_json(
            &serde_json::json!({"id": id("Microsoft.Network/bastionHosts/bas-dev"), "name": "bas-dev", "location": "westeurope",
                "sku": {"name": "Developer"},
                "properties": {"virtualNetwork": {"id": id("Microsoft.Network/virtualNetworks/vnet-dev")},
                    "networkAcls": {"ipRules": [{"addressPrefix": "203.0.113.0/24"}]}}}),
            None,
        )
        .unwrap();
        assert_eq!(dev.vnet_id(), Some(id("Microsoft.Network/virtualNetworks/vnet-dev")));
        let net = bastion_section_lines(&dev, BastionDetailSection::Network);
        assert!(net.iter().any(|(k, v)| k == "Allowed sources" && v == "203.0.113.0/24"));
    }

    #[test]
    fn ddos_plan_lists_what_it_protects() {
        let row = DdosPlanRow::from_json(
            &serde_json::json!({"id": id("Microsoft.Network/ddosProtectionPlans/ddos-hub"), "name": "ddos-hub", "location": "westeurope",
                "properties": {"provisioningState": "Succeeded",
                    "virtualNetworks": [{"id": id("Microsoft.Network/virtualNetworks/vnet-hub")}, {"id": id("Microsoft.Network/virtualNetworks/vnet-spoke")}]}}),
            None,
        )
        .unwrap();
        assert_eq!(row.list_summary().as_deref(), Some("2 VNets"));
        let p = ddos_plan_section_lines(&row, DdosPlanDetailSection::Protected);
        assert_eq!(p[0], ("VNet · vnet-hub".to_string(), id("Microsoft.Network/virtualNetworks/vnet-hub")));
        assert!(row.related().iter().any(|(l, _)| l == "Protected VNet vnet-spoke"));
        assert!(row.cli_command().unwrap().starts_with("az network ddos-protection show --ids "));
    }

    fn nic(name: &str, ip: &str, vm: Option<&str>, forwarding: bool) -> Box<dyn Resource> {
        let mut v = serde_json::json!({
            "id": id(&format!("Microsoft.Network/networkInterfaces/{name}")), "name": name, "location": "westeurope",
            "properties": {"enableIPForwarding": forwarding, "ipConfigurations": [
                {"name": "ipconfig1", "properties": {"privateIPAddress": ip}}]}
        });
        if let Some(vm) = vm {
            v["properties"]["virtualMachine"] = serde_json::json!({"id": id(&format!("Microsoft.Compute/virtualMachines/{vm}"))});
        }
        Box::new(NicRow::from_json(&v, None).unwrap())
    }

    fn vm(name: &str, publisher: &str, product: &str) -> Box<dyn Resource> {
        Box::new(
            VmRow::from_json(
                &serde_json::json!({"id": id(&format!("Microsoft.Compute/virtualMachines/{name}")), "name": name, "location": "westeurope",
                    "plan": {"name": "byol", "publisher": publisher, "product": product},
                    "properties": {"hardwareProfile": {"vmSize": "Standard_D8s_v5"}}}),
                None,
            )
            .unwrap(),
        )
    }

    fn ilb() -> Box<dyn Resource> {
        let lb = id("Microsoft.Network/loadBalancers/lb-nva");
        Box::new(
            LoadBalancerRow::from_json(
                &serde_json::json!({"id": lb, "name": "lb-nva", "location": "westeurope",
                    "properties": {
                        "frontendIPConfigurations": [{"name": "fe-trust", "properties": {"privateIPAddress": "10.0.1.10"}}],
                        "loadBalancingRules": [{"name": "ha", "properties": {"protocol": "All", "frontendPort": 0, "backendPort": 0,
                            "frontendIPConfiguration": {"id": format!("{lb}/frontendIPConfigurations/fe-trust")}}}]}}),
                None,
            )
            .unwrap(),
        )
    }

    fn route(prefix: &str, ip: &str) -> Route {
        Route { name: "r".into(), prefix: prefix.into(), next_hop_type: "VirtualAppliance".into(), next_hop_ip: Some(ip.into()) }
    }

    #[test]
    fn a_next_hop_resolves_to_the_vm_behind_a_nic_with_its_appliance_kind() {
        let nics = [nic("nic-pa-1", "10.0.1.4", Some("vm-pa-1"), true), nic("nic-off", "10.0.1.5", Some("vm-x"), false)];
        let vms = [vm("vm-pa-1", "paloaltonetworks", "vmseries-flex")];
        let hops = NextHops::from_lists(NextHopLists { nics: Some(&nics), vms: Some(&vms), ..Default::default() });
        let lines = hops.route_lines(&route("0.0.0.0/0", "10.0.1.4"), "  ");
        assert_eq!(
            lines,
            vec![("  → VM vm-pa-1 (Palo Alto VM-Series) · NIC nic-pa-1".to_string(), id("Microsoft.Compute/virtualMachines/vm-pa-1"))]
        );
        // IP forwarding off is the warning under the hop.
        let off = hops.route_lines(&route("10.9.0.0/16", "10.0.1.5"), "");
        assert!(off[1].1.starts_with("⚠ IP forwarding is off on NIC nic-off"), "{off:?}");
        // The load balancers were not loaded: a miss says so.
        let miss = hops.route_lines(&route("0.0.0.0/0", "10.0.9.4"), "");
        assert_eq!(miss[0].1, "10.0.9.4 not matched; not loaded: @lb @fw @ngfw (open them to match more)");
    }

    #[test]
    fn a_next_hop_resolves_to_an_internal_load_balancer_frontend() {
        let lbs = [ilb()];
        let nics: [Box<dyn Resource>; 0] = [];
        let hops = NextHops::from_lists(NextHopLists {
            nics: Some(&nics),
            load_balancers: Some(&lbs),
            firewalls: Some(&nics),
            ngfws: Some(&nics),
            vms: None,
        });
        let lines = hops.route_lines(&route("0.0.0.0/0", "10.0.1.10"), "");
        assert_eq!(lines, vec![("→ Load balancer lb-nva · frontend fe-trust · HA ports".to_string(), id("Microsoft.Network/loadBalancers/lb-nva"))]);
        // Every list warm, no match: says what it is not.
        let miss = hops.route_lines(&route("0.0.0.0/0", "10.0.9.4"), "");
        assert_eq!(miss[0].1, "10.0.9.4 is not a NIC, load balancer, Azure Firewall or Cloud NGFW in the warm lists");
        // A route that is not VirtualAppliance gets no line.
        let local = Route { name: "l".into(), prefix: "10.0.0.0/8".into(), next_hop_type: "VnetLocal".into(), next_hop_ip: None };
        assert!(hops.route_lines(&local, "").is_empty());
    }

    #[test]
    fn a_next_hop_resolves_to_the_azure_firewall_or_cloud_ngfw_it_names() {
        let afw: [Box<dyn Resource>; 1] = [Box::new(
            AzureFirewallRow::from_json(
                &serde_json::json!({"id": id("Microsoft.Network/azureFirewalls/afw-hub"), "name": "afw-hub", "location": "westeurope",
                    "properties": {"ipConfigurations": [{"name": "c", "properties": {"privateIPAddress": "10.0.9.4"}}]}}),
                None,
            )
            .unwrap(),
        )];
        let ngfw: [Box<dyn Resource>; 1] = [Box::new(
            CloudNgfwRow::from_json(
                &serde_json::json!({"id": id("PaloAltoNetworks.Cloudngfw/firewalls/ngfw-hub"), "name": "ngfw-hub", "location": "westeurope",
                    "properties": {"networkProfile": {"networkType": "VNET",
                        "vnetConfiguration": {"ipOfTrustSubnetForUdr": {"address": "10.0.11.4"}}}}}),
                None,
            )
            .unwrap(),
        )];
        let hops = NextHops::from_lists(NextHopLists { firewalls: Some(&afw), ngfws: Some(&ngfw), ..Default::default() });
        assert_eq!(
            hops.route_lines(&route("0.0.0.0/0", "10.0.11.4"), "  "),
            vec![("  → Cloud NGFW ngfw-hub · trust IP".to_string(), id("PaloAltoNetworks.Cloudngfw/firewalls/ngfw-hub"))],
            "a firewall forwards by design: no IP-forwarding warning"
        );
        assert_eq!(
            hops.route_lines(&route("10.9.0.0/16", " 10.0.9.4"), ""),
            vec![("→ Azure Firewall afw-hub".to_string(), id("Microsoft.Network/azureFirewalls/afw-hub"))]
        );
        // The NICs and load balancers were not loaded.
        assert_eq!(hops.miss("10.0.0.1"), "10.0.0.1 not matched; not loaded: @nic @lb (open them to match more)");
    }

    #[test]
    fn a_subnet_reads_its_route_tables_appliance_hops_from_the_warm_list() {
        let rt_id = id("Microsoft.Network/routeTables/rt-spoke");
        let subnet = SubnetRow::from_json(
            &serde_json::json!({"id": id("Microsoft.Network/virtualNetworks/vnet-spoke/subnets/app"), "name": "app",
                "properties": {"addressPrefix": "10.1.0.0/24", "routeTable": {"id": rt_id}}}),
            None,
        )
        .unwrap();
        let rts: [Box<dyn Resource>; 1] = [Box::new(
            RouteTableRow::from_json(
                &serde_json::json!({"id": rt_id, "name": "rt-spoke", "location": "westeurope", "properties": {"routes": [
                    {"name": "default", "properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.1.10"}},
                    {"name": "local", "properties": {"addressPrefix": "10.1.0.0/16", "nextHopType": "VnetLocal"}}]}}),
                None,
            )
            .unwrap(),
        )];
        let lbs = [ilb()];
        let hops = NextHops::from_lists(NextHopLists { load_balancers: Some(&lbs), ..Default::default() });
        let lines = subnet_next_hop_lines(&subnet, Some(&rts), &hops);
        assert_eq!(
            lines,
            vec![("Next hop 0.0.0.0/0 → Load balancer lb-nva · frontend fe-trust · HA ports".to_string(), id("Microsoft.Network/loadBalancers/lb-nva"))]
        );
        let cold = subnet_next_hop_lines(&subnet, None, &hops);
        assert_eq!(cold[0].1, "route table rt-spoke not loaded (open @rt to resolve its appliance hops)");
    }

    #[test]
    fn marketplace_plans_label_the_vm_kind() {
        let label = |publisher: &str, product: &str| {
            let b = vm("v", publisher, product);
            b.as_any().downcast_ref::<VmRow>().unwrap().plan.as_ref().unwrap().label()
        };
        assert_eq!(label("paloaltonetworks", "vmseries-flex"), "Palo Alto VM-Series");
        assert_eq!(label("fortinet", "fortinet_fortigate-vm_v5"), "Fortinet fortinet_fortigate-vm_v5");
        assert_eq!(label("checkpoint", "check-point-cg-r8120"), "Check Point check-point-cg-r8120");
        assert_eq!(label("cisco", "cisco-c8000v"), "Cisco cisco-c8000v");
        assert_eq!(label("contoso", "edge-router"), "contoso edge-router");
        let pa = vm("vm-pa-1", "paloaltonetworks", "vmseries-flex");
        assert_eq!(pa.list_summary().as_deref(), Some("Palo Alto VM-Series · Standard_D8s_v5"));
        assert!(pa.details().iter().any(|(k, v)| k == "Marketplace plan" && v == "Palo Alto VM-Series · paloaltonetworks / vmseries-flex / byol"));
    }
}
