//! The network access lens's evaluation (`N`, #50): which NSG rules apply
//! to a NIC, a subnet or an NSG, in the order Azure evaluates them,
//! **computed client-side from GETs**.
//!
//! ARM's effective-rules and effective-routes calls on a NIC are POST
//! actions; nebaz never makes them (`ReadOnlyPolicy` would refuse them and
//! the read-only guard refuses their names in `src/`). So this is not
//! Azure's effective view: it ignores Azure Firewall, user-defined routes
//! and AVNM security admin rules, and the lens says so.
//!
//! The model:
//! - **Layers.** Inbound traffic meets the subnet's NSG, then the NIC's;
//!   outbound the NIC's, then the subnet's. It must be allowed at both. A
//!   layer with no NSG allows everything; a layer nebaz could not read is
//!   unknown, never assumed open.
//! - **Within an NSG** the rules of one direction run by priority (lowest
//!   number first) and the first match wins. The six default rules
//!   (65000 / 65001 / 65500 each way) come from the body's
//!   `defaultSecurityRules`, or are added here when a body has none.
//! - **Shadowed**: an earlier rule of the same NSG and direction matches
//!   everything a rule matches, so the rule can never be the first match.
//! - **Across layers**: an allow rule's traffic is run through the other
//!   layer's NSG. The first rule there that overlaps it decides when it
//!   also covers it (allowed / blocked); when it only partly overlaps, the
//!   answer depends on the exact flow and the lens says that instead of
//!   guessing.
//! - **Addresses**: CIDRs (v4 and v6) compare numerically. Service tags
//!   (`VirtualNetwork`, `Internet`, `Storage.WestEurope`…) and application
//!   security groups compare by name only, never expanded: a tag is covered
//!   only by `*` or by itself, and is never provably disjoint from
//!   anything. Every claim errs towards "depends", never towards a wrong
//!   verdict.

use crate::azure::resource::name_of_id;
use crate::azure::services::compute::NicRow;
use crate::azure::services::network::{NsgRow, SecurityRule, SubnetRow, VnetRow};
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Inbound,
    Outbound,
}

impl Dir {
    pub fn word(self) -> &'static str {
        match self {
            Dir::Inbound => "Inbound",
            Dir::Outbound => "Outbound",
        }
    }

    fn matches(self, direction: &str) -> bool {
        direction.eq_ignore_ascii_case(self.word())
    }
}

// ── Matching ──────────────────────────────────────────────────────────

/// One side of a rule: `*`, a CIDR, or a name (a service tag, an ASG as
/// `asg:{id}`, or a literal nebaz cannot parse).
#[derive(Debug, Clone, PartialEq)]
enum Addr {
    Any,
    Net { v6: bool, net: u128, len: u8 },
    Name(String),
}

fn mask(bits: u128, len: u8, width: u8) -> u128 {
    if len == 0 {
        0
    } else {
        let shift = (width - len) as u32;
        (bits >> shift) << shift
    }
}

fn parse_addr(s: &str) -> Addr {
    let t = s.trim();
    if t == "*" || t.eq_ignore_ascii_case("any") {
        return Addr::Any;
    }
    let (ip, len) = match t.split_once('/') {
        Some((ip, l)) => match l.parse::<u8>() {
            Ok(l) => (ip, Some(l)),
            Err(_) => return Addr::Name(t.to_lowercase()),
        },
        None => (t, None),
    };
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        let len = len.unwrap_or(32);
        if len <= 32 {
            return Addr::Net { v6: false, net: mask(u32::from(v4) as u128, len, 32), len };
        }
    } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
        let len = len.unwrap_or(128);
        if len <= 128 {
            return Addr::Net { v6: true, net: mask(u128::from(v6), len, 128), len };
        }
    }
    Addr::Name(t.to_lowercase())
}

impl Addr {
    fn covers(&self, other: &Addr) -> bool {
        match (self, other) {
            (Addr::Any, _) => true,
            (Addr::Net { v6, net, len }, Addr::Net { v6: o6, net: onet, len: olen }) => {
                v6 == o6 && len <= olen && mask(*onet, *len, if *v6 { 128 } else { 32 }) == *net
            }
            (Addr::Name(a), Addr::Name(b)) => a == b,
            _ => false,
        }
    }

    /// Provably no address in common: only two CIDRs can be.
    fn disjoint(&self, other: &Addr) -> bool {
        match (self, other) {
            (Addr::Net { v6, net, len }, Addr::Net { v6: o6, net: onet, len: olen }) => {
                if v6 != o6 {
                    return true;
                }
                let width = if *v6 { 128 } else { 32 };
                let common = (*len).min(*olen);
                mask(*net, common, width) != mask(*onet, common, width)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Port {
    Range(u32, u32),
    Unknown(String),
}

fn parse_port(s: &str) -> Port {
    let t = s.trim();
    if t == "*" {
        return Port::Range(0, 65535);
    }
    let parsed = match t.split_once('-') {
        Some((a, b)) => a.trim().parse().ok().zip(b.trim().parse().ok()),
        None => t.parse().ok().map(|p| (p, p)),
    };
    match parsed {
        Some((a, b)) if a <= b => Port::Range(a, b),
        _ => Port::Unknown(t.to_string()),
    }
}

impl Port {
    fn covers(&self, other: &Port) -> bool {
        match (self, other) {
            (Port::Range(a, b), Port::Range(c, d)) => a <= c && d <= b,
            (Port::Range(0, 65535), _) => true,
            (Port::Unknown(a), Port::Unknown(b)) => a == b,
            _ => false,
        }
    }

    fn disjoint(&self, other: &Port) -> bool {
        match (self, other) {
            (Port::Range(a, b), Port::Range(c, d)) => b < c || d < a,
            _ => false,
        }
    }
}

/// What one rule matches: protocol, both address sides, both port sides.
/// An empty side (a malformed body) is an unknown name, so it neither
/// covers nor is disjoint from anything.
#[derive(Debug, Clone)]
struct Match {
    protocol: Option<String>,
    src: Vec<Addr>,
    sports: Vec<Port>,
    dst: Vec<Addr>,
    dports: Vec<Port>,
}

fn addrs(prefixes: &[String], asgs: &[String]) -> Vec<Addr> {
    let mut v: Vec<Addr> = prefixes.iter().map(|p| parse_addr(p)).collect();
    v.extend(asgs.iter().map(|a| Addr::Name(format!("asg:{}", a.to_lowercase()))));
    if v.is_empty() {
        v.push(Addr::Name("?".into()));
    }
    v
}

fn ports(list: &[String]) -> Vec<Port> {
    let mut v: Vec<Port> = list.iter().map(|p| parse_port(p)).collect();
    if v.is_empty() {
        v.push(Port::Unknown("?".into()));
    }
    v
}

fn all_covered<T>(outer: &[T], inner: &[T], covers: impl Fn(&T, &T) -> bool) -> bool {
    inner.iter().all(|i| outer.iter().any(|o| covers(o, i)))
}

fn all_disjoint<T>(a: &[T], b: &[T], disjoint: impl Fn(&T, &T) -> bool) -> bool {
    a.iter().all(|x| b.iter().all(|y| disjoint(x, y)))
}

impl Match {
    fn of(r: &SecurityRule) -> Match {
        let p = r.protocol.trim().to_lowercase();
        Match {
            protocol: if p == "*" || p == "any" { None } else { Some(p) },
            src: addrs(&r.source_prefixes, &r.source_asgs),
            sports: ports(&r.source_ports),
            dst: addrs(&r.destination_prefixes, &r.destination_asgs),
            dports: ports(&r.destination_ports),
        }
    }

    /// Everything `other` matches, `self` matches too.
    fn covers(&self, other: &Match) -> bool {
        let proto = match (&self.protocol, &other.protocol) {
            (None, _) => true,
            (Some(a), Some(b)) => a == b,
            (Some(_), None) => false,
        };
        proto
            && all_covered(&self.src, &other.src, Addr::covers)
            && all_covered(&self.sports, &other.sports, Port::covers)
            && all_covered(&self.dst, &other.dst, Addr::covers)
            && all_covered(&self.dports, &other.dports, Port::covers)
    }

    /// Provably nothing in common.
    fn disjoint(&self, other: &Match) -> bool {
        let proto = matches!((&self.protocol, &other.protocol), (Some(a), Some(b)) if a != b);
        proto
            || all_disjoint(&self.src, &other.src, Addr::disjoint)
            || all_disjoint(&self.sports, &other.sports, Port::disjoint)
            || all_disjoint(&self.dst, &other.dst, Addr::disjoint)
            || all_disjoint(&self.dports, &other.dports, Port::disjoint)
    }
}

// ── Rule order ────────────────────────────────────────────────────────

/// Azure's default rules for one direction, exactly as ARM returns them.
pub fn default_rules(dir: Dir) -> Vec<SecurityRule> {
    let rule = |name: &str, priority: i64, access: &str, src: &str, dst: &str| {
        let v = serde_json::json!({
            "name": name,
            "properties": {
                "priority": priority, "direction": dir.word(), "access": access, "protocol": "*",
                "sourceAddressPrefix": src, "sourcePortRange": "*",
                "destinationAddressPrefix": dst, "destinationPortRange": "*"
            }
        });
        SecurityRule::from_json(&v, true)
    };
    match dir {
        Dir::Inbound => vec![
            rule("AllowVnetInBound", 65000, "Allow", "VirtualNetwork", "VirtualNetwork"),
            rule("AllowAzureLoadBalancerInBound", 65001, "Allow", "AzureLoadBalancer", "*"),
            rule("DenyAllInBound", 65500, "Deny", "*", "*"),
        ],
        Dir::Outbound => vec![
            rule("AllowVnetOutBound", 65000, "Allow", "VirtualNetwork", "VirtualNetwork"),
            rule("AllowInternetOutBound", 65001, "Allow", "*", "Internet"),
            rule("DenyAllOutBound", 65500, "Deny", "*", "*"),
        ],
    }
}

/// One NSG's rules for one direction in evaluation order (priority,
/// lowest first), the default rules appended when the body has none.
pub fn ordered_rules(nsg: &NsgRow, dir: Dir) -> Vec<SecurityRule> {
    let mut rules: Vec<SecurityRule> = nsg.rules.iter().filter(|r| dir.matches(&r.direction)).cloned().collect();
    if !rules.iter().any(|r| r.is_default) {
        rules.extend(default_rules(dir));
    }
    rules.sort_by_key(|r| r.priority.unwrap_or(i64::MAX));
    rules
}

/// For each rule (in evaluation order), the index of the first earlier
/// rule that matches everything it matches: it is never the first match.
pub fn shadowed_by(rules: &[SecurityRule]) -> Vec<Option<usize>> {
    let m: Vec<Match> = rules.iter().map(Match::of).collect();
    (0..rules.len()).map(|i| (0..i).find(|&j| m[j].covers(&m[i]))).collect()
}

/// What an ordered rule list does with the traffic `probe` matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Rule `i` is the first to overlap the traffic and covers all of it.
    Decided(usize),
    /// Rule `i` is the first to overlap it but covers only part: the
    /// verdict depends on the exact flow.
    Depends(usize),
    /// No rule overlaps it (only an NSG without default rules).
    Undecided,
}

pub fn first_decider(rules: &[SecurityRule], probe: &SecurityRule) -> Decision {
    let p = Match::of(probe);
    for (i, r) in rules.iter().enumerate() {
        let m = Match::of(r);
        if m.disjoint(&p) {
            continue;
        }
        return if m.covers(&p) { Decision::Decided(i) } else { Decision::Depends(i) };
    }
    Decision::Undecided
}

fn is_allow(r: &SecurityRule) -> bool {
    r.access.eq_ignore_ascii_case("allow")
}

/// An inbound allow from anywhere on the internet.
fn open_to_internet(r: &SecurityRule, dir: Dir) -> bool {
    dir == Dir::Inbound
        && is_allow(r)
        && r.source_prefixes.iter().any(|s| {
            matches!(s.trim().to_lowercase().as_str(), "*" | "any" | "internet" | "0.0.0.0/0" | "::/0")
        })
}

// ── What applies to a resource ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopKind {
    Subnet,
    Nic,
}

impl HopKind {
    fn word(self) -> &'static str {
        match self {
            HopKind::Subnet => "subnet",
            HopKind::Nic => "NIC",
        }
    }
}

/// One layer of a path: a subnet or a NIC and the NSG on it.
#[derive(Debug, Clone)]
pub struct Hop {
    pub kind: HopKind,
    pub id: String,
    pub name: String,
    /// `None`: no NSG at this layer (it allows everything).
    pub nsg_id: Option<String>,
    /// `false`: the subnet or NIC itself could not be read, so the layer
    /// is unknown (never assumed open).
    pub known: bool,
}

/// A NIC in a subnet, or a subnet on its own (what applies to anything
/// placed in it).
#[derive(Debug, Clone)]
pub struct Path {
    pub nic: Option<Hop>,
    pub subnet: Option<Hop>,
}

impl Path {
    /// The layers in the order traffic meets them.
    fn layers(&self, dir: Dir) -> Vec<&Hop> {
        let (first, second) = match dir {
            Dir::Inbound => (&self.subnet, &self.nic),
            Dir::Outbound => (&self.nic, &self.subnet),
        };
        first.iter().chain(second.iter()).collect()
    }

    fn label(&self) -> String {
        match (&self.nic, &self.subnet) {
            (Some(n), Some(s)) => format!("NIC {} in subnet {}", n.name, s.name),
            (Some(n), None) => format!("NIC {} (no subnet read)", n.name),
            (None, Some(s)) => format!("Subnet {} (rules for anything placed in it)", s.name),
            (None, None) => String::new(),
        }
    }
}

/// What the lens starts from: an NSG, NICs (a VM's, a private
/// endpoint's), or subnets.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Seed {
    pub nsg: Option<String>,
    pub nics: Vec<String>,
    pub subnets: Vec<String>,
}

impl Seed {
    pub fn is_empty(&self) -> bool {
        self.nsg.is_none() && self.nics.is_empty() && self.subnets.is_empty()
    }

    /// Any id to pick the tenant pipeline by.
    pub fn any_id(&self) -> Option<&str> {
        self.nsg
            .as_deref()
            .or_else(|| self.nics.first().map(String::as_str))
            .or_else(|| self.subnets.first().map(String::as_str))
    }
}

/// Rows already loaded (the warm list caches, the on-screen list), keyed
/// by lowercased ARM id. What is here costs no call.
#[derive(Debug, Clone, Default)]
pub struct Known {
    pub nics: HashMap<String, NicRow>,
    pub subnets: HashMap<String, SubnetRow>,
    pub nsgs: HashMap<String, NsgRow>,
}

impl Known {
    pub fn add_nic(&mut self, r: &NicRow) {
        self.nics.insert(r.base.id.to_lowercase(), r.clone());
    }
    pub fn add_subnet(&mut self, r: &SubnetRow) {
        self.subnets.insert(r.id.to_lowercase(), r.clone());
    }
    pub fn add_nsg(&mut self, r: &NsgRow) {
        self.nsgs.insert(r.base.id.to_lowercase(), r.clone());
    }
}

/// A context line above the rules; `id` is where `⏎` goes.
#[derive(Debug, Clone, PartialEq)]
pub struct Note {
    pub text: String,
    pub id: Option<String>,
}

/// Everything the lens renders, resolved from a [`Seed`].
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub paths: Vec<Path>,
    /// The NSG entry point: the NSG itself.
    pub nsg_entry: Option<String>,
    /// Lowercased id → NSG.
    pub nsgs: HashMap<String, NsgRow>,
    pub notes: Vec<Note>,
    /// What could not be read (a warning line each, never an error).
    pub warnings: Vec<String>,
}

impl Resolved {
    fn nsg(&self, id: &str) -> Option<&NsgRow> {
        self.nsgs.get(&id.to_lowercase())
    }
}

/// `…/networkInterfaces/{nic}` from one of its IP configuration ids.
fn nic_of_ip_configuration(id: &str) -> Option<String> {
    let lower = id.to_lowercase();
    lower.find("/networkinterfaces/")?;
    let at = lower.find("/ipconfigurations/")?;
    Some(id[..at].to_string())
}

/// `…/virtualNetworks/{vnet}` from a subnet id.
fn vnet_of_subnet(id: &str) -> Option<String> {
    let at = id.to_lowercase().rfind("/subnets/")?;
    Some(id[..at].to_string())
}

async fn read_nic<F, Fut>(id: &str, known: &Known, fetch: &F, warnings: &mut Vec<String>) -> Option<NicRow>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    if let Some(n) = known.nics.get(&id.to_lowercase()) {
        return Some(n.clone());
    }
    match fetch(id.to_string()).await {
        Ok(v) => NicRow::from_json(&v, None).or_else(|| {
            warnings.push(format!("NIC {}: unreadable body", name_of_id(id)));
            None
        }),
        Err(e) => {
            warnings.push(format!("NIC {}: {}", name_of_id(id), e));
            None
        }
    }
}

/// A subnet from the warm lists, else from one GET of its VNet (the
/// subnets arrive embedded; every sibling is remembered too).
async fn read_subnet<F, Fut>(id: &str, known: &mut Known, fetch: &F, warnings: &mut Vec<String>) -> Option<SubnetRow>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    if let Some(s) = known.subnets.get(&id.to_lowercase()) {
        return Some(s.clone());
    }
    let vnet = vnet_of_subnet(id)?;
    match fetch(vnet).await {
        Ok(v) => {
            if let Some(vnet) = VnetRow::from_json(&v, None) {
                for s in &vnet.subnets {
                    known.add_subnet(s);
                }
            }
            let found = known.subnets.get(&id.to_lowercase()).cloned();
            if found.is_none() {
                warnings.push(format!("Subnet {}: not in its VNet", name_of_id(id)));
            }
            found
        }
        Err(e) => {
            warnings.push(format!("Subnet {}: {}", name_of_id(id), e));
            None
        }
    }
}

fn subnet_hop(id: &str, row: Option<&SubnetRow>) -> Hop {
    Hop {
        kind: HopKind::Subnet,
        id: row.map(|s| s.id.clone()).unwrap_or_else(|| id.to_string()),
        name: row
            .map(|s| format!("{}/{}", s.vnet_name, s.name))
            .unwrap_or_else(|| name_of_id(id).to_string()),
        nsg_id: row.and_then(|s| s.nsg_id.clone()),
        known: row.is_some(),
    }
}

/// Resolve what applies, reading [`Known`] first and `fetch` (one ARM GET
/// by path) for the rest. Every failure is a warning; the lens renders
/// whatever was read.
pub async fn resolve<F, Fut>(seed: Seed, mut known: Known, fetch: F) -> Resolved
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let mut out = Resolved {
        nsg_entry: seed.nsg.clone(),
        ..Default::default()
    };
    let mut subnets_seen: Vec<SubnetRow> = Vec::new();

    for nic_id in &seed.nics {
        let Some(nic) = read_nic(nic_id, &known, &fetch, &mut out.warnings).await else {
            continue;
        };
        let hop = Hop {
            kind: HopKind::Nic,
            id: nic.base.id.clone(),
            name: nic.base.name.clone(),
            nsg_id: nic.nsg_id.clone(),
            known: true,
        };
        let mut subnet_ids: Vec<String> = Vec::new();
        for c in &nic.ip_configs {
            if let Some(s) = &c.subnet_id {
                if !subnet_ids.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                    subnet_ids.push(s.clone());
                }
            }
        }
        if subnet_ids.is_empty() {
            out.paths.push(Path { nic: Some(hop.clone()), subnet: None });
        }
        for s in subnet_ids {
            let row = read_subnet(&s, &mut known, &fetch, &mut out.warnings).await;
            out.paths.push(Path { nic: Some(hop.clone()), subnet: Some(subnet_hop(&s, row.as_ref())) });
            subnets_seen.extend(row);
        }
    }

    for s in &seed.subnets {
        let row = read_subnet(s, &mut known, &fetch, &mut out.warnings).await;
        out.paths.push(Path { nic: None, subnet: Some(subnet_hop(s, row.as_ref())) });
        if let Some(row) = row {
            out.notes.extend(nic_nsg_notes(&row, &known));
            subnets_seen.push(row);
        }
    }

    // Context the rules alone do not show.
    let mut noted: Vec<String> = Vec::new();
    for s in &subnets_seen {
        if noted.contains(&s.id.to_lowercase()) {
            continue;
        }
        noted.push(s.id.to_lowercase());
        let name = format!("{}/{}", s.vnet_name, s.name);
        if !s.delegations.is_empty() {
            out.notes.push(Note {
                text: format!("Subnet {} is delegated to {}", name, s.delegations.join(", ")),
                id: Some(s.id.clone()),
            });
        }
        if let Some(rt) = &s.route_table_id {
            out.notes.push(Note {
                text: format!(
                    "Route table {} on subnet {}: its routes (a firewall or NVA next hop) are not evaluated",
                    name_of_id(rt),
                    name
                ),
                id: Some(rt.clone()),
            });
        }
    }

    // Every NSG on the path, once.
    let mut nsg_ids: Vec<String> = out.nsg_entry.iter().cloned().collect();
    for p in &out.paths {
        for h in p.nic.iter().chain(p.subnet.iter()) {
            if let Some(n) = &h.nsg_id {
                if !nsg_ids.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                    nsg_ids.push(n.clone());
                }
            }
        }
    }
    for id in nsg_ids {
        let row = match known.nsgs.get(&id.to_lowercase()) {
            Some(r) => Some(r.clone()),
            None => match fetch(id.clone()).await {
                Ok(v) => NsgRow::from_json(&v, None),
                Err(e) => {
                    out.warnings.push(format!("NSG {}: {}", name_of_id(&id), e));
                    continue;
                }
            },
        };
        match row {
            Some(r) => {
                out.nsgs.insert(id.to_lowercase(), r);
            }
            None => out.warnings.push(format!("NSG {}: unreadable body", name_of_id(&id))),
        }
    }
    out
}

/// For a subnet entry: the NICs in it (from its IP configurations) that
/// carry their own NSG, which applies after the subnet's inbound. Only the
/// warm NIC and NSG lists are read; no call per NIC.
fn nic_nsg_notes(subnet: &SubnetRow, known: &Known) -> Vec<Note> {
    let mut nics: Vec<String> = Vec::new();
    for c in &subnet.ip_configuration_ids {
        if let Some(n) = nic_of_ip_configuration(c) {
            if !nics.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                nics.push(n);
            }
        }
    }
    if nics.is_empty() {
        return Vec::new();
    }
    let mut by_nsg: Vec<(String, usize)> = Vec::new();
    let mut unknown = 0;
    for nic in &nics {
        let lower = nic.to_lowercase();
        let nsg = match known.nics.get(&lower) {
            Some(row) => Some(row.nsg_id.clone()),
            None => known
                .nsgs
                .values()
                .find(|g| g.nic_ids.iter().any(|n| n.eq_ignore_ascii_case(nic)))
                .map(|g| Some(g.base.id.clone())),
        };
        match nsg {
            Some(Some(id)) => match by_nsg.iter_mut().find(|(x, _)| x.eq_ignore_ascii_case(&id)) {
                Some((_, n)) => *n += 1,
                None => by_nsg.push((id, 1)),
            },
            Some(None) => {}
            None => unknown += 1,
        }
    }
    let mut notes = vec![Note {
        text: format!(
            "{} NIC{} in this subnet; a NIC's own NSG applies after the subnet's inbound (open the NIC or VM for its path)",
            nics.len(),
            if nics.len() == 1 { "" } else { "s" }
        ),
        id: None,
    }];
    for (id, n) in by_nsg {
        notes.push(Note {
            text: format!("NIC-level NSG {} on {} NIC{} here", name_of_id(&id), n, if n == 1 { "" } else { "s" }),
            id: Some(id),
        });
    }
    if unknown > 0 {
        notes.push(Note {
            text: format!("{} NIC{} not in the warm NIC list: their NSGs are not shown", unknown, if unknown == 1 { "" } else { "s" }),
            id: None,
        });
    }
    notes
}

// ── Lines ─────────────────────────────────────────────────────────────

/// What the other layer does with an allow rule's traffic.
#[derive(Debug, Clone, PartialEq)]
pub enum Cross {
    Allowed(String),
    Blocked(String),
    Depends(String),
    Unknown(String),
}

impl Cross {
    pub fn text(&self) -> String {
        match self {
            Cross::Allowed(s) => format!("✓ {}", s),
            Cross::Blocked(s) => format!("✗ {}", s),
            Cross::Depends(s) => format!("~ {}", s),
            Cross::Unknown(s) => format!("? {}", s),
        }
    }
}

/// One rule as the lens shows it.
#[derive(Debug, Clone)]
pub struct RuleView {
    pub dir: Dir,
    pub priority: String,
    pub name: String,
    pub allow: bool,
    pub protocol: String,
    /// `source[:ports] → destination:ports`.
    pub flow: String,
    pub nsg_name: String,
    pub is_default: bool,
    /// `{priority} {name}` of the earlier rule that covers this one.
    pub shadowed_by: Option<String>,
    pub cross: Option<Cross>,
    pub open_to_internet: bool,
}

impl RuleView {
    fn of(r: &SecurityRule, dir: Dir, nsg_name: &str) -> RuleView {
        let sport = if r.source_port == "*" { String::new() } else { format!(":{}", r.source_port) };
        RuleView {
            dir,
            priority: r.priority.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            name: r.name.clone(),
            allow: is_allow(r),
            protocol: if r.protocol == "*" { "any".into() } else { r.protocol.clone() },
            flow: format!("{}{} → {}:{}", r.source, sport, r.destination, r.destination_port),
            nsg_name: nsg_name.to_string(),
            is_default: r.is_default,
            shadowed_by: None,
            cross: None,
            open_to_internet: open_to_internet(r, dir),
        }
    }

    /// The annotation after the rule: shadowing first (it decides), else
    /// the other layer's verdict.
    pub fn annotation(&self) -> Option<String> {
        if let Some(s) = &self.shadowed_by {
            return Some(format!("⊘ shadowed by {}", s));
        }
        self.cross.as_ref().map(Cross::text)
    }

    /// Plain text for copy and the editor view.
    pub fn text(&self) -> String {
        let mut s = format!(
            "{} {:>5} {:<5} {:<4} {}  {} · {}{}",
            if self.dir == Dir::Inbound { "IN " } else { "OUT" },
            self.priority,
            if self.allow { "allow" } else { "deny" },
            self.protocol,
            self.flow,
            self.name,
            self.nsg_name,
            if self.is_default { " (default)" } else { "" }
        );
        if let Some(a) = self.annotation() {
            s.push_str("  ");
            s.push_str(&a);
        }
        s
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    /// A direction heading.
    Section,
    /// A path, a layer, or the NSG entry's own heading.
    Layer,
    Rule,
    Note,
    Warning,
    Blank,
}

#[derive(Debug, Clone)]
pub struct LensLine {
    pub kind: LineKind,
    pub text: String,
    /// Where `⏎` goes: a rule's NSG, a layer's NSG or subnet / NIC.
    pub jump: Option<String>,
    pub rule: Option<RuleView>,
}

impl LensLine {
    fn plain(kind: LineKind, text: impl Into<String>, jump: Option<String>) -> LensLine {
        LensLine { kind, text: text.into(), jump, rule: None }
    }

    /// The text `y` copies.
    pub fn copy_text(&self) -> String {
        match &self.rule {
            Some(r) => r.text(),
            None => self.text.trim().to_string(),
        }
    }
}

const CIRCLED: [&str; 2] = ["①", "②"];

fn layer_label(h: &Hop, resolved: &Resolved) -> String {
    let nsg = match &h.nsg_id {
        Some(id) => format!("NSG {}", resolved.nsg(id).map(|n| n.base.name.clone()).unwrap_or_else(|| name_of_id(id).to_string())),
        None if h.known => "no NSG".into(),
        None => "NSG unknown".into(),
    };
    format!("{} {} · {}", h.kind.word(), h.name, nsg)
}

/// The other layer's verdict on an allow rule's traffic.
fn cross_check(rule: &SecurityRule, other: &Hop, dir: Dir, resolved: &Resolved) -> Option<Cross> {
    let layer = other.kind.word();
    if !other.known {
        return Some(Cross::Unknown(format!("{} not read", layer)));
    }
    let id = other.nsg_id.as_ref()?;
    let Some(nsg) = resolved.nsg(id) else {
        return Some(Cross::Unknown(format!("{} NSG not read", layer)));
    };
    let rules = ordered_rules(nsg, dir);
    let name = |i: usize| format!("{} {}", rules[i].priority.map(|p| p.to_string()).unwrap_or_default(), rules[i].name);
    Some(match first_decider(&rules, rule) {
        Decision::Decided(i) if is_allow(&rules[i]) => Cross::Allowed(format!("{} NSG allows ({})", layer, name(i))),
        Decision::Decided(i) => Cross::Blocked(format!("blocked by {} NSG ({})", layer, name(i))),
        Decision::Depends(i) => Cross::Depends(format!("{} NSG: depends on the flow ({} overlaps first)", layer, name(i))),
        Decision::Undecided => Cross::Unknown(format!("no {} NSG rule matches", layer)),
    })
}

/// One NSG's rules for a direction as lens lines, shadowing marked and,
/// when `other` is the path's other layer, each live allow rule checked
/// against it.
fn rule_lines(nsg: &NsgRow, dir: Dir, other: Option<&Hop>, resolved: &Resolved) -> Vec<LensLine> {
    let rules = ordered_rules(nsg, dir);
    let shadow = shadowed_by(&rules);
    rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut view = RuleView::of(r, dir, &nsg.base.name);
            view.shadowed_by = shadow[i].map(|j| {
                format!("{} {}", rules[j].priority.map(|p| p.to_string()).unwrap_or_default(), rules[j].name)
            });
            if view.allow && view.shadowed_by.is_none() {
                view.cross = other.and_then(|o| cross_check(r, o, dir, resolved));
            }
            LensLine {
                kind: LineKind::Rule,
                text: view.text(),
                jump: Some(nsg.base.id.clone()),
                rule: Some(view),
            }
        })
        .collect()
}

/// Every line the lens shows, for the directions in `dirs`.
pub fn build_lines(resolved: &Resolved, dirs: &[Dir]) -> Vec<LensLine> {
    let mut lines: Vec<LensLine> = Vec::new();
    for w in &resolved.warnings {
        lines.push(LensLine::plain(LineKind::Warning, format!("! {}", w), None));
    }
    for n in &resolved.notes {
        lines.push(LensLine::plain(LineKind::Note, format!("· {}", n.text), n.id.clone()));
    }

    if let Some(id) = &resolved.nsg_entry {
        let Some(nsg) = resolved.nsg(id) else {
            lines.push(LensLine::plain(LineKind::Warning, format!("! NSG {} could not be read", name_of_id(id)), Some(id.clone())));
            return lines;
        };
        if !lines.is_empty() {
            lines.push(LensLine::plain(LineKind::Blank, "", None));
        }
        lines.push(LensLine::plain(LineKind::Layer, format!("NSG {}", nsg.base.name), Some(nsg.base.id.clone())));
        if nsg.subnet_ids.is_empty() && nsg.nic_ids.is_empty() {
            lines.push(LensLine::plain(LineKind::Note, "  associated with no subnet or NIC: these rules guard nothing", None));
        }
        for s in &nsg.subnet_ids {
            lines.push(LensLine::plain(LineKind::Note, format!("  guards subnet {}", subnet_display(s)), Some(s.clone())));
        }
        for n in &nsg.nic_ids {
            lines.push(LensLine::plain(LineKind::Note, format!("  guards NIC {}", name_of_id(n)), Some(n.clone())));
        }
        for &dir in dirs {
            lines.push(LensLine::plain(LineKind::Blank, "", None));
            lines.push(LensLine::plain(
                LineKind::Section,
                format!("{} {} · priority order, first match wins", arrow(dir), dir.word()),
                None,
            ));
            lines.extend(rule_lines(nsg, dir, None, resolved));
        }
        return lines;
    }

    // Nothing read (every NIC failed): the warnings say why.
    if resolved.paths.is_empty() {
        return lines;
    }
    let two_layers = resolved.paths.iter().any(|p| p.nic.is_some() && p.subnet.is_some());
    for &dir in dirs {
        if !lines.is_empty() {
            lines.push(LensLine::plain(LineKind::Blank, "", None));
        }
        let order = match (dir, two_layers) {
            (Dir::Inbound, true) => " · subnet NSG, then NIC NSG: both must allow",
            (Dir::Outbound, true) => " · NIC NSG, then subnet NSG: both must allow",
            _ => " · priority order, first match wins",
        };
        lines.push(LensLine::plain(LineKind::Section, format!("{} {}{}", arrow(dir), dir.word(), order), None));
        for p in &resolved.paths {
            lines.push(LensLine::plain(
                LineKind::Layer,
                p.label(),
                p.nic.as_ref().or(p.subnet.as_ref()).map(|h| h.id.clone()),
            ));
            let layers = p.layers(dir);
            for (i, hop) in layers.iter().enumerate() {
                let other = layers.get(1 - i.min(1)).filter(|_| layers.len() == 2).copied();
                lines.push(LensLine::plain(
                    LineKind::Layer,
                    format!("  {} {}", CIRCLED[i.min(1)], layer_label(hop, resolved)),
                    Some(hop.nsg_id.clone().unwrap_or_else(|| hop.id.clone())),
                ));
                if !hop.known {
                    lines.push(LensLine::plain(
                        LineKind::Warning,
                        format!("    ! the {} could not be read: this layer is unknown", hop.kind.word()),
                        Some(hop.id.clone()),
                    ));
                    continue;
                }
                let Some(nsg_id) = &hop.nsg_id else {
                    lines.push(LensLine::plain(LineKind::Note, "    no NSG: this layer allows everything", Some(hop.id.clone())));
                    continue;
                };
                match resolved.nsg(nsg_id) {
                    Some(nsg) => lines.extend(rule_lines(nsg, dir, other, resolved)),
                    None => lines.push(LensLine::plain(
                        LineKind::Warning,
                        format!("    ! NSG {} could not be read: this layer is unknown", name_of_id(nsg_id)),
                        Some(nsg_id.clone()),
                    )),
                }
            }
        }
    }
    lines
}

fn arrow(dir: Dir) -> &'static str {
    match dir {
        Dir::Inbound => "↓",
        Dir::Outbound => "↑",
    }
}

/// `vnet/subnet` from a subnet id.
fn subnet_display(id: &str) -> String {
    match vnet_of_subnet(id) {
        Some(v) => format!("{}/{}", name_of_id(&v), name_of_id(id)),
        None => name_of_id(id).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-net/providers/Microsoft.Network";

    #[allow(clippy::too_many_arguments)]
    fn rule_json(name: &str, priority: i64, direction: &str, access: &str, protocol: &str, src: &str, dst: &str, dport: &str) -> Value {
        json!({"name": name, "properties": {
            "priority": priority, "direction": direction, "access": access, "protocol": protocol,
            "sourceAddressPrefix": src, "sourcePortRange": "*",
            "destinationAddressPrefix": dst, "destinationPortRange": dport}})
    }

    fn rule(name: &str, priority: i64, access: &str, protocol: &str, src: &str, dst: &str, dport: &str) -> SecurityRule {
        SecurityRule::from_json(&rule_json(name, priority, "Inbound", access, protocol, src, dst, dport), false)
    }

    /// An NSG body; `defaults` adds ARM's `defaultSecurityRules`.
    fn nsg(name: &str, rules: Vec<Value>, defaults: bool) -> NsgRow {
        let mut d = Vec::new();
        if defaults {
            for dir in [Dir::Inbound, Dir::Outbound] {
                for r in default_rules(dir) {
                    d.push(rule_json(&r.name, r.priority.unwrap(), dir.word(), &r.access, "*", &r.source, &r.destination, "*"));
                }
            }
        }
        NsgRow::from_json(
            &json!({"id": format!("{}/networkSecurityGroups/{}", RG, name), "name": name, "location": "westeurope",
                    "properties": {"securityRules": rules, "defaultSecurityRules": d}}),
            None,
        )
        .unwrap()
    }

    fn names(rules: &[SecurityRule]) -> Vec<String> {
        rules.iter().map(|r| r.name.clone()).collect()
    }

    #[test]
    fn addresses_compare_cidrs_numerically_and_names_literally() {
        let a = parse_addr("10.0.0.0/16");
        assert!(a.covers(&parse_addr("10.0.4.0/24")));
        assert!(a.covers(&parse_addr("10.0.4.7")));
        assert!(!a.covers(&parse_addr("10.1.0.0/24")));
        assert!(!parse_addr("10.0.4.0/24").covers(&a));
        assert!(a.disjoint(&parse_addr("10.1.0.0/16")));
        assert!(!a.disjoint(&parse_addr("10.0.128.0/17")));
        // A host bit set in the prefix is masked, as Azure does.
        assert_eq!(parse_addr("10.0.0.5/16"), a);
        assert!(parse_addr("0.0.0.0/0").covers(&a));
        assert!(parse_addr("*").covers(&parse_addr("VirtualNetwork")));
        // v4 and v6 never overlap; v6 compares numerically too.
        assert!(parse_addr("::/0").disjoint(&a));
        assert!(parse_addr("fd00::/8").covers(&parse_addr("fd12:3456::/64")));
        // Tags: only themselves or `*`; never provably disjoint.
        assert!(parse_addr("Internet").covers(&parse_addr("internet")));
        assert!(!parse_addr("0.0.0.0/0").covers(&parse_addr("Internet")));
        assert!(!parse_addr("VirtualNetwork").disjoint(&a));
        assert!(!parse_addr("Storage").disjoint(&parse_addr("Sql")));
    }

    #[test]
    fn ports_and_protocols() {
        assert!(parse_port("*").covers(&parse_port("443")));
        assert!(parse_port("1000-2000").covers(&parse_port("1500")));
        assert!(!parse_port("443").covers(&parse_port("440-450")));
        assert!(parse_port("80").disjoint(&parse_port("443")));
        assert!(!parse_port("80-90").disjoint(&parse_port("90-100")));
        let tcp = Match::of(&rule("a", 100, "Allow", "Tcp", "*", "*", "443"));
        let udp = Match::of(&rule("b", 110, "Allow", "Udp", "*", "*", "443"));
        let any = Match::of(&rule("c", 120, "Allow", "*", "*", "*", "443"));
        assert!(tcp.disjoint(&udp));
        assert!(any.covers(&tcp));
        assert!(!tcp.covers(&any));
    }

    #[test]
    fn rules_run_by_priority_with_the_defaults_appended_once() {
        let g = nsg("web", vec![
            rule_json("late", 300, "Inbound", "Allow", "Tcp", "*", "*", "22"),
            rule_json("early", 100, "Inbound", "Allow", "Tcp", "*", "*", "443"),
            rule_json("out", 100, "Outbound", "Deny", "*", "*", "Internet", "*"),
        ], true);
        assert_eq!(
            names(&ordered_rules(&g, Dir::Inbound)),
            ["early", "late", "AllowVnetInBound", "AllowAzureLoadBalancerInBound", "DenyAllInBound"]
        );
        assert_eq!(
            names(&ordered_rules(&g, Dir::Outbound)),
            ["out", "AllowVnetOutBound", "AllowInternetOutBound", "DenyAllOutBound"]
        );
        // A body without defaultSecurityRules gets Azure's three, labelled default.
        let bare = nsg("bare", vec![], false);
        let r = ordered_rules(&bare, Dir::Outbound);
        assert_eq!(names(&r), ["AllowVnetOutBound", "AllowInternetOutBound", "DenyAllOutBound"]);
        assert!(r.iter().all(|r| r.is_default));
    }

    #[test]
    fn a_rule_covered_by_an_earlier_one_is_shadowed() {
        let rules = vec![
            rule("deny-ssh-anywhere", 100, "Deny", "Tcp", "*", "*", "22"),
            rule("allow-ssh-bastion", 200, "Allow", "Tcp", "10.0.1.0/24", "*", "22"),
            rule("allow-web", 300, "Allow", "Tcp", "*", "*", "80-443"),
            rule("allow-https", 310, "Allow", "Tcp", "Internet", "*", "443"),
            rule("allow-https-udp", 320, "Allow", "Udp", "*", "*", "443"),
            rule("deny-all", 4096, "Deny", "*", "*", "*", "*"),
            rule("allow-late", 4097, "Allow", "Tcp", "*", "*", "8080"),
        ];
        let s = shadowed_by(&rules);
        assert_eq!(s, vec![None, Some(0), None, Some(2), None, None, Some(5)]);
    }

    #[test]
    fn the_first_overlapping_rule_decides_only_when_it_covers() {
        let rules = vec![
            rule("allow-ssh-bastion", 100, "Allow", "Tcp", "10.0.1.0/24", "*", "22"),
            rule("deny-from-hub", 200, "Deny", "*", "10.1.0.0/16", "*", "*"),
            rule("allow-vnet", 300, "Allow", "*", "VirtualNetwork", "*", "*"),
            rule("deny-all", 4096, "Deny", "*", "*", "*", "*"),
        ];
        // Disjoint from rule 0 (port), covered by rule 1.
        assert_eq!(first_decider(&rules, &rule("p", 1, "Allow", "Tcp", "10.1.2.0/24", "*", "443")), Decision::Decided(1));
        // Inside rule 0 entirely.
        assert_eq!(first_decider(&rules, &rule("p", 1, "Allow", "Tcp", "10.0.1.4", "*", "22")), Decision::Decided(0));
        // Overlaps rule 0 only in part (a wider source): depends on the flow.
        assert_eq!(first_decider(&rules, &rule("p", 1, "Allow", "Tcp", "10.0.0.0/16", "*", "22")), Decision::Depends(0));
        // A service tag is never provably disjoint from the hub CIDR rule.
        assert_eq!(first_decider(&rules, &rule("p", 1, "Allow", "Tcp", "AzureLoadBalancer", "*", "443")), Decision::Depends(1));
        // Disjoint from 0 (protocol), but a tag may overlap the hub CIDR.
        assert_eq!(first_decider(&rules, &rule("p", 1, "Allow", "Udp", "VirtualNetwork", "*", "53")), Decision::Depends(1));
        assert_eq!(first_decider(&[], &rules[0]), Decision::Undecided);
    }

    #[test]
    fn asgs_are_named_not_expanded() {
        let v = json!({"name": "web-from-app", "properties": {
            "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
            "sourceApplicationSecurityGroups": [{"id": format!("{}/applicationSecurityGroups/app-asg", RG)}],
            "sourcePortRange": "*",
            "destinationApplicationSecurityGroups": [{"id": format!("{}/applicationSecurityGroups/web-asg", RG)}],
            "destinationPortRanges": ["80", "443"]}});
        let r = SecurityRule::from_json(&v, false);
        assert_eq!(r.source, "asg:app-asg");
        assert_eq!(r.destination, "asg:web-asg");
        let same = SecurityRule::from_json(&v, false);
        assert!(Match::of(&r).covers(&Match::of(&same)));
        // An ASG is not covered by a CIDR, and not provably outside one.
        let cidr = rule("c", 90, "Deny", "Tcp", "10.0.0.0/8", "*", "*");
        assert!(!Match::of(&cidr).covers(&Match::of(&r)));
        assert!(!Match::of(&cidr).disjoint(&Match::of(&r)));
    }

    // ── Resolution + lines ────────────────────────────────────────────

    fn vnet_body() -> Value {
        let vnet = format!("{}/virtualNetworks/vnet-app", RG);
        json!({"id": vnet, "name": "vnet-app", "location": "westeurope", "properties": {
            "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
            "subnets": [
                {"id": format!("{}/subnets/aca-infra", vnet), "name": "aca-infra", "properties": {
                    "addressPrefix": "10.0.0.0/23",
                    "networkSecurityGroup": {"id": format!("{}/networkSecurityGroups/aca-nsg", RG)},
                    "routeTable": {"id": format!("{}/routeTables/to-firewall", RG)},
                    "delegations": [{"name": "d", "properties": {"serviceName": "Microsoft.App/environments"}}],
                    "ipConfigurations": [
                        {"id": format!("{}/networkInterfaces/vm-1-nic/ipConfigurations/ipconfig1", RG)},
                        {"id": format!("{}/loadBalancers/kubernetes-internal/frontendIPConfigurations/x", RG)}
                    ]}},
                {"id": format!("{}/subnets/vms", vnet), "name": "vms", "properties": {
                    "addressPrefix": "10.0.4.0/24",
                    "networkSecurityGroup": {"id": format!("{}/networkSecurityGroups/subnet-nsg", RG)}}}
            ]}})
    }

    fn nic_body(nsg: Option<&str>) -> Value {
        let mut props = json!({"ipConfigurations": [{"name": "ipconfig1", "properties": {
            "privateIPAddress": "10.0.4.4",
            "subnet": {"id": format!("{}/virtualNetworks/vnet-app/subnets/vms", RG)}}}]});
        if let Some(n) = nsg {
            props["networkSecurityGroup"] = json!({"id": format!("{}/networkSecurityGroups/{}", RG, n)});
        }
        json!({"id": format!("{}/networkInterfaces/vm-1-nic", RG), "name": "vm-1-nic", "location": "westeurope", "properties": props})
    }

    fn nsg_body(name: &str, rules: Vec<Value>) -> Value {
        json!({"id": format!("{}/networkSecurityGroups/{}", RG, name), "name": name, "location": "westeurope",
               "properties": {"securityRules": rules,
                              "subnets": [{"id": format!("{}/virtualNetworks/vnet-app/subnets/vms", RG)}]}})
    }

    /// A fake ARM: GET by path from a fixed table, everything else 404.
    fn arm(bodies: Vec<Value>) -> impl Fn(String) -> std::future::Ready<Result<Value, String>> {
        move |path: String| {
            let hit = bodies.iter().find(|b| b["id"].as_str().is_some_and(|id| id.eq_ignore_ascii_case(&path)));
            std::future::ready(hit.cloned().ok_or_else(|| format!("404 {}", path)))
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    fn rule_line<'a>(lines: &'a [LensLine], name: &str, dir: Dir) -> &'a RuleView {
        lines
            .iter()
            .filter_map(|l| l.rule.as_ref())
            .find(|r| r.name == name && r.dir == dir)
            .unwrap_or_else(|| panic!("no rule {}", name))
    }

    #[test]
    fn a_nic_path_runs_the_subnet_nsg_then_the_nic_nsg_inbound() {
        let bodies = vec![
            nic_body(Some("nic-nsg")),
            vnet_body(),
            nsg_body("subnet-nsg", vec![
                rule_json("allow-https", 100, "Inbound", "Allow", "Tcp", "Internet", "*", "443"),
                rule_json("allow-ssh-bastion", 110, "Inbound", "Allow", "Tcp", "10.0.1.0/24", "*", "22"),
            ]),
            nsg_body("nic-nsg", vec![
                rule_json("deny-ssh", 100, "Inbound", "Deny", "Tcp", "*", "*", "22"),
                rule_json("allow-https", 200, "Inbound", "Allow", "Tcp", "*", "*", "443"),
                rule_json("allow-rdp", 300, "Inbound", "Allow", "Tcp", "10.0.0.0/16", "*", "3389"),
            ]),
        ];
        let seed = Seed { nics: vec![format!("{}/networkInterfaces/vm-1-nic", RG)], ..Default::default() };
        let r = block_on(resolve(seed, Known::default(), arm(bodies)));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.paths.len(), 1);
        let lines = build_lines(&r, &[Dir::Inbound, Dir::Outbound]);
        let layers: Vec<&str> = lines.iter().filter(|l| l.kind == LineKind::Layer).map(|l| l.text.trim()).collect();
        assert_eq!(layers[0], "NIC vm-1-nic in subnet vnet-app/vms");
        assert_eq!(layers[1], "① subnet vnet-app/vms · NSG subnet-nsg");
        assert_eq!(layers[2], "② NIC vm-1-nic · NSG nic-nsg");
        // Outbound flips the order.
        assert_eq!(layers[4], "① NIC vm-1-nic · NSG nic-nsg");
        assert!(lines.iter().any(|l| l.kind == LineKind::Section && l.text.contains("subnet NSG, then NIC NSG")));

        // Subnet allows SSH from the bastion subnet; the NIC denies all SSH first.
        let ssh = rule_line(&lines, "allow-ssh-bastion", Dir::Inbound);
        assert_eq!(ssh.cross, Some(Cross::Blocked("blocked by NIC NSG (100 deny-ssh)".into())));
        // HTTPS from Internet passes the NIC's catch-all 443 allow.
        let https = lines.iter().filter_map(|l| l.rule.as_ref()).find(|r| r.name == "allow-https" && r.nsg_name == "subnet-nsg").unwrap();
        assert_eq!(https.cross, Some(Cross::Allowed("NIC NSG allows (200 allow-https)".into())));
        assert!(https.open_to_internet);
        // RDP from the VNet's /16 meets the subnet's bastion rule? No: port
        // 3389 is disjoint from it, so the subnet's AllowVnetInBound decides
        // by name only… which a CIDR is not covered by: depends.
        let rdp = rule_line(&lines, "allow-rdp", Dir::Inbound);
        assert!(matches!(rdp.cross, Some(Cross::Depends(_))), "{:?}", rdp.cross);
        // The NIC's own SSH deny needs no cross check; its jump is the NSG.
        let deny = lines.iter().find(|l| l.rule.as_ref().is_some_and(|r| r.name == "deny-ssh")).unwrap();
        assert!(deny.rule.as_ref().unwrap().cross.is_none());
        assert!(deny.jump.as_deref().unwrap().ends_with("/networkSecurityGroups/nic-nsg"));
        // Default rules are present and labelled.
        let d = rule_line(&lines, "DenyAllInBound", Dir::Inbound);
        assert!(d.is_default && d.text().contains("(default)"));
    }

    #[test]
    fn a_layer_without_an_nsg_allows_and_an_unread_one_is_unknown() {
        // The NIC has no NSG; the subnet's NSG is missing from ARM.
        let bodies = vec![nic_body(None), vnet_body()];
        let seed = Seed { nics: vec![format!("{}/networkInterfaces/vm-1-nic", RG)], ..Default::default() };
        let r = block_on(resolve(seed, Known::default(), arm(bodies)));
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].starts_with("NSG subnet-nsg: 404"));
        let lines = build_lines(&r, &[Dir::Inbound]);
        assert!(lines[0].kind == LineKind::Warning);
        assert!(lines.iter().any(|l| l.kind == LineKind::Warning && l.text.contains("NSG subnet-nsg could not be read")));
        assert!(lines.iter().any(|l| l.kind == LineKind::Note && l.text.contains("no NSG: this layer allows everything")));
        assert!(lines.iter().all(|l| l.rule.is_none()));
    }

    #[test]
    fn a_subnet_entry_reads_the_vnet_once_and_notes_what_rules_miss() {
        let aca = format!("{}/virtualNetworks/vnet-app/subnets/aca-infra", RG);
        let mut known = Known::default();
        // The NIC in the subnet is warm and carries its own NSG.
        let mut nic = NicRow::from_json(&nic_body(Some("nic-nsg")), None).unwrap();
        nic.ip_configs[0].subnet_id = Some(aca.clone());
        known.add_nic(&nic);
        let aca_nsg = nsg_body("aca-nsg", vec![
            rule_json("allow-pp-subnet", 100, "Inbound", "Allow", "Tcp", "10.20.0.0/24", "*", "443"),
            rule_json("deny-internet", 200, "Inbound", "Deny", "*", "Internet", "*", "*"),
        ]);
        let seed = Seed { subnets: vec![aca.to_uppercase()], ..Default::default() };
        let r = block_on(resolve(seed, known, arm(vec![vnet_body(), aca_nsg])));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let notes: Vec<&str> = r.notes.iter().map(|n| n.text.as_str()).collect();
        assert!(notes[0].starts_with("1 NIC in this subnet"));
        assert_eq!(notes[1], "NIC-level NSG nic-nsg on 1 NIC here");
        assert!(notes.contains(&"Subnet vnet-app/aca-infra is delegated to Microsoft.App/environments"));
        assert!(notes.iter().any(|n| n.starts_with("Route table to-firewall on subnet vnet-app/aca-infra")));
        let lines = build_lines(&r, &[Dir::Inbound]);
        assert!(lines.iter().any(|l| l.text == "Subnet vnet-app/aca-infra (rules for anything placed in it)"));
        assert!(lines.iter().any(|l| l.text.contains("↓ Inbound · priority order")));
        // Single layer: no cross check on the allow.
        assert!(rule_line(&lines, "allow-pp-subnet", Dir::Inbound).cross.is_none());
        assert!(!rule_line(&lines, "allow-pp-subnet", Dir::Inbound).open_to_internet);
    }

    #[test]
    fn warm_rows_cost_no_call() {
        let mut known = Known::default();
        let vnet = VnetRow::from_json(&vnet_body(), None).unwrap();
        for s in &vnet.subnets {
            known.add_subnet(s);
        }
        known.add_nsg(&NsgRow::from_json(&nsg_body("subnet-nsg", vec![]), None).unwrap());
        let seed = Seed { subnets: vec![format!("{}/virtualNetworks/vnet-app/subnets/vms", RG)], ..Default::default() };
        let r = block_on(resolve(seed, known, |p: String| std::future::ready(Err::<Value, String>(format!("called {}", p)))));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.nsgs.contains_key(&format!("{}/networkSecurityGroups/subnet-nsg", RG).to_lowercase()));
    }

    #[test]
    fn an_nsg_entry_lists_what_it_guards_and_marks_shadowed_rules() {
        let body = nsg_body("subnet-nsg", vec![
            rule_json("allow-all-vnet", 100, "Inbound", "Allow", "*", "VirtualNetwork", "*", "*"),
            rule_json("allow-vnet-https", 200, "Inbound", "Allow", "Tcp", "VirtualNetwork", "*", "443"),
        ]);
        let id = format!("{}/networkSecurityGroups/subnet-nsg", RG);
        let seed = Seed { nsg: Some(id.clone()), ..Default::default() };
        let r = block_on(resolve(seed, Known::default(), arm(vec![body])));
        let lines = build_lines(&r, &[Dir::Inbound]);
        assert_eq!(lines[0].text, "NSG subnet-nsg");
        assert_eq!(lines[1].text.trim(), "guards subnet vnet-app/vms");
        assert!(lines[1].jump.as_deref().unwrap().ends_with("/subnets/vms"));
        let shadowed = rule_line(&lines, "allow-vnet-https", Dir::Inbound);
        assert_eq!(shadowed.shadowed_by.as_deref(), Some("100 allow-all-vnet"));
        assert!(shadowed.text().ends_with("⊘ shadowed by 100 allow-all-vnet"));
        // AllowVnetInBound is covered by the custom 100 too.
        assert!(rule_line(&lines, "AllowVnetInBound", Dir::Inbound).shadowed_by.is_some());
        assert!(rule_line(&lines, "DenyAllInBound", Dir::Inbound).shadowed_by.is_none());
    }

    #[test]
    fn helpers_read_ids() {
        assert_eq!(
            nic_of_ip_configuration(&format!("{}/networkInterfaces/n1/ipConfigurations/ipconfig1", RG)).as_deref(),
            Some(format!("{}/networkInterfaces/n1", RG).as_str())
        );
        assert_eq!(nic_of_ip_configuration(&format!("{}/loadBalancers/lb/frontendIPConfigurations/f", RG)), None);
        assert_eq!(subnet_display(&format!("{}/virtualNetworks/v/subnets/s", RG)), "v/s");
    }
}
