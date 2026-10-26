// copy-adapted from neboto-tui src/references.rs @ 03760c0 (RefRow, the
// warm-cache walk and its coverage; the matcher became an ARM-id reverse index)
//! "Referenced by" (`U`, #49): which **loaded** resources point at this
//! one. The reverse of the Related section, answered from the warm list
//! caches alone: no call ever fires, and the lens says which lists were
//! not loaded, so partial coverage is explicit.
//!
//! neboto matches names and ARNs as whole tokens over every field. Azure
//! has a better key: every link a row knows is already an ARM id (or a
//! Graph `graph:/` id) in its `related()`. So the index maps each id a
//! row points at to the row, and a lookup is one hash probe:
//!
//! - **Case-insensitive**: keys are lowercased (RP responses disagree on
//!   an id's casing).
//! - **Children count**: a link to `…/virtualNetworks/v/subnets/s` is also
//!   filed under `…/virtualNetworks/v`, so `U` on a VNet finds the NICs in
//!   its subnets (`via Subnet s (in it)`).
//! - **Not a reference**: the scope links every row carries (subscription,
//!   resource group), a row's own id (All resources' `Open in`), and
//!   containment either way (a VNet listing its subnets, a subnet naming
//!   its VNet).
//! - Tag keys and values that are ARM ids count too (App Insights'
//!   `hidden-link:/subscriptions/…` key, a `managed-by` tag).
//!
//! The rows are deduplicated by id, typed lists first, so a site in Apps
//! and Functions, or a VM in All resources, is one row.

use crate::azure::resource::{arm_type_chain, Resource};
use crate::azure::service::JumpView;
use std::collections::{HashMap, HashSet};

/// One resource that references the selected one.
#[derive(Debug, Clone, PartialEq)]
pub struct RefRow {
    /// The sub-tab the row came from (its group in the lens).
    pub view: JumpView,
    pub resource_type: String,
    pub name: String,
    pub id: String,
    /// The link(s) that carried the reference, as the row's Related
    /// section labels them (`NSG nsg-web`, `Subnet snet-1 (in it)`).
    pub via: String,
}

/// The normalized form of an id: trimmed, no trailing `/`, lowercased.
pub fn normalize(id: &str) -> String {
    id.trim().trim_end_matches('/').to_lowercase()
}

/// Whether a value is an id a link can carry: an ARM id below a provider
/// (not a bare subscription or group: those are scope, not references), or
/// a synthetic directory id.
fn is_link_id(id: &str) -> bool {
    let id = id.trim();
    crate::azure::graph::is_row_id(id) || (id.starts_with("/subscriptions/") && arm_type_chain(id).is_some())
}

/// The ARM resource ids above a child id, nearest first:
/// `…/virtualNetworks/v/subnets/s` → `[…/virtualNetworks/v]`. Empty for a
/// top-level resource or anything that is not an ARM id. Input normalized.
fn ancestors(id: &str) -> Vec<String> {
    let Some((_, chain)) = arm_type_chain(id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cur = id.to_string();
    for _ in 1..chain.len() {
        // Drop one `/{type}/{name}` pair.
        for _ in 0..2 {
            if let Some(i) = cur.rfind('/') {
                cur.truncate(i);
            }
        }
        out.push(cur.clone());
    }
    out
}

/// Whether one id is the other or contains it (`a` is `b` or one of its
/// ancestors). Both normalized.
fn contains(a: &str, b: &str) -> bool {
    b == a || (b.starts_with(a) && b.as_bytes().get(a.len()) == Some(&b'/'))
}

#[derive(Debug, Clone)]
struct Hit {
    row: usize,
    via: String,
}

/// The reverse of every scanned row's links: link target → the rows that
/// carry it.
#[derive(Debug, Default)]
pub struct ReverseIndex {
    rows: Vec<RefRow>,
    /// Normalized id of each row (parallel to `rows`).
    row_ids: Vec<String>,
    by_target: HashMap<String, Vec<Hit>>,
}

impl ReverseIndex {
    /// Index `lists` (each with the sub-tab it came from), in order; a row
    /// whose id an earlier list already supplied is skipped.
    #[cfg(test)]
    pub fn build<'a, I>(lists: I) -> Self
    where
        I: IntoIterator<Item = (JumpView, &'a [Box<dyn Resource>])>,
    {
        Self::build_with(lists, |_| Vec::new())
    }

    /// [`build`](Self::build) with links a row has beyond its `related()`:
    /// what only the warm lists or a loaded lazy read can tell (a gateway
    /// backend matched to a Container App, a Front Door origin).
    pub fn build_with<'a, I>(lists: I, derived: impl Fn(&dyn Resource) -> Vec<(String, String)>) -> Self
    where
        I: IntoIterator<Item = (JumpView, &'a [Box<dyn Resource>])>,
    {
        let mut index = ReverseIndex::default();
        let mut seen: HashSet<String> = HashSet::new();
        for (view, list) in lists {
            for r in list {
                let own = normalize(r.id());
                if own.is_empty() || !seen.insert(own.clone()) {
                    continue;
                }
                let extra = derived(r.as_ref());
                index.add(view, r.as_ref(), own, extra);
            }
        }
        index
    }

    fn add(&mut self, view: JumpView, r: &dyn Resource, own: String, extra: Vec<(String, String)>) {
        let mut links: Vec<(String, String)> = r.related().into_iter().chain(extra).filter(|(_, id)| is_link_id(id)).collect();
        for (k, v) in r.tags() {
            if let Some(key) = k.strip_prefix("hidden-link:").filter(|key| is_link_id(key)) {
                links.push(("Tag hidden-link".to_string(), key.to_string()));
            } else if is_link_id(k) {
                links.push((format!("Tag {}", k), k.to_string()));
            }
            if is_link_id(v) {
                links.push((format!("Tag {}", k), v.to_string()));
            }
        }
        if links.is_empty() {
            return;
        }
        let row = self.rows.len();
        let mut filed: HashSet<String> = HashSet::new();
        for (label, id) in links {
            let target = normalize(&id);
            // Its own id, or containment either way, is not a reference.
            if contains(&target, &own) || contains(&own, &target) {
                continue;
            }
            let mut file = |key: String, via: String, by_target: &mut HashMap<String, Vec<Hit>>| {
                if filed.insert(key.clone()) {
                    by_target.entry(key).or_default().push(Hit { row, via });
                } else if let Some(hit) = by_target.get_mut(&key).and_then(|v| v.iter_mut().find(|h| h.row == row)) {
                    if !hit.via.split(", ").any(|v| v == via) {
                        hit.via = format!("{}, {}", hit.via, via);
                    }
                }
            };
            for parent in ancestors(&target) {
                if !contains(&parent, &own) {
                    file(parent, format!("{} (in it)", label), &mut self.by_target);
                }
            }
            file(target, label, &mut self.by_target);
        }
        if filed.is_empty() {
            return;
        }
        self.row_ids.push(own);
        self.rows.push(RefRow {
            view,
            resource_type: r.resource_type().to_string(),
            name: r.name().to_string(),
            id: r.id().to_string(),
            via: String::new(),
        });
    }

    /// Every indexed row that links to `target`: by its id, or (a
    /// directory row) by any alias its `matches_id` answers to, such as a
    /// service principal's `(appId='…')` form. The target itself is never
    /// in the answer.
    pub fn referrers(&self, target: &dyn Resource) -> Vec<RefRow> {
        let key = normalize(target.id());
        let mut hits: Vec<&Hit> = self.by_target.get(&key).map(|v| v.iter().collect()).unwrap_or_default();
        if crate::azure::graph::is_row_id(target.id()) {
            for (k, v) in &self.by_target {
                if *k != key && crate::azure::graph::is_row_id(k) && target.matches_id(k) {
                    hits.extend(v.iter());
                }
            }
        }
        let mut out: Vec<RefRow> = Vec::new();
        for hit in hits {
            if self.row_ids[hit.row] == key {
                continue;
            }
            match out.iter_mut().find(|r| r.id == self.rows[hit.row].id) {
                Some(r) => r.via = format!("{}, {}", r.via, hit.via),
                None => out.push(RefRow { via: hit.via.clone(), ..self.rows[hit.row].clone() }),
            }
        }
        out
    }

    /// Whether no row carries a link.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// The lists most likely to point at a row of `target`'s type, for the
/// lens's "load the likely ones" key. A hand-kept table of the links the
/// Related sections carry (`docs/SERVICES.md`); empty when nothing obvious
/// points at the type.
pub fn likely_referrers(target: JumpView) -> &'static [JumpView] {
    use JumpView::*;
    match target {
        NetworkSecurityGroups => &[Nics, Subnets],
        Subnets => &[
            Nics,
            PrivateEndpoints,
            WebApps,
            ContainerAppEnvironments,
            EnterprisePolicies,
            NatGateways,
            PostgresServers,
            MysqlServers,
            AppGateways,
            VnetGateways,
        ],
        VirtualNetworks => &[
            Nics,
            PrivateEndpoints,
            WebApps,
            ContainerAppEnvironments,
            EnterprisePolicies,
            DnsResolvers,
            PrivateDnsZones,
            PostgresServers,
            MysqlServers,
            AppGateways,
            VnetGateways,
        ],
        Identities => &[
            VirtualMachines,
            Clusters,
            WebApps,
            ContainerApps,
            ContainerAppJobs,
            ServicePrincipals,
            ServiceBusNamespaces,
            EventHubNamespaces,
            PostgresServers,
            MysqlServers,
            AppGateways,
            FrontDoorProfiles,
        ],
        KeyVaults => &[PrivateEndpoints, EnterprisePolicies],
        PublicIps => &[Nics, LoadBalancers, NatGateways, AppGateways, VnetGateways],
        Disks => &[VirtualMachines],
        Nics => &[VirtualMachines, PrivateEndpoints, AppGateways],
        RouteTables | NatGateways => &[Subnets],
        AppServicePlans => &[WebApps],
        ContainerAppEnvironments => &[ContainerApps, ContainerAppJobs, WebApps, AppGateways, FrontDoorProfiles],
        // A gateway backend or a Front Door origin matched to the row.
        ContainerApps | WebApps => &[AppGateways, FrontDoorProfiles],
        AppGateways => &[PublicIps, WafPolicies],
        WafPolicies => &[AppGateways, FrontDoorProfiles],
        FrontDoorProfiles => &[WafPolicies],
        // A connection names its gateway, circuit and local gateway.
        ExpressRouteCircuits | VnetGateways | LocalGateways => &[GatewayConnections],
        LogWorkspaces => &[AppInsights, Clusters],
        Clusters => &[ResourceGroups, NodePools],
        PrivateEndpoints => &[
            Nics,
            StorageAccounts,
            KeyVaults,
            Registries,
            SqlServers,
            CosmosAccounts,
            AiAccounts,
            PostgresServers,
            MysqlServers,
            RedisCaches,
            ManagedRedis,
            ServiceBusNamespaces,
            EventHubNamespaces,
            AppGateways,
        ],
        StorageAccounts | Registries | SqlServers | CosmosAccounts | AiAccounts | RedisCaches | ManagedRedis
        | ServiceBusNamespaces | EventHubNamespaces => &[PrivateEndpoints],
        PostgresServers | MysqlServers => &[PrivateEndpoints],
        PrivateDnsZones => &[PostgresServers, MysqlServers],
        DnsResolvers => &[DnsForwardingRulesets],
        ServicePrincipals => &[AppRegistrations],
        AppRegistrations => &[ServicePrincipals],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::resource::ResourceState;

    const P: &str = "/subscriptions/0000/resourceGroups/rg/providers";

    #[derive(Clone, Debug)]
    struct Mock {
        id: String,
        links: Vec<(String, String)>,
        tags: HashMap<String, String>,
    }

    impl Resource for Mock {
        fn id(&self) -> &str {
            &self.id
        }
        fn name(&self) -> &str {
            crate::azure::resource::name_of_id(&self.id)
        }
        fn resource_type(&self) -> &str {
            "Mock"
        }
        fn state(&self) -> ResourceState {
            ResourceState::stateless()
        }
        fn tags(&self) -> &HashMap<String, String> {
            &self.tags
        }
        fn details(&self) -> Vec<(String, String)> {
            Vec::new()
        }
        fn related(&self) -> Vec<(String, String)> {
            let mut v = crate::azure::resource::scope_related(&self.id);
            v.extend(self.links.clone());
            v
        }
        fn clone_box(&self) -> Box<dyn Resource> {
            Box::new(self.clone())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn mock(path: &str, links: &[(&str, &str)], tags: &[(&str, &str)]) -> Box<dyn Resource> {
        Box::new(Mock {
            id: format!("{P}/{path}"),
            links: links.iter().map(|(k, v)| (k.to_string(), format!("{P}/{v}"))).collect(),
            tags: tags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        })
    }

    const SUBNET: &str = "Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-1";

    fn names(rows: &[RefRow]) -> Vec<(&str, &str)> {
        rows.iter().map(|r| (r.name.as_str(), r.via.as_str())).collect()
    }

    #[test]
    fn links_are_reversed_case_insensitively_and_children_reach_their_parent() {
        let nics = vec![
            mock("Microsoft.Network/networkInterfaces/nic-1", &[("Subnet snet-1", SUBNET)], &[]),
            // The RP wrote the id in another case.
            mock(
                "Microsoft.Network/networkInterfaces/nic-2",
                &[("Subnet snet-1", "MICROSOFT.NETWORK/virtualNetworks/VNET-1/subnets/snet-1/")],
                &[],
            ),
            mock("Microsoft.Network/networkInterfaces/nic-3", &[("Subnet snet-10", &format!("{SUBNET}0"))], &[]),
        ];
        let index = ReverseIndex::build([(JumpView::Nics, nics.as_slice())]);
        let subnet = mock(SUBNET, &[], &[]);
        let rows = index.referrers(subnet.as_ref());
        assert_eq!(names(&rows), vec![("nic-1", "Subnet snet-1"), ("nic-2", "Subnet snet-1")]);
        assert_eq!(rows[0].view, JumpView::Nics);

        // The VNet is reached through its subnets, snet-10's NIC included.
        let vnet = mock("Microsoft.Network/virtualNetworks/vnet-1", &[], &[]);
        let rows = index.referrers(vnet.as_ref());
        assert_eq!(
            names(&rows),
            vec![("nic-1", "Subnet snet-1 (in it)"), ("nic-2", "Subnet snet-1 (in it)"), ("nic-3", "Subnet snet-10 (in it)")]
        );
    }

    #[test]
    fn scope_self_and_containment_are_not_references() {
        let list = vec![
            // A VNet listing its own subnet; a subnet naming its VNet.
            mock("Microsoft.Network/virtualNetworks/vnet-1", &[("Subnet snet-1", SUBNET)], &[]),
            mock(SUBNET, &[("Virtual network vnet-1", "Microsoft.Network/virtualNetworks/vnet-1")], &[]),
            // All resources' `Open in` points at the row itself.
            mock("Microsoft.Web/sites/app-1", &[("Open in Apps", "Microsoft.Web/sites/app-1")], &[]),
        ];
        let index = ReverseIndex::build([(JumpView::VirtualNetworks, list.as_slice())]);
        assert!(index.is_empty(), "nothing but containment and self links");
        let group = Mock { id: "/subscriptions/0000/resourceGroups/rg".into(), links: vec![], tags: HashMap::new() };
        assert!(index.referrers(&group).is_empty());
    }

    #[test]
    fn rows_are_deduplicated_typed_list_first_and_vias_join() {
        let nsg = "Microsoft.Network/networkSecurityGroups/nsg-1";
        let typed = vec![mock("Microsoft.Network/networkInterfaces/nic-1", &[("NSG nsg-1", nsg), ("Also", nsg)], &[])];
        let generic = vec![mock("Microsoft.Network/networkInterfaces/nic-1", &[("Managed by", nsg)], &[])];
        let index = ReverseIndex::build([(JumpView::Nics, typed.as_slice()), (JumpView::AllResources, generic.as_slice())]);
        let rows = index.referrers(mock(nsg, &[], &[]).as_ref());
        assert_eq!(names(&rows), vec![("nic-1", "NSG nsg-1, Also")]);
        assert_eq!(rows[0].view, JumpView::Nics);
    }

    #[test]
    fn tag_keys_and_values_carrying_an_arm_id_count() {
        let site = format!("{P}/Microsoft.Web/sites/app-1");
        let list = vec![
            mock("Microsoft.Insights/components/appi-1", &[], &[(&format!("hidden-link:{site}"), "Resource")]),
            mock("Microsoft.Storage/storageAccounts/st1", &[], &[("managed-by", &site), ("owner", "app-1")]),
        ];
        let index = ReverseIndex::build([(JumpView::AppInsights, list.as_slice())]);
        let rows = index.referrers(mock("Microsoft.Web/sites/app-1", &[], &[]).as_ref());
        assert_eq!(
            names(&rows),
            vec![("appi-1", "Tag hidden-link"), ("st1", "Tag managed-by")]
        );
    }

    #[test]
    fn ancestors_walk_up_the_type_chain() {
        let id = normalize(&format!("{P}/Microsoft.Sql/servers/s/databases/d"));
        assert_eq!(ancestors(&id), vec![normalize(&format!("{P}/Microsoft.Sql/servers/s"))]);
        assert!(ancestors(&normalize(&format!("{P}/Microsoft.Sql/servers/s"))).is_empty());
        assert!(contains("/a/b", "/a/b/c") && !contains("/a/b", "/a/bc") && contains("/a/b", "/a/b"));
    }

    #[test]
    fn every_target_with_likely_referrers_lists_other_types() {
        for view in crate::azure::service::ServiceType::all().iter().flat_map(|s| s.views()) {
            assert!(!likely_referrers(*view).contains(view), "{view:?} lists itself");
        }
    }
}
