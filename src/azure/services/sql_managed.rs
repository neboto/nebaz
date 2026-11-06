//! SQL Managed Instance (issue #195), two SQL sub-tabs beside the logical
//! servers (SERVICES.md rule 37): managed instances
//! (`Microsoft.Sql/managedInstances`, listed with
//! `$expand=administrators/activedirectory`, the only way the Entra admin
//! comes back) and instance pools (`instancePools`). One
//! subscription-wide list each.
//!
//! An instance's databases (`{instance}/databases`) and its failover group
//! are lazy sections. Failover groups have no subscription-wide or
//! per-instance list: they are listed per group and region
//! (`{group}/providers/Microsoft.Sql/locations/{region}/instanceFailoverGroups`)
//! and matched to the instance by `managedInstancePairs`. A pool's
//! instances are matched in the warm Managed instances list.
//!
//! **Secrets never.** `administratorLoginPassword` is write-only and never
//! comes back. A database's `storageContainerSasToken` (create-only, but
//! not marked secret in the spec) is stripped before the store keeps the
//! list. The public data endpoint's host is shown as text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource, ResourceState,
};
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::edge::top_level_of;
use crate::azure::services::governance::Warm;
use crate::azure::services::sql::SQL_API_VERSION;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use serde_json::Value;
use tokio::sync::mpsc;

const INSTANCES_PATH: &str = "/providers/Microsoft.Sql/managedInstances";
const POOLS_PATH: &str = "/providers/Microsoft.Sql/instancePools";
/// The Entra admin only comes back expanded.
const EXPAND_ADMINS: &[(&str, &str)] = &[("$expand", "administrators/activedirectory")];

crate::sections! {
    pub enum ManagedInstanceDetailSection,
    pub static MANAGED_INSTANCE_SECTIONS = [
        Overview "Overview",
        Instance "Instance",
        Security "Security",
        Networking "Networking",
        Databases "Databases" => crate::app::App::trigger_mi_databases,
        FailoverGroup "Failover group" => crate::app::App::trigger_mi_failover_groups,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_mi_failover_groups,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum InstancePoolDetailSection,
    pub static INSTANCE_POOL_SECTIONS = [
        Overview "Overview",
        Pool "Pool",
        Instances "Instances" => crate::app::App::trigger_pool_instances,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

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

/// `GP_Gen5 · GeneralPurpose · 8 vCores`.
fn sku_label(v: &Value) -> String {
    let mut parts = vec![json::text(v, "/sku/name")];
    parts.extend(json::str_at(v, "/sku/tier"));
    parts.join(" · ")
}

// ── Managed instance ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ManagedInstanceRow {
    pub base: ArmBase,
    pub sku: String,
    pub family: Option<String>,
    /// `Ready`, `Stopped`, `Starting`, `Stopping`, `Creating`… (a free
    /// string in the spec).
    pub state: Option<String>,
    pub fqdn: Option<String>,
    pub admin_login: Option<String>,
    pub entra_admin: Option<String>,
    pub entra_admin_type: Option<String>,
    pub entra_only: Option<bool>,
    pub subnet_id: Option<String>,
    pub license: Option<String>,
    pub hybrid_secondary: Option<String>,
    pub vcores: Option<i64>,
    pub storage_gb: Option<i64>,
    pub storage_iops: Option<i64>,
    pub storage_throughput: Option<i64>,
    pub memory_gb: Option<i64>,
    pub general_purpose_v2: Option<bool>,
    pub collation: Option<String>,
    pub dns_zone: Option<String>,
    pub public_endpoint: Option<bool>,
    pub proxy_override: Option<String>,
    pub timezone: Option<String>,
    pub instance_pool_id: Option<String>,
    pub maintenance_id: Option<String>,
    pub min_tls: Option<String>,
    pub backup_redundancy: Option<String>,
    pub zone_redundant: Option<bool>,
    pub database_format: Option<String>,
    pub created: Option<String>,
    /// A Key Vault key URL (customer-managed TDE), not an ARM id.
    pub key_id: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub primary_identity_id: Option<String>,
    pub private_endpoint_ids: Vec<String>,
}

impl ManagedInstanceRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ManagedInstanceRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(ManagedInstanceRow {
            sku: sku_label(v),
            family: json::str_at(v, "/sku/family"),
            state: json::str_at(v, &p("state")),
            fqdn: json::str_at(v, &p("fullyQualifiedDomainName")),
            admin_login: json::str_at(v, &p("administratorLogin")),
            entra_admin: json::str_at(v, &p("administrators/login")),
            entra_admin_type: json::str_at(v, &p("administrators/principalType")),
            entra_only: json::bool_at(v, &p("administrators/azureADOnlyAuthentication")),
            subnet_id: json::arm_id(json::str_at(v, &p("subnetId"))),
            license: json::str_at(v, &p("licenseType")),
            hybrid_secondary: json::str_at(v, &p("hybridSecondaryUsage")),
            vcores: json::int_at(v, &p("vCores")),
            storage_gb: json::int_at(v, &p("storageSizeInGB")),
            storage_iops: json::int_at(v, &p("storageIOps")),
            storage_throughput: json::int_at(v, &p("storageThroughputMBps")),
            memory_gb: json::int_at(v, &p("memorySizeInGB")),
            general_purpose_v2: json::bool_at(v, &p("isGeneralPurposeV2")),
            collation: json::str_at(v, &p("collation")),
            dns_zone: json::str_at(v, &p("dnsZone")),
            public_endpoint: json::bool_at(v, &p("publicDataEndpointEnabled")),
            proxy_override: json::str_at(v, &p("proxyOverride")),
            timezone: json::str_at(v, &p("timezoneId")),
            instance_pool_id: json::arm_id(json::str_at(v, &p("instancePoolId"))),
            maintenance_id: json::str_at(v, &p("maintenanceConfigurationId")),
            min_tls: json::str_at(v, &p("minimalTlsVersion")),
            backup_redundancy: json::str_at(v, &p("currentBackupStorageRedundancy")),
            zone_redundant: json::bool_at(v, &p("zoneRedundant")),
            database_format: json::str_at(v, &p("databaseFormat")),
            created: json::str_at(v, &p("createTime")),
            key_id: json::str_at(v, &p("keyId")).filter(|k| !k.is_empty()),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            primary_identity_id: json::arm_id(json::str_at(v, &p("primaryUserAssignedIdentityId"))),
            private_endpoint_ids: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/privateEndpoint")))
                .collect(),
            base,
        })
    }

    /// Provisioning first, then `state`: a stopped instance (stop/start
    /// schedules) is stopped, not failed.
    pub fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "ready" => ResourceState::Available,
                "stopped" => ResourceState::Stopped,
                "disabled" => ResourceState::Unavailable,
                "deleting" | "dropping" => ResourceState::Deleting,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn vnet_id(&self) -> Option<String> {
        self.subnet_id.as_deref().and_then(top_level_of)
    }

    /// The public data endpoint's host: `{name}.public.` and the rest of the private
    /// FQDN (shown, never requested).
    fn public_host(&self) -> Option<String> {
        let fqdn = self.fqdn.as_deref()?;
        let (name, rest) = fqdn.split_once('.')?;
        Some(format!("{}.public.{}", name, rest))
    }

    pub fn instance_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("SKU".into(), self.sku.clone()),
            ("Hardware".into(), json::opt(self.family.clone())),
            ("vCores · memory".into(), format!("{} · {}", json::num(self.vcores), self.memory_gb.map(|m| format!("{} GB", m)).unwrap_or_else(|| "-".into()))),
            ("Storage".into(), self.storage_gb.map(|g| format!("{} GB", g)).unwrap_or_else(|| "-".into())),
        ];
        if self.general_purpose_v2 == Some(true) {
            lines.push(("General Purpose v2".into(), format!("yes · {} IOPS · {} MB/s", json::num(self.storage_iops), json::num(self.storage_throughput))));
        }
        lines.push(("License".into(), match self.license.as_deref() {
            Some(l) if same(l, "BasePrice") => "BasePrice (Azure Hybrid Benefit)".into(),
            other => json::opt(other.map(str::to_string)),
        }));
        if let Some(h) = &self.hybrid_secondary {
            lines.push(("Hybrid secondary".into(), h.clone()));
        }
        lines.push(("Zone redundant".into(), json::yes_no(self.zone_redundant)));
        lines.push(("Backup redundancy".into(), json::opt(self.backup_redundancy.clone())));
        lines.push(("Update policy".into(), json::opt(self.database_format.clone())));
        lines.push(("Collation".into(), json::opt(self.collation.clone())));
        lines.push(("Time zone".into(), json::opt(self.timezone.clone())));
        if let Some(m) = &self.maintenance_id {
            lines.push(("Maintenance window".into(), name_of_id(m).to_string()));
        }
        if let Some(p) = &self.instance_pool_id {
            lines.push((format!("Instance pool · {}", name_of_id(p)), p.clone()));
        }
        lines.push(("Created".into(), json::time(self.created.clone())));
        lines
    }

    pub fn security_rows(&self) -> Vec<(String, String)> {
        let entra = match (&self.entra_admin, &self.entra_admin_type) {
            (Some(login), Some(kind)) => format!("{} ({})", login, kind),
            (login, _) => json::opt(login.clone()),
        };
        let mut lines = vec![
            ("Entra admin".into(), entra),
            ("Entra-only auth".into(), json::yes_no(self.entra_only)),
            ("SQL admin login".into(), json::opt(self.admin_login.clone())),
            ("Min TLS".into(), json::opt(self.min_tls.clone())),
            ("TDE key".into(), if self.key_id.is_some() { "customer-managed" } else { "service-managed" }.into()),
        ];
        if let Some(k) = &self.key_id {
            lines.push(("  Key".into(), k.clone()));
        }
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        if let Some(primary) = &self.primary_identity_id {
            lines.push((format!("Primary identity · {}", name_of_id(primary)), primary.clone()));
        }
        lines
    }

    pub fn networking_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        match &self.subnet_id {
            Some(s) => lines.push((format!("Subnet · {}", subnet_label(s)), s.clone())),
            None => lines.push(("Subnet".into(), "-".into())),
        }
        lines.push(("Host".into(), json::opt(self.fqdn.clone())));
        lines.push(("DNS zone".into(), json::opt(self.dns_zone.clone())));
        lines.push(("Connection type".into(), json::opt(self.proxy_override.clone())));
        if self.public_endpoint == Some(true) {
            lines.push((
                "Public endpoint".into(),
                format!("⚠ enabled · {} on port 3342 (the subnet's NSG decides who reaches it)", self.public_host().unwrap_or_else(|| "-".into())),
            ));
        } else {
            lines.push(("Public endpoint".into(), json::yes_no(self.public_endpoint)));
        }
        for pe in &self.private_endpoint_ids {
            lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· a managed instance needs its own delegated subnet with an NSG and a route table: N on the instance shows the subnet's rules".into()));
        lines
    }

    pub fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(vnet) = self.vnet_id() {
            push_unique(&mut v, format!("VNet · {}", name_of_id(&vnet)), vnet);
        }
        if let Some(s) = &self.subnet_id {
            push_unique(&mut v, format!("Subnet · {}", subnet_label(s)), s.clone());
        }
        if let Some(p) = &self.instance_pool_id {
            push_unique(&mut v, format!("Instance pool · {}", name_of_id(p)), p.clone());
        }
        for pe in &self.private_endpoint_ids {
            push_unique(&mut v, format!("Private endpoint · {}", name_of_id(pe)), pe.clone());
        }
        let mut identities = self.user_identity_ids.clone();
        identities.extend(self.primary_identity_id.iter().cloned());
        for id in identities {
            push_unique(&mut v, format!("Identity · {}", name_of_id(&id)), id);
        }
        v
    }
}

impl Resource for ManagedInstanceRow {
    arm_row!("SQL managed instance");
    /// `GP_Gen5 · GeneralPurpose · 8 vCores · 256 GB`.
    fn list_summary(&self) -> Option<String> {
        let mut s = format!("{} · {} vCores · {}", self.sku, json::num(self.vcores), self.storage_gb.map(|g| format!("{} GB", g)).unwrap_or_else(|| "-".into()));
        if self.public_endpoint == Some(true) {
            s.push_str(" · public endpoint");
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
        Some(&MANAGED_INSTANCE_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.fqdn.clone()),
            json::opt(self.entra_admin.clone())
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("State".into(), json::opt(self.state.clone())),
            ("SKU".into(), self.sku.clone()),
            ("vCores".into(), json::num(self.vcores)),
            ("Host".into(), json::opt(self.fqdn.clone())),
            ("Public endpoint".into(), json::yes_no(self.public_endpoint)),
            ("Entra-only auth".into(), json::yes_no(self.entra_only)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        ManagedInstanceRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az sql mi show --ids {}", shell_quote(&self.base.id)))
    }
}

/// The failover groups list of an instance's group and region.
pub fn failover_groups_path(r: &ManagedInstanceRow) -> Option<String> {
    let sub = subscription_of(&r.base.id)?;
    let rg = resource_group_of(&r.base.id)?;
    Some(format!(
        "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/locations/{}/instanceFailoverGroups",
        sub, rg, r.base.location
    ))
}

/// The failover groups that pair `id` with another instance.
fn groups_with<'a>(items: &'a [Value], id: &str) -> Vec<&'a Value> {
    items
        .iter()
        .filter(|g| {
            json::arr(g, "/properties/managedInstancePairs").iter().any(|p| {
                ["/primaryManagedInstanceId", "/partnerManagedInstanceId"]
                    .iter()
                    .any(|k| json::str_at(p, k).is_some_and(|i| same(&i, id)))
            })
        })
        .collect()
}

/// The other instance of each pair `id` is in.
fn partners(items: &[Value], id: &str) -> Vec<String> {
    let mut out = Vec::new();
    for g in groups_with(items, id) {
        for p in json::arr(g, "/properties/managedInstancePairs") {
            for k in ["/primaryManagedInstanceId", "/partnerManagedInstanceId"] {
                if let Some(other) = json::arm_id(json::str_at(&p, k)).filter(|i| !same(i, id)) {
                    if !out.iter().any(|o: &String| same(o, &other)) {
                        out.push(other);
                    }
                }
            }
        }
    }
    out
}

pub fn failover_group_rows(r: &ManagedInstanceRow, lazy: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(lazy, "Failover group", |items| {
        let found = groups_with(items, &r.base.id);
        if found.is_empty() {
            return vec![(String::new(), "No failover group: the instance has no geo-replica (backups are its only copy elsewhere)".into())];
        }
        let mut lines = Vec::new();
        for g in found {
            let q = |k: &str| format!("/properties/{}", k);
            lines.push((format!("Failover group · {}", json::text(g, "/name")), json::text(g, "/id")));
            lines.push(("  Role · replication".into(), format!("{} · {}", json::text(g, &q("replicationRole")), json::text(g, &q("replicationState")))));
            let policy = json::text(g, &q("readWriteEndpoint/failoverPolicy"));
            let grace = json::int_at(g, &q("readWriteEndpoint/failoverWithDataLossGracePeriodMinutes"))
                .map(|m| format!(" after {} min (data loss allowed)", m))
                .unwrap_or_default();
            lines.push(("  Failover".into(), format!("{}{}", policy, grace)));
            lines.push(("  Read-only endpoint".into(), json::text(g, &q("readOnlyEndpoint/failoverPolicy"))));
            lines.push(("  Secondary type".into(), json::text(g, &q("secondaryType"))));
            for region in json::arr(g, &q("partnerRegions")) {
                lines.push((format!("  Partner region · {}", json::text(&region, "/location")), json::text(&region, "/replicationRole")));
            }
        }
        for p in partners(items, &r.base.id) {
            lines.push((format!("Partner instance · {}", name_of_id(&p)), p));
        }
        lines
    })
}

pub fn instance_database_rows(r: &ManagedInstanceRow, lazy: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(lazy, "Databases", |items| {
        if items.is_empty() {
            return vec![(String::new(), "No user databases".into())];
        }
        let mut lines = Vec::new();
        for d in items {
            let q = |k: &str| format!("/properties/{}", k);
            let status = json::text(d, &q("status"));
            let flagged = match status.to_lowercase().as_str() {
                "online" | "creating" | "restoring" | "updating" => status.clone(),
                _ => format!("⚠ {}", status),
            };
            lines.push((json::text(d, "/name"), flagged));
            lines.push(("  Created".into(), json::time(json::str_at(d, &q("creationDate")))));
            lines.push(("  Earliest restore point".into(), json::time(json::str_at(d, &q("earliestRestorePoint")))));
            if let Some(fg) = json::str_at(d, &q("failoverGroupId")) {
                lines.push(("  Failover group".into(), name_of_id(&fg).to_string()));
            }
            if json::bool_at(d, &q("isLedgerOn")) == Some(true) {
                lines.push(("  Ledger".into(), "on".into()));
            }
        }
        lines.push((String::new(), String::new()));
        lines.push((
            "Read command".into(),
            format!(
                "az sql midb list --mi {} -g {} --subscription {}",
                shell_quote(&r.base.name),
                shell_quote(r.resource_group().unwrap_or("-")),
                shell_quote(subscription_of(&r.base.id).unwrap_or("-"))
            ),
        ));
        lines
    })
}

/// A database's `storageContainerSasToken` (create-only, not marked secret
/// in the spec) out before the store keeps the list.
pub fn without_sas(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(p) = v.pointer_mut("/properties").and_then(Value::as_object_mut) {
        p.retain(|k, _| !k.eq_ignore_ascii_case("storageContainerSasToken"));
    }
    v
}

// ── Instance pool ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InstancePoolRow {
    pub base: ArmBase,
    pub sku: String,
    pub family: Option<String>,
    pub subnet_id: Option<String>,
    pub vcores: Option<i64>,
    pub license: Option<String>,
    pub dns_zone: Option<String>,
    pub maintenance_id: Option<String>,
}

impl InstancePoolRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<InstancePoolRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        Some(InstancePoolRow {
            sku: sku_label(v),
            family: json::str_at(v, "/sku/family"),
            subnet_id: json::arm_id(json::str_at(v, &p("subnetId"))),
            vcores: json::int_at(v, &p("vCores")),
            license: json::str_at(v, &p("licenseType")),
            dns_zone: json::str_at(v, &p("dnsZone")),
            maintenance_id: json::str_at(v, &p("maintenanceConfigurationId")),
            base,
        })
    }

    pub fn pool_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("SKU".into(), self.sku.clone()),
            ("Hardware".into(), json::opt(self.family.clone())),
            ("vCores".into(), json::num(self.vcores)),
            ("License".into(), json::opt(self.license.clone())),
            ("DNS zone".into(), json::opt(self.dns_zone.clone())),
        ];
        if let Some(s) = &self.subnet_id {
            lines.push((format!("Subnet · {}", subnet_label(s)), s.clone()));
        }
        if let Some(m) = &self.maintenance_id {
            lines.push(("Maintenance window".into(), name_of_id(m).to_string()));
        }
        lines
    }

    fn instances<'a>(&self, warm: &'a [Box<dyn Resource>]) -> Vec<&'a ManagedInstanceRow> {
        warm.iter()
            .filter_map(|r| r.as_any().downcast_ref::<ManagedInstanceRow>())
            .filter(|m| m.instance_pool_id.as_deref().is_some_and(|p| same(p, &self.base.id)))
            .collect()
    }

    pub fn instance_rows(&self, instances: Warm) -> Vec<(String, String)> {
        let Some(warm) = instances.rows() else {
            return instances.waiting("Managed instances (@sqlmi)");
        };
        let found = self.instances(warm);
        if found.is_empty() {
            return vec![(String::new(), "No managed instance in this subscription is in the pool".into())];
        }
        let used: i64 = found.iter().filter_map(|m| m.vcores).sum();
        let mut lines: Vec<(String, String)> = found
            .iter()
            .map(|m| (format!("{} · {} vCores · {}", m.base.name, json::num(m.vcores), json::opt(m.state.clone())), m.base.id.clone()))
            .collect();
        lines.push((String::new(), String::new()));
        lines.push(("vCores used".into(), format!("{} of {}", used, json::num(self.vcores))));
        lines
    }
}

impl Resource for InstancePoolRow {
    arm_row!("SQL instance pool");
    /// `GP_Gen5 · GeneralPurpose · 16 vCores`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("{} · {} vCores", self.sku, json::num(self.vcores)))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&INSTANCE_POOL_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("SKU".into(), self.sku.clone()),
            ("vCores".into(), json::num(self.vcores)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = &self.subnet_id {
            if let Some(vnet) = top_level_of(s) {
                push_unique(&mut v, format!("VNet · {}", name_of_id(&vnet)), vnet);
            }
            push_unique(&mut v, format!("Subnet · {}", subnet_label(s)), s.clone());
        }
        v
    }
    /// The name form: `instance-pool show` declares `--name` without an
    /// `id_part` (SERVICES.md rule 9).
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az sql instance-pool show -n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(self.resource_group()?),
            subscription_of(&self.base.id)?
        ))
    }
}

// ── Section dispatch ──────────────────────────────────────────────────

/// What a managed instance or pool section reads beyond its row.
pub struct ManagedContext<'a> {
    pub databases: Option<&'a Lazy<Vec<Value>>>,
    pub failover_groups: Option<&'a Lazy<Vec<Value>>>,
    pub instances: Warm<'a>,
}

pub fn managed_section_lines(r: &dyn Resource, idx: usize, cx: &ManagedContext) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    let app = crate::azure::services::rendered_by_app;
    if let Some(x) = any.downcast_ref::<ManagedInstanceRow>() {
        use ManagedInstanceDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Instance => x.instance_rows(),
            S::Security => x.security_rows(),
            S::Networking => x.networking_rows(),
            S::Databases => instance_database_rows(x, cx.databases),
            S::FailoverGroup => failover_group_rows(x, cx.failover_groups),
            S::Access | S::Activity => app(),
            S::Related => {
                let extra = match cx.failover_groups {
                    Some(Lazy::Loaded(items)) => partners(items, &x.base.id)
                        .into_iter()
                        .map(|p| (format!("Failover partner · {}", name_of_id(&p)), p))
                        .collect(),
                    _ => Vec::new(),
                };
                related_rows_with(x, extra)
            }
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<InstancePoolRow>() {
        use InstancePoolDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Pool => x.pool_rows(),
            S::Instances => x.instance_rows(cx.instances),
            S::Access | S::Activity => app(),
            S::Related => related_rows_with(
                x,
                cx.instances.rows().map(|w| x.instances(w).iter().map(|m| (format!("Instance · {}", m.base.name), m.base.id.clone())).collect()).unwrap_or_default(),
            ),
            S::Tags => tag_rows(x.tags()),
        });
    }
    None
}

// ── Provider ──────────────────────────────────────────────────────────

pub fn managed_rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    match view {
        JumpView::InstancePools => page
            .iter()
            .filter_map(|v| InstancePoolRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect(),
        _ => page
            .iter()
            .filter_map(|v| ManagedInstanceRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect(),
    }
}

/// The managed sub-tabs inside the SQL provider.
pub struct ManagedLists<'a> {
    pub scope: &'a Scope,
}

impl ManagedLists<'_> {
    fn call(view: JumpView) -> (&'static str, &'static [(&'static str, &'static str)], &'static str) {
        match view {
            JumpView::InstancePools => (POOLS_PATH, &[], "Listing SQL instance pools…"),
            _ => (INSTANCES_PATH, EXPAND_ADMINS, "Listing SQL managed instances…"),
        }
    }

    pub async fn list(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, query, _) = Self::call(view);
        let page = self.scope.list_query(path, SQL_API_VERSION, query).await?;
        Ok(managed_rows(view, &page, self.scope.tenant()))
    }

    pub async fn stream(&self, view: JumpView, event_tx: &mpsc::UnboundedSender<Event>, service_type: ServiceType) -> Result<()> {
        let (path, query, message) = Self::call(view);
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(path, SQL_API_VERSION, query, service_type, message, event_tx, |page| managed_rows(view, &page, tenant.as_deref()))
            .await;
        finish_stream(service_type, r, event_tx)
    }

    pub async fn get(&self, id: &str, view: JumpView) -> Result<Box<dyn Resource>> {
        let v = match view {
            JumpView::InstancePools => self.scope.get(id, SQL_API_VERSION).await?,
            _ => self.scope.get_query(id, SQL_API_VERSION, EXPAND_ADMINS).await?,
        };
        managed_rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-data";

    fn mi_id(name: &str) -> String {
        format!("{}/providers/Microsoft.Sql/managedInstances/{}", RG, name)
    }

    fn texts(lines: &[(String, String)]) -> String {
        lines.iter().map(|(l, v)| format!("{} = {}\n", l, v)).collect()
    }

    fn mi(state: &str, public: bool) -> ManagedInstanceRow {
        ManagedInstanceRow::from_json(
            &json!({
                "id": mi_id("sqlmi-prod"), "name": "sqlmi-prod", "location": "westeurope",
                "sku": {"name": "GP_Gen5", "tier": "GeneralPurpose", "family": "Gen5", "capacity": 8},
                "properties": {
                    "provisioningState": "Succeeded", "state": state, "vCores": 8, "storageSizeInGB": 256,
                    "fullyQualifiedDomainName": "sqlmi-prod.1a2b3c4d5e6f.database.windows.net", "dnsZone": "1a2b3c4d5e6f",
                    "subnetId": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-data/subnets/snet-sqlmi", RG),
                    "publicDataEndpointEnabled": public, "licenseType": "BasePrice", "minimalTlsVersion": "1.2",
                    "administrators": {"login": "sql-admins", "principalType": "Group", "azureADOnlyAuthentication": true}
                }
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn an_instance_parses_its_sku_entra_admin_and_subnet() {
        let m = mi("Ready", false);
        assert_eq!(m.state(), ResourceState::Available);
        assert_eq!(m.list_summary().unwrap(), "GP_Gen5 · GeneralPurpose · 8 vCores · 256 GB");
        assert!(texts(&m.security_rows()).contains("Entra admin = sql-admins (Group)"));
        assert!(texts(&m.instance_rows()).contains("License = BasePrice (Azure Hybrid Benefit)"));
        let net = texts(&m.networking_rows());
        assert!(net.contains("Subnet · vnet-data/snet-sqlmi"), "{}", net);
        assert!(m.related().iter().any(|(l, _)| l == "VNet · vnet-data"));
        assert_eq!(m.cli_command().unwrap(), format!("az sql mi show --ids {}", shell_quote(&mi_id("sqlmi-prod"))));
    }

    #[test]
    fn a_stopped_instance_is_stopped_and_a_public_endpoint_is_flagged() {
        assert_eq!(mi("Stopped", false).state(), ResourceState::Stopped);
        let m = mi("Ready", true);
        let net = texts(&m.networking_rows());
        assert!(net.contains("⚠ enabled · sqlmi-prod.public.1a2b3c4d5e6f.database.windows.net on port 3342"), "{}", net);
        assert!(m.list_summary().unwrap().ends_with("public endpoint"));
    }

    #[test]
    fn the_failover_group_is_matched_by_its_pair_and_names_the_partner() {
        let m = mi("Ready", false);
        let groups = Lazy::Loaded(vec![
            json!({"id": format!("{}/providers/Microsoft.Sql/locations/westeurope/instanceFailoverGroups/fog-other", RG), "name": "fog-other",
                   "properties": {"managedInstancePairs": [{"primaryManagedInstanceId": mi_id("other"), "partnerManagedInstanceId": mi_id("other-dr")}]}}),
            json!({"id": format!("{}/providers/Microsoft.Sql/locations/westeurope/instanceFailoverGroups/fog-orders", RG), "name": "fog-orders",
                   "properties": {"replicationRole": "Primary", "replicationState": "CATCH_UP", "secondaryType": "Geo",
                                  "readWriteEndpoint": {"failoverPolicy": "Automatic", "failoverWithDataLossGracePeriodMinutes": 60},
                                  "readOnlyEndpoint": {"failoverPolicy": "Disabled"},
                                  "partnerRegions": [{"location": "northeurope", "replicationRole": "Secondary"}],
                                  "managedInstancePairs": [{"primaryManagedInstanceId": mi_id("sqlmi-prod"), "partnerManagedInstanceId": mi_id("sqlmi-dr")}]}}),
        ]);
        let lines = texts(&failover_group_rows(&m, Some(&groups)));
        assert!(lines.contains("Failover group · fog-orders") && !lines.contains("fog-other"), "{}", lines);
        assert!(lines.contains("Failover = Automatic after 60 min (data loss allowed)"), "{}", lines);
        assert!(lines.contains(&format!("Partner instance · sqlmi-dr = {}", mi_id("sqlmi-dr"))), "{}", lines);
        assert!(texts(&failover_group_rows(&m, Some(&Lazy::Loaded(vec![])))).contains("No failover group"));
        assert_eq!(
            failover_groups_path(&m).unwrap(),
            format!("{}/providers/Microsoft.Sql/locations/westeurope/instanceFailoverGroups", RG)
        );
    }

    #[test]
    fn a_database_sas_token_is_dropped_and_an_offline_one_flagged() {
        let d = without_sas(&json!({"name": "orders", "properties": {"status": "Offline", "storageContainerSasToken": "never-shown"}}));
        assert!(!d.to_string().contains("never-shown"));
        let lines = texts(&instance_database_rows(&mi("Ready", false), Some(&Lazy::Loaded(vec![d]))));
        assert!(lines.contains("orders = ⚠ Offline"), "{}", lines);
    }

    #[test]
    fn a_pool_counts_its_instances_vcores() {
        let pool = InstancePoolRow::from_json(
            &json!({"id": format!("{}/providers/Microsoft.Sql/instancePools/pool-1", RG), "name": "pool-1", "location": "westeurope",
                    "sku": {"name": "GP_Gen5", "tier": "GeneralPurpose", "family": "Gen5"}, "properties": {"vCores": 16, "licenseType": "LicenseIncluded"}}),
            None,
        )
        .unwrap();
        let mut v = serde_json::to_value(json!({"id": mi_id("in-pool"), "name": "in-pool", "location": "westeurope",
            "sku": {"name": "GP_Gen5"}, "properties": {"vCores": 4, "state": "Ready", "instancePoolId": format!("{}/providers/Microsoft.Sql/instancePools/pool-1", RG)}})).unwrap();
        let inside = ManagedInstanceRow::from_json(&v, None).unwrap();
        v["properties"]["instancePoolId"] = json!(null);
        let warm: Vec<Box<dyn Resource>> = vec![Box::new(inside), Box::new(mi("Ready", false))];
        let lines = texts(&pool.instance_rows(Warm::Rows(&warm)));
        assert!(lines.contains("in-pool · 4 vCores · Ready") && !lines.contains("sqlmi-prod"), "{}", lines);
        assert!(lines.contains("vCores used = 4 of 16"), "{}", lines);
        assert!(pool.cli_command().unwrap().starts_with("az sql instance-pool show -n pool-1 -g rg-data"));
    }

    #[test]
    fn section_labels_keep_the_shared_order() {
        for d in [&MANAGED_INSTANCE_SECTIONS, &INSTANCE_POOL_SECTIONS] {
            let labels: Vec<&str> = d.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels[0], "Overview");
            assert_eq!(&labels[labels.len() - 4..], &["Access", "Activity", "Related", "Tags"]);
            assert!(labels.len() <= 10, "digit keys: {labels:?}");
        }
    }
}
