//! The Redis service (issue #29): Azure Cache for Redis
//! (`Microsoft.Cache/redis`) and Azure Managed Redis
//! (`Microsoft.Cache/redisEnterprise`), two subscription-wide lists. A
//! cache's firewall rules and geo-replication links, and a Managed Redis
//! cluster's databases, are lazy sections: one call per parent each, so
//! never sub-tabs (CLAUDE.md: a sub-tab is one subscription-wide list).
//!
//! Metadata only. Access keys are the `listKeys` POST on both types, which
//! nebaz never sends; the guard names the `az` commands that print them.
//! The cache GET body can still carry credentials: `accessKeys` (filled on
//! create responses) and the persistence storage connection strings under
//! `redisConfiguration`. They are removed before the row keeps the JSON
//! ([`without_secrets`]), so no section, search or raw view (`e`) shows
//! them. A cache's host name is data plane: shown as text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, summary_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows, related_rows_with, tag_rows, ArmBase,
    Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable `Microsoft.Cache/redis` version (azure-rest-api-specs,
/// 2026-10-24). The live check confirms it.
pub const REDIS_API_VERSION: &str = "2024-11-01";
/// The newest stable `Microsoft.Cache/redisEnterprise` version
/// (azure-rest-api-specs, 2026-10-24). The live check confirms it.
pub const REDIS_ENTERPRISE_API_VERSION: &str = "2026-09-01";
const CACHES_PATH: &str = "/providers/Microsoft.Cache/redis";
const CLUSTERS_PATH: &str = "/providers/Microsoft.Cache/redisEnterprise";

crate::sections! {
    pub enum RedisCacheDetailSection,
    pub static REDIS_CACHE_SECTIONS = [
        Overview "Overview",
        Security "Security",
        Network "Network" => crate::app::App::trigger_redis_firewall,
        GeoReplication "Geo-replication" => crate::app::App::trigger_redis_linked_servers,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_redis_linked_servers,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ManagedRedisDetailSection,
    pub static MANAGED_REDIS_SECTIONS = [
        Overview "Overview",
        Security "Security",
        Network "Network",
        Databases "Databases" => crate::app::App::trigger_redis_databases,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Credentials out ───────────────────────────────────────────────────

/// Remove every credential a GET body can carry, wherever it sits:
/// `accessKeys` (keys on a create response, or a database's), and any
/// `redisConfiguration` entry naming a connection string (the RDB and AOF
/// storage account connection strings).
fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.remove("accessKeys");
            map.retain(|k, _| !k.to_ascii_lowercase().contains("connection-string"));
            map.values_mut().for_each(scrub);
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every credential under `properties` removed: what a row
/// parses and keeps for `e`. Tags and the envelope are untouched.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(p) = v.get_mut("properties") {
        scrub(p);
    }
    v
}

/// The envelope of a scrubbed body. `Microsoft.Cache` returns a
/// display-name location (`West Europe`); stored as `westeurope` so `R`
/// matches.
fn base_of(v: &Value, tenant: Option<&str>) -> Option<ArmBase> {
    let mut base = ArmBase::from_json(v, tenant)?;
    base.location = base.location.replace(' ', "");
    Some(base)
}

// ── What both types share ─────────────────────────────────────────────

/// A private endpoint connection: the endpoint's id (Enter jumps) and its
/// approval status.
#[derive(Debug, Clone)]
pub struct PrivateEndpointLink {
    pub id: String,
    pub status: Option<String>,
}

fn private_endpoints(v: &Value) -> Vec<PrivateEndpointLink> {
    json::arr(v, "/properties/privateEndpointConnections")
        .iter()
        .filter_map(|c| {
            Some(PrivateEndpointLink {
                id: json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                status: json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
            })
        })
        .collect()
}

fn private_endpoint_rows(pes: &[PrivateEndpointLink]) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if pes.is_empty() {
        lines.push(("Private endpoints".into(), "-".into()));
    }
    for pe in pes {
        lines.push((format!("Private endpoint · {}", name_of_id(&pe.id)), pe.id.clone()));
        let status = match pe.status.as_deref() {
            Some(s) if !s.eq_ignore_ascii_case("approved") => format!("⚠ {}", s),
            s => json::opt(s.map(str::to_string)),
        };
        lines.push(("  Connection".into(), status));
    }
    lines
}

/// The managed identity block both types carry.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub kind: Option<String>,
    pub principal_id: Option<String>,
    pub user_ids: Vec<String>,
}

impl Identity {
    fn from_json(v: &Value) -> Identity {
        Identity {
            kind: json::str_at(v, "/identity/type"),
            principal_id: json::str_at(v, "/identity/principalId"),
            user_ids: json::user_identity_ids(v),
        }
    }

    fn rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Identity".into(), json::opt(self.kind.clone()))];
        if self.kind.as_deref().is_some_and(|t| t.to_lowercase().contains("systemassigned")) {
            lines.push(("  System-assigned principal".into(), json::opt(self.principal_id.clone())));
        }
        for id in &self.user_ids {
            lines.push((format!("  User-assigned · {}", name_of_id(id)), id.clone()));
        }
        lines
    }

    fn related(&self, v: &mut Vec<(String, String)>) {
        for id in &self.user_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
    }
}

/// `1.0` / `1.1` are flagged: both are retired for Redis.
fn tls_label(min_tls: &Option<String>) -> String {
    match min_tls.as_deref() {
        Some(v @ ("1.0" | "1.1")) => format!("⚠ {}", v),
        Some(v) => v.to_string(),
        None => "- (service default)".into(),
    }
}

fn zones_label(zones: &[String]) -> String {
    json::join(zones)
}

/// `-n {name} -g {rg} --subscription {sub}`: what `az redis
/// firewall-rules list` and `server-link list` take (`id_part=None`).
fn name_args(name: &str, id: &str) -> String {
    match (resource_group_of(id), subscription_of(id)) {
        (Some(rg), Some(sub)) => {
            format!("-n {} -g {} --subscription {}", shell_quote(name), shell_quote(rg), shell_quote(sub))
        }
        _ => format!("-n {}", shell_quote(name)),
    }
}

// ── Azure Cache for Redis ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RedisCacheRow {
    pub base: ArmBase,
    pub sku_name: Option<String>,
    pub sku_family: Option<String>,
    pub sku_capacity: Option<i64>,
    pub redis_version: Option<String>,
    pub host_name: Option<String>,
    pub port: Option<i64>,
    pub ssl_port: Option<i64>,
    pub non_ssl_port: Option<bool>,
    pub min_tls: Option<String>,
    pub public_network_access: Option<String>,
    pub access_key_auth_disabled: Option<bool>,
    /// `redisConfiguration.aad-enabled`, a string in the API.
    pub entra_auth: Option<String>,
    /// `redisConfiguration.authnotrequired`: only settable on a
    /// VNet-injected cache, and then no password is needed at all.
    pub auth_not_required: Option<String>,
    pub shard_count: Option<i64>,
    pub replicas_per_primary: Option<i64>,
    pub zones: Vec<String>,
    pub zonal_allocation: Option<String>,
    pub update_channel: Option<String>,
    /// VNet injection (classic, Premium only): the subnet's ARM id.
    pub subnet_id: Option<String>,
    pub static_ip: Option<String>,
    pub maxmemory_policy: Option<String>,
    pub rdb_backup: Option<String>,
    pub rdb_frequency: Option<String>,
    pub aof_backup: Option<String>,
    pub identity: Identity,
    pub private_endpoints: Vec<PrivateEndpointLink>,
    /// `{cache}/linkedServers/{name}` child ids (geo-replication links).
    pub linked_server_ids: Vec<String>,
}

impl RedisCacheRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<RedisCacheRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        let p = "/properties";
        let c = "/properties/redisConfiguration";
        Some(RedisCacheRow {
            sku_name: json::str_at(v, &format!("{}/sku/name", p)),
            sku_family: json::str_at(v, &format!("{}/sku/family", p)),
            sku_capacity: json::int_at(v, &format!("{}/sku/capacity", p)),
            redis_version: json::str_at(v, &format!("{}/redisVersion", p)),
            host_name: json::str_at(v, &format!("{}/hostName", p)),
            port: json::int_at(v, &format!("{}/port", p)),
            ssl_port: json::int_at(v, &format!("{}/sslPort", p)),
            non_ssl_port: json::bool_at(v, &format!("{}/enableNonSslPort", p)),
            min_tls: json::str_at(v, &format!("{}/minimumTlsVersion", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            access_key_auth_disabled: json::bool_at(v, &format!("{}/disableAccessKeyAuthentication", p)),
            entra_auth: json::str_at(v, &format!("{}/aad-enabled", c)),
            auth_not_required: json::str_at(v, &format!("{}/authnotrequired", c)),
            shard_count: json::int_at(v, &format!("{}/shardCount", p)),
            replicas_per_primary: json::int_at(v, &format!("{}/replicasPerPrimary", p))
                .or_else(|| json::int_at(v, &format!("{}/replicasPerMaster", p))),
            zones: json::strings_at(v, "/zones"),
            zonal_allocation: json::str_at(v, &format!("{}/zonalAllocationPolicy", p)),
            update_channel: json::str_at(v, &format!("{}/updateChannel", p)),
            subnet_id: json::arm_id(json::str_at(v, &format!("{}/subnetId", p))),
            static_ip: json::str_at(v, &format!("{}/staticIP", p)),
            maxmemory_policy: json::str_at(v, &format!("{}/maxmemory-policy", c)),
            rdb_backup: json::str_at(v, &format!("{}/rdb-backup-enabled", c)),
            rdb_frequency: json::str_at(v, &format!("{}/rdb-backup-frequency", c)),
            aof_backup: json::str_at(v, &format!("{}/aof-backup-enabled", c)),
            identity: Identity::from_json(v),
            private_endpoints: private_endpoints(v),
            linked_server_ids: json::ids_at(v, &format!("{}/linkedServers", p)),
            base,
        })
    }

    /// Caches report no runtime state: the ladder on `provisioningState`,
    /// except `Disabled` (the subscription is disabled), which is not a
    /// transition.
    fn ladder(&self) -> (ResourceState, String) {
        match self.base.provisioning_state.as_deref() {
            Some(s) if s.eq_ignore_ascii_case("disabled") => state_ladder(None, Some((ResourceState::Unavailable, s))),
            p => state_ladder(p, None),
        }
    }

    /// `Premium P1`, `Standard C2`.
    pub fn sku_label(&self) -> Option<String> {
        let size = match (&self.sku_family, self.sku_capacity) {
            (Some(f), Some(c)) => Some(format!("{}{}", f, c)),
            _ => None,
        };
        summary_of([self.sku_name.clone(), size]).map(|s| s.replace(" · ", " "))
    }

    pub fn is_premium(&self) -> bool {
        self.sku_name.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("premium"))
    }

    fn persistence(&self) -> String {
        let on = |s: &Option<String>| s.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("true"));
        let mut parts = Vec::new();
        if on(&self.rdb_backup) {
            parts.push(match &self.rdb_frequency {
                Some(f) => format!("RDB every {} min", f),
                None => "RDB".into(),
            });
        }
        if on(&self.aof_backup) {
            parts.push("AOF".into());
        }
        if parts.is_empty() {
            "off".into()
        } else {
            parts.join(" · ")
        }
    }

    fn ports(&self) -> String {
        let tls = self.ssl_port.map(|p| format!("{} TLS", p)).unwrap_or_else(|| "6380 TLS".into());
        if self.non_ssl_port == Some(true) {
            format!("{} · ⚠ {} plaintext", tls, self.port.unwrap_or(6379))
        } else {
            tls
        }
    }

    pub fn args(&self) -> String {
        name_args(&self.base.name, &self.base.id)
    }
}

impl Resource for RedisCacheRow {
    arm_row!("Redis cache");
    /// `Premium P1 · 3 shards · VNet`: the SKU and how it is reached.
    fn list_summary(&self) -> Option<String> {
        summary_of([
            self.sku_label(),
            self.shard_count.filter(|n| *n > 0).map(|n| format!("{} shards", n)),
            self.subnet_id.as_ref().map(|_| "VNet".to_string()),
        ])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&REDIS_CACHE_SECTIONS)
    }
    /// The host name is searchable: a connection string's host finds its
    /// cache.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.host_name.clone()),
            json::opt(self.static_ip.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("SKU".into(), json::opt(self.sku_label())),
            ("Shards".into(), json::num(self.shard_count)),
            ("Replicas per primary".into(), json::num(self.replicas_per_primary)),
            ("Redis version".into(), json::opt(self.redis_version.clone())),
            ("Zones".into(), zones_label(&self.zones)),
            ("Zonal allocation".into(), json::opt(self.zonal_allocation.clone())),
            ("Host name".into(), json::opt(self.host_name.clone())),
            ("Ports".into(), self.ports()),
            ("Update channel".into(), json::opt(self.update_channel.clone())),
            ("Max memory policy".into(), json::opt(self.maxmemory_policy.clone())),
            ("Persistence".into(), self.persistence()),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = &self.subnet_id {
            v.push((format!("Subnet {}", name_of_id(s)), s.clone()));
        }
        for pe in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(&pe.id)), pe.id.clone()));
        }
        self.identity.related(&mut v);
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az redis show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn redis_cache_section_lines(
    r: &RedisCacheRow,
    section: RedisCacheDetailSection,
    firewall: Option<&Lazy<Vec<Value>>>,
    linked: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        RedisCacheDetailSection::Overview => overview_rows(r),
        RedisCacheDetailSection::Security => cache_security_rows(r),
        RedisCacheDetailSection::Network => cache_network_rows(r, firewall),
        RedisCacheDetailSection::GeoReplication => {
            if r.linked_server_ids.is_empty() {
                let mut lines = vec![(String::new(), "· not geo-replicated (no linked servers)".to_string())];
                if !r.is_premium() {
                    lines.push((String::new(), "· passive geo-replication needs the Premium tier".into()));
                }
                return lines;
            }
            lazy_list_rows(linked, "Geo-replication", |items| linked_server_rows(items, r))
        }
        RedisCacheDetailSection::Access => crate::azure::services::rendered_by_app(),
        RedisCacheDetailSection::Activity => crate::azure::services::rendered_by_app(),
        RedisCacheDetailSection::Related => {
            // The linked caches, once Geo-replication (this section's hook
            // too) has loaded: the list body only names them as children.
            let linked_caches = match linked {
                Some(Lazy::Loaded(items)) => items
                    .iter()
                    .filter_map(|l| json::arm_id(json::str_at(l, "/properties/linkedRedisCacheId")))
                    .map(|id| (format!("Linked cache {}", name_of_id(&id)), id))
                    .collect(),
                _ => Vec::new(),
            };
            related_rows_with(r, linked_caches)
        }
        RedisCacheDetailSection::Tags => tag_rows(r.tags()),
    }
}

fn cache_security_rows(r: &RedisCacheRow) -> Vec<(String, String)> {
    let non_ssl = match r.non_ssl_port {
        Some(true) => format!("⚠ enabled ({}, plaintext)", r.port.unwrap_or(6379)),
        Some(false) => "disabled".into(),
        None => "-".into(),
    };
    let key_auth = match r.access_key_auth_disabled {
        Some(true) => "disabled (Entra only)".to_string(),
        Some(false) | None => "enabled".to_string(),
    };
    let entra = match r.entra_auth.as_deref() {
        Some(s) if s.eq_ignore_ascii_case("true") => "yes".to_string(),
        Some(_) => "no".to_string(),
        None => "-".to_string(),
    };
    let mut lines = vec![
        ("Non-SSL port".into(), non_ssl),
        ("Min TLS".into(), tls_label(&r.min_tls)),
        ("Entra auth".into(), entra),
        ("Access-key auth".into(), key_auth),
    ];
    if r.auth_not_required.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("true")) {
        lines.push(("Auth required".into(), "⚠ no (authnotrequired: anyone in the VNet can connect)".into()));
    }
    lines.push(("Public network access".into(), json::opt(r.public_network_access.clone())));
    lines.push((String::new(), String::new()));
    lines.extend(r.identity.rows());
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "· access keys are a POST nebaz never sends".into()));
    lines
}

fn cache_network_rows(r: &RedisCacheRow, firewall: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    let public_off = r.public_network_access.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("disabled"));
    let mut lines = vec![("Public network access".into(), json::opt(r.public_network_access.clone()))];
    match &r.subnet_id {
        // The value is the ARM id: Enter jumps to the subnet.
        Some(s) => {
            lines.push((format!("VNet injection · {}", name_of_id(s)), s.clone()));
            lines.push(("  Static IP".into(), json::opt(r.static_ip.clone())));
        }
        None => lines.push(("VNet injection".into(), "- (not injected)".into())),
    }
    lines.push(("Ports".into(), r.ports()));
    lines.push(("Host name".into(), json::opt(r.host_name.clone())));
    lines.push((String::new(), String::new()));
    lines.extend(private_endpoint_rows(&r.private_endpoints));
    if !r.private_endpoints.is_empty() {
        lines.push((String::new(), "· VNet callers resolve the host through its privatelink zone".into()));
    }
    if r.subnet_id.is_some() && !r.private_endpoints.is_empty() {
        lines.push((String::new(), "⚠ VNet injection and private endpoints together are not supported".into()));
    }

    lines.push((String::new(), String::new()));
    lines.push(("Firewall rules".into(), String::new()));
    lines.extend(lazy_list_rows(firewall, "  Rules", |items| {
        let mut out = Vec::new();
        if items.is_empty() {
            out.push((
                String::new(),
                if public_off {
                    "· none (public access is off; rules would not apply)".to_string()
                } else if r.subnet_id.is_some() {
                    "· none: the cache's subnet and NSG decide who reaches it".to_string()
                } else {
                    "⚠ none: every IP may connect (authentication still applies)".to_string()
                },
            ));
        }
        for rule in items {
            let start = json::text(rule, "/properties/startIP");
            let end = json::text(rule, "/properties/endIP");
            let range = if start == end { start } else { format!("{} – {}", start, end) };
            out.push((format!("  {}", json::text(rule, "/name")), range));
        }
        if public_off && !items.is_empty() {
            out.push((String::new(), "· public access is off: these rules do not apply".into()));
        }
        out.push(("  Read command".into(), format!("az redis firewall-rules list {}", r.args())));
        out
    }));
    lines
}

/// The Geo-replication section from `GET {cache}/linkedServers`: each
/// linked cache (Enter jumps), its role and location.
pub fn linked_server_rows(items: &[Value], r: &RedisCacheRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No linked servers".into()));
    }
    for l in items {
        let p = "/properties";
        lines.push((json::text(l, "/name"), String::new()));
        if let Some(id) = json::arm_id(json::str_at(l, &format!("{}/linkedRedisCacheId", p))) {
            lines.push((format!("  Linked cache · {}", name_of_id(&id)), id));
        }
        lines.push(("  Role".into(), json::text(l, &format!("{}/serverRole", p))));
        lines.push(("  Location".into(), json::text(l, &format!("{}/linkedRedisCacheLocation", p))));
        lines.push(("  State".into(), json::text(l, &format!("{}/provisioningState", p))));
        if let Some(h) = json::str_at(l, &format!("{}/geoReplicatedPrimaryHostName", p)) {
            lines.push(("  Geo primary host".into(), h));
        }
        lines.push((String::new(), String::new()));
    }
    lines.push(("Read command".into(), format!("az redis server-link list {}", r.args())));
    lines
}

// ── Azure Managed Redis (Redis Enterprise) ────────────────────────────

#[derive(Debug, Clone)]
pub struct ManagedRedisRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub sku_name: Option<String>,
    pub sku_capacity: Option<i64>,
    pub zones: Vec<String>,
    pub high_availability: Option<String>,
    pub redundancy_mode: Option<String>,
    pub min_tls: Option<String>,
    pub host_name: Option<String>,
    pub resource_state: Option<String>,
    pub redis_version: Option<String>,
    pub public_network_access: Option<String>,
    /// A Key Vault key URL (customer-managed encryption), not an ARM id.
    pub cmk_key_url: Option<String>,
    pub cmk_identity_id: Option<String>,
    pub identity: Identity,
    pub private_endpoints: Vec<PrivateEndpointLink>,
}

impl ManagedRedisRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ManagedRedisRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        let p = "/properties";
        let cmk = "/properties/encryption/customerManagedKeyEncryption";
        Some(ManagedRedisRow {
            kind: json::str_at(v, "/kind"),
            sku_name: json::str_at(v, "/sku/name"),
            sku_capacity: json::int_at(v, "/sku/capacity"),
            zones: json::strings_at(v, "/zones"),
            high_availability: json::str_at(v, &format!("{}/highAvailability", p)),
            redundancy_mode: json::str_at(v, &format!("{}/redundancyMode", p)),
            min_tls: json::str_at(v, &format!("{}/minimumTlsVersion", p)),
            host_name: json::str_at(v, &format!("{}/hostName", p)),
            resource_state: json::str_at(v, &format!("{}/resourceState", p)),
            redis_version: json::str_at(v, &format!("{}/redisVersion", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            cmk_key_url: json::str_at(v, &format!("{}/keyEncryptionKeyUrl", cmk)).filter(|k| !k.is_empty()),
            cmk_identity_id: json::arm_id(json::str_at(
                v,
                &format!("{}/keyEncryptionKeyIdentity/userAssignedIdentityResourceId", cmk),
            )),
            identity: Identity::from_json(v),
            private_endpoints: private_endpoints(v),
            base,
        })
    }

    /// The ladder, then `resourceState`: `Running` is up, `Disabled` and
    /// the `…Failed` words are down, anything else is in transition.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.resource_state.as_deref().map(|s| {
            let l = s.to_lowercase();
            let bucket = if l == "running" {
                ResourceState::Available
            } else if l == "disabled" || l.ends_with("failed") {
                ResourceState::Unavailable
            } else {
                ResourceState::Pending
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// `--cluster-name {name} -g {rg} --subscription {sub}`: what `az
    /// redisenterprise database list` takes (no `--ids`).
    pub fn cluster_args(&self) -> String {
        match (resource_group_of(&self.base.id), subscription_of(&self.base.id)) {
            (Some(rg), Some(sub)) => format!(
                "--cluster-name {} -g {} --subscription {}",
                shell_quote(&self.base.name),
                shell_quote(rg),
                shell_quote(sub)
            ),
            _ => format!("--cluster-name {}", shell_quote(&self.base.name)),
        }
    }
}

impl Resource for ManagedRedisRow {
    arm_row!("Managed Redis");
    /// `Balanced_B5`, plus `no HA` when replication is off.
    fn list_summary(&self) -> Option<String> {
        let no_ha = self
            .high_availability
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case("disabled"))
            .then_some("no HA");
        summary_of([self.sku_name.as_deref(), no_ha])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&MANAGED_REDIS_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.host_name.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("SKU".into(), json::opt(self.sku_name.clone())),
            ("Capacity".into(), json::num(self.sku_capacity)),
            ("High availability".into(), json::opt(self.high_availability.clone())),
            ("Redundancy".into(), json::opt(self.redundancy_mode.clone())),
            ("Zones".into(), zones_label(&self.zones)),
            ("Redis version".into(), json::opt(self.redis_version.clone())),
            ("Resource state".into(), json::opt(self.resource_state.clone())),
            ("Host name".into(), json::opt(self.host_name.clone())),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for pe in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(&pe.id)), pe.id.clone()));
        }
        self.identity.related(&mut v);
        if let Some(i) = &self.cmk_identity_id {
            if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(i)) {
                v.push((format!("Identity {}", name_of_id(i)), i.clone()));
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az redisenterprise show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn managed_redis_section_lines(
    r: &ManagedRedisRow,
    section: ManagedRedisDetailSection,
    databases: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        ManagedRedisDetailSection::Overview => overview_rows(r),
        ManagedRedisDetailSection::Security => {
            let mut lines = vec![
                ("Min TLS".into(), tls_label(&r.min_tls)),
                (
                    "Encryption".into(),
                    if r.cmk_key_url.is_some() { "customer-managed" } else { "service-managed" }.into(),
                ),
            ];
            if let Some(k) = &r.cmk_key_url {
                lines.push(("  Key".into(), k.clone()));
            }
            if let Some(i) = &r.cmk_identity_id {
                lines.push((format!("  Key identity · {}", name_of_id(i)), i.clone()));
            }
            lines.push(("Public network access".into(), json::opt(r.public_network_access.clone())));
            lines.push((String::new(), String::new()));
            lines.extend(r.identity.rows());
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· access-key auth and the client protocol are per database (Databases)".into()));
            lines.push((String::new(), "· access keys are a POST nebaz never sends".into()));
            lines
        }
        ManagedRedisDetailSection::Network => {
            let public = match r.public_network_access.as_deref() {
                Some(s) => s.to_string(),
                None => "- (not set: a cluster from an older API version)".into(),
            };
            let mut lines = vec![
                ("Public network access".into(), public),
                ("Host name".into(), json::opt(r.host_name.clone())),
                (String::new(), String::new()),
            ];
            lines.extend(private_endpoint_rows(&r.private_endpoints));
            lines.push((String::new(), String::new()));
            lines.push((
                String::new(),
                "· no firewall rules or VNet injection on Managed Redis: private endpoints are the private path".into(),
            ));
            lines
        }
        ManagedRedisDetailSection::Databases => {
            lazy_list_rows(databases, "Databases", |items| database_rows(items, r))
        }
        ManagedRedisDetailSection::Access => crate::azure::services::rendered_by_app(),
        ManagedRedisDetailSection::Activity => crate::azure::services::rendered_by_app(),
        ManagedRedisDetailSection::Related => related_rows(r),
        ManagedRedisDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// A linked database's cluster: `…/redisEnterprise/{c}/databases/{d}` →
/// `…/redisEnterprise/{c}`, which nebaz lists (a database is in no list).
fn cluster_of_database(id: &str) -> Option<String> {
    let lower = id.to_ascii_lowercase();
    let at = lower.rfind("/databases/")?;
    Some(id[..at].to_string())
}

/// The Databases section from `GET {cluster}/databases`.
pub fn database_rows(items: &[Value], r: &ManagedRedisRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No databases".into()));
    }
    for d in items {
        let p = "/properties";
        let protocol = match json::str_at(d, &format!("{}/clientProtocol", p)) {
            Some(s) if s.eq_ignore_ascii_case("plaintext") => format!("⚠ {}", s),
            s => json::opt(s),
        };
        let key_auth = match json::str_at(d, &format!("{}/accessKeysAuthentication", p)) {
            Some(s) if s.eq_ignore_ascii_case("disabled") => "disabled (Entra only)".to_string(),
            s => json::opt(s),
        };
        let persistence = {
            let on = |k: &str| json::bool_at(d, &format!("{}/persistence/{}", p, k)) == Some(true);
            let mut parts = Vec::new();
            if on("aofEnabled") {
                parts.push(format!("AOF {}", json::text(d, &format!("{}/persistence/aofFrequency", p))));
            }
            if on("rdbEnabled") {
                parts.push(format!("RDB {}", json::text(d, &format!("{}/persistence/rdbFrequency", p))));
            }
            if parts.is_empty() {
                "off".to_string()
            } else {
                parts.join(" · ")
            }
        };
        let modules: Vec<String> = json::arr(d, &format!("{}/modules", p))
            .iter()
            .map(|m| match json::str_at(m, "/version") {
                Some(v) => format!("{} {}", json::text(m, "/name"), v),
                None => json::text(m, "/name"),
            })
            .collect();
        lines.push((json::text(d, "/name"), String::new()));
        lines.push(("  Port".into(), json::text(d, &format!("{}/port", p))));
        lines.push(("  Client protocol".into(), protocol));
        lines.push(("  Access-key auth".into(), key_auth));
        lines.push(("  Clustering policy".into(), json::text(d, &format!("{}/clusteringPolicy", p))));
        lines.push(("  Eviction policy".into(), json::text(d, &format!("{}/evictionPolicy", p))));
        lines.push(("  Persistence".into(), persistence));
        lines.push(("  Modules".into(), json::join(&modules)));
        lines.push(("  Redis version".into(), json::text(d, &format!("{}/redisVersion", p))));
        lines.push(("  State".into(), json::text(d, &format!("{}/resourceState", p))));
        if let Some(group) = json::str_at(d, &format!("{}/geoReplication/groupNickname", p)) {
            lines.push(("  Geo-replication group".into(), group));
            for l in json::arr(d, &format!("{}/geoReplication/linkedDatabases", p)) {
                let Some(db) = json::str_at(&l, "/id") else { continue };
                let state = json::text(&l, "/state");
                match cluster_of_database(&db).and_then(|c| json::arm_id(Some(c))) {
                    // Enter jumps to the linked cluster's row.
                    Some(c) if !c.eq_ignore_ascii_case(&r.base.id) => {
                        lines.push((format!("    Linked · {} ({})", name_of_id(&c), state), c));
                    }
                    Some(_) => lines.push(("    This cluster".into(), state)),
                    None => lines.push(("    Linked".into(), db)),
                }
            }
        }
        lines.push((String::new(), String::new()));
    }
    lines.push(("Read command".into(), format!("az redisenterprise database list {}", r.cluster_args())));
    lines
}

/// The ARM path of a cache's or cluster's child list (`firewallRules`,
/// `linkedServers`, `databases`).
pub fn redis_child_path(id: &str, child: &str) -> String {
    format!("{}/{}", id.trim_end_matches('/'), child)
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct RedisService {
    scope: Scope,
}

impl RedisService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::ManagedRedis => page
                .iter()
                .filter_map(|v| ManagedRedisRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => page
                .iter()
                .filter_map(|v| RedisCacheRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
        }
    }

    fn path_of(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::ManagedRedis => (CLUSTERS_PATH, REDIS_ENTERPRISE_API_VERSION, "Listing Managed Redis…"),
            _ => (CACHES_PATH, REDIS_API_VERSION, "Listing Redis caches…"),
        }
    }
}

#[async_trait]
impl AzureService for RedisService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Redis
    }

    fn name(&self) -> &str {
        "Redis"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, _) = Self::path_of(view);
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
        let (path, version, message) = Self::path_of(view);
        let r = self
            .scope
            .stream(path, version, &[], service_type, message, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let managed = JumpView::for_arm_id(id) == Some(JumpView::ManagedRedis);
        let view = if managed { JumpView::ManagedRedis } else { JumpView::RedisCaches };
        let (_, version, _) = Self::path_of(view);
        let v = self.scope.get(id, version).await?;
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-cache";

    fn cache_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Cache/Redis/redis-prod", RG),
            "name": "redis-prod",
            "location": "West Europe",
            "zones": ["1", "2"],
            "identity": {"type": "SystemAssigned, UserAssigned", "principalId": "p-1",
                "userAssignedIdentities": {format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-redis", RG): {}}},
            "properties": {
                "provisioningState": "Succeeded",
                "sku": {"name": "Premium", "family": "P", "capacity": 1},
                "redisVersion": "6.0.14",
                "hostName": "redis-prod.cache.example",
                "port": 6379, "sslPort": 6380,
                "enableNonSslPort": true,
                "minimumTlsVersion": "1.2",
                "publicNetworkAccess": "Enabled",
                "disableAccessKeyAuthentication": false,
                "shardCount": 3,
                "replicasPerMaster": 1,
                "replicasPerPrimary": 1,
                "subnetId": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-redis", RG),
                "staticIP": "10.0.4.10",
                "accessKeys": {"primaryKey": "pk-SECRET", "secondaryKey": "sk-SECRET"},
                "redisConfiguration": {
                    "aad-enabled": "true",
                    "maxmemory-policy": "volatile-lru",
                    "rdb-backup-enabled": "true",
                    "rdb-backup-frequency": "60",
                    "rdb-storage-connection-string": "DefaultEndpointsProtocol=https;AccountKey=rdb-SECRET",
                    "aof-storage-connection-string-0": "AccountKey=aof-SECRET"
                },
                "linkedServers": [{"id": format!("{}/providers/Microsoft.Cache/Redis/redis-prod/linkedServers/redis-dr", RG)}],
                "privateEndpointConnections": [{"properties": {
                    "privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-redis", RG)},
                    "privateLinkServiceConnectionState": {"status": "Pending"}}}]
            }
        })
    }

    fn cluster_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Cache/redisEnterprise/amr-prod", RG),
            "name": "amr-prod",
            "location": "West Europe",
            "kind": "v2",
            "sku": {"name": "Balanced_B5"},
            "zones": ["1", "2", "3"],
            "properties": {
                "provisioningState": "Succeeded",
                "resourceState": "Running",
                "highAvailability": "Disabled",
                "minimumTlsVersion": "1.2",
                "hostName": "amr-prod.westeurope.example",
                "redisVersion": "7.4",
                "publicNetworkAccess": "Disabled",
                "encryption": {"customerManagedKeyEncryption": {
                    "keyEncryptionKeyUrl": "https://kv.example/keys/k/1",
                    "keyEncryptionKeyIdentity": {"identityType": "userAssignedIdentity",
                        "userAssignedIdentityResourceId": format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-cmk", RG)}}},
                "privateEndpointConnections": [{"properties": {
                    "privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-amr", RG)},
                    "privateLinkServiceConnectionState": {"status": "Approved"}}}]
            }
        })
    }

    fn everything(row: &RedisCacheRow, firewall: Option<&Lazy<Vec<Value>>>, linked: Option<&Lazy<Vec<Value>>>) -> String {
        REDIS_CACHE_SECTIONS
            .sections
            .iter()
            .enumerate()
            .flat_map(|(i, _)| redis_cache_section_lines(row, RedisCacheDetailSection::from_index(i), firewall, linked))
            .map(|(k, v)| format!("{k}{v}"))
            .collect::<String>()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = REDIS_CACHE_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Security", "Network", "Geo-replication", "Access", "Activity", "Related", "Tags"]);
        let labels: Vec<&str> = MANAGED_REDIS_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Security", "Network", "Databases", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn keys_and_storage_connection_strings_never_reach_the_row() {
        let row = RedisCacheRow::from_json(&cache_json(), None).unwrap();
        let all = everything(&row, None, None) + &row.search_text() + &row.base.raw;
        for secret in ["pk-SECRET", "sk-SECRET", "rdb-SECRET", "aof-SECRET", "AccountKey"] {
            assert!(!all.contains(secret), "{secret} leaked");
        }
        // What is not a secret stays in the raw view.
        assert!(row.base.raw.contains("maxmemory-policy"));
        // Database bodies are scrubbed too.
        let db = without_secrets(&serde_json::json!({"properties": {"accessKeys": {"primaryKey": "x"}, "port": 10000}}));
        assert!(db.pointer("/properties/accessKeys").is_none());
        assert_eq!(db.pointer("/properties/port"), Some(&serde_json::json!(10000)));
    }

    #[test]
    fn cache_row_reads_sku_security_and_network() {
        let row = RedisCacheRow::from_json(&cache_json(), None).unwrap();
        assert_eq!(row.base.location, "westeurope");
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.list_summary().as_deref(), Some("Premium P1 · 3 shards · VNet"));
        assert_eq!(row.cli_command().unwrap(), format!("az redis show --ids {}/providers/Microsoft.Cache/Redis/redis-prod", RG));

        let sec = redis_cache_section_lines(&row, RedisCacheDetailSection::Security, None, None);
        assert_eq!(sec[0], ("Non-SSL port".to_string(), "⚠ enabled (6379, plaintext)".to_string()));
        assert!(sec.iter().any(|(k, v)| k == "Entra auth" && v == "yes"));
        assert!(sec.iter().any(|(k, v)| k == "Access-key auth" && v == "enabled"));
        assert!(sec.iter().any(|(k, _)| k == "  User-assigned · id-redis"));

        let net = redis_cache_section_lines(&row, RedisCacheDetailSection::Network, None, None);
        assert!(net.iter().any(|(k, v)| k == "VNet injection · snet-redis" && v.ends_with("/subnets/snet-redis")));
        assert!(net.iter().any(|(k, v)| k == "  Connection" && v == "⚠ Pending"));
        assert!(net.iter().any(|(_, v)| v.contains("not supported")), "VNet + PE flagged");
        assert!(net.iter().any(|(k, v)| k == "  Rules" && v == "Loading…"));

        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        assert!(related.contains(&"Subnet snet-redis".to_string()));
        assert!(related.contains(&"Private endpoint pe-redis".to_string()));
        assert!(related.contains(&"Identity id-redis".to_string()));
    }

    #[test]
    fn disabled_cache_is_unavailable_and_a_transition_is_pending() {
        let mut v = cache_json();
        v["properties"]["provisioningState"] = "Disabled".into();
        let row = RedisCacheRow::from_json(&v, None).unwrap();
        assert_eq!((row.state(), row.state_label()), (ResourceState::Unavailable, "disabled".to_string()));
        v["properties"]["provisioningState"] = "Scaling".into();
        let row = RedisCacheRow::from_json(&v, None).unwrap();
        assert_eq!(row.state(), ResourceState::Pending);
    }

    #[test]
    fn firewall_rules_render_and_an_open_cache_is_flagged() {
        let mut v = cache_json();
        v["properties"].as_object_mut().unwrap().remove("subnetId");
        let row = RedisCacheRow::from_json(&v, None).unwrap();
        let empty = Lazy::Loaded(Vec::new());
        let net = redis_cache_section_lines(&row, RedisCacheDetailSection::Network, Some(&empty), None);
        assert!(net.iter().any(|(_, v)| v.starts_with("⚠ none: every IP")));
        let rules = Lazy::Loaded(vec![
            serde_json::json!({"name": "office", "properties": {"startIP": "203.0.113.0", "endIP": "203.0.113.255"}}),
            serde_json::json!({"name": "ci", "properties": {"startIP": "198.51.100.7", "endIP": "198.51.100.7"}}),
        ]);
        let net = redis_cache_section_lines(&row, RedisCacheDetailSection::Network, Some(&rules), None);
        assert!(net.iter().any(|(k, v)| k == "  office" && v == "203.0.113.0 – 203.0.113.255"));
        assert!(net.iter().any(|(k, v)| k == "  ci" && v == "198.51.100.7"));
        assert_eq!(
            net.last().unwrap().1,
            "az redis firewall-rules list -n redis-prod -g rg-cache --subscription 0000"
        );
        assert_eq!(
            redis_child_path(&row.base.id, "firewallRules"),
            format!("{}/providers/Microsoft.Cache/Redis/redis-prod/firewallRules", RG)
        );
    }

    #[test]
    fn geo_replication_links_the_linked_cache_into_related() {
        let row = RedisCacheRow::from_json(&cache_json(), None).unwrap();
        let dr = "/subscriptions/1111/resourceGroups/rg-dr/providers/Microsoft.Cache/Redis/redis-dr".to_string();
        let linked = Lazy::Loaded(vec![serde_json::json!({
            "id": format!("{}/linkedServers/redis-dr", row.base.id), "name": "redis-dr",
            "properties": {"linkedRedisCacheId": dr, "linkedRedisCacheLocation": "North Europe",
                "serverRole": "Secondary", "provisioningState": "Succeeded"}
        })]);
        let geo = redis_cache_section_lines(&row, RedisCacheDetailSection::GeoReplication, None, Some(&linked));
        assert!(geo.iter().any(|(k, v)| k == "  Linked cache · redis-dr" && *v == dr));
        assert!(geo.iter().any(|(k, v)| k == "  Role" && v == "Secondary"));
        let related = redis_cache_section_lines(&row, RedisCacheDetailSection::Related, None, Some(&linked));
        assert!(related.iter().any(|(k, v)| k == "Linked cache redis-dr" && *v == dr));
        assert!(related.last().unwrap().1.starts_with('⏎'));

        // No linked servers: a note, no call needed.
        let mut v = cache_json();
        v["properties"]["linkedServers"] = serde_json::json!([]);
        let alone = RedisCacheRow::from_json(&v, None).unwrap();
        let geo = redis_cache_section_lines(&alone, RedisCacheDetailSection::GeoReplication, None, None);
        assert!(geo[0].1.contains("not geo-replicated"));
    }

    #[test]
    fn managed_redis_reads_state_security_network_and_databases() {
        let row = ManagedRedisRow::from_json(&cluster_json(), None).unwrap();
        assert_eq!((row.state(), row.state_label()), (ResourceState::Available, "running".to_string()));
        assert_eq!(row.list_summary().as_deref(), Some("Balanced_B5 · no HA"));
        assert!(row.cli_command().unwrap().starts_with("az redisenterprise show --ids "));
        let sec = managed_redis_section_lines(&row, ManagedRedisDetailSection::Security, None);
        assert!(sec.iter().any(|(k, v)| k == "Encryption" && v == "customer-managed"));
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        assert!(related.contains(&"Identity id-cmk".to_string()));
        assert!(related.contains(&"Private endpoint pe-amr".to_string()));
        let net = managed_redis_section_lines(&row, ManagedRedisDetailSection::Network, None);
        assert!(net.iter().any(|(k, v)| k == "  Connection" && v == "Approved"));

        let other = "/subscriptions/0000/resourceGroups/rg-dr/providers/Microsoft.Cache/redisEnterprise/amr-dr".to_string();
        let dbs = Lazy::Loaded(vec![serde_json::json!({
            "name": "default",
            "properties": {"port": 10000, "clientProtocol": "Plaintext", "clusteringPolicy": "OSSCluster",
                "evictionPolicy": "NoEviction", "accessKeysAuthentication": "Disabled",
                "persistence": {"aofEnabled": true, "aofFrequency": "1s"},
                "modules": [{"name": "RediSearch", "version": "2.8"}],
                "geoReplication": {"groupNickname": "grp", "linkedDatabases": [
                    {"id": format!("{}/databases/default", row.base.id), "state": "Linked"},
                    {"id": format!("{}/databases/default", other), "state": "Linked"}
                ]}}
        })]);
        let lines = managed_redis_section_lines(&row, ManagedRedisDetailSection::Databases, Some(&dbs));
        assert!(lines.iter().any(|(k, v)| k == "  Client protocol" && v == "⚠ Plaintext"));
        assert!(lines.iter().any(|(k, v)| k == "  Access-key auth" && v == "disabled (Entra only)"));
        assert!(lines.iter().any(|(k, v)| k == "  Persistence" && v == "AOF 1s"));
        assert!(lines.iter().any(|(k, v)| k == "  Modules" && v == "RediSearch 2.8"));
        assert!(lines.iter().any(|(k, v)| k == "    Linked · amr-dr (Linked)" && *v == other));
        assert!(lines.iter().any(|(k, _)| k == "    This cluster"));
        assert_eq!(
            lines.last().unwrap().1,
            "az redisenterprise database list --cluster-name amr-prod -g rg-cache --subscription 0000"
        );
    }
}
