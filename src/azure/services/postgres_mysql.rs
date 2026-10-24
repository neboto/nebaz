//! The PostgreSQL & MySQL service (issue #28): Azure Database flexible
//! servers for both engines, two subscription-wide lists
//! (`Microsoft.DBforPostgreSQL/flexibleServers`,
//! `Microsoft.DBforMySQL/flexibleServers`). Single Server is retired and
//! stays out. The two bodies are the same shape bar a few names, so one
//! row type carries both, told apart by [`Engine`].
//!
//! A server's databases, firewall rules, Entra admins and server
//! parameters are per-server lists: lazy sections, one call each, on
//! demand (CLAUDE.md: a sub-tab is one subscription-wide list). Of the
//! parameters only the TLS and auth ones are rendered.
//!
//! `administratorLoginPassword` is write-only in the API, and MySQL's
//! `importSourceProperties.sasToken` is create-only; both are stripped
//! from the body before the row keeps it ([`without_credentials`]), so no
//! section, search or `e` view could show one even if ARM ever echoed it.
//! The server FQDN is a data-plane host, shown as text and never
//! requested.

use crate::azure::resource::{
    arm_type_chain, name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of,
    Resource, ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    finish_stream, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version that has been out long enough to be served
/// in every region (azure-rest-api-specs, 2026-10-24). `2026-10-01` is in
/// the specs since mid-October 2026 and carries the same fields.
pub const POSTGRES_API_VERSION: &str = "2025-08-01";
/// The newest stable version in azure-rest-api-specs (2026-10-24).
pub const MYSQL_API_VERSION: &str = "2024-12-30";

/// Which flexible server a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    Mysql,
}

impl Engine {
    /// The engine an ARM id belongs to, from its provider namespace.
    pub fn of_id(id: &str) -> Option<Engine> {
        let (ns, chain) = arm_type_chain(id)?;
        if chain.first().map(String::as_str) != Some("flexibleservers") {
            return None;
        }
        match ns.as_str() {
            "microsoft.dbforpostgresql" => Some(Engine::Postgres),
            "microsoft.dbformysql" => Some(Engine::Mysql),
            _ => None,
        }
    }

    pub fn of_view(view: JumpView) -> Engine {
        match view {
            JumpView::MysqlServers => Engine::Mysql,
            _ => Engine::Postgres,
        }
    }

    fn list_path(self) -> &'static str {
        match self {
            Engine::Postgres => "/providers/Microsoft.DBforPostgreSQL/flexibleServers",
            Engine::Mysql => "/providers/Microsoft.DBforMySQL/flexibleServers",
        }
    }

    pub fn api_version(self) -> &'static str {
        match self {
            Engine::Postgres => POSTGRES_API_VERSION,
            Engine::Mysql => MYSQL_API_VERSION,
        }
    }

    /// The row's `resource_type` (and the headless contract's key).
    pub fn kind(self) -> &'static str {
        match self {
            Engine::Postgres => "PostgreSQL server",
            Engine::Mysql => "MySQL server",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Engine::Postgres => "PostgreSQL",
            Engine::Mysql => "MySQL",
        }
    }

    /// The parameters the Parameters section renders, in order.
    fn notable_parameters(self) -> &'static [&'static str] {
        match self {
            Engine::Postgres => &[
                "require_secure_transport",
                "ssl_min_protocol_version",
                "ssl_max_protocol_version",
                "password_encryption",
                "pgbouncer.enabled",
                "max_connections",
            ],
            Engine::Mysql => &["require_secure_transport", "tls_version", "aad_auth_only", "max_connections"],
        }
    }

    /// Databases the engine creates itself, listed last as a note.
    fn system_databases(self) -> &'static [&'static str] {
        match self {
            Engine::Postgres => &["postgres", "azure_maintenance", "azure_sys"],
            Engine::Mysql => &["information_schema", "mysql", "performance_schema", "sys"],
        }
    }

}

/// The read command each lazy section ends with. `firewall-rule list`
/// names the server with `--name` on MySQL and `--server-name` on
/// PostgreSQL; the rest take `--server-name` (azure-cli `_params.py`).
#[derive(Debug, Clone, Copy)]
enum ReadList {
    Databases,
    Firewall,
    Admins,
    TlsParameter,
}

crate::sections! {
    pub enum FlexibleServerDetailSection,
    pub static FLEXIBLE_SERVER_SECTIONS = [
        Overview "Overview",
        Networking "Networking",
        Firewall "Firewall" => crate::app::App::trigger_flex_firewall,
        Security "Security" => crate::app::App::trigger_flex_admins,
        Parameters "Parameters" => crate::app::App::trigger_flex_parameters,
        HaBackup "HA & backup",
        Databases "Databases" => crate::app::App::trigger_flex_databases,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

/// The body with every credential under `properties` removed: what a row
/// parses and keeps for `e`. `administratorLoginPassword` and the import
/// source's SAS token are write-only, and a `storageUrl` loses its query
/// (where a SAS would ride).
pub fn without_credentials(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(p) = v.get_mut("properties").and_then(Value::as_object_mut) {
        p.remove("administratorLoginPassword");
        if let Some(import) = p.get_mut("importSourceProperties").and_then(Value::as_object_mut) {
            import.remove("sasToken");
            if let Some(Value::String(url)) = import.get_mut("storageUrl") {
                if let Some(q) = url.find('?') {
                    url.truncate(q);
                }
            }
        }
    }
    v
}

/// One private endpoint connection on the server.
#[derive(Debug, Clone)]
pub struct EndpointConnection {
    pub endpoint_id: String,
    pub status: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FlexibleServerRow {
    pub base: ArmBase,
    pub engine: Engine,
    pub version: Option<String>,
    /// PostgreSQL's `minorVersion`, MySQL's `fullVersion`.
    pub full_version: Option<String>,
    pub state: Option<String>,
    pub fqdn: Option<String>,
    pub admin_login: Option<String>,
    pub sku_name: Option<String>,
    pub sku_tier: Option<String>,
    pub storage_gb: Option<i64>,
    pub storage_autogrow: Option<String>,
    pub storage_iops: Option<i64>,
    /// PostgreSQL: the disk tier (`P20`) or type; MySQL: the storage SKU.
    pub storage_kind: Option<String>,
    pub auto_io_scaling: Option<String>,
    pub zone: Option<String>,
    pub created: Option<String>,
    // Network
    pub public_network_access: Option<String>,
    pub delegated_subnet_id: Option<String>,
    pub private_dns_zone_id: Option<String>,
    pub private_endpoints: Vec<EndpointConnection>,
    // Auth (PostgreSQL's authConfig; MySQL has none on the body)
    pub password_auth: Option<String>,
    pub entra_auth: Option<String>,
    // HA, backup, replication
    pub ha_mode: Option<String>,
    pub ha_state: Option<String>,
    pub standby_zone: Option<String>,
    pub backup_retention_days: Option<i64>,
    pub geo_backup: Option<String>,
    pub earliest_restore: Option<String>,
    pub backup_interval_hours: Option<i64>,
    pub replication_role: Option<String>,
    pub replica_capacity: Option<i64>,
    pub source_server_id: Option<String>,
    pub maintenance_window: Option<String>,
    // Encryption and identity
    pub encryption_type: Option<String>,
    /// A Key Vault key URL, shown as text; never requested.
    pub key_uri: Option<String>,
    pub key_identity_id: Option<String>,
    pub key_status: Option<String>,
    pub geo_key_uri: Option<String>,
    pub geo_key_identity_id: Option<String>,
    pub identity_type: Option<String>,
    pub principal_id: Option<String>,
    pub user_identity_ids: Vec<String>,
}

impl FlexibleServerRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<FlexibleServerRow> {
        let engine = Engine::of_id(&json::str_at(v, "/id")?)?;
        let v = &without_credentials(v);
        let base = ArmBase::from_json(v, tenant)?;
        let s = |ptr: &str| json::str_at(v, &format!("/properties{}", ptr)).filter(|x| !x.is_empty());
        let i = |ptr: &str| json::int_at(v, &format!("/properties{}", ptr));
        let dns_zone_ptr = match engine {
            Engine::Postgres => "/network/privateDnsZoneArmResourceId",
            Engine::Mysql => "/network/privateDnsZoneResourceId",
        };
        let maintenance_window = match (s("/maintenanceWindow/customWindow"), i("/maintenanceWindow/dayOfWeek")) {
            (Some(c), Some(day)) if c.eq_ignore_ascii_case("enabled") => Some(format!(
                "custom: {} {:02}:{:02} UTC",
                weekday(day),
                i("/maintenanceWindow/startHour").unwrap_or(0),
                i("/maintenanceWindow/startMinute").unwrap_or(0)
            )),
            (Some(_), _) => Some("system-managed".into()),
            _ => None,
        };
        Some(FlexibleServerRow {
            engine,
            version: s("/version"),
            full_version: s("/minorVersion").or_else(|| s("/fullVersion")),
            state: s("/state"),
            fqdn: s("/fullyQualifiedDomainName"),
            admin_login: s("/administratorLogin"),
            sku_name: json::str_at(v, "/sku/name"),
            sku_tier: json::str_at(v, "/sku/tier"),
            storage_gb: i("/storage/storageSizeGB"),
            storage_autogrow: s("/storage/autoGrow"),
            storage_iops: i("/storage/iops"),
            storage_kind: s("/storage/tier").or_else(|| s("/storage/type")).or_else(|| s("/storage/storageSku")),
            auto_io_scaling: s("/storage/autoIoScaling"),
            zone: s("/availabilityZone"),
            created: json::str_at(v, "/systemData/createdAt"),
            public_network_access: s("/network/publicNetworkAccess"),
            delegated_subnet_id: json::arm_id(s("/network/delegatedSubnetResourceId")),
            private_dns_zone_id: json::arm_id(s(dns_zone_ptr)),
            private_endpoints: json::arr(v, "/properties/privateEndpointConnections")
                .iter()
                .filter_map(|c| {
                    Some(EndpointConnection {
                        endpoint_id: json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                        status: json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    })
                })
                .collect(),
            password_auth: s("/authConfig/passwordAuth"),
            entra_auth: s("/authConfig/activeDirectoryAuth"),
            ha_mode: s("/highAvailability/mode"),
            ha_state: s("/highAvailability/state"),
            standby_zone: s("/highAvailability/standbyAvailabilityZone"),
            backup_retention_days: i("/backup/backupRetentionDays"),
            geo_backup: s("/backup/geoRedundantBackup"),
            earliest_restore: s("/backup/earliestRestoreDate"),
            backup_interval_hours: i("/backup/backupIntervalHours"),
            replication_role: s("/replicationRole").or_else(|| s("/replica/role")),
            replica_capacity: i("/replicaCapacity").or_else(|| i("/replica/capacity")),
            source_server_id: json::arm_id(s("/sourceServerResourceId")),
            maintenance_window,
            encryption_type: s("/dataEncryption/type"),
            key_uri: s("/dataEncryption/primaryKeyURI"),
            key_identity_id: json::arm_id(s("/dataEncryption/primaryUserAssignedIdentityId")),
            key_status: s("/dataEncryption/primaryEncryptionKeyStatus"),
            geo_key_uri: s("/dataEncryption/geoBackupKeyURI"),
            geo_key_identity_id: json::arm_id(s("/dataEncryption/geoBackupUserAssignedIdentityId")),
            identity_type: json::str_at(v, "/identity/type"),
            principal_id: json::str_at(v, "/identity/principalId").filter(|p| !p.is_empty()),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "ready" => ResourceState::Available,
                "stopped" => ResourceState::Stopped,
                "disabled" | "inaccessible" => ResourceState::Unavailable,
                "dropping" => ResourceState::Deleting,
                "provisioning" => ResourceState::Creating,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn is_vnet_integrated(&self) -> bool {
        self.delegated_subnet_id.is_some()
    }

    fn public_enabled(&self) -> bool {
        self.public_network_access.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("enabled"))
    }

    /// How a client reaches the server, in one phrase.
    pub fn connectivity(&self) -> &'static str {
        if self.is_vnet_integrated() {
            "private access (VNet integration)"
        } else if self.public_enabled() && !self.private_endpoints.is_empty() {
            "public access + private endpoints"
        } else if self.public_enabled() {
            "public access (firewall rules)"
        } else if !self.private_endpoints.is_empty() {
            "private endpoints only"
        } else {
            "no network path: public access off, no private endpoint"
        }
    }

    /// The VNet the delegated subnet is in.
    fn vnet_id(&self) -> Option<String> {
        let subnet = self.delegated_subnet_id.as_deref()?;
        let at = subnet.to_lowercase().rfind("/subnets/")?;
        Some(subnet[..at].to_string())
    }

    /// `--server-name {server} -g {rg} --subscription {sub}` (the flag
    /// varies; see [`Engine::firewall_server_flag`]).
    fn server_args(&self, flag: &str) -> Option<String> {
        Some(format!(
            "{} {} -g {} --subscription {}",
            flag,
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }

    /// The lazy sections' read commands, each spelled out per engine (the
    /// guard reads every `az` literal's verb). The Entra admin group is
    /// `microsoft-entra-admin` on PostgreSQL since the rename; MySQL kept
    /// `ad-admin`.
    fn read_command(&self, list: ReadList) -> String {
        let args = |flag: &str| self.server_args(flag).unwrap_or_default();
        match (self.engine, list) {
            (Engine::Postgres, ReadList::Databases) => {
                format!("az postgres flexible-server db list {}", args("--server-name"))
            }
            (Engine::Mysql, ReadList::Databases) => format!("az mysql flexible-server db list {}", args("--server-name")),
            (Engine::Postgres, ReadList::Firewall) => {
                format!("az postgres flexible-server firewall-rule list {}", args("--server-name"))
            }
            (Engine::Mysql, ReadList::Firewall) => {
                format!("az mysql flexible-server firewall-rule list {}", args("--name"))
            }
            (Engine::Postgres, ReadList::Admins) => {
                format!("az postgres flexible-server microsoft-entra-admin list {}", args("--server-name"))
            }
            (Engine::Mysql, ReadList::Admins) => {
                format!("az mysql flexible-server ad-admin list {}", args("--server-name"))
            }
            (Engine::Postgres, ReadList::TlsParameter) => format!(
                "az postgres flexible-server parameter show {} -n require_secure_transport",
                args("--server-name")
            ),
            (Engine::Mysql, ReadList::TlsParameter) => format!(
                "az mysql flexible-server parameter show {} -n require_secure_transport",
                args("--server-name")
            ),
        }
    }

    fn sku_text(&self) -> String {
        match (&self.sku_name, &self.sku_tier) {
            (Some(n), Some(t)) => format!("{} · {}", n, t),
            (n, _) => json::opt(n.clone()),
        }
    }

    fn version_text(&self) -> String {
        match (&self.version, &self.full_version) {
            (Some(v), Some(f)) if f.starts_with(v.as_str()) => f.clone(),
            (Some(v), Some(f)) => format!("{} (minor {})", v, f),
            (v, _) => json::opt(v.clone()),
        }
    }

    fn storage_text(&self) -> String {
        let mut parts = Vec::new();
        if let Some(gb) = self.storage_gb {
            parts.push(format!("{} GB", gb));
        }
        if let Some(k) = &self.storage_kind {
            parts.push(k.clone());
        }
        if let Some(a) = &self.storage_autogrow {
            parts.push(format!("autogrow {}", a.to_lowercase()));
        }
        json::join(&[parts.join(" · ")].into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>())
    }

    /// The domain the server's name lives under: its FQDN minus the first
    /// label. A private DNS zone for a VNet-integrated server must end in it.
    fn host_domain(&self) -> Option<&str> {
        self.fqdn.as_deref()?.split_once('.').map(|(_, d)| d)
    }

    /// Every identity the server names, deduplicated: user-assigned, then
    /// the encryption keys' identities.
    fn identities(&self) -> Vec<String> {
        let mut out = self.user_identity_ids.clone();
        for id in [&self.key_identity_id, &self.geo_key_identity_id].into_iter().flatten() {
            if !out.iter().any(|i| i.eq_ignore_ascii_case(id)) {
                out.push(id.clone());
            }
        }
        out
    }
}

fn weekday(d: i64) -> &'static str {
    ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].get(d as usize).copied().unwrap_or("?")
}

impl Resource for FlexibleServerRow {
    fn id(&self) -> &str {
        &self.base.id
    }
    fn name(&self) -> &str {
        &self.base.name
    }
    fn resource_type(&self) -> &str {
        self.engine.kind()
    }
    fn tags(&self) -> &std::collections::HashMap<String, String> {
        &self.base.tags
    }
    fn location(&self) -> Option<&str> {
        Some(&self.base.location)
    }
    fn tenant_id(&self) -> Option<&str> {
        self.base.tenant.as_deref()
    }
    fn raw_content(&self) -> Option<String> {
        Some(self.base.raw.clone())
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&FLEXIBLE_SERVER_SECTIONS)
    }
    /// `16 · Standard_B1ms · VNet`: version, compute, and how it is reached.
    fn list_summary(&self) -> Option<String> {
        let net = if self.is_vnet_integrated() {
            "VNet"
        } else if !self.private_endpoints.is_empty() {
            if self.public_enabled() {
                "public + PE"
            } else {
                "PE"
            }
        } else if self.public_enabled() {
            "public"
        } else {
            "no access"
        };
        crate::azure::resource::summary_of([self.version.clone(), self.sku_name.clone(), Some(net.to_string())])
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.fqdn.clone()),
            json::opt(self.version.clone()),
            json::opt(self.sku_name.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut out = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Engine".into(), self.engine.label().into()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("State".into(), json::opt(self.state.clone())),
            ("Version".into(), self.version_text()),
            ("SKU".into(), self.sku_text()),
            ("Storage".into(), self.storage_text()),
            ("IOPS".into(), json::num(self.storage_iops)),
        ];
        if let Some(a) = &self.auto_io_scaling {
            out.push(("Auto IO scaling".into(), a.clone()));
        }
        out.extend([
            ("Zone".into(), json::opt(self.zone.clone())),
            ("FQDN".into(), json::opt(self.fqdn.clone())),
            ("Connectivity".into(), self.connectivity().into()),
            ("Admin login".into(), json::opt(self.admin_login.clone())),
            ("Created".into(), json::time(self.created.clone())),
        ]);
        out
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(subnet) = &self.delegated_subnet_id {
            v.push((format!("Delegated subnet {}", name_of_id(subnet)), subnet.clone()));
        }
        if let Some(vnet) = self.vnet_id() {
            v.push((format!("VNet {}", name_of_id(&vnet)), vnet));
        }
        if let Some(zone) = &self.private_dns_zone_id {
            v.push((format!("Private DNS zone {}", name_of_id(zone)), zone.clone()));
        }
        for pe in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(&pe.endpoint_id)), pe.endpoint_id.clone()));
        }
        if let Some(src) = &self.source_server_id {
            v.push((format!("Source server {}", name_of_id(src)), src.clone()));
        }
        for id in self.identities() {
            v.push((format!("Identity {}", name_of_id(&id)), id));
        }
        if let Some(p) = &self.principal_id {
            if crate::azure::graph::is_object_id(p) {
                v.push((
                    "Service principal (system identity)".into(),
                    crate::azure::graph::row_id(crate::azure::graph::DirectoryKind::ServicePrincipal, p),
                ));
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        let id = shell_quote(&self.base.id);
        Some(match self.engine {
            Engine::Postgres => format!("az postgres flexible-server show --ids {}", id),
            Engine::Mysql => format!("az mysql flexible-server show --ids {}", id),
        })
    }
}

pub fn flexible_server_section_lines(
    r: &FlexibleServerRow,
    section: FlexibleServerDetailSection,
    lazy: FlexibleServerLazy<'_>,
) -> Vec<(String, String)> {
    match section {
        FlexibleServerDetailSection::Overview => overview_rows(r),
        FlexibleServerDetailSection::Networking => networking_rows(r),
        FlexibleServerDetailSection::Firewall => {
            lazy_list_rows(lazy.firewall, "Firewall", |items| firewall_rows(items, r))
        }
        FlexibleServerDetailSection::Security => security_rows(r, lazy.admins),
        FlexibleServerDetailSection::Parameters => {
            lazy_list_rows(lazy.parameters, "Parameters", |items| parameter_rows(items, r))
        }
        FlexibleServerDetailSection::HaBackup => ha_backup_rows(r),
        FlexibleServerDetailSection::Databases => {
            lazy_list_rows(lazy.databases, "Databases", |items| database_rows(items, r))
        }
        FlexibleServerDetailSection::Access => crate::azure::services::rendered_by_app(),
        FlexibleServerDetailSection::Activity => crate::azure::services::rendered_by_app(),
        FlexibleServerDetailSection::Related => related_rows(r),
        FlexibleServerDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The four lazy lists a server's sections read, all keyed by server id.
#[derive(Default, Clone, Copy)]
pub struct FlexibleServerLazy<'a> {
    pub databases: Option<&'a Lazy<Vec<Value>>>,
    pub firewall: Option<&'a Lazy<Vec<Value>>>,
    pub admins: Option<&'a Lazy<Vec<Value>>>,
    pub parameters: Option<&'a Lazy<Vec<Value>>>,
}

fn note(text: impl Into<String>) -> (String, String) {
    (String::new(), format!("· {}", text.into()))
}

fn blank() -> (String, String) {
    (String::new(), String::new())
}

/// Networking: how the server is reached, the VNet integration (subnet,
/// VNet, private DNS zone, each jumpable), private endpoints with their
/// approval status, and what a caller in another VNet needs.
pub fn networking_rows(r: &FlexibleServerRow) -> Vec<(String, String)> {
    let mut lines = vec![
        ("Connectivity".into(), r.connectivity().into()),
        ("Public network access".into(), json::opt(r.public_network_access.clone())),
        ("FQDN".into(), json::opt(r.fqdn.clone())),
    ];
    match &r.delegated_subnet_id {
        Some(subnet) => {
            lines.push((format!("Delegated subnet · {}", name_of_id(subnet)), subnet.clone()));
            if let Some(vnet) = r.vnet_id() {
                lines.push((format!("VNet · {}", name_of_id(&vnet)), vnet));
            }
        }
        None => lines.push(("Delegated subnet".into(), "- (not VNet-integrated)".into())),
    }
    match &r.private_dns_zone_id {
        Some(zone) => {
            let zone_name = name_of_id(zone);
            lines.push((format!("Private DNS zone · {}", zone_name), zone.clone()));
            if let Some(domain) = r.host_domain() {
                let ok = zone_name.to_lowercase().ends_with(&domain.to_lowercase());
                if !ok {
                    lines.push((String::new(), format!("⚠ the zone does not end in {}: the server name will not resolve through it", domain)));
                }
            }
        }
        None if r.is_vnet_integrated() => lines.push(("Private DNS zone".into(), "⚠ none: the name resolves only with custom DNS".into())),
        None => {}
    }
    if r.private_endpoints.is_empty() {
        lines.push(("Private endpoints".into(), "-".into()));
    }
    for pe in &r.private_endpoints {
        let status = pe.status.as_deref().unwrap_or("-");
        let flag = if status.eq_ignore_ascii_case("approved") { "" } else { "⚠ " };
        lines.push((format!("Private endpoint · {} ({}{})", name_of_id(&pe.endpoint_id), flag, status), pe.endpoint_id.clone()));
    }
    lines.push(blank());
    if r.is_vnet_integrated() {
        lines.push(note("VNet-integrated: no public endpoint, and firewall rules do not apply; the subnet's NSG does (N)"));
        lines.push(note("a caller in another VNet (a Container Apps environment, a Power Platform delegated subnet) needs a peering to this VNet and the private DNS zone linked to its own VNet (zone › VNet links)"));
    } else if !r.private_endpoints.is_empty() {
        lines.push(note("a caller reaching a private endpoint needs its privatelink zone linked to the caller's VNet (the endpoint's DNS section)"));
    }
    if r.public_enabled() {
        lines.push(note("public access is on: who gets in is in Firewall"));
    }
    lines
}

/// Security: the auth modes, the admin login (never its password), the
/// Entra admins (lazy), encryption and identity.
pub fn security_rows(r: &FlexibleServerRow, admins: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    match r.engine {
        Engine::Postgres => {
            let on = |s: &Option<String>| s.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("enabled"));
            let mode = match (on(&r.password_auth), on(&r.entra_auth)) {
                (true, true) => "password and Entra",
                (true, false) => "password only",
                (false, true) => "Entra only",
                (false, false) => "-",
            };
            lines.push(("Authentication".into(), mode.into()));
        }
        Engine::Mysql => lines.push((
            "Authentication".into(),
            "password, and Entra when an admin is set (aad_auth_only in Parameters)".into(),
        )),
    }
    lines.push(("Admin login".into(), json::opt(r.admin_login.clone())));
    lines.push(("TLS".into(), "require_secure_transport and the minimum version are in Parameters".into()));
    lines.push(blank());
    lines.push(("Entra admins".into(), String::new()));
    lines.extend(lazy_list_rows(admins, "  Entra admins", |items| admin_rows(items, r)));
    lines.push(blank());
    let cmk = r.encryption_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("azurekeyvault"));
    lines.push(("Encryption".into(), if cmk { "customer-managed key" } else { "service-managed key" }.into()));
    if let Some(k) = &r.key_uri {
        lines.push(("  Key".into(), k.clone()));
    }
    if let Some(s) = &r.key_status {
        let flag = if s.eq_ignore_ascii_case("valid") { "" } else { "⚠ " };
        lines.push(("  Key status".into(), format!("{}{}", flag, s)));
    }
    if let Some(id) = &r.key_identity_id {
        lines.push((format!("  Key identity · {}", name_of_id(id)), id.clone()));
    }
    if let Some(k) = &r.geo_key_uri {
        lines.push(("  Geo-backup key".into(), k.clone()));
    }
    lines.push(("Identity".into(), json::opt(r.identity_type.clone())));
    if let Some(p) = &r.principal_id {
        if crate::azure::graph::is_object_id(p) {
            lines.push((
                "  System identity".into(),
                crate::azure::graph::row_id(crate::azure::graph::DirectoryKind::ServicePrincipal, p),
            ));
        }
    }
    for id in &r.user_identity_ids {
        lines.push((format!("  User-assigned · {}", name_of_id(id)), id.clone()));
    }
    lines
}

/// The Entra admins from `GET {server}/administrators`. PostgreSQL names
/// the principal type, so a service principal jumps to its Graph row;
/// a user or group (and every MySQL admin, which carries no type) shows
/// its object id as text.
pub fn admin_rows(items: &[Value], r: &FlexibleServerRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "  none".into()));
    }
    for a in items {
        let p = "/properties";
        let (name, kind, oid) = match r.engine {
            Engine::Postgres => (
                json::text(a, &format!("{}/principalName", p)),
                json::str_at(a, &format!("{}/principalType", p)),
                json::str_at(a, &format!("{}/objectId", p)).or_else(|| json::str_at(a, "/name")),
            ),
            Engine::Mysql => (
                json::text(a, &format!("{}/login", p)),
                json::str_at(a, &format!("{}/administratorType", p)),
                json::str_at(a, &format!("{}/sid", p)),
            ),
        };
        let label = match &kind {
            Some(k) => format!("  {} ({})", name, k),
            None => format!("  {}", name),
        };
        let is_sp = kind.as_deref().is_some_and(|k| k.eq_ignore_ascii_case("serviceprincipal"));
        let value = match oid {
            Some(o) if is_sp && crate::azure::graph::is_object_id(&o) => {
                crate::azure::graph::row_id(crate::azure::graph::DirectoryKind::ServicePrincipal, &o)
            }
            Some(o) => format!("object id {}", o),
            None => "-".into(),
        };
        lines.push((label, value));
        if let Some(id) = json::arm_id(json::str_at(a, &format!("{}/identityResourceId", p))) {
            lines.push((format!("    Graph lookup identity · {}", name_of_id(&id)), id));
        }
    }
    lines.push((
        "  Read command".into(),
        r.read_command(ReadList::Admins),
    ));
    lines
}

/// The Parameters section from `GET {server}/configurations`: only the
/// TLS and auth parameters, each with whether it is the default.
pub fn parameter_rows(items: &[Value], r: &FlexibleServerRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    for name in r.engine.notable_parameters() {
        let Some(item) = items.iter().find(|c| json::str_at(c, "/name").as_deref() == Some(*name)) else {
            continue;
        };
        let p = "/properties";
        let value = json::text(item, &format!("{}/value", p));
        let default = json::str_at(item, &format!("{}/defaultValue", p));
        let source = json::str_at(item, &format!("{}/source", p));
        let is_default = source.as_deref() == Some("system-default") || default.as_deref() == Some(value.as_str());
        let mut text = value.clone();
        if *name == "require_secure_transport" && value.eq_ignore_ascii_case("off") {
            text = format!("⚠ {}: unencrypted connections accepted", value);
        }
        if *name == "aad_auth_only" && value.eq_ignore_ascii_case("on") {
            text = format!("{} (Entra only: password logins refused)", value);
        }
        if is_default {
            text.push_str(" (default)");
        } else if let Some(d) = default.filter(|d| !d.is_empty()) {
            text.push_str(&format!(" (default {})", d));
        }
        if json::bool_at(item, &format!("{}/isConfigPendingRestart", p)) == Some(true) {
            text.push_str(" · pending restart");
        }
        lines.push(((*name).to_string(), text));
    }
    if lines.is_empty() {
        lines.push((String::new(), "None of the TLS or auth parameters came back".into()));
    }
    lines.push(blank());
    lines.push(note(format!("{} parameters on the server; only the TLS and auth ones are shown", items.len())));
    lines.push((
        "Read command".into(),
        r.read_command(ReadList::TlsParameter),
    ));
    lines
}

/// HA & backup: high availability, backup retention and redundancy,
/// replication, the maintenance window.
pub fn ha_backup_rows(r: &FlexibleServerRow) -> Vec<(String, String)> {
    let ha_off = r.ha_mode.as_deref().is_none_or(|m| m.eq_ignore_ascii_case("disabled"));
    let mut lines = vec![("HA mode".into(), json::opt(r.ha_mode.clone()))];
    if !ha_off {
        lines.push(("HA state".into(), json::opt(r.ha_state.clone())));
        lines.push(("Standby zone".into(), json::opt(r.standby_zone.clone())));
    }
    lines.push(("Zone".into(), json::opt(r.zone.clone())));
    lines.push(blank());
    lines.push((
        "Backup retention".into(),
        r.backup_retention_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "-".into()),
    ));
    if let Some(h) = r.backup_interval_hours {
        lines.push(("Backup interval".into(), format!("every {} h", h)));
    }
    lines.push(("Geo-redundant backup".into(), json::opt(r.geo_backup.clone())));
    lines.push(("Earliest restore".into(), json::time(r.earliest_restore.clone())));
    lines.push(blank());
    lines.push(("Replication role".into(), json::opt(r.replication_role.clone())));
    lines.push(("Replica capacity".into(), json::num(r.replica_capacity)));
    if let Some(src) = &r.source_server_id {
        lines.push((format!("Source server · {}", name_of_id(src)), src.clone()));
    }
    lines.push(("Maintenance window".into(), json::opt(r.maintenance_window.clone())));
    lines
}

/// The Databases section from `GET {server}/databases`; the engine's own
/// databases listed last as a note.
pub fn database_rows(items: &[Value], r: &FlexibleServerRow) -> Vec<(String, String)> {
    let system = r.engine.system_databases();
    let is_system = |d: &Value| system.contains(&json::text(d, "/name").as_str());
    let mut lines = Vec::new();
    let user: Vec<&Value> = items.iter().filter(|d| !is_system(d)).collect();
    if user.is_empty() {
        lines.push((String::new(), "No user databases".into()));
    }
    for d in user {
        lines.push((
            json::text(d, "/name"),
            format!(
                "{} · {}",
                json::text(d, "/properties/charset"),
                json::text(d, "/properties/collation")
            ),
        ));
    }
    let sys: Vec<String> = items.iter().filter(|d| is_system(d)).map(|d| json::text(d, "/name")).collect();
    if !sys.is_empty() {
        lines.push(blank());
        lines.push(note(format!("system: {}", sys.join(", "))));
    }
    lines.push(blank());
    lines.push(("Read command".into(), r.read_command(ReadList::Databases)));
    lines
}

/// IPv4 dotted quad → u32.
fn ipv4(s: &str) -> Option<u32> {
    s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

/// The Firewall section from `GET {server}/firewallRules`: the
/// allow-Azure rule (0.0.0.0–0.0.0.0, whatever its name) and the whole
/// internet flagged, wide ranges counted. Says when the rules do not
/// apply at all.
pub fn firewall_rows(items: &[Value], r: &FlexibleServerRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if r.is_vnet_integrated() {
        lines.push((String::new(), "⚠ VNet-integrated: firewall rules do not apply".into()));
        lines.push(blank());
    } else if !r.public_enabled() {
        lines.push((String::new(), "· public access is off: these rules admit nothing".into()));
        lines.push(blank());
    }
    if items.is_empty() {
        lines.push((String::new(), "No IP rules".into()));
    }
    for rule in items {
        let name = json::text(rule, "/name");
        let start = json::text(rule, "/properties/startIpAddress");
        let end = json::text(rule, "/properties/endIpAddress");
        let range = if start == end { start.clone() } else { format!("{} – {}", start, end) };
        let text = match (ipv4(&start), ipv4(&end)) {
            (Some(0), Some(0)) => "⚠ allows every Azure service, in any tenant (0.0.0.0)".to_string(),
            (Some(0), Some(u32::MAX)) => format!("⚠ the whole internet ({})", range),
            (Some(a), Some(b)) if b >= a && (b - a) >= 65_535 => {
                format!("{} · ⚠ {} addresses", range, u64::from(b - a) + 1)
            }
            _ => range,
        };
        lines.push((name, text));
    }
    lines.push(blank());
    lines.push((
        "Read command".into(),
        r.read_command(ReadList::Firewall),
    ));
    lines
}

/// The ARM path of a server's child list (`databases`, `firewallRules`,
/// `administrators`, `configurations`).
pub fn flexible_server_child_path(server_id: &str, child: &str) -> String {
    format!("{}/{}", server_id.trim_end_matches('/'), child)
}

/// The api-version a server's child lists take, from its id.
pub fn api_version_for(server_id: &str) -> &'static str {
    Engine::of_id(server_id).unwrap_or(Engine::Postgres).api_version()
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct FlexibleServersService {
    scope: Scope,
}

impl FlexibleServersService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for FlexibleServersService {
    fn service_type(&self) -> ServiceType {
        ServiceType::PostgresMysql
    }

    fn name(&self) -> &str {
        "PostgreSQL & MySQL"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let engine = Engine::of_view(view);
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(engine.list_path(), engine.api_version())
            .await?
            .iter()
            .filter_map(|v| FlexibleServerRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect())
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let engine = Engine::of_view(view);
        let tenant = self.scope.tenant().map(str::to_string);
        let message = format!("Listing {} flexible servers…", engine.label());
        let r = self
            .scope
            .stream(engine.list_path(), engine.api_version(), &[], service_type, &message, &event_tx, |page| {
                page.iter()
                    .filter_map(|v| FlexibleServerRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, api_version_for(id)).await?;
        FlexibleServerRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-data";

    fn net(path: &str) -> String {
        format!("{}/providers/Microsoft.Network/{}", RG, path)
    }

    /// A VNet-integrated PostgreSQL server, the 2025-08-01 list shape.
    fn pg_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-prod", RG),
            "name": "pg-prod",
            "type": "Microsoft.DBforPostgreSQL/flexibleServers",
            "location": "australiaeast",
            "sku": {"name": "Standard_D4ds_v5", "tier": "GeneralPurpose"},
            "systemData": {"createdAt": "2025-06-01T18:30:22.123456Z"},
            "identity": {"type": "SystemAssigned,UserAssigned",
                "principalId": "11111111-2222-3333-4444-555555555555",
                "userAssignedIdentities": {
                    format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-pg", RG): {}
                }},
            "properties": {
                "administratorLogin": "pgadmin",
                // Write-only in the API; a body carrying it must not leak.
                "administratorLoginPassword": "hunter2",
                "authConfig": {"activeDirectoryAuth": "Enabled", "passwordAuth": "Disabled", "tenantId": "t"},
                "availabilityZone": "1",
                "backup": {"backupRetentionDays": 14, "geoRedundantBackup": "Enabled",
                    "earliestRestoreDate": "2026-10-01T00:00:00Z"},
                "dataEncryption": {"type": "AzureKeyVault", "primaryEncryptionKeyStatus": "Invalid",
                    "primaryKeyURI": "https://kv.example/keys/pg/1",
                    "primaryUserAssignedIdentityId": format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-pg", RG)},
                "fullyQualifiedDomainName": "pg-prod.postgres.database.azure.com",
                "highAvailability": {"mode": "ZoneRedundant", "standbyAvailabilityZone": "2", "state": "Healthy"},
                "maintenanceWindow": {"customWindow": "Enabled", "dayOfWeek": 0, "startHour": 2, "startMinute": 30},
                "minorVersion": "5",
                "network": {
                    "delegatedSubnetResourceId": net("virtualNetworks/vnet-data/subnets/snet-pg"),
                    "privateDnsZoneArmResourceId": net("privateDnsZones/pg-prod.private.postgres.database.azure.com"),
                    "publicNetworkAccess": "Disabled"
                },
                "replicationRole": "Primary",
                "replicaCapacity": 5,
                "state": "Ready",
                "storage": {"autoGrow": "Enabled", "iops": 2300, "storageSizeGB": 512, "tier": "P20"},
                "version": "17"
            },
            "tags": {"env": "prod"}
        })
    }

    /// A public MySQL server with a private endpoint and an import source.
    fn mysql_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.DBforMySQL/flexibleServers/my-shop", RG),
            "name": "my-shop",
            "location": "westeurope",
            "sku": {"name": "Standard_B1ms", "tier": "Burstable"},
            "properties": {
                "administratorLogin": "myadmin",
                "administratorLoginPassword": "hunter2",
                "importSourceProperties": {"storageType": "AzureBlob",
                    "storageUrl": "https://acct.example/backups?sv=2024&sig=SAS-SECRET", "sasToken": "SAS-SECRET"},
                "version": "8.0.21",
                "fullVersion": "8.0.39",
                "state": "Stopped",
                "fullyQualifiedDomainName": "my-shop.mysql.database.azure.com",
                "storage": {"storageSizeGB": 20, "iops": 360, "autoGrow": "Enabled", "autoIoScaling": "Enabled", "storageSku": "Premium_LRS"},
                "backup": {"backupRetentionDays": 7, "backupIntervalHours": 24, "geoRedundantBackup": "Disabled"},
                "highAvailability": {"mode": "Disabled", "state": "NotEnabled"},
                "network": {"publicNetworkAccess": "Enabled"},
                "privateEndpointConnections": [{"properties": {
                    "privateEndpoint": {"id": net("privateEndpoints/pe-mysql")},
                    "privateLinkServiceConnectionState": {"status": "Pending"}}}]
            }
        })
    }

    fn row(v: Value) -> FlexibleServerRow {
        FlexibleServerRow::from_json(&v, None).expect("parses")
    }

    fn every_line(r: &FlexibleServerRow) -> String {
        FLEXIBLE_SERVER_SECTIONS
            .sections
            .iter()
            .enumerate()
            .flat_map(|(i, _)| {
                flexible_server_section_lines(r, FlexibleServerDetailSection::from_index(i), FlexibleServerLazy::default())
            })
            .map(|(k, v)| format!("{k}{v}"))
            .collect::<String>()
            + &r.search_text()
            + &r.raw_content().unwrap_or_default()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = FLEXIBLE_SERVER_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            [
                "Overview",
                "Networking",
                "Firewall",
                "Security",
                "Parameters",
                "HA & backup",
                "Databases",
                "Access",
                "Activity",
                "Related",
                "Tags"
            ]
        );
    }

    #[test]
    fn engine_follows_the_provider_namespace() {
        assert_eq!(Engine::of_id(&format!("{}/providers/Microsoft.DBforPostgreSQL/flexibleServers/a", RG)), Some(Engine::Postgres));
        assert_eq!(Engine::of_id(&format!("{}/providers/microsoft.dbformysql/FLEXIBLESERVERS/a", RG)), Some(Engine::Mysql));
        assert_eq!(Engine::of_id(&format!("{}/providers/Microsoft.DBforPostgreSQL/servers/single", RG)), None, "Single Server is out");
        assert_eq!(api_version_for(&format!("{}/providers/Microsoft.DBforMySQL/flexibleServers/a", RG)), MYSQL_API_VERSION);
    }

    #[test]
    fn postgres_row_reads_state_overview_and_never_the_password() {
        let r = row(pg_json());
        assert_eq!(r.resource_type(), "PostgreSQL server");
        assert_eq!(r.state(), ResourceState::Available);
        assert_eq!(r.state_label(), "ready");
        assert_eq!(r.list_summary().as_deref(), Some("17 · Standard_D4ds_v5 · VNet"));
        let overview = r.details();
        assert!(overview.iter().any(|(k, v)| k == "SKU" && v == "Standard_D4ds_v5 · GeneralPurpose"));
        assert!(overview.iter().any(|(k, v)| k == "Storage" && v == "512 GB · P20 · autogrow enabled"));
        assert!(overview.iter().any(|(k, v)| k == "Version" && v == "17 (minor 5)"));
        assert!(overview.iter().any(|(k, v)| k == "Created" && v == "2025-06-01 18:30:22"));
        let everything = every_line(&r);
        assert!(!everything.contains("hunter2"), "the admin password leaked");
        assert!(r.cli_command().unwrap().starts_with("az postgres flexible-server show --ids /subscriptions/"));
    }

    #[test]
    fn mysql_row_strips_the_import_sas_and_reads_its_own_field_names() {
        let r = row(mysql_json());
        assert_eq!(r.resource_type(), "MySQL server");
        assert_eq!(r.state(), ResourceState::Stopped);
        assert_eq!(r.full_version.as_deref(), Some("8.0.39"));
        assert_eq!(r.storage_kind.as_deref(), Some("Premium_LRS"));
        assert_eq!(r.list_summary().as_deref(), Some("8.0.21 · Standard_B1ms · public + PE"));
        let everything = every_line(&r);
        assert!(!everything.contains("hunter2"), "the admin password leaked");
        assert!(!everything.contains("SAS-SECRET"), "the import SAS leaked");
        assert!(r.raw_content().unwrap().contains("https://acct.example/backups\""), "the URL stays, its query goes");
        let ha = ha_backup_rows(&r);
        assert!(ha.iter().any(|(k, v)| k == "Backup interval" && v == "every 24 h"));
        assert!(!ha.iter().any(|(k, _)| k == "Standby zone"), "no standby without HA");
        assert!(r.cli_command().unwrap().starts_with("az mysql flexible-server show --ids "));
    }

    #[test]
    fn networking_shows_the_vnet_integration_and_what_a_caller_needs() {
        let r = row(pg_json());
        let lines = networking_rows(&r);
        assert_eq!(lines[0], ("Connectivity".to_string(), "private access (VNet integration)".to_string()));
        assert!(lines.iter().any(|(k, v)| k == "Delegated subnet · snet-pg" && v.ends_with("/subnets/snet-pg")));
        assert!(lines.iter().any(|(k, v)| k == "VNet · vnet-data" && v.ends_with("/virtualNetworks/vnet-data")));
        assert!(lines.iter().any(|(k, v)| k.starts_with("Private DNS zone · pg-prod.private.") && v.contains("/privateDnsZones/")));
        assert!(!lines.iter().any(|(_, v)| v.contains("does not end in")), "the zone matches the FQDN's domain");
        assert!(lines.iter().any(|(_, v)| v.contains("firewall rules do not apply")));
        assert!(lines.iter().any(|(_, v)| v.contains("Container Apps environment")));

        let mut wrong = pg_json();
        wrong["properties"]["network"]["privateDnsZoneArmResourceId"] = Value::String(net("privateDnsZones/corp.internal"));
        let lines = networking_rows(&row(wrong));
        assert!(lines.iter().any(|(_, v)| v.starts_with("⚠ the zone does not end in")));

        let my = row(mysql_json());
        let lines = networking_rows(&my);
        assert_eq!(lines[0].1, "public access + private endpoints");
        assert!(lines.iter().any(|(k, _)| k == "Private endpoint · pe-mysql (⚠ Pending)"));
    }

    #[test]
    fn related_jumps_to_subnet_vnet_zone_endpoints_identities_and_the_system_principal() {
        let r = row(pg_json());
        let related: Vec<String> = r.related().into_iter().map(|(l, _)| l).collect();
        for want in [
            "Delegated subnet snet-pg",
            "VNet vnet-data",
            "Identity id-pg",
            "Service principal (system identity)",
        ] {
            assert!(related.iter().any(|l| l == want), "{want}: {related:?}");
        }
        assert!(related.iter().any(|l| l.starts_with("Private DNS zone ")));
        assert_eq!(related.iter().filter(|l| *l == "Identity id-pg").count(), 1, "the key identity is deduplicated");
        let sp = r.related().into_iter().find(|(l, _)| l.starts_with("Service principal")).unwrap().1;
        assert_eq!(JumpView::landing_for_arm_id(&sp), Some(JumpView::ServicePrincipals));
        let my: Vec<String> = row(mysql_json()).related().into_iter().map(|(l, _)| l).collect();
        assert!(my.iter().any(|l| l == "Private endpoint pe-mysql"));
    }

    #[test]
    fn security_reads_auth_modes_admins_and_encryption() {
        let r = row(pg_json());
        let admins = vec![
            serde_json::json!({"name": "aaaaaaaa-0000-0000-0000-000000000001", "properties": {
                "principalType": "ServicePrincipal", "principalName": "aca-api",
                "objectId": "aaaaaaaa-0000-0000-0000-000000000001", "tenantId": "t"}}),
            serde_json::json!({"properties": {"principalType": "Group", "principalName": "pg-admins",
                "objectId": "bbbbbbbb-0000-0000-0000-000000000002"}}),
        ];
        let lines = security_rows(&r, Some(&Lazy::Loaded(admins)));
        assert_eq!(lines[0], ("Authentication".to_string(), "Entra only".to_string()));
        assert!(lines.iter().any(|(k, v)| k == "  aca-api (ServicePrincipal)" && v == "graph:/servicePrincipals/aaaaaaaa-0000-0000-0000-000000000001"));
        assert!(lines.iter().any(|(k, v)| k == "  pg-admins (Group)" && v == "object id bbbbbbbb-0000-0000-0000-000000000002"));
        assert!(lines.iter().any(|(_, v)| v == "az postgres flexible-server microsoft-entra-admin list --server-name pg-prod -g rg-data --subscription 0000"));
        assert!(lines.iter().any(|(k, v)| k == "Encryption" && v == "customer-managed key"));
        assert!(lines.iter().any(|(k, v)| k == "  Key status" && v == "⚠ Invalid"));
        assert!(lines.iter().any(|(k, _)| k == "  System identity"));

        let my = row(mysql_json());
        let admins = vec![serde_json::json!({"properties": {"administratorType": "ActiveDirectory", "login": "dba@contoso.com",
            "sid": "cccccccc-0000-0000-0000-000000000003",
            "identityResourceId": format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-graph", RG)}})];
        let lines = security_rows(&my, Some(&Lazy::Loaded(admins)));
        assert!(lines.iter().any(|(k, v)| k == "  dba@contoso.com (ActiveDirectory)" && v == "object id cccccccc-0000-0000-0000-000000000003"));
        assert!(lines.iter().any(|(k, _)| k == "    Graph lookup identity · id-graph"));
        assert!(lines.iter().any(|(_, v)| v.starts_with("az mysql flexible-server ad-admin list --server-name my-shop")));
    }

    #[test]
    fn firewall_flags_allow_azure_the_internet_and_wide_ranges() {
        let my = row(mysql_json());
        let items = vec![
            serde_json::json!({"name": "office", "properties": {"startIpAddress": "203.0.113.0", "endIpAddress": "203.0.113.255"}}),
            serde_json::json!({"name": "AllowAllAzureServicesAndResourcesWithinAzureIps_2026-1-1",
                "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}),
            serde_json::json!({"name": "AllowAll", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}),
            serde_json::json!({"name": "isp", "properties": {"startIpAddress": "100.64.0.0", "endIpAddress": "100.127.255.255"}}),
        ];
        let lines = firewall_rows(&items, &my);
        assert_eq!(lines[0], ("office".to_string(), "203.0.113.0 – 203.0.113.255".to_string()));
        assert!(lines[1].1.starts_with("⚠ allows every Azure service"));
        assert!(lines[2].1.starts_with("⚠ the whole internet"));
        assert_eq!(lines[3].1, "100.64.0.0 – 100.127.255.255 · ⚠ 4194304 addresses");
        assert_eq!(lines.last().unwrap().1, "az mysql flexible-server firewall-rule list --name my-shop -g rg-data --subscription 0000");

        let pg = row(pg_json());
        let lines = flexible_server_section_lines(
            &pg,
            FlexibleServerDetailSection::Firewall,
            FlexibleServerLazy { firewall: Some(&Lazy::Loaded(vec![])), ..Default::default() },
        );
        assert!(lines[0].1.contains("VNet-integrated: firewall rules do not apply"));
        assert!(lines.last().unwrap().1.starts_with("az postgres flexible-server firewall-rule list --server-name pg-prod"));
        assert_eq!(
            flexible_server_child_path(&pg.base.id, "firewallRules"),
            format!("{}/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-prod/firewallRules", RG)
        );
    }

    #[test]
    fn parameters_keep_only_tls_and_auth_and_flag_plaintext() {
        let pg = row(pg_json());
        let items = vec![
            serde_json::json!({"name": "work_mem", "properties": {"value": "4096"}}),
            serde_json::json!({"name": "ssl_min_protocol_version", "properties": {"value": "TLSv1.2", "defaultValue": "TLSv1.2", "source": "system-default"}}),
            serde_json::json!({"name": "require_secure_transport", "properties": {"value": "off", "defaultValue": "on", "source": "user-override"}}),
        ];
        let lines = parameter_rows(&items, &pg);
        assert_eq!(lines[0], ("require_secure_transport".to_string(), "⚠ off: unencrypted connections accepted (default on)".to_string()));
        assert_eq!(lines[1], ("ssl_min_protocol_version".to_string(), "TLSv1.2 (default)".to_string()));
        assert!(!lines.iter().any(|(k, _)| k == "work_mem"));
        assert!(lines.iter().any(|(_, v)| v == "· 3 parameters on the server; only the TLS and auth ones are shown"));
        let my = row(mysql_json());
        let items = vec![serde_json::json!({"name": "aad_auth_only", "properties": {"value": "ON", "defaultValue": "OFF"}})];
        assert_eq!(parameter_rows(&items, &my)[0].1, "ON (Entra only: password logins refused) (default OFF)");
    }

    #[test]
    fn databases_list_user_databases_first_and_system_ones_as_a_note() {
        let pg = row(pg_json());
        let items = vec![
            serde_json::json!({"name": "postgres", "properties": {"charset": "UTF8", "collation": "en_US.utf8"}}),
            serde_json::json!({"name": "orders", "properties": {"charset": "UTF8", "collation": "en_US.utf8"}}),
            serde_json::json!({"name": "azure_maintenance", "properties": {}}),
        ];
        let lines = database_rows(&items, &pg);
        assert_eq!(lines[0], ("orders".to_string(), "UTF8 · en_US.utf8".to_string()));
        assert!(lines.iter().any(|(_, v)| v == "· system: postgres, azure_maintenance"));
        assert_eq!(lines.last().unwrap().1, "az postgres flexible-server db list --server-name pg-prod -g rg-data --subscription 0000");
    }
}
