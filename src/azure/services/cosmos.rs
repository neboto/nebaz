//! The Cosmos DB service (issue #9): database accounts, one
//! subscription-wide list, metadata only. Databases are a lazy section,
//! one call per account on a path that depends on the account's API
//! (`sqlDatabases`, `mongodbDatabases`, `cassandraKeyspaces`,
//! `gremlinDatabases`, `tables`). Containers under each database would
//! be one call per database, so they are left out.
//!
//! Keys and connection strings (`listKeys`, `readonlykeys`,
//! `listConnectionStrings`) are POSTs nebaz never sends; `keysMetadata`
//! (rotation times only) is not rendered. The document endpoint is the
//! data plane: shown as text, as SQL's FQDN is, never requested.
//!
//! Accounts report their location as a display name (`West US`); the row
//! stores the short form (`westus`) so the location filter matches.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version (checked against azure-rest-api-specs,
/// 2026-09-25).
pub const COSMOS_API_VERSION: &str = "2026-03-15";
const ACCOUNTS_PATH: &str = "/providers/Microsoft.DocumentDB/databaseAccounts";

crate::sections! {
    pub enum CosmosDetailSection,
    pub static COSMOS_SECTIONS = [
        Overview "Overview",
        Replication "Replication",
        Security "Security",
        Backup "Backup",
        Databases "Databases" => crate::app::App::trigger_cosmos_databases,
        Related "Related",
        Tags "Tags",
    ]
}

/// An account's API, from `kind` and `capabilities`: it decides the
/// Databases path and the `az` group that lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosmosApi {
    NoSql,
    MongoDb,
    Cassandra,
    Gremlin,
    Table,
}

impl CosmosApi {
    fn from_json(v: &Value) -> CosmosApi {
        let caps: Vec<String> = json::arr(v, "/properties/capabilities")
            .iter()
            .map(|c| json::text(c, "/name").to_lowercase())
            .collect();
        let has = |c: &str| caps.iter().any(|x| x == c);
        let kind = json::text(v, "/kind").to_lowercase();
        if kind == "mongodb" || has("enablemongo") {
            CosmosApi::MongoDb
        } else if has("enablecassandra") {
            CosmosApi::Cassandra
        } else if has("enablegremlin") {
            CosmosApi::Gremlin
        } else if has("enabletable") {
            CosmosApi::Table
        } else {
            CosmosApi::NoSql
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CosmosApi::NoSql => "NoSQL",
            CosmosApi::MongoDb => "MongoDB",
            CosmosApi::Cassandra => "Cassandra",
            CosmosApi::Gremlin => "Gremlin",
            CosmosApi::Table => "Table",
        }
    }

    /// The account child that lists this API's databases.
    pub fn databases_child(self) -> &'static str {
        match self {
            CosmosApi::NoSql => "sqlDatabases",
            CosmosApi::MongoDb => "mongodbDatabases",
            CosmosApi::Cassandra => "cassandraKeyspaces",
            CosmosApi::Gremlin => "gremlinDatabases",
            CosmosApi::Table => "tables",
        }
    }

    /// The `az` read command for the same list, spelled out per API so the
    /// guard sees each literal whole.
    fn list_command(self) -> &'static str {
        match self {
            CosmosApi::NoSql => "az cosmosdb sql database list",
            CosmosApi::MongoDb => "az cosmosdb mongodb database list",
            CosmosApi::Cassandra => "az cosmosdb cassandra keyspace list",
            CosmosApi::Gremlin => "az cosmosdb gremlin database list",
            CosmosApi::Table => "az cosmosdb table list",
        }
    }

    /// What one entry of the Databases section is called.
    fn noun(self) -> &'static str {
        match self {
            CosmosApi::Cassandra => "keyspaces",
            CosmosApi::Table => "tables",
            _ => "databases",
        }
    }
}

/// One region of the account, from `failoverPolicies` and `locations`.
#[derive(Debug, Clone)]
pub struct CosmosRegion {
    pub name: String,
    pub priority: i64,
    pub zone_redundant: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CosmosAccountRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub api: CosmosApi,
    /// The account's data-plane endpoint: text only.
    pub endpoint: Option<String>,
    pub serverless: bool,
    pub throughput_limit: Option<i64>,
    pub free_tier: Option<bool>,
    pub analytical_storage: Option<bool>,
    pub consistency: Option<String>,
    pub max_staleness_prefix: Option<i64>,
    pub max_interval_secs: Option<i64>,
    pub multi_region_writes: Option<bool>,
    pub automatic_failover: Option<bool>,
    /// By failover priority; priority 0 is the write region.
    pub regions: Vec<CosmosRegion>,
    pub write_regions: Vec<String>,
    pub public_network_access: Option<String>,
    pub vnet_filter: Option<bool>,
    pub ip_rules: Vec<String>,
    pub subnet_ids: Vec<String>,
    pub acl_bypass: Option<String>,
    pub local_auth_disabled: Option<bool>,
    pub key_metadata_write_disabled: Option<bool>,
    pub min_tls: Option<String>,
    /// A Key Vault key URL (customer-managed key), not an ARM id.
    pub key_uri: Option<String>,
    pub default_identity: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub private_endpoint_ids: Vec<String>,
    pub backup_type: Option<String>,
    pub backup_interval_min: Option<i64>,
    pub backup_retention_hours: Option<i64>,
    pub backup_redundancy: Option<String>,
    pub backup_tier: Option<String>,
    pub backup_migration: Option<String>,
}

impl CosmosAccountRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<CosmosAccountRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        base.location = base.location.replace(' ', "");
        let p = "/properties";
        let b = format!("{}/backupPolicy", p);
        let zones: Vec<(String, Option<bool>)> = json::arr(v, &format!("{}/locations", p))
            .iter()
            .map(|l| (json::text(l, "/locationName"), json::bool_at(l, "/isZoneRedundant")))
            .collect();
        let mut regions: Vec<CosmosRegion> = json::arr(v, &format!("{}/failoverPolicies", p))
            .iter()
            .map(|f| {
                let name = json::text(f, "/locationName");
                let zone_redundant = zones.iter().find(|(n, _)| *n == name).and_then(|(_, z)| *z);
                CosmosRegion { priority: json::int_at(f, "/failoverPriority").unwrap_or(0), zone_redundant, name }
            })
            .collect();
        regions.sort_by_key(|r| r.priority);
        let capabilities: Vec<String> =
            json::arr(v, &format!("{}/capabilities", p)).iter().map(|c| json::text(c, "/name")).collect();
        Some(CosmosAccountRow {
            kind: json::str_at(v, "/kind"),
            api: CosmosApi::from_json(v),
            endpoint: json::str_at(v, &format!("{}/documentEndpoint", p)),
            serverless: capabilities.iter().any(|c| c.eq_ignore_ascii_case("EnableServerless")),
            throughput_limit: json::int_at(v, &format!("{}/capacity/totalThroughputLimit", p)),
            free_tier: json::bool_at(v, &format!("{}/enableFreeTier", p)),
            analytical_storage: json::bool_at(v, &format!("{}/enableAnalyticalStorage", p)),
            consistency: json::str_at(v, &format!("{}/consistencyPolicy/defaultConsistencyLevel", p)),
            max_staleness_prefix: json::int_at(v, &format!("{}/consistencyPolicy/maxStalenessPrefix", p)),
            max_interval_secs: json::int_at(v, &format!("{}/consistencyPolicy/maxIntervalInSeconds", p)),
            multi_region_writes: json::bool_at(v, &format!("{}/enableMultipleWriteLocations", p)),
            automatic_failover: json::bool_at(v, &format!("{}/enableAutomaticFailover", p)),
            regions,
            write_regions: json::arr(v, &format!("{}/writeLocations", p))
                .iter()
                .map(|l| json::text(l, "/locationName"))
                .collect(),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            vnet_filter: json::bool_at(v, &format!("{}/isVirtualNetworkFilterEnabled", p)),
            ip_rules: json::arr(v, &format!("{}/ipRules", p))
                .iter()
                .map(|r| json::text(r, "/ipAddressOrRange"))
                .collect(),
            subnet_ids: json::arr(v, &format!("{}/virtualNetworkRules", p))
                .iter()
                .filter_map(|r| json::arm_id(json::str_at(r, "/id")))
                .collect(),
            acl_bypass: json::str_at(v, &format!("{}/networkAclBypass", p)),
            local_auth_disabled: json::bool_at(v, &format!("{}/disableLocalAuth", p)),
            key_metadata_write_disabled: json::bool_at(v, &format!("{}/disableKeyBasedMetadataWriteAccess", p)),
            min_tls: json::str_at(v, &format!("{}/minimalTlsVersion", p)),
            key_uri: json::str_at(v, &format!("{}/keyVaultKeyUri", p)).filter(|k| !k.is_empty()),
            default_identity: json::str_at(v, &format!("{}/defaultIdentity", p)),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            private_endpoint_ids: json::arr(v, &format!("{}/privateEndpointConnections", p))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/privateEndpoint")))
                .collect(),
            backup_type: json::str_at(v, &format!("{}/type", b)),
            backup_interval_min: json::int_at(v, &format!("{}/periodicModeProperties/backupIntervalInMinutes", b)),
            backup_retention_hours: json::int_at(
                v,
                &format!("{}/periodicModeProperties/backupRetentionIntervalInHours", b),
            ),
            backup_redundancy: json::str_at(v, &format!("{}/periodicModeProperties/backupStorageRedundancy", b)),
            backup_tier: json::str_at(v, &format!("{}/continuousModeProperties/tier", b)),
            backup_migration: match (
                json::str_at(v, &format!("{}/migrationState/status", b)),
                json::str_at(v, &format!("{}/migrationState/targetType", b)),
            ) {
                (Some(status), Some(target)) => Some(format!("to {}: {}", target, status)),
                (Some(status), None) => Some(status),
                _ => None,
            },
            base,
        })
    }

    fn capacity_mode(&self) -> String {
        if self.serverless {
            return "serverless".into();
        }
        match self.throughput_limit {
            Some(n) if n > 0 => format!("provisioned · limit {} RU/s", n),
            _ => "provisioned".into(),
        }
    }

    fn consistency_text(&self) -> String {
        let level = json::opt(self.consistency.clone());
        if !level.eq_ignore_ascii_case("BoundedStaleness") {
            return level;
        }
        format!(
            "{} ({} versions or {} s)",
            level,
            json::num(self.max_staleness_prefix),
            json::num(self.max_interval_secs)
        )
    }

    /// `--account-name {account} -g {rg} --subscription {sub}`: what the
    /// per-API database list commands take.
    fn account_args(&self) -> Option<String> {
        Some(format!(
            "--account-name {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for CosmosAccountRow {
    arm_row!("Cosmos DB Account");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&COSMOS_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.endpoint.clone()),
            self.api.label(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("API".into(), self.api.label().into()),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("Endpoint".into(), json::opt(self.endpoint.clone())),
            ("Capacity mode".into(), self.capacity_mode()),
            ("Free tier".into(), json::yes_no(self.free_tier)),
            ("Analytical storage".into(), json::yes_no(self.analytical_storage)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for subnet in &self.subnet_ids {
            v.push((format!("VNet rule subnet {}", subnet_label(subnet)), subnet.clone()));
        }
        for pe in &self.private_endpoint_ids {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az cosmosdb show --ids {}", shell_quote(&self.base.id)))
    }
}

/// `vnet/subnet` from a subnet id.
fn subnet_label(id: &str) -> String {
    let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
    match parts.len() {
        n if n >= 3 => format!("{}/{}", parts[n - 3], parts[n - 1]),
        _ => name_of_id(id).to_string(),
    }
}

pub fn cosmos_section_lines(
    r: &CosmosAccountRow,
    section: CosmosDetailSection,
    databases: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        CosmosDetailSection::Overview => overview_rows(r),
        CosmosDetailSection::Replication => {
            let mut lines = vec![
                ("Consistency".into(), r.consistency_text()),
                ("Multi-region writes".into(), json::yes_no(r.multi_region_writes)),
                ("Automatic failover".into(), json::yes_no(r.automatic_failover)),
                ("Write regions".into(), json::join(&r.write_regions)),
            ];
            if r.regions.is_empty() {
                lines.push(("Regions".into(), "-".into()));
            }
            for region in &r.regions {
                let zr = if region.zone_redundant == Some(true) { " · zone redundant" } else { "" };
                lines.push((format!("Priority {}", region.priority), format!("{}{}", region.name, zr)));
            }
            lines
        }
        CosmosDetailSection::Security => {
            let network = if r.public_network_access.as_deref().is_some_and(|a| a.eq_ignore_ascii_case("disabled")) {
                "private endpoints only"
            } else if r.vnet_filter == Some(true) || !r.ip_rules.is_empty() {
                "selected networks"
            } else {
                "all networks"
            };
            let mut lines = vec![
                ("Public network access".into(), json::opt(r.public_network_access.clone())),
                ("Network access".into(), network.into()),
            ];
            if r.ip_rules.is_empty() {
                lines.push(("IP rules".into(), "-".into()));
            }
            for ip in &r.ip_rules {
                lines.push(("IP rule".into(), ip.clone()));
            }
            for subnet in &r.subnet_ids {
                lines.push((format!("VNet rule · {}", subnet_label(subnet)), subnet.clone()));
            }
            lines.push(("ACL bypass".into(), json::opt(r.acl_bypass.clone())));
            let key_auth = match r.local_auth_disabled {
                Some(true) => "disabled (Entra only)".to_string(),
                Some(false) => "enabled".to_string(),
                None => "-".to_string(),
            };
            lines.push(("Key auth".into(), key_auth));
            let metadata = match r.key_metadata_write_disabled {
                Some(true) => "blocked".to_string(),
                Some(false) => "allowed".to_string(),
                None => "-".to_string(),
            };
            lines.push(("Metadata writes by key".into(), metadata));
            lines.push(("Min TLS".into(), json::opt(r.min_tls.clone())));
            lines.push((
                "Encryption".into(),
                if r.key_uri.is_some() { "customer-managed" } else { "service-managed" }.into(),
            ));
            if let Some(k) = &r.key_uri {
                lines.push(("  Key".into(), k.clone()));
                lines.push(("  Via identity".into(), json::opt(r.default_identity.clone())));
            }
            lines.push(("Identity".into(), json::opt(r.identity_type.clone())));
            for pe in &r.private_endpoint_ids {
                lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
            }
            lines
        }
        CosmosDetailSection::Backup => {
            let mut lines = vec![("Mode".into(), json::opt(r.backup_type.clone()))];
            if r.backup_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("continuous")) {
                lines.push(("Tier".into(), json::opt(r.backup_tier.clone())));
            } else {
                let every = r.backup_interval_min.map(|m| {
                    if m % 60 == 0 { format!("every {} h", m / 60) } else { format!("every {} min", m) }
                });
                let keep = r.backup_retention_hours.map(|h| {
                    if h % 24 == 0 { format!("{} days", h / 24) } else { format!("{} h", h) }
                });
                lines.push(("Interval".into(), json::opt(every)));
                lines.push(("Retention".into(), json::opt(keep)));
                lines.push(("Storage redundancy".into(), json::opt(r.backup_redundancy.clone())));
            }
            if let Some(m) = &r.backup_migration {
                lines.push(("Migration".into(), m.clone()));
            }
            lines
        }
        CosmosDetailSection::Databases => lazy_list_rows(databases, "Databases", |items| database_rows(items, r)),
        CosmosDetailSection::Related => related_rows(r),
        CosmosDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Databases section body from the account's per-API list.
pub fn database_rows(items: &[Value], r: &CosmosAccountRow) -> Vec<(String, String)> {
    let mut lines = vec![("API".into(), r.api.label().to_string())];
    if items.is_empty() {
        lines.push((String::new(), format!("No {}", r.api.noun())));
    }
    for db in items {
        lines.push((json::text(db, "/name"), json::text(db, "/id")));
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "· containers are one call per database; not listed".into()));
    lines.push((
        "Read command".into(),
        format!("{} {}", r.api.list_command(), r.account_args().unwrap_or_default()),
    ));
    lines
}

/// The ARM path of an account's database list for its API.
pub fn databases_path(account_id: &str, api: CosmosApi) -> String {
    format!("{}/{}", account_id.trim_end_matches('/'), api.databases_child())
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct CosmosService {
    scope: Scope,
}

impl CosmosService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for CosmosService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Cosmos
    }

    fn name(&self) -> &str {
        "Cosmos DB"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(ACCOUNTS_PATH, COSMOS_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| CosmosAccountRow::from_json(v, tenant))
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .collect())
    }

    async fn list_resources_streaming(
        &self,
        _view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(ACCOUNTS_PATH, COSMOS_API_VERSION, &[], service_type, "Listing Cosmos DB accounts…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| CosmosAccountRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, COSMOS_API_VERSION).await?;
        CosmosAccountRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-data";

    fn account_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-prod", RG),
            "name": "cosmos-prod",
            "location": "West Europe",
            "kind": "GlobalDocumentDB",
            "identity": {"type": "SystemAssigned,UserAssigned", "userAssignedIdentities": {
                format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-cosmos", RG): {}
            }},
            "properties": {
                "provisioningState": "Succeeded",
                "documentEndpoint": "https://cosmos-prod.docs.example:443/",
                "capabilities": [{"name": "EnableServerless"}],
                "consistencyPolicy": {"defaultConsistencyLevel": "BoundedStaleness", "maxStalenessPrefix": 100, "maxIntervalInSeconds": 5},
                "enableMultipleWriteLocations": false,
                "enableAutomaticFailover": true,
                "writeLocations": [{"locationName": "West Europe", "failoverPriority": 0}],
                "locations": [
                    {"locationName": "West Europe", "failoverPriority": 0, "isZoneRedundant": true},
                    {"locationName": "North Europe", "failoverPriority": 1, "isZoneRedundant": false}
                ],
                "failoverPolicies": [
                    {"locationName": "North Europe", "failoverPriority": 1},
                    {"locationName": "West Europe", "failoverPriority": 0}
                ],
                "publicNetworkAccess": "Enabled",
                "isVirtualNetworkFilterEnabled": true,
                "ipRules": [{"ipAddressOrRange": "203.0.113.7"}],
                "virtualNetworkRules": [{"id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-data/subnets/app", RG)}],
                "networkAclBypass": "AzureServices",
                "disableLocalAuth": true,
                "disableKeyBasedMetadataWriteAccess": true,
                "minimalTlsVersion": "Tls12",
                "backupPolicy": {"type": "Periodic", "periodicModeProperties": {
                    "backupIntervalInMinutes": 240, "backupRetentionIntervalInHours": 48, "backupStorageRedundancy": "Geo"}},
                "keysMetadata": {"primaryMasterKey": {"generationTime": "2022-02-25T20:30:11Z"}},
                "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-cosmos", RG)}}}]
            }
        })
    }

    fn all_lines(r: &CosmosAccountRow) -> String {
        COSMOS_SECTIONS
            .sections
            .iter()
            .enumerate()
            .flat_map(|(i, _)| cosmos_section_lines(r, CosmosDetailSection::from_index(i), None))
            .map(|(k, v)| format!("{k}{v}"))
            .collect()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = COSMOS_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Replication", "Security", "Backup", "Databases", "Related", "Tags"]
        );
    }

    #[test]
    fn account_row_reads_overview_replication_and_the_short_location() {
        let row = CosmosAccountRow::from_json(&account_json(), None).unwrap();
        assert_eq!(row.base.location, "westeurope", "display name normalised for the R filter");
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.api, CosmosApi::NoSql);
        assert!(row.details().iter().any(|(k, v)| k == "Capacity mode" && v == "serverless"));
        let rep = cosmos_section_lines(&row, CosmosDetailSection::Replication, None);
        assert_eq!(rep[0].1, "BoundedStaleness (100 versions or 5 s)");
        let regions: Vec<&(String, String)> = rep.iter().filter(|(k, _)| k.starts_with("Priority")).collect();
        assert_eq!(regions[0].1, "West Europe · zone redundant", "sorted by failover priority");
        assert_eq!(regions[1].1, "North Europe");
        assert_eq!(
            row.cli_command().unwrap(),
            format!("az cosmosdb show --ids {}/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-prod", RG)
        );
    }

    #[test]
    fn security_backup_and_related_and_no_key_material() {
        let row = CosmosAccountRow::from_json(&account_json(), None).unwrap();
        let sec = cosmos_section_lines(&row, CosmosDetailSection::Security, None);
        assert!(sec.iter().any(|(k, v)| k == "Network access" && v == "selected networks"));
        assert!(sec.iter().any(|(k, v)| k == "VNet rule · vnet-data/app" && v.ends_with("/subnets/app")));
        assert!(sec.iter().any(|(k, v)| k == "Key auth" && v == "disabled (Entra only)"));
        let backup = cosmos_section_lines(&row, CosmosDetailSection::Backup, None);
        assert!(backup.iter().any(|(k, v)| k == "Interval" && v == "every 4 h"));
        assert!(backup.iter().any(|(k, v)| k == "Retention" && v == "2 days"));
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        assert!(related.iter().any(|l| l == "VNet rule subnet vnet-data/app"));
        assert!(related.iter().any(|l| l == "Private endpoint pe-cosmos"));
        assert!(related.iter().any(|l| l == "Identity id-cosmos"));
        assert!(!all_lines(&row).contains("2022-02-25"), "keysMetadata is not rendered");
    }

    #[test]
    fn the_api_picks_the_databases_path_and_read_command() {
        let mut mongo = account_json();
        mongo["kind"] = "MongoDB".into();
        let mut cassandra = account_json();
        cassandra["properties"]["capabilities"] = serde_json::json!([{"name": "EnableCassandra"}]);
        let mut table = account_json();
        table["properties"]["capabilities"] = serde_json::json!([{"name": "EnableTable"}]);
        let cases = [
            (account_json(), "sqlDatabases", "az cosmosdb sql database list"),
            (mongo, "mongodbDatabases", "az cosmosdb mongodb database list"),
            (cassandra, "cassandraKeyspaces", "az cosmosdb cassandra keyspace list"),
            (table, "tables", "az cosmosdb table list"),
        ];
        for (v, child, cmd) in cases {
            let row = CosmosAccountRow::from_json(&v, None).unwrap();
            assert_eq!(databases_path(&row.base.id, row.api), format!("{}/{}", row.base.id, child));
            let items = vec![serde_json::json!({"name": "orders", "id": format!("{}/{}/orders", row.base.id, child)})];
            let lines = cosmos_section_lines(&row, CosmosDetailSection::Databases, Some(&Lazy::Loaded(items)));
            assert!(lines.iter().any(|(k, _)| k == "orders"));
            assert_eq!(
                lines.last().unwrap().1,
                format!("{} --account-name cosmos-prod -g rg-data --subscription 0000", cmd)
            );
        }
    }
}
