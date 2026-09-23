//! The Storage service (ticket 06): one sub-tab, storage accounts, from
//! the subscription-wide list. Blob containers are a lazy child — one ARM
//! call per account, on demand — because the Storage resource provider
//! allows 100 list calls per 5 minutes and both calls count against it.

use crate::azure::resource::{shell_quote, state_ladder, Resource, ResourceState};
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

pub const STORAGE_API_VERSION: &str = "2026-06-01";
const ACCOUNTS_PATH: &str = "/providers/Microsoft.Storage/storageAccounts";

crate::sections! {
    pub enum StorageAccountDetailSection,
    pub static STORAGE_ACCOUNT_SECTIONS = [
        Overview "Overview",
        Endpoints "Endpoints",
        Security "Security",
        Containers "Containers" => crate::app::App::trigger_containers,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct StorageAccountRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub sku: Option<String>,
    pub sku_tier: Option<String>,
    pub access_tier: Option<String>,
    pub status_primary: Option<String>,
    pub status_secondary: Option<String>,
    pub primary_location: Option<String>,
    pub secondary_location: Option<String>,
    pub creation_time: Option<String>,
    /// `(service, url)` in the API's order.
    pub endpoints: Vec<(String, String)>,
    pub allow_blob_public_access: Option<bool>,
    pub allow_shared_key_access: Option<bool>,
    pub min_tls: Option<String>,
    pub https_only: Option<bool>,
    pub public_network_access: Option<String>,
    pub network_default_action: Option<String>,
    pub encryption_key_source: Option<String>,
    pub is_hns: Option<bool>,
    pub large_file_shares: Option<String>,
}

impl StorageAccountRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<StorageAccountRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let endpoints = v
            .pointer(&format!("{}/primaryEndpoints", p))
            .and_then(|e| e.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|u| (k.clone(), u.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        Some(StorageAccountRow {
            kind: json::str_at(v, "/kind"),
            sku: json::str_at(v, "/sku/name"),
            sku_tier: json::str_at(v, "/sku/tier"),
            access_tier: json::str_at(v, &format!("{}/accessTier", p)),
            status_primary: json::str_at(v, &format!("{}/statusOfPrimary", p)),
            status_secondary: json::str_at(v, &format!("{}/statusOfSecondary", p)),
            primary_location: json::str_at(v, &format!("{}/primaryLocation", p)),
            secondary_location: json::str_at(v, &format!("{}/secondaryLocation", p)),
            creation_time: json::str_at(v, &format!("{}/creationTime", p)),
            endpoints,
            allow_blob_public_access: json::bool_at(v, &format!("{}/allowBlobPublicAccess", p)),
            allow_shared_key_access: json::bool_at(v, &format!("{}/allowSharedKeyAccess", p)),
            min_tls: json::str_at(v, &format!("{}/minimumTlsVersion", p)),
            https_only: json::bool_at(v, &format!("{}/supportsHttpsTrafficOnly", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            network_default_action: json::str_at(v, &format!("{}/networkAcls/defaultAction", p)),
            encryption_key_source: json::str_at(v, &format!("{}/encryption/keySource", p)),
            is_hns: json::bool_at(v, &format!("{}/isHnsEnabled", p)),
            large_file_shares: json::str_at(v, &format!("{}/largeFileSharesState", p)),
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.status_primary.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "available" => ResourceState::Available,
                "unavailable" => ResourceState::Unavailable,
                other => ResourceState::Unknown(other.to_string()),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for StorageAccountRow {
    arm_row!("Storage Account");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&STORAGE_ACCOUNT_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.kind.clone()),
            json::opt(self.sku.clone()),
            json::opt(self.access_tier.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Status".into(), json::opt(self.status_primary.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Kind".into(), json::opt(self.kind.clone())),
            (
                "SKU".into(),
                format!("{} · {}", json::opt(self.sku.clone()), json::opt(self.sku_tier.clone())),
            ),
            ("Access tier".into(), json::opt(self.access_tier.clone())),
            ("Primary location".into(), json::opt(self.primary_location.clone())),
            (
                "Secondary".into(),
                match (&self.secondary_location, &self.status_secondary) {
                    (Some(l), s) => format!("{} · {}", l, json::opt(s.clone())),
                    (None, _) => "-".into(),
                },
            ),
            ("Hierarchical namespace".into(), json::yes_no(self.is_hns)),
            ("Large file shares".into(), json::opt(self.large_file_shares.clone())),
            ("Created".into(), json::time(self.creation_time.clone())),
        ]
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az storage account show --ids {}", shell_quote(&self.base.id)))
    }
}

/// Body lines for one section of a storage-account row.
pub fn storage_account_section_lines(
    r: &StorageAccountRow,
    section: StorageAccountDetailSection,
    containers: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        StorageAccountDetailSection::Overview => overview_rows(r),
        StorageAccountDetailSection::Endpoints => {
            if r.endpoints.is_empty() {
                return vec![(String::new(), "No endpoints".into())];
            }
            r.endpoints.to_vec()
        }
        StorageAccountDetailSection::Security => vec![
            ("Public blob access".into(), allowed(r.allow_blob_public_access)),
            ("Shared key access".into(), allowed(r.allow_shared_key_access)),
            ("Minimum TLS".into(), json::opt(r.min_tls.clone())),
            ("HTTPS only".into(), json::yes_no(r.https_only)),
            ("Public network access".into(), json::opt(r.public_network_access.clone())),
            ("Network default action".into(), json::opt(r.network_default_action.clone())),
            ("Encryption key source".into(), json::opt(r.encryption_key_source.clone())),
        ],
        StorageAccountDetailSection::Containers => {
            lazy_list_rows(containers, "Containers", |items| container_rows(items, &r.base.name))
        }
        StorageAccountDetailSection::Related => related_rows(r),
        StorageAccountDetailSection::Tags => tag_rows(r.tags()),
    }
}

fn allowed(b: Option<bool>) -> String {
    match b {
        Some(true) => "allowed".into(),
        Some(false) => "disallowed".into(),
        None => "-".into(),
    }
}

/// The Containers section body: one line per container from the ARM
/// `blobServices/default/containers` list.
pub fn container_rows(items: &[Value], account: &str) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No containers".into()));
    } else {
        lines.push(("Containers".into(), items.len().to_string()));
        lines.push((String::new(), String::new()));
        for c in items {
            let p = "/properties";
            let mut val = format!(
                "{} · lease {} · modified {}",
                json::str_at(c, &format!("{}/publicAccess", p))
                    .map(|a| format!("public {}", a.to_lowercase()))
                    .unwrap_or_else(|| "-".into()),
                json::text(c, &format!("{}/leaseState", p)).to_lowercase(),
                json::time(json::str_at(c, &format!("{}/lastModifiedTime", p))),
            );
            if json::bool_at(c, &format!("{}/hasImmutabilityPolicy", p)) == Some(true) {
                val.push_str(" · immutable");
            }
            if json::bool_at(c, &format!("{}/hasLegalHold", p)) == Some(true) {
                val.push_str(" · legal hold");
            }
            if json::bool_at(c, &format!("{}/deleted", p)) == Some(true) {
                val.push_str(" · deleted");
            }
            lines.push((json::text(c, "/name"), val));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az storage container-rm list --storage-account {}", shell_quote(account)),
    ));
    lines
}

/// The ARM containers path of a storage-account id, for the lazy fetch.
pub fn containers_path(account_id: &str) -> String {
    format!("{}/blobServices/default/containers", account_id.trim_end_matches('/'))
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct StorageService {
    scope: Scope,
}

impl StorageService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for StorageService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Storage
    }

    fn name(&self) -> &str {
        "Storage"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(self
            .scope
            .list(ACCOUNTS_PATH, STORAGE_API_VERSION)
            .await?
            .iter()
            .filter_map(|v| StorageAccountRow::from_json(v, tenant))
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
            .stream(ACCOUNTS_PATH, STORAGE_API_VERSION, &[], service_type, "Listing storage accounts…", &event_tx, |page| {
                page.iter()
                    .filter_map(|v| StorageAccountRow::from_json(v, tenant.as_deref()))
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, STORAGE_API_VERSION).await?;
        StorageAccountRow::from_json(&v, self.scope.tenant())
            .map(|r| Box::new(r) as Box<dyn Resource>)
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_account_row_parses_status_security_and_endpoints() {
        let v = serde_json::json!({
            "id": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stprod",
            "name": "stprod",
            "location": "westeurope",
            "kind": "StorageV2",
            "sku": {"name": "Standard_LRS", "tier": "Standard"},
            "properties": {
                "provisioningState": "Succeeded",
                "statusOfPrimary": "available",
                "primaryLocation": "westeurope",
                "accessTier": "Hot",
                "creationTime": "2023-05-06T07:08:09Z",
                "primaryEndpoints": {"blob": "https://stprod.blob.core.windows.net/", "web": "https://stprod.web.core.windows.net/"},
                "allowBlobPublicAccess": false,
                "minimumTlsVersion": "TLS1_2",
                "supportsHttpsTrafficOnly": true,
                "publicNetworkAccess": "Enabled",
                "networkAcls": {"defaultAction": "Allow"},
                "encryption": {"keySource": "Microsoft.Storage"}
            }
        });
        let row = StorageAccountRow::from_json(&v, Some("t-1")).unwrap();
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "available");
        assert_eq!(row.endpoints.len(), 2);
        let sec = storage_account_section_lines(&row, StorageAccountDetailSection::Security, None);
        assert_eq!(sec[0], ("Public blob access".to_string(), "disallowed".to_string()));
        assert_eq!(sec[2], ("Minimum TLS".to_string(), "TLS1_2".to_string()));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az storage account show --ids /subscriptions/0000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stprod")
        );
        assert_eq!(row.related().len(), 2);
        let mut creating = v.clone();
        creating["properties"]["provisioningState"] = "ResolvingDNS".into();
        let row = StorageAccountRow::from_json(&creating, None).unwrap();
        assert_eq!(row.state(), ResourceState::Creating);
        assert_eq!(row.state_label(), "resolvingdns");
    }

    #[test]
    fn containers_section_covers_every_arm_and_names_the_read_command() {
        let row = StorageAccountRow::from_json(
            &serde_json::json!({"id": "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st", "name": "st"}),
            None,
        )
        .unwrap();
        let loading = storage_account_section_lines(&row, StorageAccountDetailSection::Containers, None);
        assert_eq!(loading[0].1, "Loading…");
        let items = vec![serde_json::json!({
            "name": "logs",
            "properties": {"publicAccess": "None", "leaseState": "Available", "lastModifiedTime": "2024-01-02T03:04:05Z", "hasLegalHold": true}
        })];
        let loaded = storage_account_section_lines(
            &row,
            StorageAccountDetailSection::Containers,
            Some(&Lazy::Loaded(items)),
        );
        assert_eq!(loaded[2].0, "logs");
        assert_eq!(loaded[2].1, "public none · lease available · modified 2024-01-02 03:04:05 · legal hold");
        assert!(loaded.last().unwrap().1.contains("az storage container-rm list --storage-account st"));
        assert_eq!(
            containers_path("/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st"),
            "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st/blobServices/default/containers"
        );
    }
}
