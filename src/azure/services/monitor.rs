//! The Monitor service (issue #10): Log Analytics workspaces and
//! Application Insights components, two subscription-wide lists,
//! metadata only. Querying logs is data plane and stays on the backlog.
//!
//! A workspace's shared keys are a POST nebaz never sends. A component's
//! GET body *does* carry ingestion credentials (the instrumentation key,
//! the connection string, a HockeyApp token): they are removed from the
//! JSON before the row keeps it, so no section, search or raw view (`e`)
//! can show them.
//!
//! AKS links into workspaces (the monitoring add-on's workspace); an App
//! Service app's App Insights link lives in its app settings, a POST, so
//! apps cannot link here.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable versions (checked against azure-rest-api-specs,
/// 2026-09-27). Components have had no stable version since 2020-02-02.
pub const WORKSPACE_API_VERSION: &str = "2026-03-01";
pub const COMPONENT_API_VERSION: &str = "2020-02-02";
const WORKSPACES_PATH: &str = "/providers/Microsoft.OperationalInsights/workspaces";
const COMPONENTS_PATH: &str = "/providers/Microsoft.Insights/components";

/// Component properties that are ingestion credentials: never kept.
const COMPONENT_SECRETS: &[&str] = &["InstrumentationKey", "ConnectionString", "HockeyAppToken"];

crate::sections! {
    pub enum WorkspaceDetailSection,
    pub static WORKSPACE_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ComponentDetailSection,
    pub static COMPONENT_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

/// `Enabled` / `Disabled` access, or `-`.
fn access(s: Option<String>) -> String {
    json::opt(s)
}

/// A `disableLocalAuth` flag as what it means for keys.
fn local_auth(disabled: Option<bool>) -> String {
    match disabled {
        Some(true) => "disabled (Entra only)".into(),
        Some(false) => "enabled".into(),
        None => "-".into(),
    }
}

// ── Log Analytics workspaces ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WorkspaceRow {
    pub base: ArmBase,
    /// The workspace id queries and agents use (a GUID, not a secret).
    pub customer_id: Option<String>,
    pub sku: Option<String>,
    pub capacity_reservation: Option<i64>,
    pub retention_days: Option<i64>,
    pub daily_cap_gb: Option<f64>,
    pub cap_reset: Option<String>,
    pub ingestion_status: Option<String>,
    pub ingestion_access: Option<String>,
    pub query_access: Option<String>,
    pub local_auth_disabled: Option<bool>,
    pub resource_permissions: Option<bool>,
    pub cluster_id: Option<String>,
    pub created: Option<String>,
}

impl WorkspaceRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<WorkspaceRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        base.location = base.location.replace(' ', "");
        let p = "/properties";
        let f = format!("{}/features", p);
        Some(WorkspaceRow {
            customer_id: json::str_at(v, &format!("{}/customerId", p)),
            sku: json::str_at(v, &format!("{}/sku/name", p)),
            capacity_reservation: json::int_at(v, &format!("{}/sku/capacityReservationLevel", p)),
            retention_days: json::int_at(v, &format!("{}/retentionInDays", p)),
            daily_cap_gb: v.pointer(&format!("{}/workspaceCapping/dailyQuotaGb", p)).and_then(Value::as_f64),
            cap_reset: json::str_at(v, &format!("{}/workspaceCapping/quotaNextResetTime", p)),
            ingestion_status: json::str_at(v, &format!("{}/workspaceCapping/dataIngestionStatus", p)),
            ingestion_access: json::str_at(v, &format!("{}/publicNetworkAccessForIngestion", p)),
            query_access: json::str_at(v, &format!("{}/publicNetworkAccessForQuery", p)),
            local_auth_disabled: json::bool_at(v, &format!("{}/disableLocalAuth", f)),
            resource_permissions: json::bool_at(v, &format!("{}/enableLogAccessUsingOnlyResourcePermissions", f)),
            cluster_id: json::arm_id(json::str_at(v, &format!("{}/clusterResourceId", f))),
            created: json::str_at(v, &format!("{}/createdDate", p)),
            base,
        })
    }

    fn sku_text(&self) -> String {
        match (&self.sku, self.capacity_reservation) {
            (Some(s), Some(gb)) if gb > 0 => format!("{} · {} GB/day", s, gb),
            (s, _) => json::opt(s.clone()),
        }
    }

    /// `-1` is "no cap".
    fn daily_cap(&self) -> String {
        match self.daily_cap_gb {
            Some(gb) if gb < 0.0 => "none".into(),
            Some(gb) => {
                let reset = self
                    .cap_reset
                    .as_deref()
                    .and_then(|t| t.split(['T', ' ']).nth(1))
                    .map(|t| format!(" · resets {} UTC", &t[..t.len().min(5)]))
                    .unwrap_or_default();
                format!("{} GB{}", gb, reset)
            }
            None => "-".into(),
        }
    }
}

impl Resource for WorkspaceRow {
    arm_row!("Log Analytics Workspace");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&WORKSPACE_SECTIONS)
    }
    /// The customer id is searchable: the GUID an agent config names finds
    /// its workspace.
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.customer_id.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut d = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Customer id".into(), json::opt(self.customer_id.clone())),
            ("SKU".into(), self.sku_text()),
            ("Retention".into(), self.retention_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "-".into())),
            ("Daily cap".into(), self.daily_cap()),
        ];
        if let Some(status) = &self.ingestion_status {
            d.push(("Ingestion status".into(), status.clone()));
        }
        d.extend([
            ("Public ingestion".into(), access(self.ingestion_access.clone())),
            ("Public query".into(), access(self.query_access.clone())),
            ("Local auth".into(), local_auth(self.local_auth_disabled)),
            (
                "Access mode".into(),
                match self.resource_permissions {
                    Some(true) => "resource or workspace permissions".into(),
                    Some(false) => "workspace permissions only".into(),
                    None => "-".into(),
                },
            ),
            ("Created".into(), json::time(self.created.clone())),
        ]);
        d
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(c) = &self.cluster_id {
            v.push((format!("Dedicated cluster {}", name_of_id(c)), c.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor log-analytics workspace show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn workspace_section_lines(r: &WorkspaceRow, section: WorkspaceDetailSection) -> Vec<(String, String)> {
    match section {
        WorkspaceDetailSection::Overview => overview_rows(r),
        WorkspaceDetailSection::Related => {
            let mut lines = related_rows(r);
            lines.push((
                String::new(),
                "· AKS clusters and App Insights components list their workspace in their own Related".into(),
            ));
            lines
        }
        WorkspaceDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Application Insights components ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComponentRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub application_type: Option<String>,
    /// The application id (a GUID, not a secret: API access needs a key).
    pub app_id: Option<String>,
    pub ingestion_mode: Option<String>,
    pub retention_days: Option<i64>,
    pub sampling: Option<f64>,
    pub ingestion_access: Option<String>,
    pub query_access: Option<String>,
    pub local_auth_disabled: Option<bool>,
    pub ip_masking_disabled: Option<bool>,
    pub workspace_id: Option<String>,
    pub created: Option<String>,
}

impl ComponentRow {
    /// Parses a component with its ingestion credentials stripped first,
    /// so the kept raw JSON never holds them.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ComponentRow> {
        let mut v = v.clone();
        if let Some(props) = v.get_mut("properties").and_then(Value::as_object_mut) {
            props.retain(|k, _| !COMPONENT_SECRETS.iter().any(|s| s.eq_ignore_ascii_case(k)));
        }
        let v = &v;
        let mut base = ArmBase::from_json(v, tenant)?;
        base.location = base.location.replace(' ', "");
        let p = "/properties";
        Some(ComponentRow {
            kind: json::str_at(v, "/kind"),
            application_type: json::str_at(v, &format!("{}/Application_Type", p)),
            app_id: json::str_at(v, &format!("{}/AppId", p)),
            ingestion_mode: json::str_at(v, &format!("{}/IngestionMode", p)),
            retention_days: json::int_at(v, &format!("{}/RetentionInDays", p)),
            sampling: v.pointer(&format!("{}/SamplingPercentage", p)).and_then(Value::as_f64),
            ingestion_access: json::str_at(v, &format!("{}/publicNetworkAccessForIngestion", p)),
            query_access: json::str_at(v, &format!("{}/publicNetworkAccessForQuery", p)),
            local_auth_disabled: json::bool_at(v, &format!("{}/DisableLocalAuth", p)),
            ip_masking_disabled: json::bool_at(v, &format!("{}/DisableIpMasking", p)),
            workspace_id: json::arm_id(json::str_at(v, &format!("{}/WorkspaceResourceId", p))),
            created: json::str_at(v, &format!("{}/CreationDate", p)),
            base,
        })
    }
}

impl Resource for ComponentRow {
    arm_row!("Application Insights");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&COMPONENT_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.app_id.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Application type".into(), json::opt(self.application_type.clone())),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("App id".into(), json::opt(self.app_id.clone())),
            ("Ingestion mode".into(), json::opt(self.ingestion_mode.clone())),
            (
                "Workspace".into(),
                self.workspace_id.as_deref().map(|w| name_of_id(w).to_string()).unwrap_or_else(|| "- (classic)".into()),
            ),
            ("Retention".into(), self.retention_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "-".into())),
            ("Sampling".into(), self.sampling.map(|s| format!("{}%", s)).unwrap_or_else(|| "-".into())),
            ("Public ingestion".into(), access(self.ingestion_access.clone())),
            ("Public query".into(), access(self.query_access.clone())),
            ("Local auth".into(), local_auth(self.local_auth_disabled)),
            ("IP masking".into(), match self.ip_masking_disabled {
                Some(true) => "off (client IPs stored)".into(),
                Some(false) => "on".into(),
                None => "-".into(),
            }),
            ("Created".into(), json::time(self.created.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(w) = &self.workspace_id {
            v.push((format!("Workspace {}", name_of_id(w)), w.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az monitor app-insights component show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn component_section_lines(r: &ComponentRow, section: ComponentDetailSection) -> Vec<(String, String)> {
    match section {
        ComponentDetailSection::Overview => {
            let mut lines = overview_rows(r);
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· instrumentation key and connection string are never shown".into()));
            lines.push((String::new(), "· the copied command needs the application-insights CLI extension".into()));
            lines
        }
        ComponentDetailSection::Related => related_rows(r),
        ComponentDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct MonitorService {
    scope: Scope,
}

impl MonitorService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::AppInsights => page
                .iter()
                .filter_map(|v| ComponentRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => page
                .iter()
                .filter_map(|v| WorkspaceRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
        }
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::AppInsights => (COMPONENTS_PATH, COMPONENT_API_VERSION, "Listing App Insights components…"),
            _ => (WORKSPACES_PATH, WORKSPACE_API_VERSION, "Listing Log Analytics workspaces…"),
        }
    }
}

#[async_trait]
impl AzureService for MonitorService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Monitor
    }

    fn name(&self) -> &str {
        "Monitor"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, _) = Self::list_of(view);
        Ok(Self::rows(view, &self.scope.list(path, version).await?, self.scope.tenant()))
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
            .stream(path, version, &[], service_type, label, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let tenant = self.scope.tenant();
        let not_found = || Error::ResourceNotFound(id.to_string());
        match JumpView::for_arm_id(id) {
            Some(JumpView::AppInsights) => {
                let v = self.scope.get(id, COMPONENT_API_VERSION).await?;
                Ok(Box::new(ComponentRow::from_json(&v, tenant).ok_or_else(not_found)?))
            }
            _ => {
                let v = self.scope.get(id, WORKSPACE_API_VERSION).await?;
                Ok(Box::new(WorkspaceRow::from_json(&v, tenant).ok_or_else(not_found)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-ops";

    fn workspace_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.OperationalInsights/workspaces/law-prod", RG),
            "name": "law-prod",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "customerId": "44444444-4444-4444-4444-444444444444",
                "sku": {"name": "CapacityReservation", "capacityReservationLevel": 100},
                "retentionInDays": 90,
                "workspaceCapping": {"dailyQuotaGb": 5.0, "quotaNextResetTime": "2026-09-28T06:00:00Z", "dataIngestionStatus": "RespectQuota"},
                "publicNetworkAccessForIngestion": "Enabled",
                "publicNetworkAccessForQuery": "Disabled",
                "features": {"enableLogAccessUsingOnlyResourcePermissions": true, "disableLocalAuth": true},
                "createdDate": "2025-01-02T03:04:05.678Z"
            }
        })
    }

    fn component_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/microsoft.insights/components/appi-shop", RG),
            "name": "appi-shop",
            "location": "West Europe",
            "kind": "web",
            "properties": {
                "provisioningState": "Succeeded",
                "Application_Type": "web",
                "AppId": "55555555-5555-5555-5555-555555555555",
                "InstrumentationKey": "ikey-66666666-secret",
                "ConnectionString": "InstrumentationKey=ikey-66666666-secret;IngestionEndpoint=https://ingest.example/",
                "HockeyAppToken": "hockey-secret",
                "IngestionMode": "LogAnalytics",
                "RetentionInDays": 90,
                "SamplingPercentage": 25.0,
                "publicNetworkAccessForIngestion": "Enabled",
                "publicNetworkAccessForQuery": "Enabled",
                "DisableLocalAuth": false,
                "WorkspaceResourceId": format!("{}/providers/Microsoft.OperationalInsights/workspaces/law-prod", RG),
                "CreationDate": "2025-02-03T04:05:06Z"
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for d in [&WORKSPACE_SECTIONS, &COMPONENT_SECTIONS] {
            let labels: Vec<&str> = d.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels, ["Overview", "Related", "Tags"]);
        }
    }

    #[test]
    fn workspace_row_reads_sku_cap_access_and_the_command() {
        let row = WorkspaceRow::from_json(&workspace_json(), None).unwrap();
        assert_eq!(row.state(), ResourceState::stateless());
        let d = row.details();
        let get = |k: &str| d.iter().find(|(l, _)| l == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("SKU"), "CapacityReservation · 100 GB/day");
        assert_eq!(get("Daily cap"), "5 GB · resets 06:00 UTC");
        assert_eq!(get("Public query"), "Disabled");
        assert_eq!(get("Local auth"), "disabled (Entra only)");
        assert!(row.search_text().contains("44444444-4444-4444-4444-444444444444"));
        assert!(row.cli_command().unwrap().starts_with("az monitor log-analytics workspace show --ids "));
        let mut uncapped = workspace_json();
        uncapped["properties"]["workspaceCapping"]["dailyQuotaGb"] = (-1.0).into();
        assert!(WorkspaceRow::from_json(&uncapped, None).unwrap().details().iter().any(|(k, v)| k == "Daily cap" && v == "none"));
    }

    #[test]
    fn component_row_links_its_workspace_and_never_keeps_credentials() {
        let row = ComponentRow::from_json(&component_json(), None).unwrap();
        assert_eq!(row.base.location, "westeurope");
        let related = row.related();
        let (label, id) = related.last().unwrap();
        assert_eq!(label, "Workspace law-prod");
        assert_eq!(JumpView::for_arm_id(id), Some(JumpView::LogWorkspaces));
        assert!(row.details().iter().any(|(k, v)| k == "Sampling" && v == "25%"));
        let everything: String = COMPONENT_SECTIONS
            .sections
            .iter()
            .enumerate()
            .flat_map(|(i, _)| component_section_lines(&row, ComponentDetailSection::from_index(i)))
            .map(|(k, v)| format!("{k}{v}"))
            .collect::<String>()
            + &row.search_text()
            + &row.raw_content().unwrap();
        assert!(!everything.contains("secret"), "an ingestion credential leaked");
        assert!(row.cli_command().unwrap().starts_with("az monitor app-insights component show --ids "));
    }
}
