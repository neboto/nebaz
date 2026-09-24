//! The App Service service (issue #4): apps (every `Microsoft.Web/sites`
//! row: web, API, function and Logic Apps Standard) and the plans they run
//! on. **Functions** is the same sites list filtered on `kind` (function
//! and logic apps), like VNets/Subnets (SERVICES.md rule 7). Apps lists
//! everything because a site's ARM id does not say its kind: a jump to any
//! site must land on a sub-tab that has it.
//!
//! The site's Configuration is a lazy `GET {site}/config/web`: runtime,
//! TLS, FTPS, access restrictions. App settings and connection strings are
//! a `POST …/config/appsettings/list` nebaz never sends; the `config/web`
//! body's own `appSettings` / `connectionStrings` fields are never
//! rendered even when present. The guard names the `az` commands that
//! would print them.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version with a few months behind it (checked against
/// azure-rest-api-specs, 2026-09-24).
pub const WEB_API_VERSION: &str = "2026-03-15";
const SITES_PATH: &str = "/providers/Microsoft.Web/sites";
const PLANS_PATH: &str = "/providers/Microsoft.Web/serverfarms";

const NEVER_SETTINGS: &str = "app settings and connection strings are never fetched";

crate::sections! {
    pub enum SiteDetailSection,
    pub static SITE_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration" => crate::app::App::trigger_site_config,
        Hostnames "Hostnames",
        Networking "Networking",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum PlanDetailSection,
    pub static PLAN_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

// ── Site (web app / function app) ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Hostname {
    pub name: String,
    pub ssl_state: Option<String>,
    /// `Standard` or `Repository` (the SCM / Kudu host).
    pub host_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SiteRow {
    pub base: ArmBase,
    pub kind: String,
    pub state: Option<String>,
    pub default_host: Option<String>,
    pub hostnames: Vec<Hostname>,
    pub plan_id: Option<String>,
    pub https_only: Option<bool>,
    pub client_cert: Option<bool>,
    pub client_cert_mode: Option<String>,
    pub public_network_access: Option<String>,
    pub vnet_subnet_id: Option<String>,
    pub managed_environment_id: Option<String>,
    pub outbound_ips: Vec<String>,
    pub last_modified: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub key_vault_reference_identity: Option<String>,
}

impl SiteRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<SiteRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(SiteRow {
            kind: json::str_at(v, "/kind").unwrap_or_default().to_lowercase(),
            state: json::str_at(v, &format!("{}/state", p)),
            default_host: json::str_at(v, &format!("{}/defaultHostName", p)),
            hostnames: json::arr(v, &format!("{}/hostNameSslStates", p))
                .iter()
                .map(|h| Hostname {
                    name: json::text(h, "/name"),
                    ssl_state: json::str_at(h, "/sslState"),
                    host_type: json::str_at(h, "/hostType"),
                })
                .collect(),
            plan_id: json::arm_id(json::str_at(v, &format!("{}/serverFarmId", p))),
            https_only: json::bool_at(v, &format!("{}/httpsOnly", p)),
            client_cert: json::bool_at(v, &format!("{}/clientCertEnabled", p)),
            client_cert_mode: json::str_at(v, &format!("{}/clientCertMode", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            vnet_subnet_id: json::arm_id(json::str_at(v, &format!("{}/virtualNetworkSubnetId", p))),
            managed_environment_id: json::arm_id(json::str_at(v, &format!("{}/managedEnvironmentId", p))),
            outbound_ips: json::str_at(v, &format!("{}/outboundIpAddresses", p))
                .map(|s| s.split(',').map(|ip| ip.trim().to_string()).filter(|ip| !ip.is_empty()).collect())
                .unwrap_or_default(),
            last_modified: json::str_at(v, &format!("{}/lastModifiedTimeUtc", p)),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            key_vault_reference_identity: json::arm_id(json::str_at(v, &format!("{}/keyVaultReferenceIdentity", p))),
            base,
        })
    }

    /// Function apps (and Logic Apps Standard, `functionapp,workflowapp`)
    /// go on the Function apps sub-tab; everything else is a web app.
    pub fn is_function_app(&self) -> bool {
        self.kind.contains("functionapp")
    }

    fn is_logic_app(&self) -> bool {
        self.kind.contains("workflowapp")
    }

    /// `Web app · Linux · container`, from `kind`.
    pub fn kind_label(&self) -> String {
        let what = if self.is_logic_app() {
            "Logic app (Standard)"
        } else if self.is_function_app() {
            "Function app"
        } else if self.kind.split(',').any(|k| k == "api") {
            "API app"
        } else {
            "Web app"
        };
        let mut parts = vec![what.to_string()];
        parts.push(if self.kind.contains("linux") { "Linux" } else { "Windows" }.into());
        if self.kind.contains("container") {
            parts.push("container".into());
        }
        parts.join(" · ")
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "running" => ResourceState::Running,
                "stopped" => ResourceState::Stopped,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }


    /// `-n {name} -g {rg} --subscription {sub}`.
    fn name_args(&self) -> Option<String> {
        Some(format!(
            "-n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for SiteRow {
    arm_row!("App Service app");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SITE_SECTIONS)
    }
    fn search_text(&self) -> String {
        let hosts: Vec<&str> = self.hostnames.iter().map(|h| h.name.as_str()).collect();
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.kind,
            hosts.join(" "),
            self.plan_id.as_deref().map(name_of_id).unwrap_or(""),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let client_cert = match (self.client_cert, &self.client_cert_mode) {
            (Some(true), Some(mode)) => format!("yes · {}", mode),
            (b, _) => json::yes_no(b),
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Kind".into(), self.kind_label()),
            ("State".into(), json::opt(self.state.clone())),
            ("Default hostname".into(), json::opt(self.default_host.clone())),
            ("Plan".into(), self.plan_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("HTTPS only".into(), json::yes_no(self.https_only)),
            ("Client certificates".into(), client_cert),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
            ("Last modified".into(), json::time(self.last_modified.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(plan) = &self.plan_id {
            v.push((format!("Plan {}", name_of_id(plan)), plan.clone()));
        }
        if let Some(s) = &self.vnet_subnet_id {
            v.push((format!("VNet integration subnet {}", name_of_id(s)), s.clone()));
        }
        if let Some(env) = &self.managed_environment_id {
            v.push((format!("Container Apps environment {}", name_of_id(env)), env.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        // Only a user-assigned id is an ARM id; `SystemAssigned` is not.
        if let Some(kv) = &self.key_vault_reference_identity {
            v.push((format!("Key Vault reference identity {}", name_of_id(kv)), kv.clone()));
        }
        v
    }
    /// Web apps take `--ids`. `functionapp show` re-declares its name
    /// argument without an `id_part`, so function and logic apps use the
    /// name form (SERVICES.md rule 9).
    fn cli_command(&self) -> Option<String> {
        if self.is_logic_app() {
            Some(format!("az logicapp show {}", self.name_args()?))
        } else if self.is_function_app() {
            Some(format!("az functionapp show {}", self.name_args()?))
        } else {
            Some(format!("az webapp show --ids {}", shell_quote(&self.base.id)))
        }
    }
}

pub fn site_section_lines(
    r: &SiteRow,
    section: SiteDetailSection,
    config: Option<&Lazy<Value>>,
) -> Vec<(String, String)> {
    match section {
        SiteDetailSection::Overview => overview_rows(r),
        SiteDetailSection::Configuration => match config {
            None | Some(Lazy::Loading) => vec![("Configuration".into(), "Loading…".into())],
            Some(Lazy::Error(e)) => crate::azure::services::error_rows(e),
            Some(Lazy::Loaded(v)) => config_rows(v, r),
        },
        SiteDetailSection::Hostnames => {
            if r.hostnames.is_empty() {
                return vec![(String::new(), "No hostnames".into())];
            }
            r.hostnames
                .iter()
                .map(|h| {
                    let ssl = match h.ssl_state.as_deref() {
                        Some("Disabled") | None => "no TLS binding".to_string(),
                        Some(s) => s.to_string(),
                    };
                    let kind = if h.host_type.as_deref() == Some("Repository") { " · SCM (Kudu)" } else { "" };
                    (h.name.clone(), format!("{}{}", ssl, kind))
                })
                .collect()
        }
        SiteDetailSection::Networking => {
            let mut lines = vec![("Public network access".into(), json::opt(r.public_network_access.clone()))];
            match &r.vnet_subnet_id {
                Some(s) => lines.push((format!("VNet integration · {}", name_of_id(s)), s.clone())),
                None => lines.push(("VNet integration".into(), "-".into())),
            }
            if let Some(env) = &r.managed_environment_id {
                lines.push((format!("Container Apps environment · {}", name_of_id(env)), env.clone()));
            }
            lines.push(("Outbound IPs".into(), json::join(&r.outbound_ips)));
            lines.push((String::new(), String::new()));
            lines.push((String::new(), "· access restrictions are in Configuration".into()));
            lines
        }
        SiteDetailSection::Related => related_rows(r),
        SiteDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The runtime stack from `config/web`: the Linux or Windows container
/// string, else the first language version set.
fn runtime_stack(c: &Value) -> String {
    let p = "/properties";
    for key in ["linuxFxVersion", "windowsFxVersion"] {
        if let Some(s) = json::str_at(c, &format!("{}/{}", p, key)).filter(|s| !s.is_empty()) {
            return s;
        }
    }
    for (key, label) in [
        ("javaVersion", "Java"),
        ("pythonVersion", "Python"),
        ("nodeVersion", "Node"),
        ("phpVersion", "PHP"),
        ("powerShellVersion", "PowerShell"),
        ("netFrameworkVersion", ".NET"),
    ] {
        if let Some(s) = json::str_at(c, &format!("{}/{}", p, key)).filter(|s| !s.is_empty()) {
            return format!("{} {}", label, s);
        }
    }
    "-".into()
}

/// The Configuration section body from `GET {site}/config/web`. Only
/// named, non-secret fields are read: `appSettings` and
/// `connectionStrings` are never touched, whatever the body carries.
pub fn config_rows(c: &Value, r: &SiteRow) -> Vec<(String, String)> {
    let p = "/properties";
    let at = |k: &str| format!("{}/{}", p, k);
    let mut lines = vec![
        ("Runtime".into(), runtime_stack(c)),
        ("Always on".into(), json::yes_no(json::bool_at(c, &at("alwaysOn")))),
        ("Min TLS".into(), json::text(c, &at("minTlsVersion"))),
        ("SCM min TLS".into(), json::text(c, &at("scmMinTlsVersion"))),
        ("FTPS".into(), json::text(c, &at("ftpsState"))),
        ("HTTP/2".into(), json::yes_no(json::bool_at(c, &at("http20Enabled")))),
        ("Health check path".into(), json::text(c, &at("healthCheckPath"))),
        ("32-bit worker".into(), json::yes_no(json::bool_at(c, &at("use32BitWorkerProcess")))),
        ("Web sockets".into(), json::yes_no(json::bool_at(c, &at("webSocketsEnabled")))),
        ("Remote debugging".into(), json::yes_no(json::bool_at(c, &at("remoteDebuggingEnabled")))),
        ("Route all through VNet".into(), json::yes_no(json::bool_at(c, &at("vnetRouteAllEnabled")))),
    ];
    if r.is_function_app() {
        lines.push(("Scale limit".into(), json::text(c, &at("functionAppScaleLimit"))));
        lines.push(("Min elastic instances".into(), json::text(c, &at("minimumElasticInstanceCount"))));
    }
    let restrictions = json::arr(c, &at("ipSecurityRestrictions"));
    lines.push((String::new(), String::new()));
    lines.push(("Access restrictions".into(), String::new()));
    if restrictions.is_empty() {
        lines.push((String::new(), "· none (all traffic allowed)".into()));
    }
    for rule in &restrictions {
        let source = json::arm_id(json::str_at(rule, "/vnetSubnetResourceId"));
        let label = format!(
            "  {} {} {}",
            json::text(rule, "/priority"),
            json::text(rule, "/name"),
            json::text(rule, "/action").to_lowercase()
        );
        match source {
            // A subnet source is an ARM id: Enter jumps to it.
            Some(subnet) => lines.push((label, subnet)),
            None => lines.push((
                label,
                json::str_at(rule, "/ipAddress")
                    .or_else(|| json::str_at(rule, "/tag"))
                    .unwrap_or_else(|| "-".into()),
            )),
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), NEVER_SETTINGS.into()));
    let read = if r.is_logic_app() {
        r.name_args().map(|a| format!("az logicapp config show {}", a))
    } else if r.is_function_app() {
        r.name_args().map(|a| format!("az functionapp config show {}", a))
    } else {
        Some(format!("az webapp config show --ids {}", shell_quote(&r.base.id)))
    };
    if let Some(cmd) = read {
        lines.push(("Read command".into(), cmd));
    }
    lines
}

/// The ARM path of a site's web configuration.
pub fn site_config_path(site_id: &str) -> String {
    format!("{}/config/web", site_id.trim_end_matches('/'))
}

// ── App Service plan ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PlanRow {
    pub base: ArmBase,
    pub kind: String,
    pub sku: Option<String>,
    pub tier: Option<String>,
    pub workers: Option<i64>,
    pub max_workers: Option<i64>,
    pub sites: Option<i64>,
    pub status: Option<String>,
    pub linux: Option<bool>,
    pub windows_container: Option<bool>,
    pub zone_redundant: Option<bool>,
    pub per_site_scaling: Option<bool>,
    pub elastic: Option<bool>,
    pub max_elastic_workers: Option<i64>,
}

impl PlanRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PlanRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(PlanRow {
            kind: json::str_at(v, "/kind").unwrap_or_default().to_lowercase(),
            sku: json::str_at(v, "/sku/name"),
            tier: json::str_at(v, "/sku/tier"),
            workers: json::int_at(v, "/sku/capacity"),
            max_workers: json::int_at(v, &format!("{}/maximumNumberOfWorkers", p)),
            sites: json::int_at(v, &format!("{}/numberOfSites", p)),
            status: json::str_at(v, &format!("{}/status", p)),
            linux: json::bool_at(v, &format!("{}/reserved", p)),
            windows_container: json::bool_at(v, &format!("{}/isXenon", p)),
            zone_redundant: json::bool_at(v, &format!("{}/zoneRedundant", p)),
            per_site_scaling: json::bool_at(v, &format!("{}/perSiteScaling", p)),
            elastic: json::bool_at(v, &format!("{}/elasticScaleEnabled", p)),
            max_elastic_workers: json::int_at(v, &format!("{}/maximumElasticWorkerCount", p)),
            base,
        })
    }

    fn os(&self) -> &'static str {
        match (self.linux, self.windows_container) {
            (Some(true), _) => "Linux",
            (_, Some(true)) => "Windows containers",
            _ => "Windows",
        }
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "ready" => ResourceState::Available,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for PlanRow {
    arm_row!("App Service plan");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PLAN_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.sku.clone()),
            self.os(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let sku = match (&self.sku, &self.tier) {
            (Some(s), Some(t)) => format!("{} · {}", s, t),
            (s, _) => json::opt(s.clone()),
        };
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Status".into(), json::opt(self.status.clone())),
            ("SKU".into(), sku),
            ("OS".into(), self.os().into()),
            ("Workers".into(), format!("{} of {}", json::num(self.workers), json::num(self.max_workers))),
            ("Apps".into(), json::num(self.sites)),
            ("Zone redundant".into(), json::yes_no(self.zone_redundant)),
            ("Per-app scaling".into(), json::yes_no(self.per_site_scaling)),
        ];
        if self.elastic == Some(true) || self.kind.contains("elastic") {
            lines.push(("Elastic max workers".into(), json::num(self.max_elastic_workers)));
        }
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az appservice plan show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn plan_section_lines(r: &PlanRow, section: PlanDetailSection) -> Vec<(String, String)> {
    match section {
        PlanDetailSection::Overview => overview_rows(r),
        PlanDetailSection::Related => {
            let mut lines = related_rows(r);
            lines.push((String::new(), "· the apps on this plan list it in their own Related".into()));
            lines
        }
        PlanDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct AppServiceService {
    scope: Scope,
}

impl AppServiceService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// One page of a sub-tab: every site for Apps, function and logic apps
    /// only for Functions, plans for Plans.
    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::AppServicePlans => page
                .iter()
                .filter_map(|v| PlanRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => {
                let functions_only = view == JumpView::FunctionApps;
                page.iter()
                    .filter_map(|v| SiteRow::from_json(v, tenant))
                    .filter(|s| !functions_only || s.is_function_app())
                    .map(|r| Box::new(r) as Box<dyn Resource>)
                    .collect()
            }
        }
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str) {
        match view {
            JumpView::AppServicePlans => (PLANS_PATH, "Listing App Service plans…"),
            JumpView::FunctionApps => (SITES_PATH, "Listing function apps…"),
            _ => (SITES_PATH, "Listing apps…"),
        }
    }
}

#[async_trait]
impl AzureService for AppServiceService {
    fn service_type(&self) -> ServiceType {
        ServiceType::AppService
    }

    fn name(&self) -> &str {
        "App Service"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, _) = Self::list_of(view);
        Ok(Self::rows(view, &self.scope.list(path, WEB_API_VERSION).await?, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let (path, label) = Self::list_of(view);
        let r = self
            .scope
            .stream(path, WEB_API_VERSION, &[], service_type, label, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, WEB_API_VERSION).await?;
        let tenant = self.scope.tenant();
        let not_found = || Error::ResourceNotFound(id.to_string());
        match JumpView::for_arm_id(id) {
            Some(JumpView::AppServicePlans) => Ok(Box::new(PlanRow::from_json(&v, tenant).ok_or_else(not_found)?)),
            _ => Ok(Box::new(SiteRow::from_json(&v, tenant).ok_or_else(not_found)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-web";

    fn site_json(kind: &str, state: &str) -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Web/sites/shop", RG),
            "name": "shop",
            "location": "westeurope",
            "kind": kind,
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-shop", RG): {}
            }},
            "properties": {
                "state": state,
                "defaultHostName": "shop.example.net",
                "hostNameSslStates": [
                    {"name": "shop.example.net", "sslState": "Disabled", "hostType": "Standard"},
                    {"name": "shop.scm.example.net", "sslState": "Disabled", "hostType": "Repository"},
                    {"name": "www.shop.example", "sslState": "SniEnabled", "hostType": "Standard"}
                ],
                "serverFarmId": format!("{}/providers/Microsoft.Web/serverfarms/plan-p1", RG),
                "httpsOnly": true,
                "clientCertEnabled": false,
                "publicNetworkAccess": "Enabled",
                "virtualNetworkSubnetId": format!("{}/providers/Microsoft.Network/virtualNetworks/v/subnets/app", RG),
                "outboundIpAddresses": "20.1.1.1,20.1.1.2"
            }
        })
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for desc in [&SITE_SECTIONS, &PLAN_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(labels[labels.len() - 2], "Related");
            assert_eq!(labels.last(), Some(&"Tags"));
        }
    }

    #[test]
    fn sites_split_on_kind_and_take_state_from_the_site() {
        let web = SiteRow::from_json(&site_json("app,linux", "Running"), None).unwrap();
        assert!(!web.is_function_app());
        assert_eq!(web.kind_label(), "Web app · Linux");
        assert_eq!(web.state(), ResourceState::Running);
        assert_eq!(web.state_label(), "running");
        assert!(web.cli_command().unwrap().starts_with("az webapp show --ids "));

        let func = SiteRow::from_json(&site_json("functionapp,linux,container", "Stopped"), None).unwrap();
        assert!(func.is_function_app());
        assert_eq!(func.kind_label(), "Function app · Linux · container");
        assert_eq!(func.state(), ResourceState::Stopped);
        assert_eq!(
            func.cli_command().as_deref(),
            Some("az functionapp show -n shop -g rg-web --subscription 0000")
        );

        let logic = SiteRow::from_json(&site_json("functionapp,workflowapp", "Running"), None).unwrap();
        assert!(logic.is_function_app(), "Logic Apps Standard list with the function apps");
        assert_eq!(logic.kind_label(), "Logic app (Standard) · Windows");
        assert!(logic.cli_command().unwrap().starts_with("az logicapp show -n shop"));

        let page = vec![site_json("app", "Running"), site_json("functionapp", "Running")];
        assert_eq!(AppServiceService::rows(JumpView::WebApps, &page, None).len(), 2, "Apps lists every site");
        assert_eq!(AppServiceService::rows(JumpView::FunctionApps, &page, None).len(), 1);
    }

    #[test]
    fn site_sections_read_hostnames_networking_and_related() {
        let row = SiteRow::from_json(&site_json("app", "Running"), None).unwrap();
        let hosts = site_section_lines(&row, SiteDetailSection::Hostnames, None);
        assert_eq!(hosts[1], ("shop.scm.example.net".to_string(), "no TLS binding · SCM (Kudu)".to_string()));
        assert_eq!(hosts[2].1, "SniEnabled");
        let net = site_section_lines(&row, SiteDetailSection::Networking, None);
        assert!(net.iter().any(|(k, _)| k == "VNet integration · app"));
        assert!(net.iter().any(|(k, v)| k == "Outbound IPs" && v == "20.1.1.1, 20.1.1.2"));
        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Plan plan-p1", "VNet integration subnet app", "Identity id-shop"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
    }

    #[test]
    fn configuration_never_renders_app_settings_or_connection_strings() {
        let row = SiteRow::from_json(&site_json("app,linux", "Running"), None).unwrap();
        let config = serde_json::json!({
            "properties": {
                "linuxFxVersion": "NODE|20-lts",
                "alwaysOn": true,
                "minTlsVersion": "1.2",
                "ftpsState": "Disabled",
                "http20Enabled": true,
                "healthCheckPath": "/healthz",
                "ipSecurityRestrictions": [
                    {"priority": 100, "name": "office", "action": "Allow", "ipAddress": "203.0.113.0/24"},
                    {"priority": 200, "name": "hub", "action": "Allow",
                     "vnetSubnetResourceId": format!("{}/providers/Microsoft.Network/virtualNetworks/hub/subnets/s", RG)}
                ],
                // Whatever a body carries here is never shown.
                "appSettings": [{"name": "DB_PASSWORD", "value": "hunter2"}],
                "connectionStrings": [{"name": "db", "connectionString": "Server=x;Password=hunter2"}]
            }
        });
        let lines = site_section_lines(&row, SiteDetailSection::Configuration, Some(&Lazy::Loaded(config)));
        assert_eq!(lines[0], ("Runtime".to_string(), "NODE|20-lts".to_string()));
        assert!(lines.iter().any(|(k, v)| k == "Health check path" && v == "/healthz"));
        assert!(lines.iter().any(|(k, v)| k == "  100 office allow" && v == "203.0.113.0/24"));
        let (_, hub) = lines.iter().find(|(k, _)| k == "  200 hub allow").unwrap();
        assert_eq!(
            crate::azure::service::JumpView::for_arm_id(hub),
            Some(crate::azure::service::JumpView::Subnets)
        );
        let all: String = lines.iter().map(|(k, v)| format!("{k}{v}")).collect();
        assert!(!all.contains("hunter2") && !all.contains("DB_PASSWORD"), "settings leaked: {all}");
        assert!(lines.iter().any(|(_, v)| v == NEVER_SETTINGS));
        assert!(lines.last().unwrap().1.starts_with("az webapp config show --ids "));

        let windows = serde_json::json!({"properties": {"netFrameworkVersion": "v8.0"}});
        let lines = config_rows(&windows, &row);
        assert_eq!(lines[0].1, ".NET v8.0");
        assert_eq!(site_config_path(&row.base.id), format!("{}/config/web", row.base.id));
    }

    #[test]
    fn plan_row_reads_sku_os_and_workers() {
        let plan = PlanRow::from_json(
            &serde_json::json!({
                "id": format!("{}/providers/Microsoft.Web/serverfarms/plan-p1", RG),
                "name": "plan-p1",
                "location": "westeurope",
                "kind": "linux",
                "sku": {"name": "P1v3", "tier": "PremiumV3", "capacity": 2},
                "properties": {"status": "Ready", "reserved": true, "maximumNumberOfWorkers": 30,
                    "numberOfSites": 3, "zoneRedundant": true, "provisioningState": "Succeeded"}
            }),
            None,
        )
        .unwrap();
        assert_eq!(plan.state(), ResourceState::Available);
        assert_eq!(plan.state_label(), "ready");
        assert!(plan.details().iter().any(|(k, v)| k == "SKU" && v == "P1v3 · PremiumV3"));
        assert!(plan.details().iter().any(|(k, v)| k == "OS" && v == "Linux"));
        assert!(plan.details().iter().any(|(k, v)| k == "Workers" && v == "2 of 30"));
        assert!(plan.cli_command().unwrap().starts_with("az appservice plan show --ids "));
    }
}
