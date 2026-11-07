//! Static Web Apps (#200, SERVICES.md rule 43): the App Service tab's
//! Static sites sub-tab, one subscription-wide list of
//! `Microsoft.Web/staticSites`. A site's environments (`builds`), custom
//! domains and linked backends are lazy sections, one list per site each.
//!
//! Control plane only. The deployment token (`listSecrets`) and the app
//! and function settings (`listAppSettings`, `listFunctionAppSettings`)
//! are `POST`s that return secrets; a `repositoryToken` and a database
//! connection's configuration files are removed before a row or the lazy
//! store keeps the JSON ([`without_secrets`]). The site's hostnames are
//! shown as text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::ServiceType;
use crate::azure::services::app_service::WEB_API_VERSION;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use serde_json::Value;
use tokio::sync::mpsc;

const SITES_PATH: &str = "/providers/Microsoft.Web/staticSites";

const NEVER_SECRETS: &str = "metadata from ARM; the deployment token, app settings and function settings are never fetched";

crate::sections! {
    pub enum StaticSiteDetailSection,
    pub static STATIC_SITE_SECTIONS = [
        Overview "Overview",
        Configuration "Configuration",
        Environments "Environments" => crate::app::App::trigger_swa_builds,
        Domains "Custom domains" => crate::app::App::trigger_swa_domains,
        Backends "Backends" => crate::app::App::trigger_swa_backends,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_swa_backends,
        Tags "Tags",
    ]
}

// ── Credentials out ───────────────────────────────────────────────────

/// Removed wherever they sit: the GitHub token a create takes (ARM should
/// never echo it) and a database connection's configuration files, whose
/// contents are the app's own config.
const SECRET_FIELDS: &[&str] = &["repositoryToken", "configurationFiles"];

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            map.values_mut().for_each(scrub);
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every credential removed: what a row parses and keeps
/// for `e`, and what each lazy list stores.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

// ── The row ───────────────────────────────────────────────────────────

/// A backend the site fronts: a linked backend or a bring-your-own
/// function app, with its region.
#[derive(Debug, Clone)]
pub struct Backend {
    pub id: String,
    pub region: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StaticSiteRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub default_hostname: Option<String>,
    pub repository_url: Option<String>,
    pub branch: Option<String>,
    pub provider: Option<String>,
    pub staging_policy: Option<String>,
    pub allow_config_file_updates: Option<bool>,
    pub enterprise_cdn: Option<String>,
    pub public_network_access: Option<String>,
    pub custom_domains: Vec<String>,
    pub app_location: Option<String>,
    pub api_location: Option<String>,
    pub output_location: Option<String>,
    pub skip_workflow: Option<bool>,
    /// `(endpoint id, status)` of each inbound private endpoint.
    pub private_endpoints: Vec<(String, Option<String>)>,
    pub linked_backends: Vec<Backend>,
    pub user_functions: Vec<Backend>,
    pub database_ids: Vec<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub key_vault_identity: Option<String>,
}

impl StaticSiteRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<StaticSiteRow> {
        let v = &without_secrets(raw);
        let mut base = ArmBase::from_json(v, tenant)?;
        // The list can return a display-name location (`West Europe`).
        base.location = base.location.replace(' ', "");
        let p = |f: &str| format!("/properties/{}", f);
        let build = |f: &str| json::str_at(v, &p(&format!("buildProperties/{}", f))).filter(|s| !s.is_empty());
        Some(StaticSiteRow {
            sku: json::str_at(v, "/sku/name"),
            default_hostname: json::str_at(v, &p("defaultHostname")),
            repository_url: json::str_at(v, &p("repositoryUrl")).filter(|s| !s.is_empty()),
            branch: json::str_at(v, &p("branch")).filter(|s| !s.is_empty()),
            provider: json::str_at(v, &p("provider")),
            staging_policy: json::str_at(v, &p("stagingEnvironmentPolicy")),
            allow_config_file_updates: json::bool_at(v, &p("allowConfigFileUpdates")),
            enterprise_cdn: json::str_at(v, &p("enterpriseGradeCdnStatus")),
            public_network_access: json::str_at(v, &p("publicNetworkAccess")).filter(|s| !s.is_empty()),
            custom_domains: json::strings_at(v, &p("customDomains")),
            app_location: build("appLocation"),
            api_location: build("apiLocation"),
            output_location: build("outputLocation").or_else(|| build("appArtifactLocation")),
            skip_workflow: json::bool_at(v, &p("buildProperties/skipGithubActionWorkflowGeneration")),
            private_endpoints: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .filter_map(|c| {
                    Some((
                        json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                        json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    ))
                })
                .collect(),
            linked_backends: backends_at(v, &p("linkedBackends"), "backendResourceId"),
            user_functions: backends_at(v, &p("userProvidedFunctionApps"), "properties/functionAppResourceId"),
            database_ids: json::arr(v, &p("databaseConnections"))
                .iter()
                .filter_map(|c| json::arm_id(json::str_at(c, "/resourceId")))
                .collect(),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            key_vault_identity: json::str_at(v, &p("keyVaultReferenceIdentity")),
            base,
        })
    }

    /// `-n {n} -g {rg} --subscription {sub}`: `az staticwebapp` takes the
    /// name form throughout (no `id_part`, checked 2026-11-07).
    fn name_args(&self) -> Option<String> {
        Some(format!(
            "-n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }

    fn read_command(&self, command: &str) -> (String, String) {
        ("Read command".into(), format!("{} {}", command, self.name_args().unwrap_or_default()))
    }

    fn configuration_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Staging environments".into(), json::opt(self.staging_policy.clone())),
            ("Config file updates".into(), json::yes_no(self.allow_config_file_updates)),
            ("Enterprise-grade CDN".into(), json::opt(self.enterprise_cdn.clone())),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("App location".into(), json::opt(self.app_location.clone())),
            ("API location".into(), json::opt(self.api_location.clone())),
            ("Output location".into(), json::opt(self.output_location.clone())),
            (
                "Workflow file".into(),
                match self.skip_workflow {
                    Some(true) => "not generated".into(),
                    Some(false) => "generated".into(),
                    None => "-".into(),
                },
            ),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ];
        for id in &self.user_identity_ids {
            lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
        }
        if let Some(kv) = &self.key_vault_identity {
            lines.push(("Key Vault references".into(), kv.clone()));
        }
        for (pe, status) in &self.private_endpoints {
            lines.push((format!("Private endpoint · {} ({})", name_of_id(pe), json::opt(status.clone())), pe.clone()));
        }
        for db in &self.database_ids {
            lines.push((format!("Database · {}", name_of_id(db)), db.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), NEVER_SECRETS.into()));
        lines
    }
}

fn backends_at(v: &Value, ptr: &str, id_field: &str) -> Vec<Backend> {
    json::arr(v, ptr)
        .iter()
        .filter_map(|b| {
            let region = json::str_at(b, "/region").or_else(|| json::str_at(b, "/properties/functionAppRegion"));
            Some(Backend { id: json::arm_id(json::str_at(b, &format!("/{}", id_field)))?, region })
        })
        .collect()
}

impl Resource for StaticSiteRow {
    arm_row!("Static web app");
    /// No runtime status: the ladder's provisioning rung, else stateless.
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&STATIC_SITE_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let sku = self.sku.clone()?;
        Some(match &self.provider {
            Some(p) => format!("{} · {}", sku, p),
            None => sku,
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Default hostname".into(), json::opt(self.default_hostname.clone())),
            ("Custom domains".into(), json::join(&self.custom_domains)),
            ("Repository".into(), json::opt(self.repository_url.clone())),
            ("Branch".into(), json::opt(self.branch.clone())),
            ("Provider".into(), json::opt(self.provider.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for b in &self.linked_backends {
            v.push((format!("Backend {}", name_of_id(&b.id)), b.id.clone()));
        }
        for b in &self.user_functions {
            v.push((format!("Function app {}", name_of_id(&b.id)), b.id.clone()));
        }
        for pe in self.private_endpoints.iter().map(|(id, _)| id) {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for db in &self.database_ids {
            v.push((format!("Database {}", name_of_id(db)), db.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az staticwebapp show {}", self.name_args()?))
    }
}

// ── The lazy lists ────────────────────────────────────────────────────

/// The ARM path of one of a site's child lists (`builds`,
/// `customDomains`, `linkedBackends`).
pub fn site_child_path(site_id: &str, child: &str) -> String {
    format!("{}/{}", site_id.trim_end_matches('/'), child)
}

/// A status word: `ready` plain, a failure `⚠`, anything in flight
/// lowercased.
fn status_text(status: Option<&str>, failed: &[&str]) -> String {
    match status {
        None => "-".into(),
        Some(s) if failed.iter().any(|f| f.eq_ignore_ascii_case(s)) => format!("⚠ {}", s.to_lowercase()),
        Some(s) => s.to_lowercase(),
    }
}

/// The Environments body: production first, then the previews newest
/// first, each with its hostname, branch or pull request and status.
pub fn environment_rows(items: &[Value], r: &StaticSiteRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No environments".into()));
    }
    let mut builds: Vec<&Value> = items.iter().collect();
    let is_prod = |b: &Value| json::str_at(b, "/properties/buildId").as_deref() == Some("default");
    builds.sort_by(|a, b| {
        is_prod(b).cmp(&is_prod(a)).then_with(|| {
            json::text(b, "/properties/lastUpdatedOn").cmp(&json::text(a, "/properties/lastUpdatedOn"))
        })
    });
    for b in builds {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        let title = if is_prod(b) {
            "production".to_string()
        } else {
            format!("preview {}", json::str_at(b, &p("buildId")).unwrap_or_else(|| json::text(b, "/name")))
        };
        lines.push((title, String::new()));
        lines.push(("  Hostname".into(), json::text(b, &p("hostname"))));
        if let Some(branch) = json::str_at(b, &p("sourceBranch")).filter(|s| !s.is_empty()) {
            lines.push(("  Branch".into(), branch));
        }
        if let Some(pr) = json::str_at(b, &p("pullRequestTitle")).filter(|s| !s.is_empty()) {
            lines.push(("  Pull request".into(), pr));
        }
        lines.push((
            "  Status".into(),
            status_text(json::str_at(b, &p("status")).as_deref(), &["Failed", "Detached"]),
        ));
        lines.push(("  Updated".into(), json::time(json::str_at(b, &p("lastUpdatedOn")))));
        for backend in backends_at(b, &p("linkedBackends"), "backendResourceId") {
            lines.push((format!("  Backend · {}", name_of_id(&backend.id)), backend.id));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az staticwebapp environment list"));
    lines
}

/// The Custom domains body: each domain and where its validation stands
/// (`⚠` failed or unhealthy: the domain does not serve the site).
pub fn domain_rows(items: &[Value], r: &StaticSiteRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No custom domains".into()));
    }
    for d in items {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        lines.push((json::str_at(d, &p("domainName")).unwrap_or_else(|| json::text(d, "/name")), String::new()));
        lines.push((
            "  Status".into(),
            status_text(json::str_at(d, &p("status")).as_deref(), &["Failed", "Unhealthy"]),
        ));
        lines.push(("  Added".into(), json::time(json::str_at(d, &p("createdOn")))));
        if let Some(e) = json::str_at(d, &p("errorMessage")).filter(|s| !s.is_empty()) {
            lines.push(("  Error".into(), format!("⚠ {}", e)));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az staticwebapp hostname list"));
    lines
}

/// The Backends body: the linked backends (a Function app, Container app
/// or API Management the site's `/api` routes to), then any
/// bring-your-own function app the body names.
pub fn backend_rows(items: &[Value], r: &StaticSiteRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() && r.user_functions.is_empty() {
        lines.push((String::new(), "No linked backends".into()));
    }
    for b in items {
        let p = |f: &str| format!("/properties/{}", f);
        let Some(id) = json::arm_id(json::str_at(b, &p("backendResourceId"))) else {
            continue;
        };
        lines.push((String::new(), String::new()));
        lines.push((format!("{} · {}", backend_kind(&id), name_of_id(&id)), id));
        lines.push(("  Region".into(), json::text(b, &p("region"))));
        lines.push((
            "  Provisioning".into(),
            status_text(json::str_at(b, &p("provisioningState")).as_deref(), &["Failed"]),
        ));
        lines.push(("  Linked".into(), json::time(json::str_at(b, &p("createdOn")))));
    }
    for f in &r.user_functions {
        lines.push((String::new(), String::new()));
        lines.push((format!("Function app (bring your own) · {}", name_of_id(&f.id)), f.id.clone()));
        lines.push(("  Region".into(), json::opt(f.region.clone())));
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az staticwebapp backends show"));
    lines
}

/// What a backend id names, by its ARM type.
fn backend_kind(id: &str) -> &'static str {
    let lower = id.to_lowercase();
    if lower.contains("/providers/microsoft.app/containerapps/") {
        "Container app"
    } else if lower.contains("/providers/microsoft.apimanagement/") {
        "API Management"
    } else if lower.contains("/providers/microsoft.web/sites/") {
        "Function app"
    } else {
        "Backend"
    }
}

/// Body lines for one section of a static web app; `None` for another
/// type.
pub fn static_site_section_lines(
    r: &dyn Resource,
    idx: usize,
    builds: Option<&Lazy<Vec<Value>>>,
    domains: Option<&Lazy<Vec<Value>>>,
    backends: Option<&Lazy<Vec<Value>>>,
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<StaticSiteRow>()?;
    use StaticSiteDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Configuration => x.configuration_rows(),
        S::Environments => lazy_list_rows(builds, "Environments", |items| environment_rows(items, x)),
        S::Domains => lazy_list_rows(domains, "Custom domains", |items| domain_rows(items, x)),
        S::Backends => lazy_list_rows(backends, "Backends", |items| backend_rows(items, x)),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let extra = match backends {
                Some(Lazy::Loaded(items)) => items
                    .iter()
                    .filter_map(|b| json::arm_id(json::str_at(b, "/properties/backendResourceId")))
                    .map(|id| (format!("Backend {}", name_of_id(&id)), id))
                    .collect(),
                _ => Vec::new(),
            };
            related_rows_with(x, extra)
        }
        S::Tags => tag_rows(x.tags()),
    })
}

fn rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| StaticSiteRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

// ── Provider (the App Service tab delegates its Static sites view) ───

pub struct StaticSiteLists<'a> {
    pub scope: &'a Scope,
}

impl StaticSiteLists<'_> {
    pub async fn list(&self) -> Result<Vec<Box<dyn Resource>>> {
        let page = self.scope.list(SITES_PATH, WEB_API_VERSION).await?;
        Ok(rows(&page, self.scope.tenant()))
    }

    pub async fn stream(&self, event_tx: &mpsc::UnboundedSender<Event>, service_type: ServiceType) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(SITES_PATH, WEB_API_VERSION, &[], service_type, "Listing static web apps…", event_tx, |page| {
                rows(&page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, event_tx)
    }

    pub async fn get(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, WEB_API_VERSION).await?;
        rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-web";

    fn site_id() -> String {
        format!("{}/providers/Microsoft.Web/staticSites/swa-shop", RG)
    }

    fn api_id() -> String {
        format!("{}/providers/Microsoft.App/containerApps/ca-api", RG)
    }

    fn site() -> StaticSiteRow {
        StaticSiteRow::from_json(
            &json!({
                "id": site_id(), "name": "swa-shop", "location": "West Europe",
                "sku": {"name": "Standard", "tier": "Standard"},
                "properties": {
                    "defaultHostname": "swa-shop.example", "repositoryUrl": "https://github.com/contoso/shop",
                    "branch": "main", "provider": "GitHub", "repositoryToken": "ghp_planted",
                    "customDomains": ["shop.contoso.example"],
                    "stagingEnvironmentPolicy": "Enabled", "allowConfigFileUpdates": true,
                    "enterpriseGradeCdnStatus": "Disabled",
                    "buildProperties": {"appLocation": "/", "apiLocation": "", "outputLocation": "dist",
                        "skipGithubActionWorkflowGeneration": false},
                    "linkedBackends": [{"backendResourceId": api_id(), "region": "westeurope"}],
                    "databaseConnections": [{"resourceId": format!("{}/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-shop", RG),
                        "configurationFiles": [{"fileName": "staticwebapp.database.config.json", "contents": "cGxhbnRlZA=="}]}],
                    "privateEndpointConnections": [{"properties": {
                        "privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-swa", RG)},
                        "privateLinkServiceConnectionState": {"status": "Approved"}
                    }}]
                }
            }),
            Some("t-1"),
        )
        .unwrap()
    }

    fn get<'a>(lines: &'a [(String, String)], key: &str) -> Option<&'a str> {
        lines.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = STATIC_SITE_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Configuration", "Environments", "Custom domains", "Backends", "Access", "Activity", "Related", "Tags"]
        );
    }

    #[test]
    fn a_site_reads_its_repository_build_and_the_name_form_command() {
        let row = site();
        assert_eq!(row.base.location, "westeurope");
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.list_summary().as_deref(), Some("Standard · GitHub"));
        assert_eq!(row.cli_command().as_deref(), Some("az staticwebapp show -n swa-shop -g rg-web --subscription 0000"));
        let details = row.details();
        assert_eq!(get(&details, "Default hostname"), Some("swa-shop.example"));
        assert_eq!(get(&details, "Custom domains"), Some("shop.contoso.example"));

        let config = row.configuration_rows();
        assert_eq!(get(&config, "API location"), Some("-"), "an empty location is no location");
        assert_eq!(get(&config, "Output location"), Some("dist"));
        assert_eq!(get(&config, "Workflow file"), Some("generated"));
        assert!(config.iter().any(|(k, _)| k == "Private endpoint · pe-swa (Approved)"));
        assert_eq!(config.last().unwrap().1, NEVER_SECRETS);

        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Backend ca-api", "Private endpoint pe-swa", "Database cosmos-shop"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
    }

    #[test]
    fn the_token_and_configuration_files_never_reach_the_row() {
        let row = site();
        assert!(!row.base.raw.contains("ghp_planted"));
        assert!(!row.base.raw.contains("cGxhbnRlZA=="));
        assert!(!row.base.raw.contains("configurationFiles"));
        assert!(row.base.raw.contains("cosmos-shop"), "the connection itself stays");
    }

    #[test]
    fn environments_put_production_first_and_flag_a_failed_preview() {
        let row = site();
        let items = vec![
            json!({"name": "1", "properties": {"buildId": "12", "hostname": "swa-shop-12.example", "sourceBranch": "feature/cart",
                "pullRequestTitle": "Cart redesign", "status": "Failed", "lastUpdatedOn": "2026-11-01T00:00:00Z"}}),
            json!({"name": "default", "properties": {"buildId": "default", "hostname": "swa-shop.example", "sourceBranch": "main",
                "status": "Ready", "lastUpdatedOn": "2026-10-30T00:00:00Z",
                "linkedBackends": [{"backendResourceId": api_id()}]}}),
        ];
        let lazy = Lazy::Loaded(items);
        let lines = static_site_section_lines(&row, StaticSiteDetailSection::Environments as usize, Some(&lazy), None, None).unwrap();
        let titles: Vec<&str> = lines.iter().filter(|(k, v)| !k.starts_with(' ') && !k.is_empty() && v.is_empty()).map(|(k, _)| k.as_str()).collect();
        assert_eq!(titles, ["production", "preview 12"]);
        let statuses: Vec<&str> = lines.iter().filter(|(k, _)| k == "  Status").map(|(_, v)| v.as_str()).collect();
        assert_eq!(statuses, ["ready", "⚠ failed"]);
        assert!(lines.iter().any(|(k, v)| k == "  Backend · ca-api" && v == &api_id()));
        assert_eq!(lines.last().unwrap().1, "az staticwebapp environment list -n swa-shop -g rg-web --subscription 0000");
    }

    #[test]
    fn domains_and_backends_render_their_status() {
        let row = site();
        let domains = Lazy::Loaded(vec![
            json!({"properties": {"domainName": "shop.contoso.example", "status": "Ready"}}),
            json!({"properties": {"domainName": "beta.contoso.example", "status": "Failed", "errorMessage": "CNAME not found"}}),
        ]);
        let lines = static_site_section_lines(&row, StaticSiteDetailSection::Domains as usize, None, Some(&domains), None).unwrap();
        let statuses: Vec<&str> = lines.iter().filter(|(k, _)| k == "  Status").map(|(_, v)| v.as_str()).collect();
        assert_eq!(statuses, ["ready", "⚠ failed"]);
        assert_eq!(get(&lines, "  Error"), Some("⚠ CNAME not found"));

        let func = format!("{}/providers/Microsoft.Web/sites/func-api", RG);
        let backends = Lazy::Loaded(vec![
            json!({"properties": {"backendResourceId": api_id(), "region": "westeurope", "provisioningState": "Succeeded"}}),
            json!({"properties": {"backendResourceId": func, "region": "westeurope", "provisioningState": "Failed"}}),
        ]);
        let lines = static_site_section_lines(&row, StaticSiteDetailSection::Backends as usize, None, None, Some(&backends)).unwrap();
        assert!(lines.iter().any(|(k, v)| k == "Container app · ca-api" && v == &api_id()));
        assert!(lines.iter().any(|(k, v)| k == "Function app · func-api" && v == &func));
        assert!(lines.iter().any(|(k, v)| k == "  Provisioning" && v == "⚠ failed"));

        let related = static_site_section_lines(&row, StaticSiteDetailSection::Related as usize, None, None, Some(&backends)).unwrap();
        assert!(related.iter().any(|(_, id)| id == &func), "the lazy list adds the function app");
        assert_eq!(related.iter().filter(|(_, id)| id == &api_id()).count(), 1, "deduplicated");

        let empty = static_site_section_lines(&row, StaticSiteDetailSection::Domains as usize, None, Some(&Lazy::Loaded(vec![])), None).unwrap();
        assert_eq!(empty[0].1, "No custom domains");
        let loading = static_site_section_lines(&row, StaticSiteDetailSection::Backends as usize, None, None, Some(&Lazy::Loading)).unwrap();
        assert_eq!(loading[0].1, "Loading…");
        assert_eq!(site_child_path(&row.base.id, "builds"), format!("{}/builds", site_id()));
    }
}
