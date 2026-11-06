//! AI Search (#196, SERVICES.md rule 38): the Foundry tab's Search
//! services sub-tab, one subscription-wide list of
//! `Microsoft.Search/searchServices`. A service's shared private links
//! (its outbound private connections to storage, Cosmos or a Foundry
//! account) are a lazy section, one list per service.
//!
//! Control plane only. The admin and query keys (`listAdminKeys`,
//! `listQueryKeys`) are `POST`s that return secrets, and indexes,
//! indexers and skillsets live on the service's own endpoint; the guard
//! names that host. The endpoint is shown as text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::ServiceType;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version with months behind it (azure-rest-api-specs,
/// checked 2026-11-07; 2026-11-01 is days old).
pub const SEARCH_API_VERSION: &str = "2025-05-01";
const SERVICES_PATH: &str = "/providers/Microsoft.Search/searchServices";

const NEVER_KEYS: &str = "metadata from ARM; API keys, indexes and documents are never fetched";

crate::sections! {
    pub enum SearchDetailSection,
    pub static SEARCH_SECTIONS = [
        Overview "Overview",
        Service "Service",
        Network "Network",
        Security "Security",
        SharedLinks "Shared private links" => crate::app::App::trigger_search_shared_links,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_search_shared_links,
        Tags "Tags",
    ]
}

/// One inbound private endpoint, as the service body lists it.
#[derive(Debug, Clone)]
pub struct EndpointConnection {
    pub endpoint_id: String,
    pub status: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SearchServiceRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub status: Option<String>,
    pub status_details: Option<String>,
    pub replicas: Option<i64>,
    pub partitions: Option<i64>,
    pub hosting_mode: Option<String>,
    pub compute_type: Option<String>,
    pub semantic_search: Option<String>,
    pub endpoint: Option<String>,
    pub upgrade_available: Option<String>,
    pub upgraded_at: Option<String>,
    pub public_network_access: Option<String>,
    pub bypass: Option<String>,
    pub ip_rules: Vec<String>,
    pub exfiltration_blocks: Vec<String>,
    pub private_endpoints: Vec<EndpointConnection>,
    /// The targets of the shared private links the body carries (the
    /// lazy list is the section's source; this feeds Related at once).
    pub shared_link_targets: Vec<String>,
    pub disable_local_auth: Option<bool>,
    /// `apiKeyOnly` or `aadOrApiKey`, the one key `authOptions` holds.
    pub auth_option: Option<String>,
    pub aad_failure_mode: Option<String>,
    pub cmk_enforcement: Option<String>,
    pub cmk_compliance: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
}

impl SearchServiceRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<SearchServiceRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        let auth = v.pointer("/properties/authOptions").and_then(Value::as_object);
        Some(SearchServiceRow {
            sku: json::str_at(v, "/sku/name"),
            status: json::str_at(v, &p("status")),
            status_details: json::str_at(v, &p("statusDetails")).filter(|s| !s.is_empty()),
            replicas: json::int_at(v, &p("replicaCount")),
            partitions: json::int_at(v, &p("partitionCount")),
            hosting_mode: json::str_at(v, &p("hostingMode")),
            compute_type: json::str_at(v, &p("computeType")),
            semantic_search: json::str_at(v, &p("semanticSearch")),
            endpoint: json::str_at(v, &p("endpoint")),
            upgrade_available: json::str_at(v, &p("upgradeAvailable")),
            upgraded_at: json::str_at(v, &p("serviceUpgradedAt")),
            public_network_access: json::str_at(v, &p("publicNetworkAccess")),
            bypass: json::str_at(v, &p("networkRuleSet/bypass")),
            ip_rules: json::arr(v, &p("networkRuleSet/ipRules")).iter().filter_map(|r| json::str_at(r, "/value")).collect(),
            exfiltration_blocks: json::strings_at(v, &p("dataExfiltrationProtections")),
            private_endpoints: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .filter_map(|c| {
                    Some(EndpointConnection {
                        endpoint_id: json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                        status: json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    })
                })
                .collect(),
            shared_link_targets: json::arr(v, &p("sharedPrivateLinkResources"))
                .iter()
                .filter_map(|l| json::arm_id(json::str_at(l, "/properties/privateLinkResourceId")))
                .collect(),
            disable_local_auth: json::bool_at(v, &p("disableLocalAuth")),
            auth_option: auth.and_then(|o| o.keys().next().cloned()),
            aad_failure_mode: json::str_at(v, &p("authOptions/aadOrApiKey/aadAuthFailureMode")),
            cmk_enforcement: json::str_at(v, &p("encryptionWithCmk/enforcement")),
            cmk_compliance: json::str_at(v, &p("encryptionWithCmk/encryptionComplianceStatus")),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    /// Provisioning first, then the service's own `status`: `running` is
    /// the healthy word, `degraded` and `error` are trouble.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "running" => ResourceState::Available,
                "provisioning" => ResourceState::Creating,
                "deleting" => ResourceState::Deleting,
                "disabled" | "stopped" => ResourceState::Stopped,
                "degraded" | "error" => ResourceState::Unavailable,
                _ => ResourceState::Unknown(s.to_lowercase()),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// Search units, the billing unit: replicas × partitions (a free
    /// service has neither).
    fn search_units(&self) -> Option<i64> {
        Some(self.replicas? * self.partitions?)
    }

    /// How the service's own API takes a caller: keys, Entra ID or both.
    pub fn auth_text(&self) -> String {
        if self.disable_local_auth == Some(true) {
            return "Entra ID only (API keys off)".into();
        }
        match self.auth_option.as_deref() {
            Some("aadOrApiKey") => match &self.aad_failure_mode {
                Some(mode) => format!("Entra ID or API key · on failure {}", mode),
                None => "Entra ID or API key".into(),
            },
            Some("apiKeyOnly") => "API key only".into(),
            Some(other) => other.to_string(),
            None => "-".into(),
        }
    }

    /// `--search-service-name {n} -g {rg} --subscription {sub}`: the child
    /// lists take the name form (no `id_part`, checked 2026-11-07).
    fn child_args(&self) -> Option<String> {
        Some(format!(
            "--search-service-name {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }

    fn service_rows(&self) -> Vec<(String, String)> {
        // Status, SKU and the endpoint are on Overview.
        let mut lines: Vec<(String, String)> = Vec::new();
        if let Some(d) = &self.status_details {
            lines.push(("Status details".into(), d.clone()));
        }
        lines.extend([
            ("Replicas".into(), json::opt(self.replicas.map(|n| n.to_string()))),
            ("Partitions".into(), json::opt(self.partitions.map(|n| n.to_string()))),
            ("Search units".into(), json::opt(self.search_units().map(|n| n.to_string()))),
            ("Hosting mode".into(), json::opt(self.hosting_mode.clone())),
            ("Compute".into(), json::opt(self.compute_type.clone())),
            ("Semantic ranker".into(), json::opt(self.semantic_search.clone())),
            ("Upgrade".into(), json::opt(self.upgrade_available.clone())),
            ("Last upgraded".into(), json::time(self.upgraded_at.clone())),
        ]);
        lines
    }

    fn network_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Bypass".into(), json::opt(self.bypass.clone())),
            ("IP rules".into(), if self.ip_rules.is_empty() { "none".into() } else { json::join(&self.ip_rules) }),
        ];
        if !self.exfiltration_blocks.is_empty() {
            lines.push(("Data exfiltration".into(), format!("blocked: {}", json::join(&self.exfiltration_blocks))));
        }
        for pe in &self.private_endpoints {
            lines.push((
                format!("Private endpoint · {} ({})", name_of_id(&pe.endpoint_id), json::opt(pe.status.clone())),
                pe.endpoint_id.clone(),
            ));
        }
        lines
    }

    fn security_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Authentication".into(), self.auth_text()),
            ("Identity".into(), json::opt(self.identity_type.clone())),
            ("CMK enforcement".into(), json::opt(self.cmk_enforcement.clone())),
            ("CMK compliance".into(), json::opt(self.cmk_compliance.clone())),
        ];
        for id in &self.user_identity_ids {
            lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), NEVER_KEYS.into()));
        lines
    }
}

impl Resource for SearchServiceRow {
    arm_row!("Search service");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SEARCH_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let sku = self.sku.clone()?;
        Some(match (self.replicas, self.partitions) {
            (Some(r), Some(p)) => format!("{} · {}×{}", sku, r, p),
            _ => sku,
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Status".into(), json::opt(self.status.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Endpoint".into(), json::opt(self.endpoint.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for pe in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(&pe.endpoint_id)), pe.endpoint_id.clone()));
        }
        for t in &self.shared_link_targets {
            v.push((format!("Shared link to {}", name_of_id(t)), t.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az search service show --ids {}", shell_quote(&self.base.id)))
    }
}

/// The Shared private links body from the service's list: what each link
/// reaches, the sub-resource, and whether the target's owner approved it
/// (`⚠` for anything but Approved: the indexer cannot use it).
pub fn shared_link_rows(items: &[Value], r: &SearchServiceRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No shared private links".into()));
    }
    for l in items {
        let p = |f: &str| format!("/properties/{}", f);
        let status = json::str_at(l, &p("status"));
        let status_text = match status.as_deref() {
            Some("Approved") => "approved".to_string(),
            Some(s) => format!("⚠ {}", s.to_lowercase()),
            None => "-".into(),
        };
        lines.push((String::new(), String::new()));
        lines.push((json::text(l, "/name"), String::new()));
        if let Some(target) = json::arm_id(json::str_at(l, &p("privateLinkResourceId"))) {
            lines.push((format!("  Target · {}", name_of_id(&target)), target));
        }
        lines.push(("  Sub-resource".into(), json::text(l, &p("groupId"))));
        lines.push(("  Status".into(), status_text));
        if let Some(ps) = json::str_at(l, &p("provisioningState")) {
            lines.push(("  Provisioning".into(), ps.to_lowercase()));
        }
        if let Some(region) = json::str_at(l, &p("resourceRegion")) {
            lines.push(("  Region".into(), region));
        }
        if let Some(msg) = json::str_at(l, &p("requestMessage")).filter(|m| !m.is_empty()) {
            lines.push(("  Request".into(), msg));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az search service shared-private-link-resource list {}", r.child_args().unwrap_or_default()),
    ));
    lines
}

/// The targets the lazy list names, for Related.
fn shared_link_targets(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|l| json::arm_id(json::str_at(l, "/properties/privateLinkResourceId")))
        .collect()
}

/// The ARM path of a service's shared private link list.
pub fn shared_links_path(service_id: &str) -> String {
    format!("{}/sharedPrivateLinkResources", service_id.trim_end_matches('/'))
}

/// Body lines for one section of a search service; `None` for another
/// type.
pub fn search_section_lines(
    r: &dyn Resource,
    idx: usize,
    shared_links: Option<&Lazy<Vec<Value>>>,
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<SearchServiceRow>()?;
    use SearchDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Service => x.service_rows(),
        S::Network => x.network_rows(),
        S::Security => x.security_rows(),
        S::SharedLinks => lazy_list_rows(shared_links, "Shared private links", |items| shared_link_rows(items, x)),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let extra = match shared_links {
                Some(Lazy::Loaded(items)) => shared_link_targets(items)
                    .into_iter()
                    .map(|t| (format!("Shared link to {}", name_of_id(&t)), t))
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
        .filter_map(|v| SearchServiceRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

// ── Provider (the Foundry tab delegates its Search services view) ────

pub struct SearchLists<'a> {
    pub scope: &'a Scope,
}

impl SearchLists<'_> {
    pub async fn list(&self) -> Result<Vec<Box<dyn Resource>>> {
        let page = self.scope.list(SERVICES_PATH, SEARCH_API_VERSION).await?;
        Ok(rows(&page, self.scope.tenant()))
    }

    pub async fn stream(&self, event_tx: &mpsc::UnboundedSender<Event>, service_type: ServiceType) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(SERVICES_PATH, SEARCH_API_VERSION, &[], service_type, "Listing search services…", event_tx, |page| {
                rows(&page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, event_tx)
    }

    pub async fn get(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, SEARCH_API_VERSION).await?;
        rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-ai";

    fn svc_id(name: &str) -> String {
        format!("{}/providers/Microsoft.Search/searchServices/{}", RG, name)
    }

    fn storage_id() -> String {
        format!("{}/providers/Microsoft.Storage/storageAccounts/stdocs", RG)
    }

    fn service(status: &str, auth: Value, local_off: bool) -> SearchServiceRow {
        SearchServiceRow::from_json(
            &json!({
                "id": svc_id("srch-prod"), "name": "srch-prod", "location": "swedencentral",
                "sku": {"name": "standard"},
                "identity": {"type": "SystemAssigned"},
                "properties": {
                    "provisioningState": "succeeded", "status": status, "statusDetails": "",
                    "replicaCount": 3, "partitionCount": 2, "hostingMode": "Default", "computeType": "Default",
                    "semanticSearch": "standard", "upgradeAvailable": "notAvailable",
                    "endpoint": "https://srch-prod.example/",
                    "publicNetworkAccess": "Disabled",
                    "networkRuleSet": {"bypass": "AzureServices", "ipRules": [{"value": "203.0.113.0/24"}]},
                    "dataExfiltrationProtections": ["BlockAll"],
                    "disableLocalAuth": local_off,
                    "authOptions": auth,
                    "encryptionWithCmk": {"enforcement": "Unspecified", "encryptionComplianceStatus": "Compliant"},
                    "privateEndpointConnections": [{"properties": {
                        "privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-srch", RG)},
                        "privateLinkServiceConnectionState": {"status": "Approved"}
                    }}],
                    "sharedPrivateLinkResources": [{"properties": {"privateLinkResourceId": storage_id(), "groupId": "blob"}}]
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
        let labels: Vec<&str> = SEARCH_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Service", "Network", "Security", "Shared private links", "Access", "Activity", "Related", "Tags"]
        );
    }

    #[test]
    fn a_service_reads_its_capacity_network_and_the_ids_command() {
        let row = service("running", json!({"apiKeyOnly": {}}), false);
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "running");
        assert_eq!(row.list_summary().as_deref(), Some("standard · 3×2"));
        assert_eq!(row.cli_command(), Some(format!("az search service show --ids {}", svc_id("srch-prod"))));

        let svc = row.service_rows();
        assert_eq!(get(&svc, "Search units"), Some("6"));
        assert_eq!(get(&svc, "Semantic ranker"), Some("standard"));
        assert!(get(&svc, "Status details").is_none(), "an empty statusDetails is no line");

        let net = row.network_rows();
        assert_eq!(get(&net, "IP rules"), Some("203.0.113.0/24"));
        assert_eq!(get(&net, "Data exfiltration"), Some("blocked: BlockAll"));
        assert!(net.iter().any(|(k, _)| k == "Private endpoint · pe-srch (Approved)"));

        let related: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Private endpoint pe-srch", "Shared link to stdocs"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
    }

    #[test]
    fn authentication_names_keys_entra_or_both() {
        assert_eq!(service("running", json!({"apiKeyOnly": {}}), false).auth_text(), "API key only");
        assert_eq!(
            service("running", json!({"aadOrApiKey": {"aadAuthFailureMode": "http401WithBearerChallenge"}}), false).auth_text(),
            "Entra ID or API key · on failure http401WithBearerChallenge"
        );
        assert_eq!(service("running", Value::Null, true).auth_text(), "Entra ID only (API keys off)");
        let sec = service("running", Value::Null, true).security_rows();
        assert_eq!(sec.last().unwrap().1, NEVER_KEYS);
    }

    #[test]
    fn status_buckets_follow_the_ladder() {
        assert_eq!(service("degraded", Value::Null, false).state(), ResourceState::Unavailable);
        assert_eq!(service("stopped", Value::Null, false).state(), ResourceState::Stopped);
        assert_eq!(service("provisioning", Value::Null, false).state(), ResourceState::Creating);
    }

    #[test]
    fn shared_links_show_target_status_and_join_related() {
        let row = service("running", json!({"apiKeyOnly": {}}), false);
        let cosmos = format!("{}/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-docs", RG);
        let items = vec![
            json!({"name": "spl-blob", "properties": {"privateLinkResourceId": storage_id(), "groupId": "blob",
                "status": "Approved", "provisioningState": "Succeeded"}}),
            json!({"name": "spl-cosmos", "properties": {"privateLinkResourceId": cosmos, "groupId": "Sql",
                "status": "Pending", "requestMessage": "indexer"}}),
        ];
        let lazy = Lazy::Loaded(items);
        let lines = search_section_lines(&row, SearchDetailSection::SharedLinks as usize, Some(&lazy)).unwrap();
        let statuses: Vec<&str> = lines.iter().filter(|(k, _)| k == "  Status").map(|(_, v)| v.as_str()).collect();
        assert_eq!(statuses, ["approved", "⚠ pending"]);
        assert!(lines.iter().any(|(k, v)| k == "  Target · cosmos-docs" && v == &cosmos));
        assert_eq!(
            lines.last().unwrap().1,
            "az search service shared-private-link-resource list --search-service-name srch-prod -g rg-ai --subscription 0000"
        );

        let related = search_section_lines(&row, SearchDetailSection::Related as usize, Some(&lazy)).unwrap();
        assert!(related.iter().any(|(_, id)| id == &cosmos), "the lazy list adds the Cosmos target");
        assert_eq!(related.iter().filter(|(_, id)| id == &storage_id()).count(), 1, "deduplicated");

        let loading = search_section_lines(&row, SearchDetailSection::SharedLinks as usize, Some(&Lazy::Loading)).unwrap();
        assert_eq!(loading[0].1, "Loading…");
        assert_eq!(shared_links_path(&row.base.id), format!("{}/sharedPrivateLinkResources", svc_id("srch-prod")));
    }
}
