// copy-adapted from neboto-tui src/ownership.rs @ 03760c0 (tag-driven
// ownership, case-insensitive configured keys, the one-line summary); ARM's
// own `managedBy` and the resource-group deployment lookup are new in nebaz
//! Ownership ribbon (#48): "who owns this resource?", one dim line on the
//! detail pane's top border, e.g.
//! `⛓ managed by aks-1 · terraform · owner alice · deployed by main 2026-10-20`.
//!
//! Three sources, cheapest first:
//!
//! - **Tags** (zero calls): the configured `ownership_tags`, tried in order
//!   and matched case-insensitively (`owner` covers `Owner`); a key ending
//!   in `:` is a prefix (`hidden-link:` reads App Insights' link to the
//!   app it watches). Plus IaC hints whatever the config says: a
//!   `managed-by`-style tag's value as written, and `terraform` / `bicep` /
//!   `pulumi` / `azd` when a tag key or value names one.
//! - **ARM's `managedBy`** (zero calls, read from the row's raw ARM body):
//!   set on an AKS node resource group (the cluster), a managed app's
//!   group, a Databricks group, an attached disk (its VM). The Related
//!   section carries it as a link (`related_rows`), so `⏎` jumps there.
//! - **The deployment that last touched it** (lazy, one call per resource
//!   group, cached per group): the group's `Microsoft.Resources/deployments`
//!   list, matched by `outputResources` and `dependencies` resource id; for
//!   the newest few deployments that did not succeed (they carry no
//!   `outputResources`), their `…/operations`, matched by
//!   `targetResource.id`. GETs only. A failure is `⚠` text on the ribbon.

use crate::azure::arm::ArmClient;
use crate::azure::resource::{name_of_id, Resource};
use crate::azure::services::json;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Default `ownership_tags`. Case-insensitive, so `owner` also covers
/// `Owner`; a trailing `:` makes the entry a key prefix.
pub const DEFAULT_OWNERSHIP_TAGS: &[&str] = &["owner", "team", "CreatedBy", "cost-center", "azd-env-name", "hidden-link:"];

/// Tag keys whose value names the tool that manages the resource
/// (`terraform`, `bicep`, `pulumi`), shown as written.
const MANAGED_BY_TAGS: &[&str] = &["managedby", "managed-by", "managed_by", "provisioner", "iac", "deployedby", "deployed-by"];

/// IaC tools a tag key or value may name.
const IAC_WORDS: &[&str] = &["terraform", "bicep", "pulumi", "crossplane"];

/// `Microsoft.Resources/deployments` (the Resources spec the generic list
/// also uses).
pub const DEPLOYMENTS_API_VERSION: &str = "2025-04-01";
/// The deployments read per group (newest first after sorting).
pub const DEPLOYMENTS_MAX: usize = 100;
/// How many not-succeeded deployments have their operations read.
pub const DEPLOYMENT_OPERATIONS_MAX: usize = 3;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ownership {
    /// ARM's `managedBy`: the resource that manages this one.
    pub managed_by: Option<String>,
    /// IaC hints: a managed-by tag's value, a tool a tag names.
    pub iac: Vec<String>,
    /// The configured tags that are set, as `label value`, in config order.
    pub tags: Vec<String>,
}

impl Ownership {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.managed_by.is_none() && self.iac.is_empty() && self.tags.is_empty()
    }

    /// The parts of the ribbon, in display order.
    pub fn parts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if let Some(m) = &self.managed_by {
            parts.push(format!("managed by {}", name_of_id(m)));
        }
        parts.extend(self.iac.iter().cloned());
        parts.extend(self.tags.iter().cloned());
        parts
    }
}

/// The row's ARM `managedBy`, from its raw ARM body (every `ArmBase` row
/// keeps one), when it is set.
pub fn managed_by_of(r: &dyn Resource) -> Option<String> {
    let raw = r.raw_content()?;
    if !raw.contains("\"managedBy\"") {
        return None;
    }
    let v: Value = serde_json::from_str(&raw).ok()?;
    json::str_at(&v, "/managedBy").map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Resolve ownership from a row's tags and its `managedBy`, with the
/// configured `ownership_tags`.
pub fn resource_ownership(tags: &HashMap<String, String>, managed_by: Option<String>, ownership_tags: &[String]) -> Ownership {
    let value = |v: &String| {
        let t = v.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    // Sorted, so a prefix entry matching several keys reads the same every frame.
    let mut sorted: Vec<(&String, &String)> = tags.iter().collect();
    sorted.sort();
    let find = |want: &str| sorted.iter().find(|(k, _)| k.trim().eq_ignore_ascii_case(want)).and_then(|(_, v)| value(v));

    let mut out = Ownership { managed_by, ..Default::default() };
    for want in ownership_tags {
        let want = want.trim();
        if want.is_empty() {
            continue;
        }
        let part = if let Some(prefix) = want.strip_suffix(':') {
            let prefix = prefix.to_ascii_lowercase();
            sorted
                .iter()
                .find_map(|(k, _)| {
                    let (head, rest) = k.trim().split_once(':')?;
                    (head.eq_ignore_ascii_case(&prefix) && !rest.is_empty()).then(|| rest.to_string())
                })
                .map(|rest| match prefix.as_str() {
                    "hidden-link" => format!("linked to {}", name_of_id(&rest)),
                    _ => format!("{} {}", prefix, rest),
                })
        } else {
            find(want).map(|v| match want.to_ascii_lowercase().as_str() {
                "azd-env-name" => format!("azd env {}", v),
                key => format!("{} {}", key, v),
            })
        };
        if let Some(p) = part.filter(|p| !out.tags.contains(p)) {
            out.tags.push(p);
        }
    }

    let mut iac: Vec<String> = Vec::new();
    let push = |s: String, iac: &mut Vec<String>| {
        if !iac.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
            iac.push(s);
        }
    };
    for k in MANAGED_BY_TAGS {
        if let Some(v) = find(k) {
            push(v, &mut iac);
        }
    }
    for (k, v) in &sorted {
        let (k, v) = (k.to_ascii_lowercase(), v.to_ascii_lowercase());
        for word in IAC_WORDS {
            if k.contains(word) || v.contains(word) {
                push(word.to_string(), &mut iac);
            }
        }
        if k.starts_with("azd-") && !out.tags.iter().any(|t| t.starts_with("azd ")) {
            push("azd".to_string(), &mut iac);
        }
    }
    out.iac = iac;
    out
}

// ── Deployments (lazy, one call per resource group) ───────────────────

/// One deployment of a resource group, as the list returns it.
#[derive(Debug, Clone, PartialEq)]
pub struct Deployment {
    pub name: String,
    pub timestamp: Option<String>,
    pub state: Option<String>,
    /// The template spec's name or the linked template's file, when the
    /// deployment came from one (an inline template, e.g. from Bicep or
    /// `az deployment group create -f`, has neither).
    pub template: Option<String>,
    /// Lowercased ids of the resources it created or touched.
    pub targets: Vec<String>,
}

/// A resource group's deployments, newest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RgDeployments {
    pub deployments: Vec<Deployment>,
    /// A deployment's operations that could not be read (non-fatal).
    pub warnings: Vec<String>,
}

fn norm(id: &str) -> String {
    id.trim().trim_end_matches('/').to_lowercase()
}

impl Deployment {
    pub fn from_json(v: &Value) -> Option<Deployment> {
        let name = json::str_at(v, "/name")?;
        let mut targets: Vec<String> = Vec::new();
        for r in json::arr(v, "/properties/outputResources") {
            targets.extend(json::str_at(&r, "/id").map(|s| norm(&s)));
        }
        for d in json::arr(v, "/properties/dependencies") {
            targets.extend(json::str_at(&d, "/id").map(|s| norm(&s)));
        }
        let template = json::str_at(v, "/properties/templateLink/id")
            .filter(|id| id.to_lowercase().contains("/microsoft.resources/templatespecs/"))
            .map(|id| {
                // `…/templateSpecs/{name}/versions/{v}` → `spec {name} {v}`.
                let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
                match parts.iter().position(|p| p.eq_ignore_ascii_case("templateSpecs")) {
                    Some(i) => match (parts.get(i + 1), parts.get(i + 3)) {
                        (Some(n), Some(ver)) => format!("spec {} {}", n, ver),
                        (Some(n), None) => format!("spec {}", n),
                        _ => format!("spec {}", name_of_id(&id)),
                    },
                    None => format!("spec {}", name_of_id(&id)),
                }
            })
            .or_else(|| {
                json::str_at(v, "/properties/templateLink/uri")
                    .map(|u| u.split('?').next().unwrap_or("").rsplit('/').next().unwrap_or("").to_string())
                    .filter(|f| !f.is_empty())
            });
        Some(Deployment {
            name,
            timestamp: json::str_at(v, "/properties/timestamp"),
            state: json::str_at(v, "/properties/provisioningState"),
            template,
            targets,
        })
    }

    /// Whether it created or touched `id`.
    pub fn touched(&self, id: &str) -> bool {
        let id = norm(id);
        self.targets.contains(&id)
    }

    /// `deployed by main (spec web 1.2) 2026-10-20 14:03`, with the state
    /// when it did not succeed.
    pub fn describe(&self) -> String {
        let mut out = format!("deployed by {}", self.name);
        if let Some(t) = &self.template {
            out.push_str(&format!(" ({})", t));
        }
        if let Some(ts) = &self.timestamp {
            out.push_str(&format!(" {}", ts.get(..16).unwrap_or(ts).replace('T', " ")));
        }
        if let Some(s) = self.state.as_deref().filter(|s| !s.eq_ignore_ascii_case("succeeded")) {
            out.push_str(&format!(" ({})", s.to_lowercase()));
        }
        out
    }
}

impl RgDeployments {
    /// The newest deployment that touched `id`.
    pub fn last_for(&self, id: &str) -> Option<&Deployment> {
        self.deployments.iter().find(|d| d.touched(id))
    }

    /// Build from the list's rows (sorted newest first) and, per
    /// deployment name, the target ids its operations name.
    pub fn from_parts(rows: &[Value], operations: HashMap<String, Vec<String>>, warnings: Vec<String>) -> RgDeployments {
        let mut deployments: Vec<Deployment> = rows.iter().filter_map(Deployment::from_json).collect();
        // ISO timestamps sort as text; a deployment without one goes last.
        deployments.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        for d in &mut deployments {
            if let Some(ids) = operations.get(&d.name) {
                d.targets.extend(ids.iter().map(|s| norm(s)));
            }
        }
        RgDeployments { deployments, warnings }
    }
}

/// The ids an operations list names (`properties.targetResource.id`).
fn operation_targets(ops: &[Value]) -> Vec<String> {
    ops.iter().filter_map(|o| json::str_at(o, "/properties/targetResource/id")).collect()
}

/// `{group}/providers/Microsoft.Resources/deployments`.
pub fn deployments_path(rg_id: &str) -> String {
    format!("{}/providers/Microsoft.Resources/deployments", rg_id.trim_end_matches('/'))
}

/// The lazy fetch behind the ribbon's deployment part: the group's
/// deployments (first page, up to [`DEPLOYMENTS_MAX`]), then the
/// operations of the newest few that did not succeed.
pub async fn fetch_rg_deployments(arm: Arc<ArmClient>, rg_id: String) -> Result<RgDeployments, String> {
    let path = deployments_path(&rg_id);
    let top = DEPLOYMENTS_MAX.to_string();
    let mut rows: Vec<Value> = Vec::new();
    arm.list_pages_while(&path, DEPLOYMENTS_API_VERSION, &[("$top", top.as_str())], |page| {
        rows.extend(page);
        rows.len() < DEPLOYMENTS_MAX
    })
    .await
    .map_err(|e| e.to_string())?;
    rows.truncate(DEPLOYMENTS_MAX);
    let sorted = RgDeployments::from_parts(&rows, HashMap::new(), Vec::new());
    let unfinished: Vec<String> = sorted
        .deployments
        .iter()
        .filter(|d| !d.state.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("succeeded")))
        .take(DEPLOYMENT_OPERATIONS_MAX)
        .map(|d| d.name.clone())
        .collect();
    let mut operations = HashMap::new();
    let mut warnings = Vec::new();
    for name in unfinished {
        let ops_path = format!("{}/{}/operations", path, name);
        match arm.list(&ops_path, DEPLOYMENTS_API_VERSION).await {
            Ok(ops) => {
                operations.insert(name, operation_targets(&ops));
            }
            Err(e) => warnings.push(format!("operations of {}: {}", name, e)),
        }
    }
    Ok(RgDeployments::from_parts(&rows, operations, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn defaults() -> Vec<String> {
        DEFAULT_OWNERSHIP_TAGS.iter().map(|s| s.to_string()).collect()
    }

    const RG: &str = "/subscriptions/0000/resourceGroups/rg/providers";

    #[test]
    fn nothing_set_is_empty() {
        let o = resource_ownership(&tags(&[("env", "dev")]), None, &defaults());
        assert!(o.is_empty());
        assert!(o.parts().is_empty());
    }

    #[test]
    fn configured_tags_match_case_insensitively_in_config_order() {
        let t = tags(&[("Team", "payments"), ("Owner", "alice"), ("createdby", "bob"), ("Cost-Center", "cc-12"), ("owner2", "x")]);
        let o = resource_ownership(&t, None, &defaults());
        assert_eq!(o.tags, vec!["owner alice", "team payments", "createdby bob", "cost-center cc-12"]);
        // A custom list replaces the defaults; blank values are skipped.
        let t = tags(&[("squad", " "), ("Team", "payments")]);
        let o = resource_ownership(&t, None, &["squad".into(), "TEAM".into()]);
        assert_eq!(o.tags, vec!["team payments"]);
    }

    #[test]
    fn azd_hidden_link_and_iac_hints() {
        let site = format!("{RG}/Microsoft.Web/sites/app-1");
        let t = tags(&[
            ("azd-env-name", "dev"),
            ("azd-service-name", "api"),
            (&format!("hidden-link:{site}"), "Resource"),
            ("managed-by", "Terraform"),
            ("terraform_module", "net"),
            ("deployed-with", "bicep v0.30"),
        ]);
        let o = resource_ownership(&t, None, &defaults());
        assert_eq!(o.tags, vec!["azd env dev", "linked to app-1"]);
        // The managed-by value as written, then the tools tags name (no
        // second "terraform"), and no bare `azd` when its env is shown.
        assert_eq!(o.iac, vec!["Terraform", "bicep"]);
    }

    #[test]
    fn arm_managed_by_leads_the_parts() {
        let cluster = format!("{RG}/Microsoft.ContainerService/managedClusters/aks-1");
        let o = resource_ownership(&tags(&[("owner", "alice")]), Some(cluster.clone()), &defaults());
        assert_eq!(o.parts(), vec!["managed by aks-1".to_string(), "owner alice".to_string()]);
        assert_eq!(o.managed_by.as_deref(), Some(cluster.as_str()));
    }

    #[test]
    fn managed_by_is_read_from_the_raw_arm_body() {
        let v = json!({"id": format!("{RG}/Microsoft.Compute/disks/d1"), "name": "d1", "location": "x",
            "managedBy": format!("{RG}/Microsoft.Compute/virtualMachines/vm-1"), "properties": {"diskSizeGB": 1}});
        let disk = crate::azure::services::compute::DiskRow::from_json(&v, None).unwrap();
        assert_eq!(managed_by_of(&disk).as_deref().map(name_of_id), Some("vm-1"));
        let v = json!({"id": format!("{RG}/Microsoft.Compute/disks/d2"), "name": "d2", "location": "x", "properties": {}});
        assert_eq!(managed_by_of(&crate::azure::services::compute::DiskRow::from_json(&v, None).unwrap()), None);
    }

    #[test]
    fn the_newest_deployment_touching_the_id_wins() {
        let vm = format!("{RG}/Microsoft.Compute/virtualMachines/vm-1");
        let rows = vec![
            json!({"name": "old", "properties": {"timestamp": "2026-01-01T00:00:00Z", "provisioningState": "Succeeded",
                "outputResources": [{"id": vm.to_uppercase()}]}}),
            json!({"name": "main", "properties": {"timestamp": "2026-10-20T14:03:11.5Z", "provisioningState": "Succeeded",
                "templateLink": {"id": "/subscriptions/0000/resourceGroups/specs/providers/Microsoft.Resources/templateSpecs/web/versions/1.2"},
                "outputResources": [{"id": vm.clone()}]}}),
            json!({"name": "other", "properties": {"timestamp": "2026-10-21T00:00:00Z", "provisioningState": "Succeeded",
                "outputResources": [{"id": format!("{RG}/Microsoft.Web/sites/app-1")}]}}),
            // A failed one carries no outputResources: its operations do.
            json!({"name": "broken", "properties": {"timestamp": "2026-10-22T09:00:00Z", "provisioningState": "Failed"}}),
        ];
        let d = RgDeployments::from_parts(&rows, HashMap::new(), Vec::new());
        assert_eq!(d.deployments.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), vec!["broken", "other", "main", "old"]);
        assert_eq!(d.last_for(&vm).unwrap().describe(), "deployed by main (spec web 1.2) 2026-10-20 14:03");

        let ops = HashMap::from([("broken".to_string(), operation_targets(&[json!({"properties": {"targetResource": {"id": vm.clone()}}})]))]);
        let d = RgDeployments::from_parts(&rows, ops, Vec::new());
        assert_eq!(d.last_for(&vm).unwrap().describe(), "deployed by broken 2026-10-22 09:00 (failed)");
        assert!(d.last_for(&format!("{RG}/Microsoft.Compute/virtualMachines/vm-2")).is_none());
    }

    #[test]
    fn a_linked_template_names_its_file() {
        let d = Deployment::from_json(&json!({"name": "n", "properties": {"templateLink": {"uri": "https://x.example/t/azuredeploy.json?sv=1"}}}))
            .unwrap();
        assert_eq!(d.template.as_deref(), Some("azuredeploy.json"));
        assert_eq!(deployments_path("/subscriptions/0/resourceGroups/rg"), "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Resources/deployments");
    }
}
