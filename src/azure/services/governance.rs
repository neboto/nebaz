//! The Governance tab (#155, ADR 0009): what is enforced on the
//! subscription and who decided it. Four subscription-wide lists under
//! `Microsoft.Authorization`, each the subscription's own view **with what
//! it inherits**:
//!
//! - policy assignments, unfiltered: the ones made at the management
//!   groups above the subscription, on it, and on its groups and
//!   resources (`atScope()` would drop the last two);
//! - policy exemptions, unfiltered the same way;
//! - custom policy definitions and initiatives, one sub-tab of two lists
//!   (`policyType eq 'Custom'`; the built-ins are thousands of rows), which
//!   include the ones stored at the management groups above;
//! - resource locks, every one in the subscription.
//!
//! A row made at a management group has an id that starts at
//! `/providers/…`: it keys, caches and jumps on that id in the current
//! subscription (ADR 0009, decision 4). An assignment's definition is
//! looked up in the warm definitions list, never by a GET at the
//! management group; a built-in resolves with one lazy GET by id (decision
//! 2). Compliance is POST only and never read (decision 6).
//!
//! These rows have no RBAC of their own and no tags, so the tail is
//! Activity and Related; and no region (an assignment's `location` is
//! where its identity lives), so they pass every `R` filter.

use crate::azure::resource::{extension_scope, name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::directory::{now_unix, Expiry};
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_lines, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

pub const ASSIGNMENTS_PATH: &str = "/providers/Microsoft.Authorization/policyAssignments";
pub const EXEMPTIONS_PATH: &str = "/providers/Microsoft.Authorization/policyExemptions";
pub const DEFINITIONS_PATH: &str = "/providers/Microsoft.Authorization/policyDefinitions";
pub const SET_DEFINITIONS_PATH: &str = "/providers/Microsoft.Authorization/policySetDefinitions";
pub const LOCKS_PATH: &str = "/providers/Microsoft.Authorization/locks";
/// Policy's stable spec: `2025-03-01` (azure-rest-api-specs, 2026-10-28;
/// `2025-11-01` and later are a few months old and add nothing shown here).
pub const POLICY_API_VERSION: &str = "2025-03-01";
/// Exemptions have no stable api-version; `2022-07-01-preview` is the
/// newest the CLI and the portal have read for years.
pub const EXEMPTIONS_API_VERSION: &str = "2022-07-01-preview";
/// Locks' newest stable (`2020-05-01`).
pub const LOCKS_API_VERSION: &str = "2020-05-01";
/// The definitions filter: custom only.
const CUSTOM: (&str, &str) = ("$filter", "policyType eq 'Custom'");

crate::sections! {
    pub enum PolicyAssignmentDetailSection,
    pub static POLICY_ASSIGNMENT_SECTIONS = [
        Overview "Overview",
        Assignment "Assignment",
        Definition "Definition" => crate::app::App::trigger_policy_definition,
        Parameters "Parameters",
        Exemptions "Exemptions" => crate::app::App::trigger_policy_exemptions,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum PolicyExemptionDetailSection,
    pub static POLICY_EXEMPTION_SECTIONS = [
        Overview "Overview",
        Exemption "Exemption",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum PolicyDefinitionDetailSection,
    pub static POLICY_DEFINITION_SECTIONS = [
        Overview "Overview",
        Definition "Definition",
        Rule "Rule",
        Parameters "Parameters",
        Assignments "Assignments" => crate::app::App::trigger_policy_assignments,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum LockDetailSection,
    pub static LOCK_SECTIONS = [
        Overview "Overview",
        Lock "Lock",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

/// Whether an id is a governance row's: an Authorization policy, exemption
/// or lock, wherever it was made: no RBAC of its own, so neither an Access
/// section nor the `C` picker's role-assignment read.
pub fn is_governance_id(id: &str) -> bool {
    matches!(
        JumpView::for_arm_id(id),
        Some(JumpView::PolicyAssignments | JumpView::PolicyExemptions | JumpView::PolicyDefinitions | JumpView::ResourceLocks)
    )
}

/// A built-in definition or initiative: stored at the tenant root, readable
/// by anyone, never in the custom lists.
pub fn is_builtin_definition(id: &str) -> bool {
    id.to_ascii_lowercase()
        .starts_with("/providers/microsoft.authorization/policy")
}

/// Where a row was made, in words: `management group corp`, `subscription`,
/// `resource group rg-hub`, a resource's name, or `tenant root`.
pub fn scope_words(scope: Option<&str>) -> String {
    match scope {
        None => "tenant root".into(),
        Some(s) => crate::azure::services::access::scope_words(s),
    }
}

/// The parameter values an assignment sets, or a definition declares,
/// one line each: `name = value`, a value as compact JSON.
fn parameter_lines(params: &Value, declared: bool) -> Vec<(String, String)> {
    let Some(map) = params.as_object().filter(|m| !m.is_empty()) else {
        return vec![(String::new(), "No parameters".into())];
    };
    let mut names: Vec<&String> = map.keys().collect();
    names.sort_by_key(|n| n.to_ascii_lowercase());
    names
        .into_iter()
        .map(|n| {
            let p = &map[n];
            let value = if declared {
                let kind = json::text(p, "/type");
                let default = p.get("defaultValue").map(compact).map(|d| format!(" · default {}", d)).unwrap_or_default();
                let allowed = p.get("allowedValues").map(compact).map(|a| format!(" · one of {}", a)).unwrap_or_default();
                format!("{}{}{}", kind, default, allowed)
            } else {
                p.get("value").map(compact).unwrap_or_else(|| "-".into())
            };
            (n.clone(), value)
        })
        .collect()
}

fn compact(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// `metadata.createdBy` / `assignedBy` and the times, when ARM kept them.
fn audit_lines(meta: &Value) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    for (label, ptr, is_time) in [
        ("Assigned by", "/assignedBy", false),
        ("Created by", "/createdBy", false),
        ("Created", "/createdOn", true),
        ("Updated by", "/updatedBy", false),
        ("Updated", "/updatedOn", true),
    ] {
        if let Some(v) = json::str_at(meta, ptr).filter(|s| !s.is_empty()) {
            lines.push((label.to_string(), if is_time { json::time(Some(v)) } else { v }));
        }
    }
    lines
}

/// Governance rows show their display name: an assignment's `name` is
/// often a GUID.
fn display_base(v: &Value, tenant: Option<&str>) -> Option<ArmBase> {
    let mut base = ArmBase::from_json(v, tenant)?;
    if let Some(d) = json::str_at(v, "/properties/displayName").filter(|d| !d.trim().is_empty()) {
        base.name = d;
    }
    Some(base)
}

/// The short name ARM addresses a row by (its last segment), for the
/// `az … --name` commands.
fn arm_name(id: &str) -> &str {
    name_of_id(id)
}

/// `--scope <scope>`, the one way `az policy` takes a scope.
fn scope_arg(scope: Option<&str>) -> String {
    scope.map(|s| format!(" --scope {}", shell_quote(s))).unwrap_or_default()
}

/// Where another governance list stands, for a section that reads it: in
/// the list cache (or loaded for the section), being fetched, failed, or
/// not asked for.
#[derive(Clone, Copy)]
pub enum Warm<'a> {
    Rows(&'a [Box<dyn Resource>]),
    Loading,
    Failed(&'a str),
    Cold,
}

impl<'a> Warm<'a> {
    pub fn rows(self) -> Option<&'a [Box<dyn Resource>]> {
        match self {
            Warm::Rows(r) => Some(r),
            _ => None,
        }
    }

    /// The body while the rows are not there: `Loading…`, the error, or
    /// which sub-tab to open.
    fn waiting(self, subtab: &str) -> Vec<(String, String)> {
        match self {
            Warm::Loading => vec![(String::new(), "Loading…".into())],
            Warm::Failed(e) => crate::azure::services::error_rows(e),
            _ => vec![(String::new(), format!("Open the {} sub-tab to load them", subtab))],
        }
    }
}

// ── Policy assignments ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyAssignmentRow {
    pub base: ArmBase,
    pub scope: Option<String>,
    pub not_scopes: Vec<String>,
    pub definition_id: Option<String>,
    pub definition_version: Option<String>,
    pub enforcement_mode: Option<String>,
    pub assignment_type: Option<String>,
    pub description: Option<String>,
    pub parameters: Value,
    pub non_compliance: Vec<String>,
    pub identity_type: Option<String>,
    pub identity_principal: Option<String>,
    pub identity_location: Option<String>,
    pub user_identities: Vec<String>,
    pub resource_selectors: usize,
    pub overrides: usize,
    pub metadata: Value,
}

impl PolicyAssignmentRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PolicyAssignmentRow> {
        let base = display_base(v, tenant)?;
        let p = |s: &str| format!("/properties/{}", s);
        Some(PolicyAssignmentRow {
            scope: json::str_at(v, &p("scope")).or_else(|| extension_scope(&base.id).map(str::to_string)),
            not_scopes: json::strings_at(v, &p("notScopes")),
            definition_id: json::str_at(v, &p("policyDefinitionId")),
            definition_version: json::str_at(v, &p("definitionVersion")),
            enforcement_mode: json::str_at(v, &p("enforcementMode")),
            assignment_type: json::str_at(v, &p("assignmentType")),
            description: json::str_at(v, &p("description")).filter(|d| !d.trim().is_empty()),
            parameters: v.pointer("/properties/parameters").cloned().unwrap_or(Value::Null),
            non_compliance: json::arr(v, &p("nonComplianceMessages"))
                .iter()
                .map(|m| match json::str_at(m, "/policyDefinitionReferenceId") {
                    Some(r) => format!("{} ({})", json::text(m, "/message"), r),
                    None => json::text(m, "/message"),
                })
                .collect(),
            identity_type: json::str_at(v, "/identity/type").filter(|t| !t.eq_ignore_ascii_case("none")),
            identity_principal: json::str_at(v, "/identity/principalId"),
            identity_location: json::str_at(v, "/location"),
            user_identities: json::user_identity_ids(v),
            resource_selectors: json::arr(v, &p("resourceSelectors")).len(),
            overrides: json::arr(v, &p("overrides")).len(),
            metadata: v.pointer("/properties/metadata").cloned().unwrap_or(Value::Null),
            base,
        })
    }

    pub fn is_initiative(&self) -> bool {
        self.definition_id.as_deref().is_some_and(|d| d.to_ascii_lowercase().contains("/policysetdefinitions/"))
    }

    pub fn is_enforced(&self) -> bool {
        !self.enforcement_mode.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("DoNotEnforce"))
    }

    /// Made at a management group (or the tenant root) and inherited.
    pub fn is_inherited(&self) -> bool {
        !self.scope.as_deref().is_some_and(|s| s.starts_with("/subscriptions/"))
    }

    pub fn assignment_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Scope".into(), scope_words(self.scope.as_deref())),
            (String::new(), self.scope.clone().unwrap_or_else(|| "-".into())),
        ];
        if self.is_inherited() {
            lines.push((String::new(), "· made above the subscription: it applies to everything in it".into()));
        }
        if self.not_scopes.is_empty() {
            lines.push(("Excluded scopes".into(), "none".into()));
        } else {
            for (i, s) in self.not_scopes.iter().enumerate() {
                let label = if i == 0 { "Excluded scopes" } else { "" };
                lines.push((label.into(), s.clone()));
            }
        }
        lines.push((String::new(), String::new()));
        let mode = json::opt(self.enforcement_mode.clone());
        lines.push((
            "Enforcement".into(),
            if self.is_enforced() { mode } else { format!("⚠ {}: evaluated and reported, never denied or remediated", mode) },
        ));
        lines.push(("Kind".into(), if self.is_initiative() { "initiative".into() } else { "policy".into() }));
        if let Some(v) = &self.definition_version {
            lines.push(("Definition version".into(), v.clone()));
        }
        if let Some(t) = &self.assignment_type {
            lines.push(("Assignment type".into(), t.clone()));
        }
        if self.resource_selectors > 0 {
            lines.push(("Resource selectors".into(), self.resource_selectors.to_string()));
        }
        if self.overrides > 0 {
            lines.push(("Overrides".into(), self.overrides.to_string()));
        }
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        lines.push((String::new(), String::new()));
        match &self.identity_type {
            Some(t) => {
                lines.push(("Identity".into(), t.clone()));
                if let Some(p) = &self.identity_principal {
                    lines.push(("  Principal".into(), p.clone()));
                }
                for id in &self.user_identities {
                    lines.push(("  User-assigned".into(), id.clone()));
                }
                if let Some(l) = &self.identity_location {
                    lines.push(("  Location".into(), l.clone()));
                }
                lines.push((String::new(), "· deployIfNotExists and modify effects remediate as this identity".into()));
            }
            None => lines.push(("Identity".into(), "none".into())),
        }
        if !self.non_compliance.is_empty() {
            lines.push((String::new(), String::new()));
            for (i, m) in self.non_compliance.iter().enumerate() {
                lines.push((if i == 0 { "Non-compliance message".into() } else { String::new() }, m.clone()));
            }
        }
        let audit = audit_lines(&self.metadata);
        if !audit.is_empty() {
            lines.push((String::new(), String::new()));
            lines.extend(audit);
        }
        lines
    }

    pub fn parameter_rows(&self) -> Vec<(String, String)> {
        parameter_lines(&self.parameters, false)
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = if self.is_enforced() {
            (ResourceState::Available, "Enforced")
        } else {
            (ResourceState::Pending, "Not enforced")
        };
        state_ladder(None, Some(runtime))
    }
}

/// The Definition section: the definition this assignment applies, from
/// the warm custom definitions (`defs`) or the lazy built-in read.
pub fn assignment_definition_rows(r: &PolicyAssignmentRow, defs: Warm, builtin: Option<&Lazy<Value>>) -> Vec<(String, String)> {
    let Some(def_id) = r.definition_id.as_deref() else {
        return vec![(String::new(), "No definition id on the assignment".into())];
    };
    let mut lines = vec![("Id".into(), def_id.to_string())];
    let warm = defs.rows().and_then(|rows| {
        rows.iter()
            .find(|d| d.id().eq_ignore_ascii_case(def_id))
            .and_then(|d| d.as_any().downcast_ref::<PolicyDefinitionRow>())
    });
    if let Some(d) = warm {
        lines.extend(d.definition_rows());
        return lines;
    }
    if is_builtin_definition(def_id) {
        lines.push(("Type".into(), "BuiltIn".into()));
        match builtin {
            Some(Lazy::Loaded(v)) => match PolicyDefinitionRow::from_json(v, None) {
                Some(d) => lines.extend(d.definition_rows().into_iter().filter(|(k, _)| k != "Type")),
                None => lines.push((String::new(), "⚠ the definition read returned no id".into())),
            },
            Some(Lazy::Error(e)) => lines.extend(crate::azure::services::error_rows(e)),
            _ => lines.push((String::new(), "Loading…".into())),
        }
        return lines;
    }
    match defs {
        Warm::Rows(_) => lines.push((
            String::new(),
            "Not in this subscription's custom definitions: stored at a scope this account cannot read".into(),
        )),
        other => lines.extend(other.waiting("Definitions")),
    }
    lines
}

/// The Exemptions section: the warm exemptions that name this assignment.
pub fn assignment_exemption_rows(r: &PolicyAssignmentRow, exemptions: Warm) -> Vec<(String, String)> {
    let Some(rows) = exemptions.rows() else {
        return exemptions.waiting("Exemptions");
    };
    let mine: Vec<&PolicyExemptionRow> = rows
        .iter()
        .filter_map(|e| e.as_any().downcast_ref::<PolicyExemptionRow>())
        .filter(|e| e.assignment_id.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(&r.base.id)))
        .collect();
    if mine.is_empty() {
        return vec![(String::new(), "No exemptions".into())];
    }
    let now = now_unix();
    let mut lines = Vec::new();
    for e in mine {
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines.push((format!("{} · {}", e.base.name, json::opt(e.category.clone())), e.base.id.clone()));
        lines.push(("  Scope".into(), scope_words(e.scope.as_deref())));
        lines.push(("  Expires".into(), e.expiry_words(now)));
    }
    lines
}

impl Resource for PolicyAssignmentRow {
    arm_row!("Policy assignment");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `management group corp · initiative · not enforced`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([
            Some(scope_words(self.scope.as_deref())),
            self.is_initiative().then(|| "initiative".to_string()),
            (!self.is_enforced()).then(|| "not enforced".to_string()),
        ])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&POLICY_ASSIGNMENT_SECTIONS)
    }
    fn search_text(&self) -> String {
        [
            self.base.id.as_str(),
            self.base.name.as_str(),
            self.scope.as_deref().unwrap_or(""),
            self.definition_id.as_deref().unwrap_or(""),
            self.description.as_deref().unwrap_or(""),
        ]
        .join(" ")
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Assignment name".into(), arm_name(&self.base.id).to_string()),
            ("Id".into(), self.base.id.clone()),
            ("Scope".into(), scope_words(self.scope.as_deref())),
            ("Enforcement".into(), json::opt(self.enforcement_mode.clone())),
            ("Kind".into(), if self.is_initiative() { "initiative".into() } else { "policy".into() }),
            ("Definition".into(), json::opt(self.definition_id.clone())),
            ("Excluded scopes".into(), self.not_scopes.len().to_string()),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = self.scope.as_deref().filter(|s| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(s))) {
            v.push((format!("Assigned at {}", scope_words(Some(s))), s.to_string()));
        }
        if let Some(d) = &self.definition_id {
            let what = if self.is_initiative() { "Initiative" } else { "Definition" };
            v.push((format!("{} {}", what, name_of_id(d)), d.clone()));
        }
        for id in &self.user_identities {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    /// `az policy assignment show` takes `--name` and `--scope`, no `--ids`.
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az policy assignment show --name {}{}",
            shell_quote(arm_name(&self.base.id)),
            scope_arg(self.scope.as_deref())
        ))
    }
}

// ── Policy exemptions ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyExemptionRow {
    pub base: ArmBase,
    pub scope: Option<String>,
    pub assignment_id: Option<String>,
    pub category: Option<String>,
    pub expires_on: Option<String>,
    pub reference_ids: Vec<String>,
    pub description: Option<String>,
    pub metadata: Value,
}

impl PolicyExemptionRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PolicyExemptionRow> {
        let base = display_base(v, tenant)?;
        let p = |s: &str| format!("/properties/{}", s);
        Some(PolicyExemptionRow {
            scope: extension_scope(&base.id).map(str::to_string),
            assignment_id: json::str_at(v, &p("policyAssignmentId")),
            category: json::str_at(v, &p("exemptionCategory")),
            expires_on: json::str_at(v, &p("expiresOn")),
            reference_ids: json::strings_at(v, &p("policyDefinitionReferenceIds")),
            description: json::str_at(v, &p("description")).filter(|d| !d.trim().is_empty()),
            metadata: v.pointer("/properties/metadata").cloned().unwrap_or(Value::Null),
            base,
        })
    }

    /// No end date is `never`, not unknown: an exemption without
    /// `expiresOn` lasts until someone deletes it.
    pub fn expiry(&self, now: i64) -> Option<Expiry> {
        self.expires_on.as_deref().map(|e| Expiry::of(Some(e), now))
    }

    pub fn expiry_words(&self, now: i64) -> String {
        match self.expiry(now) {
            None => "never".into(),
            Some(x) => format!("{} ({})", json::time(self.expires_on.clone()), x.describe()),
        }
    }

    pub fn exemption_rows(&self, assignments: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
        let now = now_unix();
        let mut lines = vec![
            ("Category".into(), json::opt(self.category.clone())),
            ("Expires".into(), self.expiry_words(now)),
            ("Scope".into(), scope_words(self.scope.as_deref())),
            (String::new(), self.scope.clone().unwrap_or_else(|| "-".into())),
            (String::new(), String::new()),
        ];
        let assignment = self.assignment_id.as_deref().and_then(|a| {
            assignments?.iter().find(|r| r.id().eq_ignore_ascii_case(a)).map(|r| r.name().to_string())
        });
        lines.push(("Assignment".into(), assignment.unwrap_or_else(|| json::opt(self.assignment_id.as_deref().map(|a| name_of_id(a).to_string())))));
        lines.push((String::new(), json::opt(self.assignment_id.clone())));
        if self.reference_ids.is_empty() {
            lines.push(("Exempts".into(), "every policy in the assignment".into()));
        } else {
            for (i, r) in self.reference_ids.iter().enumerate() {
                lines.push((if i == 0 { "Exempts".into() } else { String::new() }, r.clone()));
            }
        }
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        let audit = audit_lines(&self.metadata);
        if !audit.is_empty() {
            lines.push((String::new(), String::new()));
            lines.extend(audit);
        }
        lines
    }

    fn ladder(&self, now: i64) -> (ResourceState, String) {
        let runtime = match self.expiry(now) {
            None => (ResourceState::Available, "Active".to_string()),
            Some(Expiry::Expired) => (ResourceState::Stopped, "Expired".into()),
            Some(Expiry::Expiring(_)) => (ResourceState::Pending, "Expiring".into()),
            Some(_) => (ResourceState::Available, "Active".into()),
        };
        state_ladder(None, Some((runtime.0, runtime.1.as_str())))
    }
}

impl Resource for PolicyExemptionRow {
    arm_row!("Policy exemption");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `Waiver · resource group rg-legacy · expires in 12 d`.
    fn list_summary(&self) -> Option<String> {
        let now = now_unix();
        crate::azure::resource::summary_of([
            self.category.clone(),
            Some(scope_words(self.scope.as_deref())),
            self.expiry(now).map(|x| match x {
                Expiry::Expired | Expiry::Expiring(_) => x.describe(),
                _ => format!("until {}", json::time(self.expires_on.clone()).get(..10).unwrap_or("-")),
            }),
        ])
    }
    fn state(&self) -> ResourceState {
        self.ladder(now_unix()).0
    }
    fn state_label(&self) -> String {
        self.ladder(now_unix()).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&POLICY_EXEMPTION_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Exemption name".into(), arm_name(&self.base.id).to_string()),
            ("Id".into(), self.base.id.clone()),
            ("Scope".into(), scope_words(self.scope.as_deref())),
            ("Category".into(), json::opt(self.category.clone())),
            ("Expires".into(), self.expiry_words(now_unix())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = self.scope.as_deref().filter(|s| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(s))) {
            v.push((format!("Exempts {}", scope_words(Some(s))), s.to_string()));
        }
        if let Some(a) = &self.assignment_id {
            v.push((format!("Assignment {}", name_of_id(a)), a.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az policy exemption show --name {}{}",
            shell_quote(arm_name(&self.base.id)),
            scope_arg(self.scope.as_deref())
        ))
    }
}

// ── Policy definitions and initiatives ────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyDefinitionRow {
    pub base: ArmBase,
    pub initiative: bool,
    pub policy_type: Option<String>,
    pub mode: Option<String>,
    pub category: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub rule: Value,
    pub parameters: Value,
    /// An initiative's members: `(definition id, reference id)`.
    pub members: Vec<(String, Option<String>)>,
    pub metadata: Value,
}

impl PolicyDefinitionRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PolicyDefinitionRow> {
        let base = display_base(v, tenant)?;
        let p = |s: &str| format!("/properties/{}", s);
        let initiative = base.id.to_ascii_lowercase().contains("/policysetdefinitions/");
        // The effect is a literal, or a parameter whose default it takes.
        let effect = json::str_at(v, &p("policyRule/then/effect")).map(|e| {
            match e.strip_prefix("[parameters('").and_then(|r| r.strip_suffix("')]")) {
                Some(param) => json::str_at(v, &p(&format!("parameters/{}/defaultValue", param)))
                    .map(|d| format!("{} (parameter {}, default)", d, param))
                    .unwrap_or_else(|| format!("parameter {}", param)),
                None => e,
            }
        });
        Some(PolicyDefinitionRow {
            initiative,
            policy_type: json::str_at(v, &p("policyType")),
            mode: json::str_at(v, &p("mode")),
            category: json::str_at(v, &p("metadata/category")),
            version: json::str_at(v, &p("version")).or_else(|| json::str_at(v, &p("metadata/version"))),
            description: json::str_at(v, &p("description")).filter(|d| !d.trim().is_empty()),
            effect,
            rule: v.pointer("/properties/policyRule").cloned().unwrap_or(Value::Null),
            parameters: v.pointer("/properties/parameters").cloned().unwrap_or(Value::Null),
            members: json::arr(v, &p("policyDefinitions"))
                .iter()
                .filter_map(|m| Some((json::str_at(m, "/policyDefinitionId")?, json::str_at(m, "/policyDefinitionReferenceId"))))
                .collect(),
            metadata: v.pointer("/properties/metadata").cloned().unwrap_or(Value::Null),
            base,
        })
    }

    /// Stored at: a management group, the subscription, or the tenant root
    /// (a built-in).
    pub fn scope(&self) -> Option<&str> {
        extension_scope(&self.base.id)
    }

    pub fn definition_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Display name".into(), self.base.name.clone()),
            ("Type".into(), json::opt(self.policy_type.clone())),
            ("Kind".into(), if self.initiative { "initiative".into() } else { "policy".into() }),
            ("Stored at".into(), scope_words(self.scope())),
            ("Category".into(), json::opt(self.category.clone())),
            ("Version".into(), json::opt(self.version.clone())),
        ];
        if self.initiative {
            lines.push(("Policies".into(), self.members.len().to_string()));
        } else {
            lines.push(("Mode".into(), json::opt(self.mode.clone())));
            lines.push(("Effect".into(), json::opt(self.effect.clone())));
        }
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        let audit = audit_lines(&self.metadata);
        if !audit.is_empty() {
            lines.push((String::new(), String::new()));
            lines.extend(audit);
        }
        lines
    }

    /// A policy's rule as pretty JSON; an initiative's member policies.
    pub fn rule_rows(&self) -> Vec<(String, String)> {
        if self.initiative {
            if self.members.is_empty() {
                return vec![(String::new(), "No policies".into())];
            }
            return self
                .members
                .iter()
                .map(|(id, reference)| (reference.clone().unwrap_or_else(|| name_of_id(id).to_string()), id.clone()))
                .collect();
        }
        if self.rule.is_null() {
            return vec![(String::new(), "No rule".into())];
        }
        serde_json::to_string_pretty(&self.rule)
            .unwrap_or_default()
            .lines()
            .map(|l| (String::new(), l.to_string()))
            .collect()
    }

    pub fn parameter_rows(&self) -> Vec<(String, String)> {
        parameter_lines(&self.parameters, true)
    }
}

/// The Assignments section: the warm assignments that apply this
/// definition directly (one inside an initiative is the initiative's).
pub fn definition_assignment_rows(r: &PolicyDefinitionRow, assignments: Warm) -> Vec<(String, String)> {
    let Some(rows) = assignments.rows() else {
        return assignments.waiting("Assignments");
    };
    let mine: Vec<&PolicyAssignmentRow> = rows
        .iter()
        .filter_map(|a| a.as_any().downcast_ref::<PolicyAssignmentRow>())
        .filter(|a| a.definition_id.as_deref().is_some_and(|d| d.eq_ignore_ascii_case(&r.base.id)))
        .collect();
    if mine.is_empty() {
        return vec![(String::new(), "Not assigned anywhere this subscription can see".into())];
    }
    mine.into_iter()
        .map(|a| {
            let enforced = if a.is_enforced() { "" } else { " · not enforced" };
            (format!("{} · {}{}", a.base.name, scope_words(a.scope.as_deref()), enforced), a.base.id.clone())
        })
        .collect()
}

impl Resource for PolicyDefinitionRow {
    arm_row!("Policy definition");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `initiative · Security Center · 12 policies` / `policy · Network · deny`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([
            Some(if self.initiative { "initiative".to_string() } else { "policy".to_string() }),
            self.category.clone(),
            if self.initiative {
                Some(format!("{} policies", self.members.len()))
            } else {
                self.effect.as_deref().map(|e| e.split(' ').next().unwrap_or(e).to_string())
            },
        ])
    }
    fn state(&self) -> ResourceState {
        ResourceState::stateless()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&POLICY_DEFINITION_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Definition name".into(), arm_name(&self.base.id).to_string()),
            ("Id".into(), self.base.id.clone()),
            ("Kind".into(), if self.initiative { "initiative".into() } else { "policy".into() }),
            ("Stored at".into(), scope_words(self.scope())),
            ("Category".into(), json::opt(self.category.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = self.scope().filter(|s| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(s))) {
            v.push((format!("Stored at {}", scope_words(Some(s))), s.to_string()));
        }
        for (id, reference) in &self.members {
            v.push((format!("Policy {}", reference.clone().unwrap_or_else(|| name_of_id(id).to_string())), id.clone()));
        }
        v
    }
    /// `az policy definition|set-definition show --name` with
    /// `--management-group` or `--subscription` for where it is stored.
    fn cli_command(&self) -> Option<String> {
        let at = match self.scope() {
            Some(s) if s.starts_with("/subscriptions/") => {
                format!(" --subscription {}", shell_quote(crate::azure::resource::subscription_of(s).unwrap_or("")))
            }
            Some(s) => format!(" --management-group {}", shell_quote(name_of_id(s))),
            None => String::new(),
        };
        let name = shell_quote(arm_name(&self.base.id));
        Some(if self.initiative {
            format!("az policy set-definition show --name {}{}", name, at)
        } else {
            format!("az policy definition show --name {}{}", name, at)
        })
    }
}

// ── Resource locks ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LockRow {
    pub base: ArmBase,
    pub level: Option<String>,
    pub notes: Option<String>,
    pub owners: Vec<String>,
}

impl LockRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<LockRow> {
        let base = ArmBase::from_json(v, tenant)?;
        Some(LockRow {
            level: json::str_at(v, "/properties/level"),
            notes: json::str_at(v, "/properties/notes").filter(|n| !n.trim().is_empty()),
            owners: json::arr(v, "/properties/owners").iter().filter_map(|o| json::str_at(o, "/applicationId")).collect(),
            base,
        })
    }

    /// What the lock is on: the subscription, a group or a resource.
    pub fn scope(&self) -> Option<&str> {
        extension_scope(&self.base.id)
    }

    pub fn is_read_only(&self) -> bool {
        self.level.as_deref().is_some_and(|l| l.eq_ignore_ascii_case("ReadOnly"))
    }

    pub fn lock_rows(&self) -> Vec<(String, String)> {
        let explain = if self.is_read_only() {
            "no change and no delete; also blocks the POST reads, such as listing a storage account's keys"
        } else {
            "changes allowed, no delete"
        };
        let mut lines = vec![
            ("Level".into(), json::opt(self.level.clone())),
            (String::new(), format!("· {}", explain)),
            ("On".into(), scope_words(self.scope())),
            (String::new(), self.scope().unwrap_or("-").to_string()),
            (String::new(), "· inherited by everything below it".into()),
            ("Notes".into(), json::opt(self.notes.clone())),
        ];
        for (i, o) in self.owners.iter().enumerate() {
            lines.push((if i == 0 { "Owners".into() } else { String::new() }, o.clone()));
        }
        lines
    }
}

impl Resource for LockRow {
    arm_row!("Resource lock");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `CanNotDelete · resource group rg-hub`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([self.level.clone(), Some(scope_words(self.scope()))])
    }
    fn state(&self) -> ResourceState {
        ResourceState::stateless()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&LOCK_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Level".into(), json::opt(self.level.clone())),
            ("On".into(), scope_words(self.scope())),
            ("Notes".into(), json::opt(self.notes.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = self.scope().filter(|s| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(s))) {
            v.push((format!("Locks {}", scope_words(Some(s))), s.to_string()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az lock show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Section dispatch ──────────────────────────────────────────────────

/// What the governance sections read besides the row: the warm lists of
/// the current subscription, and the lazy built-in definition.
pub struct GovernanceContext<'a> {
    pub assignments: Warm<'a>,
    pub exemptions: Warm<'a>,
    pub definitions: Warm<'a>,
    pub builtin_definition: Option<&'a Lazy<Value>>,
}

/// Every governance type's section body, or `None` for another type.
pub fn governance_section_lines(r: &dyn Resource, idx: usize, cx: &GovernanceContext) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    if let Some(a) = any.downcast_ref::<PolicyAssignmentRow>() {
        use PolicyAssignmentDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(a),
            S::Assignment => a.assignment_rows(),
            S::Definition => assignment_definition_rows(a, cx.definitions, cx.builtin_definition),
            S::Parameters => a.parameter_rows(),
            S::Exemptions => assignment_exemption_rows(a, cx.exemptions),
            S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_lines(a.related()),
        });
    }
    if let Some(e) = any.downcast_ref::<PolicyExemptionRow>() {
        use PolicyExemptionDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(e),
            S::Exemption => e.exemption_rows(cx.assignments.rows()),
            S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_lines(e.related()),
        });
    }
    if let Some(d) = any.downcast_ref::<PolicyDefinitionRow>() {
        use PolicyDefinitionDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(d),
            S::Definition => d.definition_rows(),
            S::Rule => d.rule_rows(),
            S::Parameters => d.parameter_rows(),
            S::Assignments => definition_assignment_rows(d, cx.assignments),
            S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_lines(d.related()),
        });
    }
    if let Some(l) = any.downcast_ref::<LockRow>() {
        use LockDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(l),
            S::Lock => l.lock_rows(),
            S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_lines(l.related()),
        });
    }
    None
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct GovernanceService {
    scope: Scope,
}

impl GovernanceService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<T: Resource + 'static>(rows: Vec<T>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::PolicyExemptions => Self::boxed(page.iter().filter_map(|v| PolicyExemptionRow::from_json(v, tenant)).collect()),
            JumpView::PolicyDefinitions => Self::boxed(page.iter().filter_map(|v| PolicyDefinitionRow::from_json(v, tenant)).collect()),
            JumpView::ResourceLocks => Self::boxed(page.iter().filter_map(|v| LockRow::from_json(v, tenant)).collect()),
            _ => Self::boxed(page.iter().filter_map(|v| PolicyAssignmentRow::from_json(v, tenant)).collect()),
        }
    }

    /// The list (or lists) behind a sub-tab: definitions are two.
    #[allow(clippy::type_complexity)]
    fn lists_of(view: JumpView) -> &'static [(&'static str, &'static str, &'static [(&'static str, &'static str)], &'static str)] {
        match view {
            JumpView::PolicyExemptions => &[(EXEMPTIONS_PATH, EXEMPTIONS_API_VERSION, &[], "Listing policy exemptions…")],
            JumpView::PolicyDefinitions => &[
                (DEFINITIONS_PATH, POLICY_API_VERSION, &[CUSTOM], "Listing custom policy definitions…"),
                (SET_DEFINITIONS_PATH, POLICY_API_VERSION, &[CUSTOM], "Listing custom initiatives…"),
            ],
            JumpView::ResourceLocks => &[(LOCKS_PATH, LOCKS_API_VERSION, &[], "Listing resource locks…")],
            _ => &[(ASSIGNMENTS_PATH, POLICY_API_VERSION, &[], "Listing policy assignments…")],
        }
    }

    pub fn api_version_for(id: &str) -> &'static str {
        let lower = id.to_ascii_lowercase();
        if lower.contains("/policyexemptions/") {
            EXEMPTIONS_API_VERSION
        } else if lower.contains("/locks/") {
            LOCKS_API_VERSION
        } else {
            POLICY_API_VERSION
        }
    }
}

#[async_trait]
impl AzureService for GovernanceService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Governance
    }

    fn name(&self) -> &str {
        "Governance"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        let mut out = Vec::new();
        let mut first_err = None;
        for (path, version, query, _) in Self::lists_of(view) {
            match self.scope.list_query(path, version, query).await {
                Ok(page) => out.extend(Self::rows(view, &page, tenant)),
                Err(e) => first_err = first_err.or(Some(e)),
            }
        }
        match first_err {
            Some(e) if out.is_empty() => Err(e),
            _ => Ok(out),
        }
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let lists = Self::lists_of(view);
        let mut total = 0usize;
        let mut failures = Vec::new();
        for (path, version, query, label) in lists {
            let r = self
                .scope
                .stream(path, version, query, service_type, label, &event_tx, |page| Self::rows(view, &page, tenant.as_deref()))
                .await;
            match r {
                Ok(n) => total += n,
                Err(e) => failures.push(e),
            }
        }
        // One of the two definition lists failing beside the other is a
        // warning; only nothing streaming at all is the list's error.
        if failures.len() == lists.len() {
            return finish_stream(service_type, Err(failures.remove(0)), &event_tx);
        }
        for e in failures {
            let _ = event_tx.send(Event::ResourceLoadWarning { service: service_type, warning: e.to_string() });
        }
        finish_stream(service_type, Ok(total), &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, Self::api_version_for(id)).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::PolicyAssignments);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SUB: &str = "/subscriptions/0000";
    const MG: &str = "/providers/Microsoft.Management/managementGroups/corp";
    const RG: &str = "/subscriptions/0000/resourceGroups/rg-hub";

    fn assignment(scope: &str, def: &str, mode: &str) -> Value {
        json!({
            "id": format!("{}/providers/Microsoft.Authorization/policyAssignments/deny-public-ip", scope),
            "name": "deny-public-ip",
            "type": "Microsoft.Authorization/policyAssignments",
            "location": "westeurope",
            "identity": {"type": "SystemAssigned", "principalId": "11111111-1111-1111-1111-111111111111"},
            "properties": {
                "displayName": "Deny public IPs",
                "scope": scope,
                "notScopes": [format!("{}/resourceGroups/rg-edge", SUB)],
                "policyDefinitionId": def,
                "enforcementMode": mode,
                "parameters": {"effect": {"value": "Deny"}, "listOfAllowed": {"value": ["a", "b"]}},
                "nonComplianceMessages": [{"message": "Public IPs need an exception"}],
                "metadata": {"assignedBy": "Platform team", "createdOn": "2026-01-02T03:04:05Z"}
            }
        })
    }

    fn definition(scope: &str, set: bool) -> Value {
        let kind = if set { "policySetDefinitions" } else { "policyDefinitions" };
        json!({
            "id": format!("{}/providers/Microsoft.Authorization/{}/deny-pip", scope, kind),
            "name": "deny-pip",
            "properties": {
                "displayName": "Deny public IP addresses",
                "policyType": "Custom",
                "mode": "All",
                "metadata": {"category": "Network", "version": "1.0.0"},
                "parameters": {"effect": {"type": "String", "defaultValue": "Deny", "allowedValues": ["Audit", "Deny"]}},
                "policyRule": {"if": {"field": "type", "equals": "Microsoft.Network/publicIPAddresses"},
                    "then": {"effect": "[parameters('effect')]"}},
                "policyDefinitions": [{"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/abc",
                    "policyDefinitionReferenceId": "denyPip"}]
            }
        })
    }

    fn exemption(expires: Option<&str>, assignment: &str) -> Value {
        json!({
            "id": format!("{}/providers/Microsoft.Authorization/policyExemptions/legacy-pip", RG),
            "name": "legacy-pip",
            "properties": {
                "displayName": "Legacy jump box",
                "policyAssignmentId": assignment,
                "exemptionCategory": "Waiver",
                "expiresOn": expires,
            }
        })
    }

    #[test]
    fn an_inherited_assignment_reads_its_scope_and_enforcement() {
        let def = format!("{}/providers/Microsoft.Authorization/policyDefinitions/deny-pip", MG);
        let a = PolicyAssignmentRow::from_json(&assignment(MG, &def, "DoNotEnforce"), None).unwrap();
        assert_eq!(a.base.name, "Deny public IPs");
        assert!(a.is_inherited() && !a.is_enforced() && !a.is_initiative());
        assert_eq!(a.filter_location(), None, "the identity's location is not where it applies");
        assert_eq!(a.list_summary().as_deref(), Some("management group corp · not enforced"));
        assert_eq!((a.state(), a.state_label().as_str()), (ResourceState::Pending, "not enforced"));
        let rows = a.assignment_rows();
        assert!(rows.iter().any(|(k, v)| k == "Enforcement" && v.starts_with("⚠ DoNotEnforce")));
        assert!(rows.iter().any(|(k, v)| k == "Assigned by" && v == "Platform team"));
        assert!(a.parameter_rows().iter().any(|(k, v)| k == "listOfAllowed" && v == r#"["a","b"]"#));
        assert_eq!(
            a.cli_command().as_deref(),
            Some("az policy assignment show --name deny-public-ip --scope /providers/Microsoft.Management/managementGroups/corp")
        );
        assert!(a.related().iter().any(|(k, v)| k == "Assigned at management group corp" && v == MG));
    }

    #[test]
    fn a_definition_resolves_from_the_warm_list_or_says_why_not() {
        let def_id = format!("{}/providers/Microsoft.Authorization/policyDefinitions/deny-pip", MG);
        let a = PolicyAssignmentRow::from_json(&assignment(SUB, &def_id, "Default"), None).unwrap();
        assert_eq!((a.state(), a.is_inherited()), (ResourceState::Available, false));
        let cold = assignment_definition_rows(&a, Warm::Cold, None);
        assert!(cold.iter().any(|(_, v)| v.starts_with("Open the Definitions sub-tab")));
        assert!(assignment_definition_rows(&a, Warm::Loading, None).iter().any(|(_, v)| v == "Loading…"));
        let defs: Vec<Box<dyn Resource>> = vec![Box::new(PolicyDefinitionRow::from_json(&definition(MG, false), None).unwrap())];
        let warm = assignment_definition_rows(&a, Warm::Rows(&defs), None);
        assert!(warm.iter().any(|(k, v)| k == "Effect" && v == "Deny (parameter effect, default)"));
        assert!(warm.iter().any(|(k, v)| k == "Stored at" && v == "management group corp"));
        let empty: Vec<Box<dyn Resource>> = Vec::new();
        assert!(assignment_definition_rows(&a, Warm::Rows(&empty), None).iter().any(|(_, v)| v.starts_with("Not in this subscription")));
        // A built-in: the lazy read, never the warm list.
        let b = PolicyAssignmentRow::from_json(
            &assignment(SUB, "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9", "Default"),
            None,
        )
        .unwrap();
        assert!(b.is_initiative());
        assert!(assignment_definition_rows(&b, Warm::Rows(&empty), None).iter().any(|(_, v)| v == "Loading…"));
        let loaded = Lazy::Loaded(definition("", true));
        let lines = assignment_definition_rows(&b, Warm::Rows(&empty), Some(&loaded));
        assert!(lines.iter().any(|(k, v)| k == "Policies" && v == "1"));
    }

    #[test]
    fn an_exemption_expires_and_names_its_assignment() {
        let a_id = format!("{}/providers/Microsoft.Authorization/policyAssignments/deny-public-ip", MG);
        let e = PolicyExemptionRow::from_json(&exemption(Some("2026-11-05T00:00:00Z"), &a_id), None).unwrap();
        assert_eq!(e.scope.as_deref(), Some(RG));
        let now = crate::azure::services::directory::iso_to_unix("2026-10-28T00:00:00Z").unwrap();
        assert_eq!(e.expiry(now), Some(Expiry::Expiring(8)));
        assert_eq!(e.ladder(now).0, ResourceState::Pending);
        let later = now + 30 * 86_400;
        assert_eq!(e.ladder(later).0, ResourceState::Stopped);
        let never = PolicyExemptionRow::from_json(&exemption(None, &a_id), None).unwrap();
        assert_eq!(never.expiry_words(now), "never");
        assert_eq!(never.ladder(now).1, "active");
        let assignments: Vec<Box<dyn Resource>> = vec![Box::new(
            PolicyAssignmentRow::from_json(&assignment(MG, "/providers/Microsoft.Authorization/policyDefinitions/x", "Default"), None)
                .unwrap(),
        )];
        assert!(never.exemption_rows(Some(&assignments)).iter().any(|(k, v)| k == "Assignment" && v == "Deny public IPs"));
        let a = assignments[0].as_any().downcast_ref::<PolicyAssignmentRow>().unwrap();
        let exemptions: Vec<Box<dyn Resource>> = vec![Box::new(never.clone())];
        assert!(assignment_exemption_rows(a, Warm::Rows(&exemptions)).iter().any(|(k, _)| k == "Legacy jump box · Waiver"));
        assert_eq!(
            never.cli_command().as_deref(),
            Some("az policy exemption show --name legacy-pip --scope /subscriptions/0000/resourceGroups/rg-hub")
        );
    }

    #[test]
    fn an_initiative_lists_its_policies_and_where_it_is_assigned() {
        let d = PolicyDefinitionRow::from_json(&definition(SUB, true), None).unwrap();
        assert!(d.initiative);
        assert_eq!(d.list_summary().as_deref(), Some("initiative · Network · 1 policies"));
        assert_eq!(d.rule_rows(), vec![("denyPip".to_string(), "/providers/Microsoft.Authorization/policyDefinitions/abc".to_string())]);
        assert_eq!(d.cli_command().as_deref(), Some("az policy set-definition show --name deny-pip --subscription 0000"));
        let p = PolicyDefinitionRow::from_json(&definition(MG, false), None).unwrap();
        assert_eq!(p.cli_command().as_deref(), Some("az policy definition show --name deny-pip --management-group corp"));
        assert!(p.rule_rows().iter().any(|(_, l)| l.contains("Microsoft.Network/publicIPAddresses")));
        assert!(p.parameter_rows().iter().any(|(k, v)| k == "effect" && v == r#"String · default Deny · one of ["Audit","Deny"]"#));
        let assignments: Vec<Box<dyn Resource>> =
            vec![Box::new(PolicyAssignmentRow::from_json(&assignment(MG, &p.base.id, "DoNotEnforce"), None).unwrap())];
        assert_eq!(
            definition_assignment_rows(&p, Warm::Rows(&assignments))[0].0,
            "Deny public IPs · management group corp · not enforced"
        );
    }

    #[test]
    fn a_lock_on_a_resource_names_what_it_locks() {
        let target = format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-hub", RG);
        let l = LockRow::from_json(
            &json!({
                "id": format!("{}/providers/Microsoft.Authorization/locks/no-delete", target),
                "name": "no-delete",
                "properties": {"level": "CanNotDelete", "notes": "hub"}
            }),
            None,
        )
        .unwrap();
        assert_eq!(l.scope(), Some(target.as_str()));
        assert_eq!(l.list_summary().as_deref(), Some("CanNotDelete · vnet-hub"));
        assert!(l.related().iter().any(|(k, v)| k == "Locks vnet-hub" && *v == target));
        assert_eq!(JumpView::for_arm_id(&l.base.id), Some(JumpView::ResourceLocks));
        assert!(is_governance_id(&l.base.id));
    }

    #[test]
    fn section_labels() {
        let labels = |d: &crate::sections::SectionDescriptor| d.sections.iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(
            labels(&POLICY_ASSIGNMENT_SECTIONS),
            ["Overview", "Assignment", "Definition", "Parameters", "Exemptions", "Activity", "Related"]
        );
        assert_eq!(labels(&POLICY_EXEMPTION_SECTIONS), ["Overview", "Exemption", "Activity", "Related"]);
        assert_eq!(
            labels(&POLICY_DEFINITION_SECTIONS),
            ["Overview", "Definition", "Rule", "Parameters", "Assignments", "Activity", "Related"]
        );
        assert_eq!(labels(&LOCK_SECTIONS), ["Overview", "Lock", "Activity", "Related"]);
    }
}
