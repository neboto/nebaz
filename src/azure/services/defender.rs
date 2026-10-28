//! The Defender tab (#156, ADR 0010): the subscription's security posture
//! as Microsoft Defender for Cloud reports it, read-only. Four lists under
//! `Microsoft.Security`, all GETs:
//!
//! - recommendations: the assessments (one row per recommendation and
//!   resource), joined client-side with the assessment metadata for their
//!   severity, description and remediation (the list cannot expand it);
//!   healthy and not-applicable rows are noise (`a`);
//! - alerts: Defender's security alerts, stripped of what can carry a
//!   secret before the raw JSON is kept (a process command line, the
//!   extended properties, the supporting evidence);
//! - secure score: the overall score and its controls, one sub-tab of two
//!   lists;
//! - plans: which Defender plans are on (`pricings`).
//!
//! Defender's findings are its own tab and never `@audit` rows: nebaz's
//! checks and Defender's recommendations overlap, and the same problem
//! twice is noise (ADR 0010). These rows have no RBAC and no tags of their
//! own, so the tail is Activity and Related (like governance's), and no
//! region (an alert's `locations/{x}` is where Defender keeps it), so they
//! pass every `R` filter.

use std::collections::HashMap;

use crate::azure::resource::{
    extension_scope, name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, Resource, ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::governance::Warm;
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_lines, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

pub const ASSESSMENTS_PATH: &str = "/providers/Microsoft.Security/assessments";
/// Read twice: at the tenant root as written (the built-in metadata,
/// readable by anyone) and under the subscription (its custom metadata).
pub const METADATA_PATH: &str = "/providers/Microsoft.Security/assessmentMetadata";
pub const ALERTS_PATH: &str = "/providers/Microsoft.Security/alerts";
pub const SECURE_SCORES_PATH: &str = "/providers/Microsoft.Security/secureScores";
pub const SCORE_CONTROLS_PATH: &str = "/providers/Microsoft.Security/secureScoreControls";
pub const PRICINGS_PATH: &str = "/providers/Microsoft.Security/pricings";
/// Assessments' newest stable (`2025-05-04`); its list cannot `$expand`
/// the metadata, hence the join.
pub const ASSESSMENTS_API_VERSION: &str = "2025-05-04";
/// Alerts' newest stable.
pub const ALERTS_API_VERSION: &str = "2022-01-01";
/// Secure score's only stable.
pub const SECURE_SCORE_API_VERSION: &str = "2020-01-01";
/// Pricings: `2024-01-01` (`2026-07-01` is three months old and adds
/// nothing shown here).
pub const PRICINGS_API_VERSION: &str = "2024-01-01";
const EXPAND_DEFINITION: (&str, &str) = ("$expand", "definition");

crate::sections! {
    pub enum RecommendationDetailSection,
    pub static RECOMMENDATION_SECTIONS = [
        Overview "Overview",
        Recommendation "Recommendation",
        Resources "Resources" => crate::app::App::trigger_defender_recommendations,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum AlertDetailSection,
    pub static ALERT_SECTIONS = [
        Overview "Overview",
        Alert "Alert",
        Entities "Entities",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum SecureScoreDetailSection,
    pub static SECURE_SCORE_SECTIONS = [
        Overview "Overview",
        Score "Score",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum ScoreControlDetailSection,
    pub static SCORE_CONTROL_SECTIONS = [
        Overview "Overview",
        Control "Control",
        Recommendations "Recommendations" => crate::app::App::trigger_defender_recommendations,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum PlanDetailSection,
    pub static PLAN_SECTIONS = [
        Overview "Overview",
        Plan "Plan",
        Extensions "Extensions",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

/// Whether an id is a Defender row's: no RBAC of its own, so neither an
/// Access section nor the `C` picker's role-assignment read.
pub fn is_defender_id(id: &str) -> bool {
    matches!(
        JumpView::for_arm_id(id),
        Some(JumpView::DefenderRecommendations | JumpView::DefenderAlerts | JumpView::SecureScore | JumpView::DefenderPlans)
    )
}

/// Defender's text fields carry light HTML (`<br>`, `<a href…>`): tags
/// out, entities decoded, whitespace collapsed.
pub fn plain_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut tag: Option<String> = None;
    for c in s.chars() {
        match (c, tag.as_mut()) {
            ('<', None) => tag = Some(String::new()),
            ('>', Some(t)) => {
                // A block tag separates words; an inline one does not.
                let name: String = t.trim_start_matches('/').chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
                if matches!(name.to_ascii_lowercase().as_str(), "br" | "p" | "div" | "li" | "ul" | "ol" | "tr" | "td" | "h1" | "h2" | "h3") {
                    out.push(' ');
                }
                tag = None;
            }
            (_, Some(t)) => t.push(c),
            (_, None) => out.push(c),
        }
    }
    let out = out.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn opt_text(v: &Value, ptr: &str) -> Option<String> {
    json::str_at(v, ptr).map(|s| plain_text(&s)).filter(|s| !s.is_empty())
}

fn display_base(v: &Value, ptr: &str, tenant: Option<&str>) -> Option<ArmBase> {
    let mut base = ArmBase::from_json(v, tenant)?;
    if let Some(d) = json::str_at(v, ptr).filter(|d| !d.trim().is_empty()) {
        base.name = d;
    }
    Some(base)
}

/// `High` → `high`; Defender's severities are one word.
fn lower(s: &Option<String>) -> String {
    s.as_deref().unwrap_or("-").to_ascii_lowercase()
}

// ── Recommendations (assessments) ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RecommendationRow {
    pub base: ArmBase,
    /// The assessment's key (its name, a GUID), shared by every resource
    /// the same recommendation is about, and the metadata's name.
    pub key: String,
    pub resource_id: Option<String>,
    pub source: Option<String>,
    pub status: Option<String>,
    pub cause: Option<String>,
    pub status_description: Option<String>,
    pub first_evaluated: Option<String>,
    pub status_changed: Option<String>,
    pub risk: Option<String>,
    pub portal: Option<String>,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub categories: Vec<String>,
    pub threats: Vec<String>,
    pub user_impact: Option<String>,
    pub effort: Option<String>,
    pub assessment_type: Option<String>,
    pub policy_definition: Option<String>,
}

impl RecommendationRow {
    /// `metadata` is the joined `assessmentMetadata` row's properties;
    /// an assessment that carries its own `properties.metadata` wins.
    pub fn from_json(v: &Value, metadata: Option<&Value>, tenant: Option<&str>) -> Option<RecommendationRow> {
        let base = display_base(v, "/properties/displayName", tenant)?;
        let own = v.pointer("/properties/metadata").filter(|m| m.is_object());
        let md = own.or(metadata).cloned().unwrap_or(Value::Null);
        let resource_id = ["/properties/resourceDetails/Id", "/properties/resourceDetails/id", "/properties/resourceDetails/ResourceId"]
            .iter()
            .find_map(|p| json::str_at(v, p))
            .or_else(|| extension_scope(&base.id).map(str::to_string));
        Some(RecommendationRow {
            key: name_of_id(&base.id).to_string(),
            resource_id,
            source: json::str_at(v, "/properties/resourceDetails/Source").or_else(|| json::str_at(v, "/properties/resourceDetails/source")),
            status: json::str_at(v, "/properties/status/code"),
            cause: json::str_at(v, "/properties/status/cause").filter(|c| !c.is_empty()),
            status_description: opt_text(v, "/properties/status/description"),
            first_evaluated: json::str_at(v, "/properties/status/firstEvaluationDate"),
            status_changed: json::str_at(v, "/properties/status/statusChangeDate"),
            risk: json::str_at(v, "/properties/risk/level"),
            portal: json::str_at(v, "/properties/links/azurePortal").filter(|p| !p.is_empty()),
            severity: json::str_at(&md, "/severity"),
            description: opt_text(&md, "/description"),
            remediation: opt_text(&md, "/remediationDescription"),
            categories: json::strings_at(&md, "/categories"),
            threats: json::strings_at(&md, "/threats"),
            user_impact: json::str_at(&md, "/userImpact"),
            effort: json::str_at(&md, "/implementationEffort"),
            assessment_type: json::str_at(&md, "/assessmentType"),
            policy_definition: json::str_at(&md, "/policyDefinitionId"),
            base,
        })
    }

    pub fn is_unhealthy(&self) -> bool {
        self.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("Unhealthy"))
    }

    fn resource_name(&self) -> Option<String> {
        self.resource_id.as_deref().map(|r| name_of_id(r).to_string())
    }

    /// Unhealthy ranks by severity (high red, the rest amber), healthy is
    /// green, not applicable grey. The label is the severity while
    /// unhealthy, so `F` filters by it.
    fn ladder(&self) -> (ResourceState, String) {
        let status = self.status.as_deref().unwrap_or("");
        let runtime = if status.eq_ignore_ascii_case("Unhealthy") {
            let sev = lower(&self.severity);
            let bucket = if sev == "high" { ResourceState::Unavailable } else { ResourceState::Pending };
            (bucket, if self.severity.is_some() { sev } else { "unhealthy".into() })
        } else if status.eq_ignore_ascii_case("Healthy") {
            (ResourceState::Available, "healthy".into())
        } else if status.eq_ignore_ascii_case("NotApplicable") {
            (ResourceState::Stopped, "not applicable".into())
        } else {
            return state_ladder(None, None);
        };
        state_ladder(None, Some((runtime.0, runtime.1.as_str())))
    }

    pub fn recommendation_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![(
            "Status".into(),
            match &self.cause {
                Some(c) => format!("{} ({})", json::opt(self.status.clone()), c),
                None => json::opt(self.status.clone()),
            },
        )];
        if let Some(d) = &self.status_description {
            lines.push((String::new(), d.clone()));
        }
        lines.push(("Severity".into(), json::opt(self.severity.clone())));
        if let Some(r) = &self.risk {
            lines.push(("Risk".into(), r.clone()));
        }
        lines.push(("Resource".into(), self.resource_name().unwrap_or_else(|| "-".into())));
        if let Some(r) = &self.resource_id {
            lines.push((String::new(), r.clone()));
        }
        lines.push(("Category".into(), json::join(&self.categories)));
        if !self.threats.is_empty() {
            lines.push(("Threats".into(), json::join(&self.threats)));
        }
        lines.push(("User impact".into(), json::opt(self.user_impact.clone())));
        lines.push(("Effort".into(), json::opt(self.effort.clone())));
        lines.push(("Kind".into(), json::opt(self.assessment_type.clone())));
        lines.push(("First evaluated".into(), json::time(self.first_evaluated.clone())));
        lines.push(("Status changed".into(), json::time(self.status_changed.clone())));
        lines.push((String::new(), String::new()));
        lines.push(("Description".into(), json::opt(self.description.clone())));
        lines.push(("Remediation".into(), json::opt(self.remediation.clone())));
        if self.severity.is_none() {
            lines.push((String::new(), "· no metadata for this assessment: severity and remediation unknown".into()));
        }
        if let Some(p) = &self.policy_definition {
            lines.push(("Policy".into(), p.clone()));
        }
        if let Some(p) = &self.portal {
            lines.push(("Portal".into(), p.clone()));
        }
        lines
    }
}

/// The Resources section: every resource the same recommendation is
/// about in the warm list, unhealthy first.
pub fn recommendation_resource_rows(r: &RecommendationRow, recommendations: Warm) -> Vec<(String, String)> {
    let Some(rows) = recommendations.rows() else {
        return waiting(recommendations);
    };
    let mut same: Vec<&RecommendationRow> = rows
        .iter()
        .filter_map(|x| x.as_any().downcast_ref::<RecommendationRow>())
        .filter(|x| x.key.eq_ignore_ascii_case(&r.key))
        .collect();
    same.sort_by_key(|x| !x.is_unhealthy());
    let unhealthy = same.iter().filter(|x| x.is_unhealthy()).count();
    let mut lines = vec![(String::new(), format!("{} resource(s), {} unhealthy", same.len(), unhealthy))];
    lines.extend(same.into_iter().map(|x| {
        (
            format!("{} · {}", x.resource_name().unwrap_or_else(|| "-".into()), lower(&x.status)),
            x.resource_id.clone().unwrap_or_else(|| x.base.id.clone()),
        )
    }));
    lines
}

fn waiting(w: Warm) -> Vec<(String, String)> {
    match w {
        Warm::Loading => vec![(String::new(), "Loading…".into())],
        Warm::Failed(e) => crate::azure::services::error_rows(e),
        _ => vec![(String::new(), "Open the Recommendations sub-tab to load them".into())],
    }
}

impl Resource for RecommendationRow {
    arm_row!("Defender recommendation");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `vm-jump-01 · Networking`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([self.resource_name(), self.categories.first().cloned()])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    /// Healthy and not-applicable assessments outnumber the unhealthy ones
    /// many times over; `a` shows them.
    fn is_noise(&self) -> bool {
        !self.is_unhealthy()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&RECOMMENDATION_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.base.name,
            self.resource_id.as_deref().unwrap_or(""),
            self.categories.join(" "),
            self.severity.as_deref().unwrap_or("")
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Assessment".into(), self.key.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Status".into(), json::opt(self.status.clone())),
            ("Severity".into(), json::opt(self.severity.clone())),
            ("Resource".into(), json::opt(self.resource_id.clone())),
            ("Source".into(), json::opt(self.source.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(r) = self.resource_id.as_deref().filter(|r| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(r))) {
            v.push((format!("About {}", name_of_id(r)), r.to_string()));
        }
        v
    }
    /// `az security assessment show` takes the key and the resource.
    fn cli_command(&self) -> Option<String> {
        let on = self.resource_id.as_deref().map(|r| format!(" --assessed-resource-id {}", shell_quote(r))).unwrap_or_default();
        Some(format!("az security assessment show --name {}{}", shell_quote(&self.key), on))
    }
}

// ── Alerts ────────────────────────────────────────────────────────────

/// The entity fields an alert may show: names and addresses. Never a
/// command line, a URL (it can carry a SAS token) or anything else.
const ENTITY_FIELDS: &[&str] = &[
    "type",
    "hostName",
    "netBiosName",
    "osFamily",
    "address",
    "accountName",
    "upnSuffix",
    "ntDomain",
    "name",
    "fileName",
    "domainName",
    "resourceName",
    "resourceId",
    "azureResourceId",
];

/// The alert body with what can carry a secret removed: the extended
/// properties (free-form, often a command line), the supporting evidence,
/// and every entity field outside [`ENTITY_FIELDS`]. Applied before
/// `ArmBase` keeps the raw JSON, so `e` cannot show it either.
pub fn sanitize_alert(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(p) = v.get_mut("properties").and_then(Value::as_object_mut) {
        p.remove("extendedProperties");
        p.remove("supportingEvidence");
        if let Some(Value::Array(entities)) = p.get_mut("entities") {
            for e in entities.iter_mut() {
                if let Some(o) = e.as_object_mut() {
                    o.retain(|k, _| ENTITY_FIELDS.contains(&k.as_str()));
                }
            }
            entities.retain(|e| e.as_object().is_some_and(|o| o.len() > 1));
        }
    }
    v
}

#[derive(Debug, Clone)]
pub struct AlertRow {
    pub base: ArmBase,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub alert_type: Option<String>,
    pub description: Option<String>,
    pub remediation: Vec<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub generated: Option<String>,
    pub compromised_entity: Option<String>,
    pub intent: Option<String>,
    pub product: Option<String>,
    pub is_incident: bool,
    pub techniques: Vec<String>,
    pub resource_ids: Vec<String>,
    /// `(type, what)` per entity, from the sanitized body.
    pub entities: Vec<(String, String)>,
    pub alert_uri: Option<String>,
}

impl AlertRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AlertRow> {
        let v = sanitize_alert(v);
        let base = display_base(&v, "/properties/alertDisplayName", tenant)?;
        let p = |s: &str| format!("/properties/{}", s);
        Some(AlertRow {
            severity: json::str_at(&v, &p("severity")),
            status: json::str_at(&v, &p("status")),
            alert_type: json::str_at(&v, &p("alertType")),
            description: opt_text(&v, &p("description")),
            remediation: json::strings_at(&v, &p("remediationSteps")).iter().map(|s| plain_text(s)).filter(|s| !s.is_empty()).collect(),
            start: json::str_at(&v, &p("startTimeUtc")),
            end: json::str_at(&v, &p("endTimeUtc")),
            generated: json::str_at(&v, &p("timeGeneratedUtc")),
            compromised_entity: json::str_at(&v, &p("compromisedEntity")).filter(|c| !c.is_empty()),
            intent: json::str_at(&v, &p("intent")),
            product: json::str_at(&v, &p("productName")),
            is_incident: json::bool_at(&v, &p("isIncident")).unwrap_or(false),
            techniques: json::strings_at(&v, &p("techniques")),
            resource_ids: json::arr(&v, &p("resourceIdentifiers"))
                .iter()
                .filter_map(|r| json::str_at(r, "/azureResourceId"))
                .collect(),
            entities: json::arr(&v, &p("entities")).iter().filter_map(entity_line).collect(),
            alert_uri: json::str_at(&v, &p("alertUri")),
            base,
        })
    }

    /// The `locations/{x}` segment: where Defender keeps the alert (the
    /// CLI's `--location`), not where the resource is.
    pub fn asc_location(&self) -> Option<&str> {
        let parts: Vec<&str> = self.base.id.split('/').collect();
        parts.iter().position(|p| p.eq_ignore_ascii_case("locations")).and_then(|i| parts.get(i + 1)).copied()
    }

    fn ladder(&self) -> (ResourceState, String) {
        let status = self.status.as_deref().unwrap_or("");
        let bucket = match status.to_ascii_lowercase().as_str() {
            "active" if lower(&self.severity) == "high" => ResourceState::Unavailable,
            "active" | "inprogress" => ResourceState::Pending,
            "resolved" => ResourceState::Available,
            "dismissed" => ResourceState::Stopped,
            _ => return state_ladder(None, None),
        };
        let label = if status.eq_ignore_ascii_case("InProgress") { "in progress" } else { status };
        state_ladder(None, Some((bucket, label)))
    }

    pub fn alert_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Severity".into(), json::opt(self.severity.clone())),
            ("Status".into(), json::opt(self.status.clone())),
            ("Kind".into(), if self.is_incident { "incident (several alerts)".into() } else { "alert".into() }),
            ("Type".into(), json::opt(self.alert_type.clone())),
            ("Intent".into(), json::opt(self.intent.clone())),
        ];
        if !self.techniques.is_empty() {
            lines.push(("Techniques".into(), json::join(&self.techniques)));
        }
        lines.extend([
            ("Entity".into(), json::opt(self.compromised_entity.clone())),
            ("Started".into(), json::time(self.start.clone())),
            ("Ended".into(), json::time(self.end.clone())),
            ("Generated".into(), json::time(self.generated.clone())),
            ("Product".into(), json::opt(self.product.clone())),
            (String::new(), String::new()),
            ("Description".into(), json::opt(self.description.clone())),
        ]);
        for (i, s) in self.remediation.iter().enumerate() {
            lines.push((if i == 0 { "Remediation".into() } else { String::new() }, s.clone()));
        }
        if let Some(u) = &self.alert_uri {
            lines.push(("Portal".into(), u.clone()));
        }
        lines
    }

    pub fn entity_rows(&self) -> Vec<(String, String)> {
        if self.entities.is_empty() {
            return vec![(String::new(), "No entities".into())];
        }
        let mut lines: Vec<(String, String)> = self.entities.iter().map(|(t, w)| (t.clone(), w.clone())).collect();
        lines.push((String::new(), String::new()));
        lines.push((String::new(), "· names and addresses only: command lines and extended properties are not shown".into()));
        lines
    }
}

/// One entity as `(type, what)`: its name, address or id.
fn entity_line(e: &Value) -> Option<(String, String)> {
    let kind = json::str_at(e, "/type")?;
    let account = json::str_at(e, "/accountName").map(|a| match json::str_at(e, "/upnSuffix") {
        Some(s) => format!("{}@{}", a, s),
        None => a,
    });
    let what = json::str_at(e, "/hostName")
        .or(account)
        .or_else(|| json::str_at(e, "/address"))
        .or_else(|| json::str_at(e, "/fileName"))
        .or_else(|| json::str_at(e, "/domainName"))
        .or_else(|| json::str_at(e, "/name"))
        .or_else(|| json::str_at(e, "/resourceName"))
        .or_else(|| json::str_at(e, "/azureResourceId"))
        .or_else(|| json::str_at(e, "/resourceId"))?;
    Some((kind, what))
}

impl Resource for AlertRow {
    arm_row!("Defender alert");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `High · vm-jump-01`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([self.severity.clone(), self.compromised_entity.clone()])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ALERT_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Severity".into(), json::opt(self.severity.clone())),
            ("Status".into(), json::opt(self.status.clone())),
            ("Started".into(), json::time(self.start.clone())),
            ("Entity".into(), json::opt(self.compromised_entity.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for r in &self.resource_ids {
            if !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(r)) {
                v.push((format!("About {}", name_of_id(r)), r.clone()));
            }
        }
        v
    }
    /// `az security alert show` takes the name, the location and the group.
    fn cli_command(&self) -> Option<String> {
        let rg = resource_group_of(&self.base.id).map(|g| format!(" --resource-group {}", shell_quote(g))).unwrap_or_default();
        Some(format!(
            "az security alert show --name {} --location {}{}",
            shell_quote(name_of_id(&self.base.id)),
            shell_quote(self.asc_location().unwrap_or("-")),
            rg
        ))
    }
}

// ── Secure score ──────────────────────────────────────────────────────

fn score_of(v: &Value) -> (f64, f64, f64) {
    let f = |p: &str| v.pointer(p).and_then(Value::as_f64).unwrap_or(0.0);
    (f("/properties/score/current"), f("/properties/score/max"), f("/properties/score/percentage"))
}

#[derive(Debug, Clone)]
pub struct SecureScoreRow {
    pub base: ArmBase,
    pub current: f64,
    pub max: f64,
    pub percentage: f64,
    pub weight: Option<i64>,
}

impl SecureScoreRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<SecureScoreRow> {
        let base = display_base(v, "/properties/displayName", tenant)?;
        let (current, max, percentage) = score_of(v);
        Some(SecureScoreRow { current, max, percentage, weight: json::int_at(v, "/properties/weight"), base })
    }

    pub fn score_rows(&self) -> Vec<(String, String)> {
        vec![
            ("Score".into(), format!("{:.0}%", self.percentage * 100.0)),
            ("Points".into(), format!("{:.2} of {:.0}", self.current, self.max)),
            ("Weight".into(), json::num(self.weight)),
            (String::new(), "· the sum of the controls' points: each control's rows below say what it would add".into()),
        ]
    }
}

impl Resource for SecureScoreRow {
    arm_row!("Secure score");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `61% · 35.20 of 58`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("{:.0}% · {:.2} of {:.0}", self.percentage * 100.0, self.current, self.max))
    }
    fn state(&self) -> ResourceState {
        ResourceState::stateless()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SECURE_SCORE_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Score".into(), format!("{:.0}%", self.percentage * 100.0)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az security secure-scores show --name {}", shell_quote(name_of_id(&self.base.id))))
    }
}

#[derive(Debug, Clone)]
pub struct ScoreControlRow {
    pub base: ArmBase,
    pub current: f64,
    pub max: f64,
    pub percentage: f64,
    pub healthy: i64,
    pub unhealthy: i64,
    pub not_applicable: i64,
    pub description: Option<String>,
    pub source: Option<String>,
    /// The assessment keys (metadata names) the control is made of.
    pub assessment_keys: Vec<String>,
}

impl ScoreControlRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ScoreControlRow> {
        let base = display_base(v, "/properties/displayName", tenant)?;
        let (current, max, percentage) = score_of(v);
        let n = |p: &str| json::int_at(v, &format!("/properties/{}", p)).unwrap_or(0);
        Some(ScoreControlRow {
            current,
            max,
            percentage,
            healthy: n("healthyResourceCount"),
            unhealthy: n("unhealthyResourceCount"),
            not_applicable: n("notApplicableResourceCount"),
            description: opt_text(v, "/properties/definition/properties/description"),
            source: json::str_at(v, "/properties/definition/properties/source/sourceType"),
            assessment_keys: json::arr(v, "/properties/definition/properties/assessmentDefinitions")
                .iter()
                .filter_map(|a| json::str_at(a, "/id"))
                .map(|id| name_of_id(&id).to_ascii_lowercase())
                .collect(),
            base,
        })
    }

    /// The points fixing everything in the control would add.
    pub fn gain(&self) -> f64 {
        (self.max - self.current).max(0.0)
    }

    pub fn control_rows(&self) -> Vec<(String, String)> {
        vec![
            ("Points".into(), format!("{:.2} of {:.0} ({:.0}%)", self.current, self.max, self.percentage * 100.0)),
            ("Potential gain".into(), format!("+{:.2}", self.gain())),
            ("Unhealthy".into(), self.unhealthy.to_string()),
            ("Healthy".into(), self.healthy.to_string()),
            ("Not applicable".into(), self.not_applicable.to_string()),
            ("Source".into(), json::opt(self.source.clone())),
            ("Description".into(), json::opt(self.description.clone())),
        ]
    }

    fn ladder(&self) -> (ResourceState, String) {
        if self.max <= 0.0 {
            return state_ladder(None, None);
        }
        let runtime = if self.unhealthy > 0 { (ResourceState::Pending, "gaps") } else { (ResourceState::Available, "met") };
        state_ladder(None, Some(runtime))
    }
}

/// A control's Recommendations: the warm unhealthy ones it is made of.
pub fn control_recommendation_rows(c: &ScoreControlRow, recommendations: Warm) -> Vec<(String, String)> {
    let Some(rows) = recommendations.rows() else {
        return waiting(recommendations);
    };
    let mine: Vec<&RecommendationRow> = rows
        .iter()
        .filter_map(|x| x.as_any().downcast_ref::<RecommendationRow>())
        .filter(|x| x.is_unhealthy() && c.assessment_keys.contains(&x.key.to_ascii_lowercase()))
        .collect();
    if mine.is_empty() {
        return vec![(String::new(), "No unhealthy recommendation in this control".into())];
    }
    mine.into_iter()
        .map(|x| (format!("{} · {}", x.base.name, x.resource_name().unwrap_or_else(|| "-".into())), x.base.id.clone()))
        .collect()
}

impl Resource for ScoreControlRow {
    arm_row!("Secure score control");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `+3.00 · 4 unhealthy`.
    fn list_summary(&self) -> Option<String> {
        Some(format!("+{:.2} · {} unhealthy", self.gain(), self.unhealthy))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SCORE_CONTROL_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Points".into(), format!("{:.2} of {:.0}", self.current, self.max)),
            ("Unhealthy".into(), self.unhealthy.to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(score) = extension_score(&self.base.id) {
            v.push(("Secure score".into(), score));
        }
        v
    }
    /// The CLI shows a control only in the subscription's list.
    fn cli_command(&self) -> Option<String> {
        Some("az security secure-score-controls list".into())
    }
}

/// `…/secureScores/{name}` out of a control's id.
fn extension_score(id: &str) -> Option<String> {
    let lower = id.to_ascii_lowercase();
    let at = lower.find("/securescorecontrols/")?;
    Some(id[..at].to_string())
}

// ── Plans (pricings) ──────────────────────────────────────────────────

/// A plan's API name in the portal's words.
pub fn plan_words(name: &str) -> &str {
    match name.to_ascii_lowercase().as_str() {
        "virtualmachines" => "Servers",
        "sqlservers" => "Azure SQL databases",
        "sqlservervirtualmachines" => "SQL servers on machines",
        "opensourcerelationaldatabases" => "Open-source relational databases",
        "cosmosdbs" => "Azure Cosmos DB",
        "appservices" => "App Service",
        "storageaccounts" => "Storage",
        "keyvaults" => "Key Vault",
        "arm" => "Resource Manager",
        "dns" => "DNS",
        "containers" => "Containers",
        "kubernetesservice" => "Kubernetes Service (retired)",
        "containerregistry" => "Container registries (retired)",
        "cloudposture" => "Defender CSPM",
        "api" => "APIs",
        "ai" => "AI services",
        _ => name,
    }
}

#[derive(Debug, Clone)]
pub struct PlanRow {
    pub base: ArmBase,
    pub plan: String,
    pub tier: Option<String>,
    pub sub_plan: Option<String>,
    pub trial_left: Option<String>,
    pub enabled_since: Option<String>,
    pub deprecated: bool,
    pub replaced_by: Vec<String>,
    /// `(name, on, status)` per extension.
    pub extensions: Vec<(String, bool, Option<String>)>,
    pub enforce: Option<String>,
    pub inherited: Option<String>,
    pub inherited_from: Option<String>,
    pub coverage: Option<String>,
}

impl PlanRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<PlanRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        let plan = name_of_id(&base.id).to_string();
        base.name = plan_words(&plan).to_string();
        let p = |s: &str| format!("/properties/{}", s);
        Some(PlanRow {
            tier: json::str_at(v, &p("pricingTier")),
            sub_plan: json::str_at(v, &p("subPlan")),
            trial_left: json::str_at(v, &p("freeTrialRemainingTime")).filter(|t| t != "PT0S"),
            enabled_since: json::str_at(v, &p("enablementTime")),
            deprecated: json::bool_at(v, &p("deprecated")).unwrap_or(false),
            replaced_by: json::strings_at(v, &p("replacedBy")),
            extensions: json::arr(v, &p("extensions"))
                .iter()
                .map(|e| {
                    (
                        json::text(e, "/name"),
                        json::str_at(e, "/isEnabled").is_some_and(|b| b.eq_ignore_ascii_case("True")),
                        json::str_at(e, "/operationStatus/code"),
                    )
                })
                .collect(),
            enforce: json::str_at(v, &p("enforce")),
            inherited: json::str_at(v, &p("inherited")),
            inherited_from: json::str_at(v, &p("inheritedFrom")).filter(|s| !s.is_empty()),
            coverage: json::str_at(v, &p("resourcesCoverageStatus")),
            plan,
            base,
        })
    }

    pub fn is_on(&self) -> bool {
        self.tier.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("Standard"))
    }

    pub fn plan_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Plan".into(), format!("{} ({})", plan_words(&self.plan), self.plan)),
            ("Tier".into(), json::opt(self.tier.clone())),
        ];
        if !self.is_on() {
            lines.push((String::new(), "· Free: recommendations only, no alerts from this plan".into()));
        }
        lines.extend([
            ("Sub-plan".into(), json::opt(self.sub_plan.clone())),
            ("On since".into(), json::time(self.enabled_since.clone())),
            ("Trial left".into(), json::opt(self.trial_left.clone())),
            ("Coverage".into(), json::opt(self.coverage.clone())),
            ("Enforced below".into(), json::opt(self.enforce.clone())),
            ("Inherited".into(), json::opt(self.inherited.clone())),
        ]);
        if let Some(f) = &self.inherited_from {
            lines.push(("From".into(), f.clone()));
        }
        if self.deprecated {
            lines.push(("Retired".into(), format!("replaced by {}", json::join(&self.replaced_by))));
        }
        lines
    }

    pub fn extension_rows(&self) -> Vec<(String, String)> {
        if self.extensions.is_empty() {
            return vec![(String::new(), "No extensions".into())];
        }
        self.extensions
            .iter()
            .map(|(n, on, status)| {
                let s = status.as_deref().map(|s| format!(" · {}", s)).unwrap_or_default();
                (n.clone(), format!("{}{}", if *on { "on" } else { "off" }, s))
            })
            .collect()
    }
}

impl Resource for PlanRow {
    arm_row!("Defender plan");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `Standard · P2` / `Free`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([self.tier.clone(), self.sub_plan.clone()])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    /// A retired plan is listed but can't be turned on.
    fn is_noise(&self) -> bool {
        self.deprecated
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&PLAN_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!("{} {}", self.base.name, self.plan)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Plan".into(), self.plan.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Tier".into(), json::opt(self.tier.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(f) = self.inherited_from.as_deref().filter(|f| f.starts_with('/')) {
            v.push(("Inherited from".into(), f.to_string()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az security pricing show --name {}", shell_quote(&self.plan)))
    }
}

impl PlanRow {
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = if self.is_on() { (ResourceState::Available, "on") } else { (ResourceState::Stopped, "off") };
        state_ladder(None, Some(runtime))
    }
}

// ── Section dispatch ──────────────────────────────────────────────────

/// Every Defender type's section body, or `None` for another type.
/// `recommendations` is the warm Recommendations list (the Resources and
/// a control's Recommendations read it).
pub fn defender_section_lines(r: &dyn Resource, idx: usize, recommendations: Warm) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    let app = crate::azure::services::rendered_by_app;
    if let Some(x) = any.downcast_ref::<RecommendationRow>() {
        use RecommendationDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Recommendation => x.recommendation_rows(),
            S::Resources => recommendation_resource_rows(x, recommendations),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    if let Some(x) = any.downcast_ref::<AlertRow>() {
        use AlertDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Alert => x.alert_rows(),
            S::Entities => x.entity_rows(),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    if let Some(x) = any.downcast_ref::<SecureScoreRow>() {
        use SecureScoreDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Score => x.score_rows(),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    if let Some(x) = any.downcast_ref::<ScoreControlRow>() {
        use ScoreControlDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Control => x.control_rows(),
            S::Recommendations => control_recommendation_rows(x, recommendations),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    if let Some(x) = any.downcast_ref::<PlanRow>() {
        use PlanDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Plan => x.plan_rows(),
            S::Extensions => x.extension_rows(),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    None
}

// ── Provider ──────────────────────────────────────────────────────────

/// The joined metadata, keyed by lowercased assessment key.
type Metadata = HashMap<String, Value>;

pub struct DefenderService {
    scope: Scope,
}

impl DefenderService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<T: Resource + 'static>(rows: Vec<T>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], md: &Metadata, tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::DefenderAlerts => Self::boxed(page.iter().filter_map(|v| AlertRow::from_json(v, tenant)).collect()),
            JumpView::DefenderPlans => Self::boxed(page.iter().filter_map(|v| PlanRow::from_json(v, tenant)).collect()),
            JumpView::SecureScore => page
                .iter()
                .filter_map(|v| {
                    if json::text(v, "/id").to_ascii_lowercase().contains("/securescorecontrols/") {
                        ScoreControlRow::from_json(v, tenant).map(|r| Box::new(r) as Box<dyn Resource>)
                    } else {
                        SecureScoreRow::from_json(v, tenant).map(|r| Box::new(r) as Box<dyn Resource>)
                    }
                })
                .collect(),
            _ => Self::boxed(
                page.iter()
                    .filter_map(|v| {
                        let key = name_of_id(&json::text(v, "/id")).to_ascii_lowercase();
                        RecommendationRow::from_json(v, md.get(&key), tenant)
                    })
                    .collect(),
            ),
        }
    }

    /// The list (or lists) behind a sub-tab: the score is two.
    #[allow(clippy::type_complexity)]
    fn lists_of(view: JumpView) -> &'static [(&'static str, &'static str, &'static [(&'static str, &'static str)], &'static str)] {
        match view {
            JumpView::DefenderAlerts => &[(ALERTS_PATH, ALERTS_API_VERSION, &[], "Listing Defender alerts…")],
            JumpView::DefenderPlans => &[(PRICINGS_PATH, PRICINGS_API_VERSION, &[], "Listing Defender plans…")],
            JumpView::SecureScore => &[
                (SECURE_SCORES_PATH, SECURE_SCORE_API_VERSION, &[], "Reading the secure score…"),
                (SCORE_CONTROLS_PATH, SECURE_SCORE_API_VERSION, &[EXPAND_DEFINITION], "Listing secure score controls…"),
            ],
            _ => &[(ASSESSMENTS_PATH, ASSESSMENTS_API_VERSION, &[], "Listing Defender recommendations…")],
        }
    }

    /// The assessment metadata, built-in (tenant root) and the
    /// subscription's custom, keyed by name. A failure only costs the
    /// severities: the recommendations still list.
    async fn metadata(&self) -> (Metadata, Vec<Error>) {
        let mut md = Metadata::new();
        let mut errors = Vec::new();
        let tenant = self.scope.list_query_at(METADATA_PATH, ASSESSMENTS_API_VERSION, &[]).await;
        let custom = self.scope.list_query(METADATA_PATH, ASSESSMENTS_API_VERSION, &[]).await;
        for r in [tenant, custom] {
            match r {
                Ok(items) => {
                    for m in items {
                        if let Some(p) = m.get("properties") {
                            md.insert(json::text(&m, "/name").to_ascii_lowercase(), p.clone());
                        }
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        (md, errors)
    }

    pub fn api_version_for(id: &str) -> &'static str {
        match JumpView::for_arm_id(id) {
            Some(JumpView::DefenderAlerts) => ALERTS_API_VERSION,
            Some(JumpView::SecureScore) => SECURE_SCORE_API_VERSION,
            Some(JumpView::DefenderPlans) => PRICINGS_API_VERSION,
            _ => ASSESSMENTS_API_VERSION,
        }
    }
}

fn metadata_warning(errors: &[Error]) -> Option<String> {
    errors.first().map(|e| format!("assessment metadata not read, so no severities or remediation: {}", e))
}

#[async_trait]
impl AzureService for DefenderService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Defender
    }

    fn name(&self) -> &str {
        "Defender"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        let md = if view == JumpView::DefenderRecommendations { self.metadata().await.0 } else { Metadata::new() };
        let mut out = Vec::new();
        let mut first_err = None;
        for (path, version, query, _) in Self::lists_of(view) {
            match self.scope.list_query(path, version, query).await {
                Ok(page) => out.extend(Self::rows(view, &page, &md, tenant)),
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
        let md = if view == JumpView::DefenderRecommendations {
            let (md, errors) = self.metadata().await;
            if let Some(w) = metadata_warning(&errors) {
                let _ = event_tx.send(Event::ResourceLoadWarning { service: service_type, warning: w });
            }
            md
        } else {
            Metadata::new()
        };
        let lists = Self::lists_of(view);
        let mut total = 0usize;
        let mut failures = Vec::new();
        for (path, version, query, label) in lists {
            let r = self
                .scope
                .stream(path, version, query, service_type, label, &event_tx, |page| Self::rows(view, &page, &md, tenant.as_deref()))
                .await;
            match r {
                Ok(n) => total += n,
                Err(e) => failures.push(e),
            }
        }
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
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::DefenderRecommendations);
        Self::rows(view, std::slice::from_ref(&v), &Metadata::new(), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SUB: &str = "/subscriptions/0000";
    const VM: &str = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1";

    fn assessment(status: &str) -> Value {
        json!({
            "id": format!("{}/providers/Microsoft.Security/assessments/805651bc-6ecd-4c73-9b55-97a19d0582d0", VM),
            "name": "805651bc-6ecd-4c73-9b55-97a19d0582d0",
            "type": "Microsoft.Security/assessments",
            "properties": {
                "displayName": "Management ports should be closed on your virtual machines",
                "resourceDetails": {"Source": "Azure", "Id": VM},
                "status": {"code": status, "firstEvaluationDate": "2026-01-01T00:00:00Z", "statusChangeDate": "2026-02-01T00:00:00Z"},
                "links": {"azurePortal": "portal.azure.com/#blade/x"}
            }
        })
    }

    fn metadata() -> Value {
        json!({"displayName": "Management ports…", "severity": "High", "categories": ["Networking"],
            "description": "Open <b>ports</b>&nbsp;are risky.", "remediationDescription": "Close them.<br>Use JIT.",
            "userImpact": "Low", "implementationEffort": "Low", "threats": ["DataExfiltration"], "assessmentType": "BuiltIn"})
    }

    #[test]
    fn a_recommendation_joins_its_metadata_and_names_its_resource() {
        let r = RecommendationRow::from_json(&assessment("Unhealthy"), Some(&metadata()), None).unwrap();
        assert_eq!(r.resource_id.as_deref(), Some(VM));
        assert_eq!(r.state_label(), "high");
        assert_eq!(r.state(), ResourceState::Unavailable);
        assert!(!r.is_noise());
        assert_eq!(r.description.as_deref(), Some("Open ports are risky."));
        assert_eq!(r.list_summary().as_deref(), Some("vm-1 · Networking"));
        assert!(r.related().iter().any(|(l, id)| l == "About vm-1" && id == VM));
        assert_eq!(JumpView::for_arm_id(&r.base.id), Some(JumpView::DefenderRecommendations));
        assert!(is_defender_id(&r.base.id));
        let cli = r.cli_command().unwrap();
        assert!(cli.starts_with("az security assessment show --name 805651bc") && cli.ends_with(VM), "{cli}");

        let healthy = RecommendationRow::from_json(&assessment("Healthy"), None, None).unwrap();
        assert!(healthy.is_noise());
        assert_eq!(healthy.state_label(), "healthy");
        assert!(healthy.recommendation_rows().iter().any(|(_, v)| v.contains("no metadata")));
    }

    #[test]
    fn an_alert_drops_what_can_carry_a_secret() {
        let v = json!({
            "id": format!("{}/resourceGroups/rg/providers/Microsoft.Security/locations/westeurope/alerts/2517_abc", SUB),
            "name": "2517_abc",
            "properties": {
                "alertDisplayName": "Suspicious process executed",
                "severity": "High", "status": "Active", "compromisedEntity": "vm-1",
                "extendedProperties": {"command line": "mysql -pS3cret"},
                "supportingEvidence": {"type": "tabularEvidences"},
                "entities": [
                    {"$id": "1", "type": "host", "hostName": "vm-1"},
                    {"$id": "2", "type": "process", "commandLine": "mysql -pS3cret", "processId": "0x1"},
                    {"$id": "3", "type": "account", "accountName": "alex", "upnSuffix": "contoso.com"}
                ],
                "resourceIdentifiers": [{"type": "AzureResource", "azureResourceId": VM}],
                "remediationSteps": ["Isolate the <b>VM</b>."]
            }
        });
        let a = AlertRow::from_json(&v, None).unwrap();
        assert!(!a.base.raw.contains("S3cret"), "the raw JSON never keeps it: {}", a.base.raw);
        assert_eq!(a.entities, [("host".to_string(), "vm-1".to_string()), ("account".into(), "alex@contoso.com".into())]);
        assert_eq!(a.state(), ResourceState::Unavailable);
        assert_eq!(a.state_label(), "active");
        assert_eq!(a.remediation, ["Isolate the VM."]);
        assert_eq!(a.asc_location(), Some("westeurope"));
        assert_eq!(a.cli_command().unwrap(), "az security alert show --name 2517_abc --location westeurope --resource-group rg");
        assert!(a.related().iter().any(|(_, id)| id == VM));
        assert_eq!(JumpView::for_arm_id(&a.base.id), Some(JumpView::DefenderAlerts));
    }

    #[test]
    fn a_control_lists_its_unhealthy_recommendations() {
        let c = json!({
            "id": format!("{}/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls/abc", SUB),
            "name": "abc",
            "properties": {"displayName": "Secure management ports", "score": {"current": 2.0, "max": 8, "percentage": 0.25},
                "healthyResourceCount": 1, "unhealthyResourceCount": 3, "notApplicableResourceCount": 0,
                "definition": {"properties": {"assessmentDefinitions": [
                    {"id": "/providers/Microsoft.Security/assessmentMetadata/805651bc-6ecd-4c73-9b55-97a19d0582d0"}]}}}
        });
        let c = ScoreControlRow::from_json(&c, None).unwrap();
        assert_eq!(c.list_summary().as_deref(), Some("+6.00 · 3 unhealthy"));
        assert_eq!(c.state_label(), "gaps");
        assert_eq!(JumpView::for_arm_id(&c.base.id), Some(JumpView::SecureScore));
        assert!(c.related().iter().any(|(l, id)| l == "Secure score" && id.ends_with("/secureScores/ascScore")));
        let recs: Vec<Box<dyn Resource>> = vec![
            Box::new(RecommendationRow::from_json(&assessment("Unhealthy"), Some(&metadata()), None).unwrap()),
            Box::new(RecommendationRow::from_json(&assessment("Healthy"), None, None).unwrap()),
        ];
        let lines = control_recommendation_rows(&c, Warm::Rows(&recs));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].0.ends_with("· vm-1"));
    }

    #[test]
    fn a_plan_reads_on_or_off_and_retired_is_noise() {
        let p = |name: &str, tier: &str, deprecated: bool| {
            PlanRow::from_json(
                &json!({"id": format!("{}/providers/Microsoft.Security/pricings/{}", SUB, name), "name": name,
                    "properties": {"pricingTier": tier, "subPlan": "P2", "deprecated": deprecated,
                        "extensions": [{"name": "MdeDesignatedSubscription", "isEnabled": "False"}]}}),
                None,
            )
            .unwrap()
        };
        let vm = p("VirtualMachines", "Standard", false);
        assert_eq!(vm.base.name, "Servers");
        assert_eq!(vm.state_label(), "on");
        assert_eq!(vm.cli_command().unwrap(), "az security pricing show --name VirtualMachines");
        assert_eq!(vm.extension_rows(), [("MdeDesignatedSubscription".to_string(), "off".to_string())]);
        let kv = p("KeyVaults", "Free", false);
        assert_eq!(kv.state_label(), "off");
        assert!(!kv.is_noise());
        assert!(p("KubernetesService", "Free", true).is_noise());
        assert_eq!(JumpView::for_arm_id(&vm.base.id), Some(JumpView::DefenderPlans));
    }

    #[test]
    fn plain_text_strips_defender_html() {
        assert_eq!(plain_text("a<br/>b &amp; <a href='x'>c</a>"), "a b & c");
    }

    #[test]
    fn section_labels() {
        let labels = |d: &crate::sections::SectionDescriptor| d.sections.iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(labels(&RECOMMENDATION_SECTIONS), ["Overview", "Recommendation", "Resources", "Activity", "Related"]);
        assert_eq!(labels(&ALERT_SECTIONS), ["Overview", "Alert", "Entities", "Activity", "Related"]);
        assert_eq!(labels(&SECURE_SCORE_SECTIONS), ["Overview", "Score", "Activity", "Related"]);
        assert_eq!(labels(&SCORE_CONTROL_SECTIONS), ["Overview", "Control", "Recommendations", "Activity", "Related"]);
        assert_eq!(labels(&PLAN_SECTIONS), ["Overview", "Plan", "Extensions", "Activity", "Related"]);
    }
}
