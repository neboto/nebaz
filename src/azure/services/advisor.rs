//! The Advisor tab (#157, ADR 0011): Azure Advisor's recommendations for
//! the subscription, read-only. Three lists under `Microsoft.Advisor`, all
//! GETs:
//!
//! - recommendations: one row per recommendation and resource, ranked by
//!   impact. The list is what Advisor last computed: `generateRecommendations`
//!   is a POST and is never called, so each row says when Advisor last
//!   looked. Security recommendations are Defender's own assessments
//!   (Advisor relays them), so they are noise (`a`) and link to the
//!   Defender row instead of standing beside it;
//! - score: the Advisor score overall and per category;
//! - suppressions: the recommendations someone snoozed or dismissed.
//!
//! Like Defender's, these rows are never `@audit` findings (ADR 0011), have
//! no RBAC and no tags of their own (the tail is Activity and Related), and
//! no region, so they pass every `R` filter.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, subscription_id_of, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::backup::ago;
use crate::azure::services::governance::Warm;
use crate::azure::services::{arm_row, finish_stream, json, overview_rows, related_lines, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

pub const RECOMMENDATIONS_PATH: &str = "/providers/Microsoft.Advisor/recommendations";
pub const SCORE_PATH: &str = "/providers/Microsoft.Advisor/advisorScore";
pub const SUPPRESSIONS_PATH: &str = "/providers/Microsoft.Advisor/suppressions";
/// Advisor's newest stable but one: `2026-10-01` is two weeks old, and
/// what it adds (a recommendation's status, the review it belongs to) is
/// not shown here. One version for all three lists.
pub const ADVISOR_API_VERSION: &str = "2025-01-01";

crate::sections! {
    pub enum AdvisorRecommendationDetailSection,
    pub static ADVISOR_RECOMMENDATION_SECTIONS = [
        Overview "Overview",
        Recommendation "Recommendation",
        Resources "Resources" => crate::app::App::trigger_advisor_recommendations,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum AdvisorScoreDetailSection,
    pub static ADVISOR_SCORE_SECTIONS = [
        Overview "Overview",
        Score "Score",
        Recommendations "Recommendations" => crate::app::App::trigger_advisor_recommendations,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

crate::sections! {
    pub enum AdvisorSuppressionDetailSection,
    pub static ADVISOR_SUPPRESSION_SECTIONS = [
        Overview "Overview",
        Suppression "Suppression",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

/// Whether an id is an Advisor row's: no RBAC of its own, so neither an
/// Access section nor the `C` picker's role-assignment read.
pub fn is_advisor_id(id: &str) -> bool {
    matches!(
        JumpView::for_arm_id(id),
        Some(JumpView::AdvisorRecommendations | JumpView::AdvisorScore | JumpView::AdvisorSuppressions)
    )
}

/// A category in the portal's words: `HighAvailability` is Reliability
/// there, and the score's `Advisor` entry is the overall score.
pub fn category_words(c: &str) -> &str {
    match c.to_ascii_lowercase().as_str() {
        "highavailability" => "Reliability",
        "operationalexcellence" => "Operational excellence",
        "cost" => "Cost",
        "security" => "Security",
        "performance" => "Performance",
        "advisor" => "Overall",
        _ => c,
    }
}

fn is_security(c: Option<&str>) -> bool {
    c.is_some_and(|c| c.eq_ignore_ascii_case("Security"))
}

/// `2026-10-25 02:01 (3d ago)`, or `-`.
fn time_ago(s: Option<&str>, now: i64) -> String {
    match s.and_then(crate::azure::metrics::parse_iso_utc) {
        Some(t) => format!("{} ({})", json::unix_to_ymdhm(t), ago(t, now)),
        None => "-".into(),
    }
}

/// `2026-11-30 00:00 (in 25d)`, `(expired)` once past, or `-`.
fn until(s: Option<&str>, now: i64) -> String {
    match s.and_then(crate::azure::metrics::parse_iso_utc) {
        Some(t) if t <= now => format!("{} (expired)", json::unix_to_ymdhm(t)),
        Some(t) => format!("{} (in {})", json::unix_to_ymdhm(t), ago(now, t).trim_end_matches(" ago")),
        None => "-".into(),
    }
}

/// `subscription` or the resource's own name.
fn subject(resource: Option<&str>) -> String {
    match resource {
        Some(r) if subscription_id_of(r).is_some_and(|s| s.eq_ignore_ascii_case(r.trim_end_matches('/'))) => "subscription".into(),
        Some(r) => name_of_id(r).to_string(),
        None => "-".into(),
    }
}

// ── Recommendations ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdvisorRecommendationRow {
    pub base: ArmBase,
    /// The recommendation type's GUID, shared by every resource the same
    /// recommendation is about.
    pub type_id: Option<String>,
    pub category: Option<String>,
    /// The sub-category (`control`): `ServiceUpgradeAndRetirement`, …
    pub control: Option<String>,
    pub impact: Option<String>,
    pub risk: Option<String>,
    pub resource_id: Option<String>,
    /// What Advisor got it from: for Security, the Defender assessment.
    pub source: Option<String>,
    pub resource_kind: Option<String>,
    pub problem: Option<String>,
    pub solution: Option<String>,
    pub description: Option<String>,
    pub benefits: Option<String>,
    pub learn_more: Option<String>,
    pub last_updated: Option<String>,
    /// Advisor's free-form extras (a right-size's target SKU, the
    /// savings), the strings and numbers only.
    pub extended: Vec<(String, String)>,
}

impl AdvisorRecommendationRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AdvisorRecommendationRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| json::str_at(v, &format!("/properties/{}", k)).filter(|s| !s.trim().is_empty());
        let problem = p("shortDescription/problem");
        if let Some(name) = problem.clone().or_else(|| p("label")) {
            base.name = name;
        }
        let resource_id = p("resourceMetadata/resourceId").or_else(|| crate::azure::resource::extension_scope(&base.id).map(str::to_string));
        let mut extended: Vec<(String, String)> = v
            .pointer("/properties/extendedProperties")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, x)| match x {
                        Value::String(s) if !s.is_empty() => Some((k.clone(), s.clone())),
                        Value::Number(n) => Some((k.clone(), n.to_string())),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        extended.sort();
        Some(AdvisorRecommendationRow {
            type_id: p("recommendationTypeId"),
            category: p("category"),
            control: p("control"),
            impact: p("impact"),
            risk: p("risk"),
            source: p("resourceMetadata/source"),
            resource_kind: p("resourceMetadata/singular").or_else(|| p("impactedField")),
            solution: p("shortDescription/solution").filter(|s| Some(s) != problem.as_ref()),
            description: p("description"),
            benefits: p("potentialBenefits"),
            learn_more: p("learnMoreLink"),
            last_updated: p("lastUpdated"),
            problem,
            resource_id,
            extended,
            base,
        })
    }

    pub fn is_security(&self) -> bool {
        is_security(self.category.as_deref())
    }

    fn category_label(&self) -> Option<String> {
        self.category.as_deref().map(|c| category_words(c).to_string())
    }

    /// The Defender assessment a Security recommendation relays.
    pub fn defender_source(&self) -> Option<&str> {
        self.source.as_deref().filter(|s| s.to_ascii_lowercase().contains("/providers/microsoft.security/assessments/"))
    }

    /// `1,260 EUR a year`, from a cost recommendation's extras.
    pub fn savings(&self) -> Option<String> {
        let get = |k: &str| self.extended.iter().find(|(x, _)| x.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
        let (amount, per) = match get("annualSavingsAmount") {
            Some(a) => (a, "a year"),
            None => (get("savingsAmount")?, "a month"),
        };
        let amount = amount.parse::<f64>().ok()?;
        Some(format!("{} {} {}", thousands(amount.round() as i64), get("savingsCurrency").unwrap_or(""), per).replace("  ", " "))
    }

    /// High impact is red, medium amber, low grey; the label is the impact,
    /// so `F` filters by it.
    fn ladder(&self) -> (ResourceState, String) {
        let Some(impact) = self.impact.as_deref() else {
            return state_ladder(None, None);
        };
        let label = impact.to_ascii_lowercase();
        let bucket = match label.as_str() {
            "high" => ResourceState::Unavailable,
            "medium" => ResourceState::Pending,
            _ => ResourceState::Stopped,
        };
        state_ladder(None, Some((bucket, label.as_str())))
    }

    pub fn recommendation_rows(&self, now: i64) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Impact".into(), json::opt(self.impact.clone())),
            ("Category".into(), json::opt(self.category_label())),
        ];
        if let Some(c) = &self.control {
            lines.push(("Sub-category".into(), c.clone()));
        }
        if let Some(r) = self.risk.as_deref().filter(|r| !r.eq_ignore_ascii_case("None")) {
            lines.push(("Risk".into(), r.to_string()));
        }
        lines.push((
            "Resource".into(),
            match &self.resource_kind {
                Some(k) => format!("{} ({})", subject(self.resource_id.as_deref()), k),
                None => subject(self.resource_id.as_deref()),
            },
        ));
        if let Some(r) = &self.resource_id {
            lines.push((String::new(), r.clone()));
        }
        if let Some(s) = self.savings() {
            lines.push(("Savings".into(), s));
        }
        lines.push(("Last updated".into(), time_ago(self.last_updated.as_deref(), now)));
        lines.push((String::new(), "· what Advisor last computed: nebaz never asks it to re-run (a POST)".into()));
        lines.push((String::new(), String::new()));
        lines.push(("Problem".into(), json::opt(self.problem.clone())));
        if let Some(s) = &self.solution {
            lines.push(("Solution".into(), s.clone()));
        }
        if let Some(b) = &self.benefits {
            lines.push(("Benefits".into(), b.clone()));
        }
        if let Some(d) = &self.description {
            lines.push(("Description".into(), d.clone()));
        }
        if let Some(l) = &self.learn_more {
            lines.push(("Learn more".into(), l.clone()));
        }
        if let Some(d) = self.defender_source() {
            lines.push((String::new(), String::new()));
            lines.push(("Defender".into(), d.to_string()));
            lines.push((String::new(), "· a Defender recommendation Advisor relays: the Defender tab has its severity and remediation".into()));
        }
        if !self.extended.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("━━ Details".into(), String::new()));
            lines.extend(self.extended.iter().cloned());
        }
        lines
    }
}

/// `1260` → `1,260`.
fn thousands(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{}", out)
    } else {
        out
    }
}

fn recommendations_in(rows: &[Box<dyn Resource>]) -> impl Iterator<Item = &AdvisorRecommendationRow> {
    rows.iter().filter_map(|x| x.as_any().downcast_ref::<AdvisorRecommendationRow>())
}

fn impact_rank(r: &AdvisorRecommendationRow) -> u8 {
    match r.impact.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("high") => 0,
        Some("medium") => 1,
        Some("low") => 2,
        _ => 3,
    }
}

fn waiting(w: Warm) -> Vec<(String, String)> {
    match w {
        Warm::Loading => vec![(String::new(), "Loading…".into())],
        Warm::Failed(e) => crate::azure::services::error_rows(e),
        _ => vec![(String::new(), "Open the Recommendations sub-tab to load them".into())],
    }
}

/// The Resources section: every resource the same recommendation is
/// about in the warm list.
pub fn recommendation_resource_rows(r: &AdvisorRecommendationRow, recommendations: Warm) -> Vec<(String, String)> {
    let Some(rows) = recommendations.rows() else {
        return waiting(recommendations);
    };
    let same: Vec<&AdvisorRecommendationRow> = match &r.type_id {
        Some(t) => recommendations_in(rows).filter(|x| x.type_id.as_deref().is_some_and(|y| y.eq_ignore_ascii_case(t))).collect(),
        None => recommendations_in(rows).filter(|x| x.base.id.eq_ignore_ascii_case(&r.base.id)).collect(),
    };
    let mut lines = vec![(String::new(), format!("{} resource(s)", same.len().max(1)))];
    if same.is_empty() {
        lines.push((subject(r.resource_id.as_deref()), r.resource_id.clone().unwrap_or_else(|| r.base.id.clone())));
    }
    lines.extend(same.into_iter().map(|x| {
        let what = match x.savings() {
            Some(s) => format!("{} · {}", subject(x.resource_id.as_deref()), s),
            None => subject(x.resource_id.as_deref()),
        };
        (what, x.resource_id.clone().unwrap_or_else(|| x.base.id.clone()))
    }));
    lines
}

impl Resource for AdvisorRecommendationRow {
    arm_row!("Advisor recommendation");
    /// A recommendation's own id is no portal page: the resource's is, and
    /// it has an Advisor blade.
    fn portal_url(&self) -> Option<String> {
        crate::azure::resource::portal_url_for(self.resource_id.as_deref().unwrap_or(&self.base.id), self.base.tenant.as_deref())
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `vm-jump-01 · Cost · 1,260 EUR a year`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([Some(subject(self.resource_id.as_deref())), self.category_label(), self.savings()])
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    /// Security recommendations are Defender's, relayed: the Defender tab
    /// lists them already. `a` shows them.
    fn is_noise(&self) -> bool {
        self.is_security()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ADVISOR_RECOMMENDATION_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.base.name,
            self.resource_id.as_deref().unwrap_or(""),
            self.category_label().unwrap_or_default(),
            self.control.as_deref().unwrap_or(""),
            self.impact.as_deref().unwrap_or("")
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Category".into(), json::opt(self.category_label())),
            ("Impact".into(), json::opt(self.impact.clone())),
            ("Resource".into(), json::opt(self.resource_id.clone())),
            ("Type".into(), json::opt(self.type_id.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(r) = self.resource_id.as_deref().filter(|r| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(r))) {
            v.push((format!("About {}", name_of_id(r)), r.to_string()));
        }
        if let Some(d) = self.defender_source() {
            v.push(("Defender recommendation".into(), d.to_string()));
        }
        v
    }
    /// `az advisor recommendation list` has no `show`; `--ids` narrows it
    /// to the resource. A subscription-wide one narrows by category
    /// (the CLI's `--category` knows four of the five).
    fn cli_command(&self) -> Option<String> {
        let on_sub = subject(self.resource_id.as_deref()) == "subscription";
        match (&self.resource_id, on_sub) {
            (Some(r), false) => Some(format!("az advisor recommendation list --ids {}", shell_quote(r))),
            _ => {
                let cat = self
                    .category
                    .as_deref()
                    .filter(|c| ["Cost", "HighAvailability", "Performance", "Security"].iter().any(|k| k.eq_ignore_ascii_case(c)))
                    .map(|c| format!(" --category {}", c))
                    .unwrap_or_default();
                Some(format!("az advisor recommendation list{}", cat))
            }
        }
    }
}

// ── Score ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdvisorScoreRow {
    pub base: ArmBase,
    /// The category (`Cost`, …) or `Advisor` for the overall score.
    pub category: String,
    /// Percent, 0–100.
    pub score: Option<f64>,
    pub potential: Option<f64>,
    pub impacted: Option<f64>,
    pub date: Option<String>,
    /// The daily history, oldest first.
    pub history: Vec<(String, f64)>,
}

impl AdvisorScoreRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AdvisorScoreRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        let category = base.name.clone();
        base.name = category_words(&category).to_string();
        let f = |p: &str| v.pointer(&format!("/properties/lastRefreshedScore/{}", p)).and_then(Value::as_f64);
        let mut history: Vec<(String, f64)> = json::arr(v, "/properties/timeSeries")
            .iter()
            .find(|t| json::text(t, "/aggregationLevel").eq_ignore_ascii_case("day"))
            .map(|t| {
                json::arr(t, "/scoreHistory")
                    .iter()
                    .filter_map(|h| Some((json::str_at(h, "/date")?, h.get("score")?.as_f64()?)))
                    .collect()
            })
            .unwrap_or_default();
        history.sort_by(|a, b| a.0.cmp(&b.0));
        Some(AdvisorScoreRow {
            score: f("score"),
            potential: f("potentialScoreIncrease"),
            impacted: f("impactedResourceCount"),
            date: json::str_at(v, "/properties/lastRefreshedScore/date"),
            history,
            category,
            base,
        })
    }

    pub fn is_overall(&self) -> bool {
        self.category.eq_ignore_ascii_case("Advisor")
    }

    fn pct(x: Option<f64>) -> String {
        x.map(|x| format!("{:.0}%", x)).unwrap_or_else(|| "-".into())
    }

    /// The change over the daily history: `+4` points, or `None` with
    /// fewer than two days.
    fn trend(&self) -> Option<f64> {
        let (first, last) = (self.history.first()?, self.history.last()?);
        (self.history.len() > 1).then_some(last.1 - first.1)
    }

    pub fn score_rows(&self, now: i64) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Score".into(), Self::pct(self.score)),
            ("Possible gain".into(), self.potential.map(|p| format!("+{:.0}% on the overall score", p)).unwrap_or_else(|| "-".into())),
            ("Impacted".into(), self.impacted.map(|n| format!("{:.0} resource(s)", n)).unwrap_or_else(|| "-".into())),
            ("Computed".into(), time_ago(self.date.as_deref(), now)),
        ];
        if let Some(t) = self.trend() {
            lines.push(("Trend".into(), format!("{:+.0} points over {} days", t, self.history.len())));
        }
        if !self.history.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("━━ History (daily)".into(), String::new()));
            lines.extend(self.history.iter().rev().map(|(d, s)| (d.get(..10).unwrap_or(d).to_string(), format!("{:.0}%", s))));
        }
        lines
    }
}

/// A score row's Recommendations: the warm ones in its category (every
/// non-Security one for the overall score), high impact first.
pub fn score_recommendation_rows(s: &AdvisorScoreRow, recommendations: Warm) -> Vec<(String, String)> {
    let Some(rows) = recommendations.rows() else {
        return waiting(recommendations);
    };
    let mut recs: Vec<&AdvisorRecommendationRow> = recommendations_in(rows)
        .filter(|r| if s.is_overall() { !r.is_security() } else { r.category.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(&s.category)) })
        .collect();
    recs.sort_by_key(|r| impact_rank(r));
    if recs.is_empty() {
        return vec![(String::new(), "No recommendations in this category".into())];
    }
    let mut lines = vec![(String::new(), format!("{} recommendation(s)", recs.len()))];
    lines.extend(recs.into_iter().map(|r| {
        (format!("{} · {} · {}", r.impact.as_deref().unwrap_or("-").to_ascii_lowercase(), r.base.name, subject(r.resource_id.as_deref())), r.base.id.clone())
    }));
    lines
}

impl Resource for AdvisorScoreRow {
    arm_row!("Advisor score");
    /// The subscription's page: a score's id is no portal page.
    fn portal_url(&self) -> Option<String> {
        let sub = subscription_id_of(&self.base.id)?;
        crate::azure::resource::portal_url_for(&sub, self.base.tenant.as_deref())
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `72% · +3% possible · 4 resources`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([
            Some(Self::pct(self.score)),
            self.potential.filter(|p| *p > 0.0).map(|p| format!("+{:.0}% possible", p)),
            self.impacted.filter(|n| *n > 0.0).map(|n| format!("{:.0} resource(s)", n)),
        ])
    }
    fn state(&self) -> ResourceState {
        ResourceState::stateless()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ADVISOR_SCORE_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Score".into(), Self::pct(self.score)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    /// The CLI has no score command.
    fn cli_command(&self) -> Option<String> {
        None
    }
}

// ── Suppressions ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdvisorSuppressionRow {
    pub base: ArmBase,
    /// The suppressed recommendation: the id's parent.
    pub recommendation_id: Option<String>,
    /// What that recommendation is about.
    pub resource_id: Option<String>,
    /// `7.00:00:00`; `-1` (or none) means dismissed for good.
    pub ttl: Option<String>,
    pub expires: Option<String>,
}

impl AdvisorSuppressionRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AdvisorSuppressionRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let lower = base.id.to_ascii_lowercase();
        let recommendation_id = lower.rfind("/suppressions/").map(|at| base.id[..at].to_string());
        let resource_id = recommendation_id.as_deref().and_then(crate::azure::resource::extension_scope).map(str::to_string);
        Some(AdvisorSuppressionRow {
            ttl: json::str_at(v, "/properties/ttl").filter(|t| !t.is_empty()),
            expires: json::str_at(v, "/properties/expirationTimeStamp").filter(|t| !t.is_empty()),
            recommendation_id,
            resource_id,
            base,
        })
    }

    /// Snoozed for a while, or dismissed for good.
    pub fn is_dismissed(&self) -> bool {
        self.ttl.as_deref().is_none_or(|t| t.trim() == "-1")
    }

    /// `7.00:00:00` → `7 days`; `01:00:00` → `1 hour(s)`.
    fn ttl_words(&self) -> String {
        let Some(t) = self.ttl.as_deref().filter(|_| !self.is_dismissed()) else {
            return "for good".into();
        };
        let (days, rest) = t.split_once('.').unwrap_or(("0", t));
        let hours = rest.split(':').next().and_then(|h| h.parse::<u32>().ok()).unwrap_or(0);
        match days.parse::<u32>().unwrap_or(0) {
            0 => format!("{} hour(s)", hours),
            1 => "1 day".into(),
            d => format!("{} days", d),
        }
    }

    pub fn suppression_rows(&self, now: i64) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Kind".into(), if self.is_dismissed() { "dismissed".into() } else { "snoozed".into() }),
            ("For".into(), self.ttl_words()),
            ("Expires".into(), if self.is_dismissed() { "never".into() } else { until(self.expires.as_deref(), now) }),
            ("Resource".into(), subject(self.resource_id.as_deref())),
        ];
        if let Some(r) = &self.resource_id {
            lines.push((String::new(), r.clone()));
        }
        if let Some(r) = &self.recommendation_id {
            lines.push(("Recommendation".into(), r.clone()));
            lines.push((String::new(), "· a suppressed recommendation is not in the Recommendations list until it returns".into()));
        }
        lines
    }
}

impl Resource for AdvisorSuppressionRow {
    arm_row!("Advisor suppression");
    /// A suppression's own id is no portal page: the resource's is, and
    /// it has an Advisor blade.
    fn portal_url(&self) -> Option<String> {
        crate::azure::resource::portal_url_for(self.resource_id.as_deref().unwrap_or(&self.base.id), self.base.tenant.as_deref())
    }
    fn filter_location(&self) -> Option<&str> {
        None
    }
    /// `stcontosoordersprod · 30 days`.
    fn list_summary(&self) -> Option<String> {
        crate::azure::resource::summary_of([Some(subject(self.resource_id.as_deref())), Some(self.ttl_words())])
    }
    fn state(&self) -> ResourceState {
        ResourceState::Stopped
    }
    fn state_label(&self) -> String {
        if self.is_dismissed() { "dismissed" } else { "snoozed" }.into()
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ADVISOR_SUPPRESSION_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!("{} {}", self.base.name, self.resource_id.as_deref().unwrap_or(""))
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Recommendation".into(), json::opt(self.recommendation_id.clone())),
            ("Resource".into(), json::opt(self.resource_id.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(r) = self.resource_id.as_deref().filter(|r| !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(r))) {
            v.push((format!("About {}", name_of_id(r)), r.to_string()));
        }
        v
    }
    /// The CLI has no suppression command.
    fn cli_command(&self) -> Option<String> {
        None
    }
}

// ── Section dispatch ──────────────────────────────────────────────────

/// Every Advisor type's section body, or `None` for another type.
/// `recommendations` is the warm Recommendations list (a recommendation's
/// Resources and a score's Recommendations read it).
pub fn advisor_section_lines(r: &dyn Resource, idx: usize, recommendations: Warm, now: i64) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    let app = crate::azure::services::rendered_by_app;
    if let Some(x) = any.downcast_ref::<AdvisorRecommendationRow>() {
        use AdvisorRecommendationDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Recommendation => x.recommendation_rows(now),
            S::Resources => recommendation_resource_rows(x, recommendations),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    if let Some(x) = any.downcast_ref::<AdvisorScoreRow>() {
        use AdvisorScoreDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Score => x.score_rows(now),
            S::Recommendations => score_recommendation_rows(x, recommendations),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    if let Some(x) = any.downcast_ref::<AdvisorSuppressionRow>() {
        use AdvisorSuppressionDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Suppression => x.suppression_rows(now),
            S::Activity => app(),
            S::Related => related_lines(x.related()),
        });
    }
    None
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct AdvisorService {
    scope: Scope,
}

impl AdvisorService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        fn boxed<T: Resource + 'static>(r: Option<T>) -> Option<Box<dyn Resource>> {
            r.map(|r| Box::new(r) as Box<dyn Resource>)
        }
        page.iter()
            .filter_map(|v| match view {
                JumpView::AdvisorScore => boxed(AdvisorScoreRow::from_json(v, tenant)),
                JumpView::AdvisorSuppressions => boxed(AdvisorSuppressionRow::from_json(v, tenant)),
                _ => boxed(AdvisorRecommendationRow::from_json(v, tenant)),
            })
            .collect()
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str) {
        match view {
            JumpView::AdvisorScore => (SCORE_PATH, "Reading the Advisor score…"),
            JumpView::AdvisorSuppressions => (SUPPRESSIONS_PATH, "Listing Advisor suppressions…"),
            _ => (RECOMMENDATIONS_PATH, "Listing Advisor recommendations…"),
        }
    }
}

#[async_trait]
impl AzureService for AdvisorService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Advisor
    }

    fn name(&self) -> &str {
        "Advisor"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let page = self.scope.list_query(Self::list_of(view).0, ADVISOR_API_VERSION, &[]).await?;
        Ok(Self::rows(view, &page, self.scope.tenant()))
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
            .stream(path, ADVISOR_API_VERSION, &[], service_type, label, &event_tx, |page| Self::rows(view, &page, tenant.as_deref()))
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, ADVISOR_API_VERSION).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::AdvisorRecommendations);
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
    const VM: &str = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1";
    const NOW: i64 = 1_793_000_000;

    fn rec(category: &str, impact: &str, on: &str, type_id: &str) -> Value {
        json!({
            "id": format!("{}/providers/Microsoft.Advisor/recommendations/{}-{}", on, type_id, name_of_id(on)),
            "name": format!("{}-{}", type_id, name_of_id(on)),
            "type": "Microsoft.Advisor/recommendations",
            "properties": {
                "category": category, "impact": impact, "impactedField": "Microsoft.Compute/virtualMachines",
                "impactedValue": name_of_id(on), "recommendationTypeId": type_id, "risk": "Warning",
                "lastUpdated": "2026-10-28T09:00:00Z",
                "shortDescription": {"problem": "Right-size or shut down underutilized virtual machines", "solution": "Right-size or shut down underutilized virtual machines"},
                "resourceMetadata": {"resourceId": on, "singular": "Virtual machine"},
                "extendedProperties": {"annualSavingsAmount": "1260.4", "savingsCurrency": "EUR", "targetSku": "Standard_B2s", "nested": {"x": 1}},
                "learnMoreLink": "https://aka.ms/aa_lowusagerec_learnmore"
            }
        })
    }

    #[test]
    fn a_recommendation_reads_its_impact_savings_and_resource() {
        let r = AdvisorRecommendationRow::from_json(&rec("Cost", "High", VM, "e10b1381"), None).unwrap();
        assert_eq!(r.base.name, "Right-size or shut down underutilized virtual machines");
        assert_eq!(r.state_label(), "high");
        assert_eq!(r.state(), ResourceState::Unavailable);
        assert!(!r.is_noise());
        assert_eq!(r.savings().as_deref(), Some("1,260 EUR a year"));
        assert_eq!(r.list_summary().as_deref(), Some("vm-1 · Cost · 1,260 EUR a year"));
        assert_eq!(r.solution, None, "a solution that repeats the problem is dropped");
        assert_eq!(r.extended.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["annualSavingsAmount", "savingsCurrency", "targetSku"]);
        assert!(r.related().iter().any(|(l, id)| l == "About vm-1" && id == VM));
        assert_eq!(JumpView::for_arm_id(&r.base.id), Some(JumpView::AdvisorRecommendations));
        assert!(is_advisor_id(&r.base.id));
        assert!(r.portal_url().unwrap().ends_with("/resource/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"));
        assert_eq!(r.cli_command().unwrap(), format!("az advisor recommendation list --ids {}", VM));
        let lines = r.recommendation_rows(NOW);
        assert!(lines.iter().any(|(l, v)| l == "Last updated" && v.ends_with("ago)")), "{lines:?}");
        assert!(lines.iter().any(|(l, v)| l == "Resource" && v == "vm-1 (Virtual machine)"));
    }

    #[test]
    fn a_security_recommendation_is_noise_and_links_to_defender() {
        let mut v = rec("Security", "Medium", VM, "abc");
        let assessment = format!("{}/providers/Microsoft.Security/assessments/805651bc", VM);
        v["properties"]["resourceMetadata"]["source"] = json!(assessment);
        let r = AdvisorRecommendationRow::from_json(&v, None).unwrap();
        assert!(r.is_noise());
        assert_eq!(r.state(), ResourceState::Pending);
        assert!(r.related().iter().any(|(l, id)| l == "Defender recommendation" && *id == assessment));
        assert_eq!(JumpView::for_arm_id(&assessment), Some(JumpView::DefenderRecommendations));
    }

    #[test]
    fn a_subscription_wide_recommendation_lists_by_category() {
        let r = AdvisorRecommendationRow::from_json(&rec("HighAvailability", "Low", SUB, "svc"), None).unwrap();
        assert_eq!(r.list_summary().as_deref().map(|s| s.starts_with("subscription · Reliability")), Some(true));
        assert_eq!(r.state(), ResourceState::Stopped);
        assert_eq!(r.cli_command().unwrap(), "az advisor recommendation list --category HighAvailability");
        let ops = AdvisorRecommendationRow::from_json(&rec("OperationalExcellence", "Low", SUB, "svc"), None).unwrap();
        assert_eq!(ops.cli_command().unwrap(), "az advisor recommendation list", "the CLI's --category has no OperationalExcellence");
    }

    #[test]
    fn resources_and_a_score_read_the_warm_list() {
        let vm2 = VM.replace("vm-1", "vm-2");
        let recs: Vec<Box<dyn Resource>> = vec![
            Box::new(AdvisorRecommendationRow::from_json(&rec("Cost", "High", VM, "t1"), None).unwrap()),
            Box::new(AdvisorRecommendationRow::from_json(&rec("Cost", "Low", &vm2, "t1"), None).unwrap()),
            Box::new(AdvisorRecommendationRow::from_json(&rec("Security", "High", VM, "t2"), None).unwrap()),
        ];
        let first = recs[0].as_any().downcast_ref::<AdvisorRecommendationRow>().unwrap();
        let lines = recommendation_resource_rows(first, Warm::Rows(&recs));
        assert_eq!(lines[0].1, "2 resource(s)");
        assert!(lines.iter().any(|(l, id)| l.starts_with("vm-2") && *id == vm2));
        assert_eq!(recommendation_resource_rows(first, Warm::Loading)[0].1, "Loading…");

        let score = |name: &str| {
            AdvisorScoreRow::from_json(
                &json!({"id": format!("{}/providers/Microsoft.Advisor/advisorScore/{}", SUB, name), "name": name,
                    "properties": {"lastRefreshedScore": {"date": "2026-10-28T00:00:00Z", "score": 72.4, "potentialScoreIncrease": 3.1, "impactedResourceCount": 4},
                        "timeSeries": [{"aggregationLevel": "day", "scoreHistory": [
                            {"date": "2026-10-28T00:00:00Z", "score": 72.4}, {"date": "2026-10-21T00:00:00Z", "score": 68.0}]}]}}),
                None,
            )
            .unwrap()
        };
        let cost = score("Cost");
        assert_eq!(cost.base.name, "Cost");
        assert_eq!(cost.list_summary().as_deref(), Some("72% · +3% possible · 4 resource(s)"));
        assert!(cost.score_rows(NOW).iter().any(|(l, v)| l == "Trend" && v == "+4 points over 2 days"));
        assert_eq!(score_recommendation_rows(&cost, Warm::Rows(&recs)).len(), 3, "a count and the two cost rows");
        let overall = score("Advisor");
        assert_eq!(overall.base.name, "Overall");
        assert!(overall.is_overall());
        let lines = score_recommendation_rows(&overall, Warm::Rows(&recs));
        assert_eq!(lines.len(), 3, "security is Defender's: {lines:?}");
        assert_eq!(JumpView::for_arm_id(&cost.base.id), Some(JumpView::AdvisorScore));
    }

    #[test]
    fn a_suppression_names_its_recommendation_and_resource() {
        let rec_id = format!("{}/providers/Microsoft.Advisor/recommendations/r-1", VM);
        let s = |ttl: &str| {
            AdvisorSuppressionRow::from_json(
                &json!({"id": format!("{}/suppressions/snooze-1", rec_id), "name": "snooze-1",
                    "properties": {"suppressionId": "g-1", "ttl": ttl, "expirationTimeStamp": "2026-11-30T00:00:00Z"}}),
                None,
            )
            .unwrap()
        };
        let snoozed = s("30.00:00:00");
        assert_eq!(snoozed.recommendation_id.as_deref(), Some(rec_id.as_str()));
        assert_eq!(snoozed.resource_id.as_deref(), Some(VM));
        assert_eq!(snoozed.state_label(), "snoozed");
        assert_eq!(snoozed.list_summary().as_deref(), Some("vm-1 · 30 days"));
        assert!(snoozed.related().iter().any(|(_, id)| id == VM));
        assert_eq!(JumpView::for_arm_id(&snoozed.base.id), Some(JumpView::AdvisorSuppressions));
        let dismissed = s("-1");
        assert!(dismissed.is_dismissed());
        assert_eq!(dismissed.list_summary().as_deref(), Some("vm-1 · for good"));
    }

    #[test]
    fn thousands_groups_digits() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1260), "1,260");
        assert_eq!(thousands(-1234567), "-1,234,567");
    }

    #[test]
    fn section_labels() {
        let labels = |d: &crate::sections::SectionDescriptor| d.sections.iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(labels(&ADVISOR_RECOMMENDATION_SECTIONS), ["Overview", "Recommendation", "Resources", "Activity", "Related"]);
        assert_eq!(labels(&ADVISOR_SCORE_SECTIONS), ["Overview", "Score", "Recommendations", "Activity", "Related"]);
        assert_eq!(labels(&ADVISOR_SUPPRESSION_SECTIONS), ["Overview", "Suppression", "Activity", "Related"]);
    }
}
