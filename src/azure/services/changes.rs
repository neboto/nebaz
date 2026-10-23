// ported from neboto-tui src/aws/services/changes.rs @ 08fcd0c (adapted:
// the subscription's Activity Log, ARM deployments and Resource Health in
// place of CloudTrail, Config, CloudFormation, CodePipeline / CodeBuild,
// Auto Scaling and RDS; noise from the caller's directory object)
//! `@changes` (#61, ADR 0006): what changed recently, subscription-wide,
//! newest first, over a `[` / `]` window (15m … 7d). A regular service
//! that **fetches** (not a view over warm caches): one list per window,
//! cached per window like any list; the sub-tabs (All / Activity /
//! Deployments / Health) filter it by source without a call.
//!
//! - **Activity**: the subscription's Activity Log through the Activity
//!   section's query, no scope term, collapsed to operations and kept to
//!   the changes (`timeline::is_change_operation`). At most
//!   [`ACTIVITY_PAGES`] pages, newest first; past that a warning says how
//!   far back it got.
//! - **Deployments**: ARM deployments in the window, from the groups the
//!   Activity Log saw a `Microsoft.Resources/deployments` operation in (a
//!   subscription has no deployment list across its groups), at most
//!   [`MAX_DEPLOYMENT_GROUPS`] groups.
//! - **Health**: every resource's current Resource Health status whose
//!   last transition is in the window.
//!
//! Each source streams its batch when done; a failing source is a
//! warning, and only every source failing is the list's error. Resource
//! Graph's `resourcechanges` would be the ideal source, but it is a POST.
//!
//! **Noise** (`a` hides it): Activity rows whose caller is not a person.
//! A caller is a UPN, an object or app id, or a service name; an id is
//! looked up in Microsoft Graph (ADR 0004, at most [`MAX_CALLER_LOOKUPS`]):
//! a managed identity or an app Microsoft owns is noise, the tenant's own
//! apps (a CI pipeline) are not. A service name or no caller is the
//! platform, noise too. Deployments and health are never noise.

use crate::azure::arm::ArmClient;
use crate::azure::resource::{name_of_id, resource_group_of, shell_quote, state_ladder, subscription_of, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::activity::{activity_query_since, ACTIVITY_API_VERSION};
use crate::azure::services::{overview_rows, related_lines, Scope};
use crate::azure::timeline::{
    activity_rows, caller_kind, deployment_rows, health_rows, now_secs, principal_noise, rg_deployments_path,
    subscription_health_path, CallerKind, TimelineRow, TimelineSource, DEPLOYMENTS_API_VERSION, HEALTH_API_VERSION,
};
use crate::error::{Error, Result};
use crate::event::{Event, LoadProgress};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Activity Log pages per load: a busy subscription's week is thousands
/// of pages, and the question is "just before this started".
pub const ACTIVITY_PAGES: usize = 10;

/// Resource Health pages per load (every resource's current status).
pub const HEALTH_PAGES: usize = 20;

/// Callers looked up in the directory per load.
pub const MAX_CALLER_LOOKUPS: usize = 50;

/// Resource groups whose deployment history is read per load…
pub const MAX_DEPLOYMENT_GROUPS: usize = 20;

/// …and deployments per group (the history is newest first by default,
/// not guaranteed: the window filter keeps the answer right).
pub const MAX_DEPLOYMENTS_PER_GROUP: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChangesWindow {
    FifteenMinutes,
    #[default]
    OneHour,
    SixHours,
    OneDay,
    SevenDays,
}

impl ChangesWindow {
    pub const ALL: [ChangesWindow; 5] = [
        ChangesWindow::FifteenMinutes,
        ChangesWindow::OneHour,
        ChangesWindow::SixHours,
        ChangesWindow::OneDay,
        ChangesWindow::SevenDays,
    ];

    pub fn secs(self) -> i64 {
        match self {
            ChangesWindow::FifteenMinutes => 900,
            ChangesWindow::OneHour => 3600,
            ChangesWindow::SixHours => 6 * 3600,
            ChangesWindow::OneDay => 86_400,
            ChangesWindow::SevenDays => 7 * 86_400,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ChangesWindow::FifteenMinutes => "15m",
            ChangesWindow::OneHour => "1h",
            ChangesWindow::SixHours => "6h",
            ChangesWindow::OneDay => "24h",
            ChangesWindow::SevenDays => "7d",
        }
    }

    /// The list cache's variant: one list per window.
    pub fn variant(self) -> &'static str {
        match self {
            ChangesWindow::FifteenMinutes => "changes-15m",
            ChangesWindow::OneHour => "changes-1h",
            ChangesWindow::SixHours => "changes-6h",
            ChangesWindow::OneDay => "changes-24h",
            ChangesWindow::SevenDays => "changes-7d",
        }
    }

    pub fn wider(self) -> Self {
        let i = Self::ALL.iter().position(|w| *w == self).unwrap_or(0);
        Self::ALL[(i + 1).min(Self::ALL.len() - 1)]
    }

    pub fn narrower(self) -> Self {
        let i = Self::ALL.iter().position(|w| *w == self).unwrap_or(0);
        Self::ALL[i.saturating_sub(1)]
    }

    /// `--since`: a window's label (`15m`, `1h`, `6h`, `24h`, `7d`) or
    /// the same span spelled another way (`1d`, `60m`, `168h`).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_lowercase();
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
        let n: i64 = num.parse().ok()?;
        let secs = n * match unit {
            "m" | "min" | "mins" => 60,
            "h" | "hr" | "hrs" => 3600,
            "d" | "day" | "days" => 86_400,
            "w" => 7 * 86_400,
            _ => return None,
        };
        Self::ALL.into_iter().find(|w| w.secs() == secs)
    }
}

crate::sections! {
    pub enum ChangeDetailSection,
    pub static CHANGE_SECTIONS = [
        Overview "Overview",
        Related "Related",
    ]
}

/// One change: a timeline row with its noise verdict.
#[derive(Debug, Clone)]
pub struct ChangeRow {
    pub row: TimelineRow,
    /// `change:{source key}`: unique per row, never an ARM id (the row is
    /// an event; its resource is in Related).
    pub id: String,
    pub display: String,
    /// Why this is noise (`a` hides it), when it is.
    pub noise: Option<String>,
    pub tenant: Option<String>,
    tags: HashMap<String, String>,
}

impl ChangeRow {
    pub fn new(row: TimelineRow, noise: Option<String>, tenant: Option<String>) -> Self {
        let display = if row.subject.is_empty() { row.what.clone() } else { format!("{}  {}", row.what, row.subject) };
        ChangeRow { id: format!("change:{}", row.key), display, row, noise, tenant, tags: HashMap::new() }
    }

    fn ladder(&self) -> (ResourceState, String) {
        state_ladder(self.row.failed.then_some("Failed"), None)
    }
}

impl Resource for ChangeRow {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.display
    }
    fn resource_type(&self) -> &str {
        self.row.source().kind()
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CHANGE_SECTIONS)
    }
    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }
    fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
    /// The resource it happened to: `rg:` filters by it.
    fn resource_group(&self) -> Option<&str> {
        self.row.target.as_deref().and_then(resource_group_of)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.display,
            self.row.who,
            self.row.detail,
            self.row.target.as_deref().unwrap_or(""),
            self.row.source().label(),
            self.row.status
        )
    }
    fn list_summary(&self) -> Option<String> {
        let who = if self.row.who.is_empty() { "-" } else { &self.row.who };
        Some(format!("{} · {}", self.row.time, who))
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut d = self.row.fields.clone();
        if let Some(reason) = &self.noise {
            d.push(("Noise".into(), format!("{} (a hides it)", reason)));
        }
        d
    }
    fn is_noise(&self) -> bool {
        self.noise.is_some()
    }
    fn related(&self) -> Vec<(String, String)> {
        self.row.links.clone()
    }
    /// The read command for the change itself: the operation's events, or
    /// the deployment. Health has none (`az rest` is not a read verb).
    fn cli_command(&self) -> Option<String> {
        let field = |k: &str| self.row.fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.clone());
        match self.row.source() {
            TimelineSource::Activity => {
                let corr = field("Correlation id").filter(|c| c != "-")?;
                let sub = self.row.target.as_deref().and_then(subscription_of)?;
                Some(format!(
                    "az monitor activity-log list --correlation-id {} --subscription {}",
                    shell_quote(&corr),
                    shell_quote(sub)
                ))
            }
            TimelineSource::Deployment => {
                let id = field("Id")?;
                let rg = resource_group_of(&id)?;
                Some(format!(
                    "az deployment group show -g {} -n {} --subscription {}",
                    shell_quote(rg),
                    shell_quote(name_of_id(&id)),
                    shell_quote(subscription_of(&id)?)
                ))
            }
            _ => None,
        }
    }
    fn portal_url(&self) -> Option<String> {
        self.row.target.as_deref().and_then(|t| crate::azure::resource::portal_url_for(t, self.tenant.as_deref()))
    }
    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub fn change_section_lines(r: &ChangeRow, section: ChangeDetailSection) -> Vec<(String, String)> {
    match section {
        ChangeDetailSection::Overview => overview_rows(r),
        ChangeDetailSection::Related => related_lines(r.related()),
    }
}

/// Whether sub-tab `view` shows `r`: every row outside `@changes`, every
/// change under All, one source under the others.
pub fn view_admits(view: JumpView, r: &dyn Resource) -> bool {
    let Some(c) = r.as_any().downcast_ref::<ChangeRow>() else {
        return true;
    };
    match view {
        JumpView::ChangesActivity => c.row.source() == TimelineSource::Activity,
        JumpView::ChangesDeployments => c.row.source() == TimelineSource::Deployment,
        JumpView::ChangesHealth => c.row.source() == TimelineSource::Health,
        _ => true,
    }
}

/// A change row's time, for the newest-first default sort.
pub fn time_of(r: &dyn Resource) -> Option<i64> {
    r.as_any().downcast_ref::<ChangeRow>().map(|c| c.row.ts_secs)
}

/// What a change row is about (the `W` timeline opens on it).
pub fn target_of(r: &dyn Resource) -> Option<String> {
    r.as_any().downcast_ref::<ChangeRow>().and_then(|c| c.row.target.clone())
}

// ── Noise ───────────────────────────────────────────────────────────────

/// Each caller's noise verdict, from the string and, for an id, its
/// directory object. Returns the verdicts and a warning when the
/// directory could not be read.
async fn classify_callers(
    graph: &std::result::Result<Arc<ArmClient>, String>,
    callers: BTreeSet<String>,
) -> (HashMap<String, Option<String>>, Option<String>) {
    let mut verdicts: HashMap<String, Option<String>> = HashMap::new();
    let mut ids = Vec::new();
    for c in callers {
        match caller_kind(&c) {
            CallerKind::Person => {
                verdicts.insert(c, None);
            }
            CallerKind::Platform => {
                verdicts.insert(c, Some("Azure platform".into()));
            }
            CallerKind::Principal => ids.push(c),
        }
    }
    if ids.is_empty() {
        return (verdicts, None);
    }
    let graph = match graph {
        Ok(g) => g.clone(),
        Err(e) => return (verdicts, Some(format!("callers not classified: {}", e))),
    };
    let skipped = ids.len().saturating_sub(MAX_CALLER_LOOKUPS);
    let mut tasks = tokio::task::JoinSet::new();
    for id in ids.into_iter().take(MAX_CALLER_LOOKUPS) {
        let graph = graph.clone();
        tasks.spawn(async move {
            let verdict = lookup_principal(&graph, &id).await;
            (id, verdict)
        });
    }
    let mut denied = false;
    while let Some(joined) = tasks.join_next().await {
        let Ok((id, verdict)) = joined else { continue };
        match verdict {
            Ok(v) => {
                verdicts.insert(id, v.map(str::to_string));
            }
            Err(e) => denied |= crate::azure::graph::is_denied(&e),
        }
    }
    let warning = if denied {
        Some("callers not classified: directory read not allowed for this account".into())
    } else if skipped > 0 {
        Some(format!("{} callers not classified (the first {} were)", skipped, MAX_CALLER_LOOKUPS))
    } else {
        None
    };
    (verdicts, warning)
}

/// An object id first, then an app id: the log names a principal either
/// way. A caller in neither is not noise.
async fn lookup_principal(graph: &ArmClient, id: &str) -> std::result::Result<Option<&'static str>, String> {
    let paths = [
        crate::azure::graph::directory_object_path(id),
        crate::azure::graph::service_principal_by_app_id_path(id),
    ];
    for path in paths.into_iter().flatten() {
        match graph.graph_get(&path, &[]).await {
            Ok(v) => return Ok(principal_noise(&v)),
            Err(e) => {
                let e = e.to_string();
                if !crate::azure::graph::is_not_found(&e) {
                    return Err(e);
                }
            }
        }
    }
    Ok(None)
}

/// The groups (and the subscription itself, `None`) the log saw a
/// deployment operation in.
pub fn deployment_scopes(events: &[Value]) -> BTreeSet<Option<String>> {
    events
        .iter()
        .filter(|e| {
            crate::azure::services::json::text(e, "/operationName/value")
                .to_lowercase()
                .starts_with("microsoft.resources/deployments/")
        })
        .filter_map(|e| crate::azure::services::json::str_at(e, "/resourceId"))
        .map(|id| resource_group_of(&id).map(|rg| rg.to_lowercase()))
        .collect()
}

// ── The provider ────────────────────────────────────────────────────────

pub struct ChangesService {
    scope: Scope,
    graph: std::result::Result<Arc<ArmClient>, String>,
    window: ChangesWindow,
}

impl ChangesService {
    pub fn new(scope: Scope, graph: std::result::Result<Arc<ArmClient>, String>, window: ChangesWindow) -> Self {
        Self { scope, graph, window }
    }

    /// The Activity Log, capped: the events and, past the cap, how far
    /// back they reach.
    async fn activity(&self, arm: &ArmClient, sub: &str, since: i64) -> Result<(Vec<Value>, Option<i64>)> {
        let path = format!("/subscriptions/{}/providers/Microsoft.Insights/eventtypes/management/values", sub);
        let query = activity_query_since(&format!("/subscriptions/{}", sub), since);
        let pairs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let mut events = Vec::new();
        let mut pages = 0usize;
        arm.list_pages_while(&path, ACTIVITY_API_VERSION, &pairs, |page| {
            pages += 1;
            events.extend(page);
            pages < ACTIVITY_PAGES
        })
        .await?;
        let reach = (pages >= ACTIVITY_PAGES).then(|| {
            events
                .iter()
                .filter_map(|e| crate::azure::services::json::str_at(e, "/eventTimestamp"))
                .filter_map(|t| crate::azure::timeline::parse_ts(&t))
                .min()
                .unwrap_or(since)
        });
        Ok((events, reach))
    }

    async fn health(&self, arm: &ArmClient, sub: &str) -> Result<(Vec<Value>, bool)> {
        let mut items = Vec::new();
        let mut pages = 0usize;
        arm.list_pages_while(&subscription_health_path(sub), HEALTH_API_VERSION, &[], |page| {
            pages += 1;
            items.extend(page);
            pages < HEALTH_PAGES
        })
        .await?;
        Ok((items, pages >= HEALTH_PAGES))
    }

    /// Every scope's deployments, concurrently; the failures as warnings.
    async fn deployments(
        &self,
        arm: &Arc<ArmClient>,
        sub: &str,
        scopes: BTreeSet<Option<String>>,
    ) -> (Vec<Value>, Vec<String>) {
        let mut warnings = Vec::new();
        if scopes.len() > MAX_DEPLOYMENT_GROUPS {
            warnings.push(format!(
                "Deployments: {} resource groups had deployments, the first {} read",
                scopes.len(),
                MAX_DEPLOYMENT_GROUPS
            ));
        }
        let mut tasks = tokio::task::JoinSet::new();
        for scope in scopes.into_iter().take(MAX_DEPLOYMENT_GROUPS) {
            let path = match &scope {
                Some(rg) => rg_deployments_path(sub, rg),
                None => format!("/subscriptions/{}/providers/Microsoft.Resources/deployments", sub),
            };
            let arm = arm.clone();
            tasks.spawn(async move {
                let mut items = Vec::new();
                let r = arm
                    .list_pages_while(&path, DEPLOYMENTS_API_VERSION, &[], |page| {
                        items.extend(page);
                        items.len() < MAX_DEPLOYMENTS_PER_GROUP
                    })
                    .await;
                (scope, r.map(|_| items))
            });
        }
        let mut all = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((scope, result)) = joined else { continue };
            match result {
                Ok(items) => all.extend(items),
                Err(e) => failed.push(format!("{}: {}", scope.as_deref().unwrap_or("subscription"), short(&e.to_string()))),
            }
        }
        if !failed.is_empty() {
            failed.sort();
            warnings.push(format!("Deployments unread in {} (first: {})", failed.len(), failed[0]));
        }
        (all, warnings)
    }
}

fn short(e: &str) -> String {
    let first = e.lines().next().unwrap_or(e);
    if first.chars().count() > 160 {
        format!("{}…", first.chars().take(160).collect::<String>())
    } else {
        first.to_string()
    }
}

/// Stream one source's rows as a batch.
fn batch(tx: &mpsc::UnboundedSender<Event>, service: ServiceType, loaded: &AtomicUsize, rows: Vec<ChangeRow>, message: &str) {
    let total = loaded.fetch_add(rows.len(), Ordering::Relaxed) + rows.len();
    let resources: Vec<Box<dyn Resource>> = rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect();
    let _ = tx.send(Event::ResourcesPartiallyLoaded {
        service,
        resources,
        progress: LoadProgress { loaded_count: total, total_count: None, status_message: Some(message.into()) },
    });
}

#[async_trait]
impl AzureService for ChangesService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Changes
    }

    fn name(&self) -> &str {
        "Changes"
    }

    /// The whole list (headless): the stream, collected.
    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.list_resources_streaming(view, tx, ServiceType::Changes).await?;
        let mut all = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let Event::ResourcesPartiallyLoaded { resources, .. } = ev {
                all.extend(resources);
            }
        }
        Ok(all)
    }

    /// Every source, whatever the sub-tab: the sub-tabs filter one list.
    async fn list_resources_streaming(
        &self,
        _view: JumpView,
        tx: mpsc::UnboundedSender<Event>,
        service: ServiceType,
    ) -> Result<()> {
        let (arm, sub) = match (self.scope.arm(), self.scope.current()) {
            (Ok(arm), Ok(entry)) => (arm.clone(), entry.id.clone()),
            (Err(e), _) | (_, Err(e)) => return crate::azure::services::finish_stream(service, Err(e), &tx),
        };
        let tenant = self.scope.tenant().map(str::to_string);
        let since = now_secs() - self.window.secs();
        let loaded = AtomicUsize::new(0);

        // Activity (then the deployments it points at) and health at once;
        // each source's batch streams as soon as it is done.
        let activity_then_deployments = async {
            let mut warns = Vec::new();
            let (events, reach) = match self.activity(&arm, &sub, since).await {
                Ok(r) => r,
                Err(e) => return (Err(e), warns),
            };
            if let Some(reach) = reach {
                warns.push(format!(
                    "Activity Log: stopped after {} pages, back to {} UTC; [ narrows the window",
                    ACTIVITY_PAGES,
                    crate::azure::services::json::unix_to_ymdhm(reach)
                ));
            }
            let rows = activity_rows(&events, since, false);
            let callers: BTreeSet<String> = rows.iter().map(|r| r.caller.clone()).collect();
            let (verdicts, warn) = classify_callers(&self.graph, callers).await;
            warns.extend(warn);
            let rows = rows
                .into_iter()
                .map(|r| {
                    let noise = verdicts.get(&r.caller).cloned().flatten();
                    ChangeRow::new(r, noise, tenant.clone())
                })
                .collect();
            batch(&tx, service, &loaded, rows, "Activity Log");
            let (items, dep_warns) = self.deployments(&arm, &sub, deployment_scopes(&events)).await;
            warns.extend(dep_warns);
            let deps =
                deployment_rows(&items, since, None).into_iter().map(|r| ChangeRow::new(r, None, tenant.clone())).collect();
            batch(&tx, service, &loaded, deps, "deployments");
            (Ok(()), warns)
        };
        let health = async {
            let (items, capped) = self.health(&arm, &sub).await?;
            let rows = health_rows(&items, since).into_iter().map(|r| ChangeRow::new(r, None, tenant.clone())).collect();
            batch(&tx, service, &loaded, rows, "Resource Health");
            Ok::<bool, Error>(capped)
        };
        let ((activity, mut warnings), health) = tokio::join!(activity_then_deployments, health);
        let health_err = match health {
            Ok(capped) => {
                if capped {
                    warnings.push(format!(
                        "Resource Health: the first {} pages of statuses read; some resources not checked",
                        HEALTH_PAGES
                    ));
                }
                None
            }
            Err(e) => Some(e),
        };
        match (activity, health_err) {
            // Nothing could stream: the list's error is the Activity Log's.
            (Err(e), Some(_)) => crate::azure::services::finish_stream(service, Err(e), &tx),
            (activity, health_err) => {
                if let Err(e) = activity {
                    warnings.push(format!("Activity Log (and so deployments): {}", short(&e.to_string())));
                }
                if let Some(e) = health_err {
                    warnings.push(format!("Resource Health: {}", short(&e.to_string())));
                }
                for warning in warnings {
                    let _ = tx.send(Event::ResourceLoadWarning { service, warning });
                }
                crate::azure::services::finish_stream(service, Ok(loaded.into_inner()), &tx)
            }
        }
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        Err(Error::InvalidConfig(format!("{} is a change, not a resource", id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::timeline::tests::{deployment, event, health, VM};
    use crate::azure::timeline::{health_rows, TimelineRow};

    fn change(row: TimelineRow, noise: Option<&str>) -> ChangeRow {
        ChangeRow::new(row, noise.map(str::to_string), None)
    }

    #[test]
    fn windows_step_and_parse() {
        assert_eq!(ChangesWindow::default(), ChangesWindow::OneHour);
        assert_eq!(ChangesWindow::FifteenMinutes.narrower(), ChangesWindow::FifteenMinutes);
        assert_eq!(ChangesWindow::OneDay.wider().wider(), ChangesWindow::SevenDays);
        assert_eq!(ChangesWindow::parse("6h"), Some(ChangesWindow::SixHours));
        assert_eq!(ChangesWindow::parse("1d"), Some(ChangesWindow::OneDay));
        assert_eq!(ChangesWindow::parse("15M"), Some(ChangesWindow::FifteenMinutes));
        assert_eq!(ChangesWindow::parse("1w"), Some(ChangesWindow::SevenDays));
        assert_eq!(ChangesWindow::parse("2h"), None);
        assert_eq!(ChangesWindow::parse("h"), None);
        let variants: BTreeSet<&str> = ChangesWindow::ALL.iter().map(|w| w.variant()).collect();
        assert_eq!(variants.len(), ChangesWindow::ALL.len(), "one cache entry per window");
    }

    #[test]
    fn a_change_row_names_what_happened_to_what_and_links_to_it() {
        let rows = activity_rows(
            &[event("2026-10-20T10:00:00Z", "c1", "Microsoft.Compute/virtualMachines/write", "Failed", "ops@x.com")],
            0,
            false,
        );
        let r = change(rows[0].clone(), None);
        assert_eq!(r.name(), "Microsoft.Compute/virtualMachines/write  vm1");
        assert_eq!(r.resource_type(), "Activity Log");
        assert_eq!(r.state_label(), "failed");
        assert_eq!(r.list_cell(), "2026-10-20 10:00 · ops@x.com");
        assert_eq!(r.resource_group(), Some("rg-app"));
        assert!(r.id().starts_with("change:act:c1:"));
        assert_eq!(r.related(), vec![("Resource · vm1".to_string(), VM.to_string())]);
        assert_eq!(target_of(&r).as_deref(), Some(VM));
        assert_eq!(
            r.cli_command().unwrap(),
            "az monitor activity-log list --correlation-id c1 --subscription 0000"
        );
        let labels: Vec<&str> = CHANGE_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Related"]);
    }

    #[test]
    fn noise_is_classification_and_sub_tabs_filter_by_source() {
        let act = change(
            activity_rows(&[event("2026-10-20T10:00:00Z", "c1", "x/write", "Succeeded", "Microsoft.Advisor")], 0, false)[0]
                .clone(),
            Some("Azure platform"),
        );
        assert!(act.is_noise());
        assert!(act.details().iter().any(|(k, v)| k == "Noise" && v.starts_with("Azure platform")));
        let dep = change(
            deployment_rows(&[deployment("main", "2026-10-20T07:00:00Z", "Succeeded", &[VM])], 0, None)[0].clone(),
            None,
        );
        assert!(!dep.is_noise());
        assert_eq!(
            dep.cli_command().unwrap(),
            "az deployment group show -g rg-app -n main --subscription 0000"
        );
        let hl = change(health_rows(&[health("2026-10-20T09:00:00Z", "Degraded", true)], 0)[0].clone(), None);
        assert!(hl.cli_command().is_none());
        for (view, admitted) in [
            (JumpView::ChangesAll, [true, true, true]),
            (JumpView::ChangesActivity, [true, false, false]),
            (JumpView::ChangesDeployments, [false, true, false]),
            (JumpView::ChangesHealth, [false, false, true]),
        ] {
            let got = [view_admits(view, &act), view_admits(view, &dep), view_admits(view, &hl)];
            assert_eq!(got, admitted, "{view:?}");
        }
    }

    #[test]
    fn deployment_scopes_come_from_the_log() {
        let mut dep = event("2026-10-20T10:00:00Z", "c1", "Microsoft.Resources/deployments/write", "Succeeded", "a@x.com");
        dep["resourceId"] = "/subscriptions/0000/resourceGroups/RG-App/providers/Microsoft.Resources/deployments/main".into();
        let mut sub_dep = dep.clone();
        sub_dep["resourceId"] = "/subscriptions/0000/providers/Microsoft.Resources/deployments/policy".into();
        let other = event("2026-10-20T10:00:00Z", "c2", "Microsoft.Compute/virtualMachines/write", "Succeeded", "a@x.com");
        let scopes = deployment_scopes(&[dep, sub_dep, other]);
        assert_eq!(scopes, BTreeSet::from([None, Some("rg-app".to_string())]));
    }

    #[tokio::test]
    async fn callers_split_into_people_platform_and_principals() {
        let callers = BTreeSet::from(["ops@x.com".to_string(), "Microsoft.Advisor".to_string(), String::new()]);
        let (verdicts, warning) = classify_callers(&Err("no graph".into()), callers).await;
        assert_eq!(verdicts["ops@x.com"], None);
        assert_eq!(verdicts["Microsoft.Advisor"].as_deref(), Some("Azure platform"));
        assert_eq!(verdicts[""].as_deref(), Some("Azure platform"));
        assert!(warning.is_none(), "no id to look up, no directory needed");
        let ids = BTreeSet::from(["1b2c3d4e-0000-4000-8000-0123456789ab".to_string()]);
        let (verdicts, warning) = classify_callers(&Err("no graph".into()), ids).await;
        assert!(verdicts.is_empty(), "an unclassified principal is not noise");
        assert_eq!(warning.as_deref(), Some("callers not classified: no graph"));
    }
}
