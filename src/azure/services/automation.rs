//! Azure Automation (#202, SERVICES.md rule 44): the Automation tab, one
//! subscription-wide list of `Microsoft.Automation/automationAccounts`.
//! An account's runbooks, schedules (with the job schedules that tie them
//! to runbooks), recent jobs, hybrid worker groups (and each group's
//! workers) and linked workspace are lazy, read when a section opens.
//!
//! Stricter than usual: the account's variables, credentials,
//! certificates and connections are never read, though most are GETs (an
//! unencrypted variable's value comes back in its body), and neither is a
//! runbook's content, a job's output or streams, or a DSC configuration's
//! script; the guard names those paths. A runbook's content links and
//! parameter defaults and a job schedule's parameters are removed before
//! the store keeps a body ([`without_secrets`]). Starting, stopping and
//! publishing are POSTs and PUTs.

use crate::azure::arm::ArmClient;
use crate::azure::metrics::iso_utc;
use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::directory::iso_to_unix;
use crate::azure::services::{
    arm_row, error_rows, finish_stream, json, lazy_list_rows, overview_rows, related_rows_with, tag_rows, ArmBase,
    Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;

/// The newest stable version (azure-rest-api-specs, the spec last
/// touched 2026-09-18, checked 2026-11-07).
pub const AUTOMATION_API_VERSION: &str = "2024-10-23";
const ACCOUNTS_PATH: &str = "/providers/Microsoft.Automation/automationAccounts";

/// How far back Jobs reads, and the most it keeps.
pub const JOB_WINDOW_DAYS: i64 = 7;
pub const MAX_JOBS: usize = 200;
/// How many jobs the section lists (the counts cover them all).
const JOBS_SHOWN: usize = 25;
/// Worker groups whose workers are read; the rest are counted.
pub const MAX_WORKER_GROUPS: usize = 25;
/// A worker not heard from for longer than this is ⚠.
const WORKER_STALE_SECS: i64 = 86_400;

const NEVER_SECRETS: &str =
    "metadata from ARM; variables, credentials, certificates, connections, runbook content and job output are never fetched";

crate::sections! {
    pub enum AutomationDetailSection,
    pub static AUTOMATION_SECTIONS = [
        Overview "Overview",
        Runbooks "Runbooks" => crate::app::App::trigger_aa_runbooks,
        Schedules "Schedules" => crate::app::App::trigger_aa_schedules,
        Jobs "Jobs" => crate::app::App::trigger_aa_jobs,
        Workers "Hybrid workers" => crate::app::App::trigger_aa_workers,
        Configuration "Configuration",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_aa_related,
        Tags "Tags",
    ]
}

// ── Credentials out ───────────────────────────────────────────────────

/// Removed wherever they sit: a runbook's published and draft content
/// links (a storage URL, sometimes with a SAS), its parameter defaults,
/// and the values a job schedule passes.
const SECRET_FIELDS: &[&str] = &["publishContentLink", "draftContentLink", "draft", "parameters"];

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

/// The body with the fields above removed: what a row parses and keeps
/// for `e`, and what each lazy list stores.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

/// `{account}/{child}` for the child lists.
pub fn account_child_path(account_id: &str, child: &str) -> String {
    format!("{}/{}", account_id.trim_end_matches('/'), child)
}

/// The Jobs read's `$filter`: jobs started in the window before `now`.
pub fn jobs_filter(now: i64) -> String {
    format!("properties/startTime ge {}", iso_utc(now - JOB_WINDOW_DAYS * 86_400))
}

// ── The row ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AutomationAccountRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub account_state: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub description: Option<String>,
    pub public_network_access: Option<bool>,
    pub disable_local_auth: Option<bool>,
    pub key_source: Option<String>,
    pub key_name: Option<String>,
    pub key_vault_uri: Option<String>,
    pub encryption_identity: Option<String>,
    pub hybrid_service_url: Option<String>,
    /// `(endpoint id, status)` of each inbound private endpoint.
    pub private_endpoints: Vec<(String, Option<String>)>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
}

impl AutomationAccountRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<AutomationAccountRow> {
        let v = &without_secrets(raw);
        let mut base = ArmBase::from_json(v, tenant)?;
        // A display-name location (`West Europe`) collapses to the short one.
        base.location = base.location.replace(' ', "");
        let p = |f: &str| format!("/properties/{}", f);
        Some(AutomationAccountRow {
            sku: json::str_at(v, &p("sku/name")),
            account_state: json::str_at(v, &p("state")),
            created: json::str_at(v, &p("creationTime")),
            modified: json::str_at(v, &p("lastModifiedTime")),
            description: json::str_at(v, &p("description")).filter(|s| !s.is_empty()),
            public_network_access: json::bool_at(v, &p("publicNetworkAccess")),
            disable_local_auth: json::bool_at(v, &p("disableLocalAuth")),
            key_source: json::str_at(v, &p("encryption/keySource")),
            key_name: json::str_at(v, &p("encryption/keyVaultProperties/keyName")),
            key_vault_uri: json::str_at(v, &p("encryption/keyVaultProperties/keyvaultUri")),
            encryption_identity: json::arm_id(json::str_at(v, &p("encryption/identity/userAssignedIdentity"))),
            hybrid_service_url: json::str_at(v, &p("automationHybridServiceUrl")),
            private_endpoints: json::arr(v, &p("privateEndpointConnections"))
                .iter()
                .filter_map(|c| {
                    Some((
                        json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                        json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
                    ))
                })
                .collect(),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    /// Provisioning first, then the account's own `state`: `Ok` is the
    /// healthy word; `Suspended` (a subscription problem) and
    /// `Unavailable` are trouble.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.account_state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "ok" => ResourceState::Available,
                "suspended" | "unavailable" => ResourceState::Unavailable,
                _ => ResourceState::Unknown(s.to_lowercase()),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// `--automation-account-name {n} -g {rg} --subscription {sub}`: the
    /// child lists take the account by name.
    fn child_args(&self) -> Option<String> {
        Some(format!(
            "--automation-account-name {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }

    fn read_command(&self, command: &str) -> (String, String) {
        ("Read command".into(), format!("{} {}", command, self.child_args().unwrap_or_default()))
    }

    pub fn local_auth_text(&self) -> String {
        match self.disable_local_auth {
            Some(true) => "off (Entra ID only)".into(),
            _ => "on (webhooks and agent keys work)".into(),
        }
    }

    fn configuration_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Local auth".into(), self.local_auth_text()),
            (
                "Public network access".into(),
                match self.public_network_access {
                    Some(false) => "disabled".into(),
                    _ => "enabled".into(),
                },
            ),
            ("Encryption".into(), json::opt(self.key_source.clone())),
        ];
        if let Some(k) = &self.key_name {
            lines.push(("Key".into(), format!("{} in {}", k, json::opt(self.key_vault_uri.clone()))));
        }
        if let Some(id) = &self.encryption_identity {
            lines.push((format!("Encryption identity · {}", name_of_id(id)), id.clone()));
        }
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        for id in &self.user_identity_ids {
            lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
        }
        lines.push(("Hybrid service URL".into(), json::opt(self.hybrid_service_url.clone())));
        for (pe, status) in &self.private_endpoints {
            lines.push((format!("Private endpoint · {} ({})", name_of_id(pe), json::opt(status.clone())), pe.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), NEVER_SECRETS.into()));
        lines
    }
}

impl Resource for AutomationAccountRow {
    arm_row!("Automation account");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&AUTOMATION_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        self.sku.clone()
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("State".into(), json::opt(self.account_state.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Created".into(), json::time(self.created.clone())),
            ("Modified".into(), json::time(self.modified.clone())),
            ("Description".into(), json::opt(self.description.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for pe in self.private_endpoints.iter().map(|(id, _)| id) {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for id in self.user_identity_ids.iter().chain(self.encryption_identity.iter()) {
            if !v.iter().any(|(_, existing)| existing == id) {
                v.push((format!("Identity {}", name_of_id(id)), id.clone()));
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az automation account show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── The lazy reads ────────────────────────────────────────────────────

/// The Hybrid workers read: each group with its workers (or why they did
/// not list), for the first [`MAX_WORKER_GROUPS`].
#[derive(Debug, Clone, Default)]
pub struct WorkerGroups {
    pub groups: Vec<(Value, std::result::Result<Vec<Value>, String>)>,
    pub skipped: usize,
}

/// `{account}/hybridRunbookWorkerGroups`, then each group's
/// `hybridRunbookWorkers`. A failed worker list stays on its group.
pub async fn fetch_worker_groups(
    arm: std::result::Result<Arc<ArmClient>, String>,
    account_id: String,
) -> std::result::Result<WorkerGroups, String> {
    let arm = arm?;
    let groups_path = format!("{}/hybridRunbookWorkerGroups", account_id.trim_end_matches('/'));
    let groups = arm.list(&groups_path, AUTOMATION_API_VERSION).await.map_err(crate::error::Error::message)?;
    let mut out = WorkerGroups { skipped: groups.len().saturating_sub(MAX_WORKER_GROUPS), ..Default::default() };
    for group in groups.into_iter().take(MAX_WORKER_GROUPS) {
        let path = format!("{}/{}/hybridRunbookWorkers", groups_path, json::text(&group, "/name"));
        let workers = arm.list(&path, AUTOMATION_API_VERSION).await.map_err(crate::error::Error::message);
        out.groups.push((without_secrets(&group), workers.map(|w| w.iter().map(without_secrets).collect())));
    }
    Ok(out)
}

/// Every lazy read an account's sections draw on.
#[derive(Default, Clone, Copy)]
pub struct AccountLazy<'a> {
    pub runbooks: Option<&'a Lazy<Vec<Value>>>,
    pub schedules: Option<&'a Lazy<Vec<Value>>>,
    pub job_schedules: Option<&'a Lazy<Vec<Value>>>,
    pub jobs: Option<&'a Lazy<Vec<Value>>>,
    pub workers: Option<&'a Lazy<WorkerGroups>>,
    pub workspace: Option<&'a Lazy<Value>>,
}

fn loaded<T>(lazy: Option<&Lazy<T>>) -> Option<&T> {
    match lazy {
        Some(Lazy::Loaded(v)) => Some(v),
        _ => None,
    }
}

/// When a job started, else when it was created: the sort key.
fn job_time(j: &Value) -> String {
    json::str_at(j, "/properties/startTime")
        .or_else(|| json::str_at(j, "/properties/creationTime"))
        .unwrap_or_default()
}

fn job_runbook(j: &Value) -> Option<String> {
    json::str_at(j, "/properties/runbook/name")
}

/// A job status: completed plain, a failure `⚠`, the rest lowercased.
fn job_status(status: Option<&str>) -> String {
    match status {
        None => "-".into(),
        Some(s) if ["failed", "suspended", "blocked", "stopped"].contains(&s.to_lowercase().as_str()) => {
            format!("⚠ {}", s.to_lowercase())
        }
        Some(s) => s.to_lowercase(),
    }
}

/// `(schedule name, run on)` for each job schedule naming `runbook`.
fn schedules_of(job_schedules: &[Value], runbook: &str) -> Vec<String> {
    job_schedules
        .iter()
        .filter(|js| json::str_at(js, "/properties/runbook/name").is_some_and(|r| r.eq_ignore_ascii_case(runbook)))
        .filter_map(|js| json::str_at(js, "/properties/schedule/name"))
        .collect()
}

/// The Runbooks body: each runbook's type, state, runtime and logging,
/// the schedules that start it and its newest job in the window (`⚠` when
/// it failed).
pub fn runbook_rows(items: &[Value], r: &AutomationAccountRow, lazy: &AccountLazy) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No runbooks".into()));
    }
    let mut runbooks: Vec<&Value> = items.iter().collect();
    runbooks.sort_by_key(|b| json::text(b, "/name").to_lowercase());
    for b in runbooks {
        let p = |f: &str| format!("/properties/{}", f);
        let name = json::text(b, "/name");
        lines.push((String::new(), String::new()));
        lines.push((name.clone(), String::new()));
        lines.push(("  Type".into(), json::text(b, &p("runbookType"))));
        let state = match json::str_at(b, &p("state")).as_deref() {
            Some("Published") => "published".to_string(),
            Some("Edit") => "edit (a draft is not published)".into(),
            Some("New") => "new (never published)".into(),
            Some(s) => s.to_lowercase(),
            None => "-".into(),
        };
        lines.push(("  State".into(), state));
        if let Some(env) = json::str_at(b, &p("runtimeEnvironment")) {
            lines.push(("  Runtime".into(), env));
        }
        lines.push(("  Modified".into(), json::time(json::str_at(b, &p("lastModifiedTime")))));
        let logging: Vec<&str> = [("verbose", p("logVerbose")), ("progress", p("logProgress"))]
            .iter()
            .filter(|(_, ptr)| json::bool_at(b, ptr) == Some(true))
            .map(|(word, _)| *word)
            .collect();
        lines.push(("  Logging".into(), if logging.is_empty() { "-".into() } else { logging.join(", ") }));
        if let Some(js) = loaded(lazy.job_schedules) {
            let names = schedules_of(js, &name);
            lines.push(("  Schedules".into(), if names.is_empty() { "none".into() } else { names.join(", ") }));
        }
        match lazy.jobs {
            Some(Lazy::Loaded(jobs)) => {
                let last = jobs
                    .iter()
                    .filter(|j| job_runbook(j).is_some_and(|n| n.eq_ignore_ascii_case(&name)))
                    .max_by_key(|j| job_time(j));
                lines.push((
                    "  Last job".into(),
                    match last {
                        Some(j) => format!(
                            "{} · {}",
                            job_status(json::str_at(j, "/properties/status").as_deref()),
                            json::time(Some(job_time(j)))
                        ),
                        None => format!("none in {} days", JOB_WINDOW_DAYS),
                    },
                ));
            }
            Some(Lazy::Loading) | None => lines.push(("  Last job".into(), "Loading…".into())),
            Some(Lazy::Error(_)) => {}
        }
        if let Some(d) = json::str_at(b, &p("description")).filter(|s| !s.is_empty()) {
            lines.push(("  Description".into(), d));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az automation runbook list"));
    lines
}

/// `every 1 day`, `once`, `every 4 hours`.
fn recurrence(s: &Value) -> String {
    let freq = json::str_at(s, "/properties/frequency").unwrap_or_default();
    if freq.eq_ignore_ascii_case("OneTime") {
        return "once".into();
    }
    let interval = s.pointer("/properties/interval").and_then(|i| i.as_i64().or_else(|| i.as_str()?.parse().ok()));
    let unit = freq.to_lowercase();
    match interval {
        Some(1) | None => format!("every {}", unit),
        Some(n) => format!("every {} {}s", n, unit),
    }
}

/// The Schedules body: each schedule's recurrence, whether it is on, its
/// next run and the runbooks it starts (and where they run).
pub fn schedule_rows(items: &[Value], r: &AutomationAccountRow, lazy: &AccountLazy, now: i64) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No schedules".into()));
    }
    let mut schedules: Vec<&Value> = items.iter().collect();
    schedules.sort_by_key(|s| json::text(s, "/name").to_lowercase());
    for s in schedules {
        let p = |f: &str| format!("/properties/{}", f);
        let name = json::text(s, "/name");
        let enabled = json::bool_at(s, &p("isEnabled"));
        lines.push((String::new(), String::new()));
        lines.push((name.clone(), String::new()));
        lines.push(("  Recurrence".into(), recurrence(s)));
        lines.push(("  Enabled".into(), json::yes_no(enabled)));
        lines.push(("  Next run".into(), json::time(json::str_at(s, &p("nextRun")))));
        if let Some(exp) = json::str_at(s, &p("expiryTime")).filter(|e| !e.starts_with("9999")) {
            let past = iso_to_unix(&exp).is_some_and(|t| t < now);
            let text = json::time(Some(exp));
            lines.push(("  Expires".into(), if past && enabled == Some(true) { format!("⚠ expired {}", text) } else { text }));
        }
        lines.push(("  Time zone".into(), json::text(s, &p("timeZone"))));
        match lazy.job_schedules {
            Some(Lazy::Loaded(js)) => {
                let starts: Vec<String> = js
                    .iter()
                    .filter(|j| json::str_at(j, "/properties/schedule/name").is_some_and(|n| n.eq_ignore_ascii_case(&name)))
                    .filter_map(|j| {
                        let runbook = json::str_at(j, "/properties/runbook/name")?;
                        Some(match json::str_at(j, "/properties/runOn").filter(|g| !g.is_empty()) {
                            Some(group) => format!("{} (on {})", runbook, group),
                            None => runbook,
                        })
                    })
                    .collect();
                lines.push(("  Starts".into(), if starts.is_empty() { "no runbook".into() } else { starts.join(", ") }));
            }
            Some(Lazy::Error(e)) => lines.push(("  Starts".into(), format!("⚠ {}", e))),
            _ => lines.push(("  Starts".into(), "Loading…".into())),
        }
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az automation schedule list"));
    lines
}

/// The Jobs body: the window's counts, then the newest jobs with their
/// runbook, status, who started them and where they ran.
pub fn job_rows(items: &[Value], r: &AutomationAccountRow) -> Vec<(String, String)> {
    let mut jobs: Vec<&Value> = items.iter().collect();
    jobs.sort_by_key(|j| std::cmp::Reverse(job_time(j)));
    let failed = jobs
        .iter()
        .filter(|j| job_status(json::str_at(j, "/properties/status").as_deref()).starts_with('⚠'))
        .count();
    let mut summary = format!("{} in the last {} days", jobs.len(), JOB_WINDOW_DAYS);
    if jobs.len() >= MAX_JOBS {
        summary = format!("the newest {} in the last {} days", MAX_JOBS, JOB_WINDOW_DAYS);
    }
    let mut lines = vec![("Jobs".into(), summary)];
    if failed > 0 {
        lines.push(("Failed or stopped".into(), format!("⚠ {}", failed)));
    }
    for j in jobs.iter().take(JOBS_SHOWN) {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        lines.push((
            format!("{} · {}", json::time(Some(job_time(j))), job_runbook(j).unwrap_or_else(|| "-".into())),
            String::new(),
        ));
        lines.push(("  Status".into(), job_status(json::str_at(j, &p("status")).as_deref())));
        lines.push(("  Ended".into(), json::time(json::str_at(j, &p("endTime")))));
        lines.push(("  Started by".into(), json::text(j, &p("startedBy"))));
        lines.push((
            "  Ran on".into(),
            json::str_at(j, &p("runOn")).filter(|g| !g.is_empty()).unwrap_or_else(|| "Azure".into()),
        ));
    }
    if jobs.len() > JOBS_SHOWN {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("… {} older jobs not shown", jobs.len() - JOBS_SHOWN)));
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az automation job list"));
    lines
}

/// The Hybrid workers body: each group, its Run As credential's name, and
/// each worker with its machine (jumpable) and when it was last seen
/// (`⚠` after a day: jobs sent to it queue).
pub fn worker_rows(w: &WorkerGroups, r: &AutomationAccountRow, now: i64) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if w.groups.is_empty() {
        lines.push((String::new(), "No hybrid worker groups".into()));
    }
    for (group, workers) in &w.groups {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        lines.push((json::text(group, "/name"), String::new()));
        lines.push(("  Type".into(), json::text(group, &p("groupType"))));
        if let Some(c) = json::str_at(group, &p("credential/name")) {
            lines.push(("  Run As credential".into(), c));
        }
        match workers {
            Ok(workers) if workers.is_empty() => lines.push(("  Workers".into(), "none".into())),
            Ok(workers) => {
                for wk in workers {
                    let name = json::str_at(wk, &p("workerName")).unwrap_or_else(|| json::text(wk, "/name"));
                    let label = format!("  {} · {}", json::text(wk, &p("workerType")), name);
                    lines.push((label, json::arm_id(json::str_at(wk, &p("vmResourceId"))).unwrap_or_default()));
                    if let Some(ip) = json::str_at(wk, &p("ip")).filter(|s| !s.is_empty()) {
                        lines.push(("    IP".into(), ip));
                    }
                    let seen = json::str_at(wk, &p("lastSeenDateTime"));
                    let stale = seen.as_deref().and_then(iso_to_unix).is_some_and(|t| now - t > WORKER_STALE_SECS);
                    let text = json::time(seen);
                    lines.push(("    Last seen".into(), if stale { format!("⚠ {}", text) } else { text }));
                }
            }
            Err(e) => lines.extend(error_rows(e)),
        }
    }
    if w.skipped > 0 {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("… {} more groups, workers not read", w.skipped)));
    }
    lines.push((String::new(), String::new()));
    lines.push(r.read_command("az automation hrwg list"));
    lines
}

/// The machines the worker read names, for Related.
fn worker_machines(w: &WorkerGroups) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (_, workers) in &w.groups {
        for wk in workers.iter().flatten() {
            if let Some(id) = json::arm_id(json::str_at(wk, "/properties/vmResourceId")) {
                out.push((format!("Hybrid worker {}", name_of_id(&id)), id));
            }
        }
    }
    out
}

/// Body lines for one section of an Automation account; `None` for
/// another type.
pub fn automation_section_lines(
    r: &dyn Resource,
    idx: usize,
    lazy: AccountLazy,
    now: i64,
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<AutomationAccountRow>()?;
    use AutomationDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Runbooks => lazy_list_rows(lazy.runbooks, "Runbooks", |items| runbook_rows(items, x, &lazy)),
        S::Schedules => lazy_list_rows(lazy.schedules, "Schedules", |items| schedule_rows(items, x, &lazy, now)),
        S::Jobs => lazy_list_rows(lazy.jobs, "Jobs", |items| job_rows(items, x)),
        S::Workers => match lazy.workers {
            None | Some(Lazy::Loading) => vec![("Hybrid workers".into(), "Loading…".into())],
            Some(Lazy::Error(e)) => error_rows(e),
            Some(Lazy::Loaded(w)) => worker_rows(w, x, now),
        },
        S::Configuration => x.configuration_rows(),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let mut extra = Vec::new();
            if let Some(ws) = loaded(lazy.workspace).and_then(|v| json::arm_id(json::str_at(v, "/id"))) {
                extra.push((format!("Linked workspace {}", name_of_id(&ws)), ws));
            }
            if let Some(w) = loaded(lazy.workers) {
                extra.extend(worker_machines(w));
            }
            related_rows_with(x, extra)
        }
        S::Tags => tag_rows(x.tags()),
    })
}

fn rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| AutomationAccountRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct AutomationService {
    scope: Scope,
}

impl AutomationService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl AzureService for AutomationService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Automation
    }

    fn name(&self) -> &str {
        "Automation"
    }

    async fn list_resources(&self, _view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        Ok(rows(&self.scope.list(ACCOUNTS_PATH, AUTOMATION_API_VERSION).await?, self.scope.tenant()))
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
            .stream(
                ACCOUNTS_PATH,
                AUTOMATION_API_VERSION,
                &[],
                service_type,
                "Listing Automation accounts…",
                &event_tx,
                |page| rows(&page, tenant.as_deref()),
            )
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, AUTOMATION_API_VERSION).await?;
        rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-ops";
    /// 2026-11-07T00:00:00Z.
    const NOW: i64 = 1_794_009_600;

    fn account_id() -> String {
        format!("{}/providers/Microsoft.Automation/automationAccounts/aa-ops", RG)
    }

    fn account(state: &str, local_off: Option<bool>) -> AutomationAccountRow {
        AutomationAccountRow::from_json(
            &json!({
                "id": account_id(), "name": "aa-ops", "location": "West Europe",
                "identity": {"type": "SystemAssigned"},
                "properties": {
                    "sku": {"name": "Basic"}, "state": state, "creationTime": "2021-03-01T10:00:00Z",
                    "publicNetworkAccess": true, "disableLocalAuth": local_off,
                    "encryption": {"keySource": "Microsoft.Automation"},
                    "automationHybridServiceUrl": "https://aa-ops.jrds.example",
                    "privateEndpointConnections": [{"properties": {
                        "privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-aa", RG)},
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

    fn all<'a>(lines: &'a [(String, String)], key: &str) -> Vec<&'a str> {
        lines.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = AUTOMATION_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            [
                "Overview", "Runbooks", "Schedules", "Jobs", "Hybrid workers", "Configuration", "Access", "Activity",
                "Related", "Tags"
            ]
        );
    }

    #[test]
    fn an_account_reads_its_state_auth_and_the_ids_command() {
        let row = account("Ok", None);
        assert_eq!(row.base.location, "westeurope");
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "ok");
        assert_eq!(row.list_summary().as_deref(), Some("Basic"));
        assert_eq!(row.cli_command(), Some(format!("az automation account show --ids {}", account_id())));
        let config = row.configuration_rows();
        assert_eq!(get(&config, "Local auth"), Some("on (webhooks and agent keys work)"));
        assert!(config.iter().any(|(k, _)| k == "Private endpoint · pe-aa (Approved)"));
        assert_eq!(config.last().unwrap().1, NEVER_SECRETS);
        assert_eq!(account("Ok", Some(true)).local_auth_text(), "off (Entra ID only)");
        assert_eq!(account("Suspended", None).state(), ResourceState::Unavailable);
    }

    #[test]
    fn content_links_and_parameters_never_reach_the_store() {
        let runbook = json!({"name": "Stop-Vms", "properties": {
            "runbookType": "PowerShell", "state": "Published",
            "publishContentLink": {"uri": "https://store.example/rb?sig=planted"},
            "draft": {"draftContentLink": {"uri": "https://store.example/d?sig=planted"}},
            "parameters": {"Password": {"defaultValue": "planted"}}
        }});
        let clean = without_secrets(&runbook).to_string();
        assert!(!clean.contains("planted"), "a planted value survived the scrub");
        assert!(clean.contains("PowerShell"));
        let schedule_link = json!({"properties": {"parameters": {"token": "planted"}, "runbook": {"name": "Stop-Vms"}}});
        assert!(!without_secrets(&schedule_link).to_string().contains("planted"));
    }

    #[test]
    fn runbooks_name_their_schedules_and_flag_a_failed_last_job() {
        let row = account("Ok", None);
        let runbooks = vec![
            json!({"name": "Stop-Vms", "properties": {"runbookType": "PowerShell72", "state": "Published", "logVerbose": true,
                "runtimeEnvironment": "ps-7.2", "lastModifiedTime": "2026-10-01T00:00:00Z"}}),
            json!({"name": "Patch-Linux", "properties": {"runbookType": "Python3", "state": "Edit"}}),
        ];
        let job_schedules = vec![json!({"properties": {"schedule": {"name": "nightly"}, "runbook": {"name": "Stop-Vms"}}})];
        let jobs = vec![
            json!({"properties": {"runbook": {"name": "Stop-Vms"}, "status": "Completed", "startTime": "2026-11-05T19:00:00Z"}}),
            json!({"properties": {"runbook": {"name": "Stop-Vms"}, "status": "Failed", "startTime": "2026-11-06T19:00:00Z"}}),
        ];
        let (js, jb) = (Lazy::Loaded(job_schedules), Lazy::Loaded(jobs));
        let lazy = AccountLazy { job_schedules: Some(&js), jobs: Some(&jb), ..Default::default() };
        let lines = runbook_rows(&runbooks, &row, &lazy);
        assert_eq!(all(&lines, "  State"), ["edit (a draft is not published)", "published"]);
        assert_eq!(all(&lines, "  Schedules"), ["none", "nightly"]);
        assert_eq!(all(&lines, "  Last job"), ["none in 7 days", "⚠ failed · 2026-11-06 19:00:00"]);
        assert_eq!(all(&lines, "  Logging"), ["-", "verbose"]);
        assert_eq!(
            lines.last().unwrap().1,
            "az automation runbook list --automation-account-name aa-ops -g rg-ops --subscription 0000"
        );
    }

    #[test]
    fn schedules_show_recurrence_and_what_they_start() {
        let row = account("Ok", None);
        let schedules = vec![
            json!({"name": "nightly", "properties": {"frequency": "Day", "interval": 1, "isEnabled": true,
                "nextRun": "2026-11-07T19:00:00Z", "expiryTime": "9999-12-31T23:59:00+00:00", "timeZone": "Europe/Amsterdam"}}),
            json!({"name": "q3-freeze", "properties": {"frequency": "Hour", "interval": 4, "isEnabled": true,
                "expiryTime": "2026-09-30T00:00:00Z"}}),
        ];
        let js = Lazy::Loaded(vec![json!({"properties": {"schedule": {"name": "nightly"}, "runbook": {"name": "Stop-Vms"},
            "runOn": "hwg-onprem"}})]);
        let lazy = AccountLazy { job_schedules: Some(&js), ..Default::default() };
        let lines = schedule_rows(&schedules, &row, &lazy, NOW);
        assert_eq!(all(&lines, "  Recurrence"), ["every day", "every 4 hours"]);
        assert_eq!(all(&lines, "  Starts"), ["Stop-Vms (on hwg-onprem)", "no runbook"]);
        assert_eq!(all(&lines, "  Expires"), ["⚠ expired 2026-09-30 00:00:00"], "the far-future expiry is no line");
    }

    #[test]
    fn jobs_list_newest_first_with_a_failure_count() {
        let row = account("Ok", None);
        let jobs = vec![
            json!({"properties": {"runbook": {"name": "A"}, "status": "Completed", "startTime": "2026-11-05T00:00:00Z", "startedBy": "Schedule"}}),
            json!({"properties": {"runbook": {"name": "B"}, "status": "Failed", "startTime": "2026-11-06T00:00:00Z", "runOn": "hwg-onprem"}}),
        ];
        let lines = job_rows(&jobs, &row);
        assert_eq!(get(&lines, "Jobs"), Some("2 in the last 7 days"));
        assert_eq!(get(&lines, "Failed or stopped"), Some("⚠ 1"));
        assert_eq!(all(&lines, "  Status"), ["⚠ failed", "completed"]);
        assert_eq!(all(&lines, "  Ran on"), ["hwg-onprem", "Azure"]);
        assert_eq!(jobs_filter(NOW), "properties/startTime ge 2026-10-31T00:00:00Z");
    }

    #[test]
    fn workers_jump_to_their_machine_and_a_quiet_one_is_flagged() {
        let row = account("Ok", None);
        let vm = format!("{}/providers/Microsoft.Compute/virtualMachines/vm-hw-01", RG);
        let w = WorkerGroups {
            groups: vec![
                (
                    json!({"name": "hwg-onprem", "properties": {"groupType": "User", "credential": {"name": "svc-runbooks"}}}),
                    Ok(vec![
                        json!({"properties": {"workerName": "vm-hw-01", "workerType": "HybridV2", "vmResourceId": vm,
                            "ip": "10.0.0.4", "lastSeenDateTime": "2026-11-06T23:00:00Z"}}),
                        json!({"properties": {"workerName": "srv-old", "workerType": "HybridV1", "lastSeenDateTime": "2026-10-01T00:00:00Z"}}),
                    ]),
                ),
                (json!({"name": "hwg-empty", "properties": {"groupType": "User"}}), Err("403 AuthorizationFailed: no".into())),
            ],
            skipped: 0,
        };
        let lines = worker_rows(&w, &row, NOW);
        assert!(lines.iter().any(|(k, v)| k == "  HybridV2 · vm-hw-01" && v == &vm));
        assert_eq!(all(&lines, "    Last seen"), ["2026-11-06 23:00:00", "⚠ 2026-10-01 00:00:00"]);
        assert_eq!(get(&lines, "  Run As credential"), Some("svc-runbooks"));
        assert!(lines.iter().any(|(_, v)| v == "⚠ 403 AuthorizationFailed: no"));

        let lw = Lazy::Loaded(w);
        let ws_id = format!("{}/providers/Microsoft.OperationalInsights/workspaces/law-ops", RG);
        let ws = Lazy::Loaded(json!({"id": ws_id}));
        let lazy = AccountLazy { workers: Some(&lw), workspace: Some(&ws), ..Default::default() };
        let related = automation_section_lines(&row, AutomationDetailSection::Related as usize, lazy, NOW).unwrap();
        assert!(related.iter().any(|(l, id)| l == "Linked workspace law-ops" && id == &ws_id));
        assert!(related.iter().any(|(l, id)| l == "Hybrid worker vm-hw-01" && id == &vm));
        assert_eq!(account_child_path(&account_id(), "runbooks"), format!("{}/runbooks", account_id()));
    }
}
