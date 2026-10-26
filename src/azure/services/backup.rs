//! The Backup service (issue #32): what is protected, by which policy, and
//! whether the last backup worked. Recovery Services vaults
//! (`Microsoft.RecoveryServices/vaults`: Azure VMs, file shares, SQL and
//! SAP HANA in a VM, MARS / DPM) and Backup vaults
//! (`Microsoft.DataProtection/backupVaults`: disks, blobs, PostgreSQL, AKS).
//! Two subscription-wide lists; its own tab (SERVICES.md rule 31).
//!
//! Per vault, from the list body: redundancy and cross-region restore,
//! soft delete, immutability, multi-user authorization, customer-managed
//! keys, public network access and private endpoints, alert settings.
//! Lazy, one read per vault each: a Recovery Services vault's
//! `backupProtectedItems` (source resource, policy, protection state,
//! health, last backup status and time, latest recovery point),
//! `backupPolicies` (schedule, retention, instant restore) and its failed
//! `backupJobs` of the last week; a Backup vault's `backupInstances`,
//! `backupPolicies` and `backupJobs` (the jobs give each instance its last
//! backup, which the instance body does not carry).
//!
//! **The other half** (a VM's Related naming its vault) is
//! [`protection_of`]: a reverse look-up over the protected items and backup
//! instances already in the lazy store, no call. It knows what the vaults
//! opened this session (or `r` in `@audit`) have read.
//!
//! **Never**: a backup instance's `datasourceAuthCredentials` (a secret
//! store reference that can carry a value), stripped before anything keeps
//! the body ([`without_secrets`]). Every read is a `GET`; the vault's
//! `backupStatus`, `refreshContainers`, a resource guard's
//! `backupSecurityPIN`, a Backup vault's `findRestorableTimeRanges` and
//! every trigger, restore and validate are `POST`s nebaz never sends (the
//! guard refuses the literals).

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_lines, tag_rows, ArmBase, Scope};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::{Lazy, LazyMap};
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// `Microsoft.RecoveryServices/vaults` (the RecoveryServices spec,
/// azure-rest-api-specs, checked 2026-10-26; in the specs since August).
pub const RSV_API_VERSION: &str = "2026-07-01";
/// The vault's backup children (`backupProtectedItems`, `backupPolicies`,
/// `backupJobs`): the RecoveryServicesBackup spec's version, which differs
/// from the vault's. `2026-10-01` is newer but landed this month.
pub const RSV_BACKUP_API_VERSION: &str = "2026-08-01";
/// `Microsoft.DataProtection` (the version the `dataprotection` CLI
/// extension pins; `2026-07-01` is a month in the specs).
pub const DPP_API_VERSION: &str = "2026-06-01";

const RECOVERY_VAULTS_PATH: &str = "/providers/Microsoft.RecoveryServices/vaults";
const BACKUP_VAULTS_PATH: &str = "/providers/Microsoft.DataProtection/backupVaults";

/// How far back a Recovery Services vault's failed jobs are read.
pub const FAILED_JOBS_DAYS: i64 = 7;
/// How many of a Backup vault's jobs are read (its list has no filter).
pub const BACKUP_VAULT_JOBS_MAX: usize = 100;
/// A protected item on a daily (or more frequent) schedule whose last
/// backup is older than this is stale.
pub const STALE_HOURS_DAILY: i64 = 36;
/// The same for a weekly schedule: a week and a day.
pub const STALE_HOURS_WEEKLY: i64 = 8 * 24;

crate::sections! {
    pub enum RecoveryVaultDetailSection,
    pub static RECOVERY_VAULT_SECTIONS = [
        Overview "Overview",
        Security "Security",
        ProtectedItems "Protected items" => crate::app::App::trigger_backup_items,
        Policies "Policies" => crate::app::App::trigger_backup_policies,
        Jobs "Failed jobs" => crate::app::App::trigger_backup_jobs,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum BackupVaultDetailSection,
    pub static BACKUP_VAULT_SECTIONS = [
        Overview "Overview",
        Security "Security",
        Instances "Backup instances" => crate::app::App::trigger_backup_items,
        Policies "Policies" => crate::app::App::trigger_backup_policies,
        Jobs "Jobs" => crate::app::App::trigger_backup_jobs,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Secrets out of the JSON ───────────────────────────────────────────

/// A backup instance's data source credentials (a secret store reference
/// whose `value` may be the secret itself).
const SECRET_FIELDS: &[&str] = &["datasourceAuthCredentials", "secretStoreResource"];

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

/// The body with the credential fields removed, at any depth.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

// ── Paths and small readers ───────────────────────────────────────────

/// `{vault}/{child}`: `backupProtectedItems`, `backupPolicies`,
/// `backupJobs`, `backupInstances`.
pub fn vault_child_path(vault_id: &str, child: &str) -> String {
    format!("{}/{}", vault_id.trim_end_matches('/'), child)
}

/// The child reads' version for a vault id (either kind).
pub fn child_api_version(vault_id: &str) -> &'static str {
    if is_backup_vault(vault_id) {
        DPP_API_VERSION
    } else {
        RSV_BACKUP_API_VERSION
    }
}

/// Whether an id is a `Microsoft.DataProtection` Backup vault.
pub fn is_backup_vault(id: &str) -> bool {
    id.to_lowercase().contains("/microsoft.dataprotection/backupvaults/")
}

/// A Backup Management Service job-filter time: `2026-10-19 09:05:00 AM`
/// (UTC), the format the `$filter` on `backupJobs` takes.
pub fn job_filter_time(secs: i64) -> String {
    let iso = crate::azure::metrics::iso_utc(secs); // 2026-10-19T09:05:00Z
    let date = &iso[..10];
    let h: i64 = iso[11..13].parse().unwrap_or(0);
    let (h12, ampm) = match h {
        0 => (12, "AM"),
        1..=11 => (h, "AM"),
        12 => (12, "PM"),
        _ => (h - 12, "PM"),
    };
    format!("{} {:02}:{} {}", date, h12, &iso[14..19], ampm)
}

/// The `$filter` for a Recovery Services vault's failed jobs of the last
/// [`FAILED_JOBS_DAYS`].
pub fn failed_jobs_filter(now: i64) -> String {
    format!(
        "status eq 'Failed' and startTime eq '{}' and endTime eq '{}'",
        job_filter_time(now - FAILED_JOBS_DAYS * 86_400),
        job_filter_time(now)
    )
}

fn same_id(a: &str, b: &str) -> bool {
    a.trim_end_matches('/').eq_ignore_ascii_case(b.trim_end_matches('/'))
}

fn eq(a: Option<&str>, b: &str) -> bool {
    a.is_some_and(|a| a.eq_ignore_ascii_case(b))
}

/// An ISO time to Unix seconds; `None` for the `0001-01-01` "never".
fn when(s: Option<&str>) -> Option<i64> {
    let t = crate::azure::metrics::parse_iso_utc(s?)?;
    (t > 946_684_800).then_some(t) // after 2000-01-01
}

/// `45m ago`, `3h ago`, `2d ago`.
pub fn ago(t: i64, now: i64) -> String {
    let d = (now - t).max(0);
    if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 2 * 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

/// `2026-10-25 02:01 (30h ago)`, or `-`.
fn time_ago(s: Option<&str>, now: i64) -> String {
    match when(s) {
        Some(t) => format!("{} ({})", json::unix_to_ymdhm(t), ago(t, now)),
        None => "never".into(),
    }
}

/// `LocallyRedundant` → `LRS`.
fn redundancy_short(r: &str) -> String {
    match r.to_lowercase().as_str() {
        "locallyredundant" => "LRS".into(),
        "georedundant" => "GRS".into(),
        "zoneredundant" => "ZRS".into(),
        _ => r.to_string(),
    }
}

/// A protected item's or instance's data source kind, readable.
fn workload_label(w: &str) -> String {
    let lower = w.to_lowercase();
    let known = match lower.as_str() {
        "vm" | "azureiaasvm" | "microsoft.compute/virtualmachines" => "Azure VM",
        "azurefileshare" | "azurestorage" => "File share",
        "sqldatabase" | "sqldb" => "SQL in VM",
        "saphanadatabase" | "saphanadbinstance" => "SAP HANA",
        "sapasedatabase" => "SAP ASE",
        "filefolder" | "mab" => "Files and folders (MARS)",
        "microsoft.compute/disks" => "Managed disk",
        "microsoft.storage/storageaccounts/blobservices" => "Blobs",
        "microsoft.dbforpostgresql/flexibleservers" => "PostgreSQL flexible",
        "microsoft.dbforpostgresql/servers/databases" => "PostgreSQL",
        "microsoft.containerservice/managedclusters" => "AKS",
        "microsoft.dbformysql/flexibleservers" => "MySQL flexible",
        _ => "",
    };
    if known.is_empty() {
        w.to_string()
    } else {
        known.to_string()
    }
}

/// `{"…": {"id": …}}` private endpoint connections: (endpoint id, status).
fn private_endpoints(v: &Value) -> Vec<(String, String)> {
    json::arr(v, "/properties/privateEndpointConnections")
        .iter()
        .filter_map(|c| {
            let id = json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?;
            Some((id, json::text(c, "/properties/privateLinkServiceConnectionState/status")))
        })
        .collect()
}

// ── Protected item health (shared with @audit) ────────────────────────

/// What is wrong with one protected item or backup instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemFlag {
    /// The last backup did not complete: the status word, the error.
    LastBackupFailed(String),
    /// Protected, but the last backup is older than the schedule allows:
    /// hours since it, the threshold.
    Stale(i64, i64),
    /// The protection itself is broken (`ProtectionError`,
    /// `ConfiguringProtectionFailed`).
    ProtectionError(String),
    /// The service's health verdict is not a pass (`ActionRequired`).
    Health(String),
}

impl ItemFlag {
    pub fn text(&self) -> String {
        match self {
            ItemFlag::LastBackupFailed(s) => format!("last backup {}", s),
            ItemFlag::Stale(h, max) => format!("last backup {}h ago (more than {}h)", h, max),
            ItemFlag::ProtectionError(s) => format!("protection {}", s),
            ItemFlag::Health(s) => format!("health {}", s),
        }
    }
}

/// A status word that means the backup did not complete.
fn failed_word(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("fail") || l == "unhealthy"
}

/// The stale threshold for a protected item: weekly schedules get a week
/// and a day, everything else a day and a half. `policy` is the item's
/// policy from the vault's warm policy list, when it is there.
pub fn stale_hours(policy: Option<&Value>) -> i64 {
    let Some(p) = policy else {
        return STALE_HOURS_DAILY;
    };
    let mut freqs: Vec<String> = json::str_at(p, "/properties/schedulePolicy/scheduleRunFrequency").into_iter().collect();
    for sub in json::arr(p, "/properties/subProtectionPolicy") {
        if eq(json::str_at(&sub, "/policyType").as_deref(), "Full") {
            freqs.extend(json::str_at(&sub, "/schedulePolicy/scheduleRunFrequency"));
        }
    }
    if !freqs.is_empty() && freqs.iter().all(|f| f.eq_ignore_ascii_case("Weekly")) {
        STALE_HOURS_WEEKLY
    } else {
        STALE_HOURS_DAILY
    }
}

/// A Recovery Services protected item's problems, given now and the
/// stale threshold.
pub fn item_flags(item: &Value, now: i64, max_hours: i64) -> Vec<ItemFlag> {
    let p = |k: &str| format!("/properties/{}", k);
    let mut flags = Vec::new();
    let state = json::str_at(item, &p("protectionState")).unwrap_or_default();
    if let Some(s) = json::str_at(item, &p("lastBackupStatus")).filter(|s| failed_word(s)) {
        let err = json::str_at(item, &p("lastBackupErrorDetail/message"))
            .or_else(|| json::str_at(item, &p("lastBackupErrorDetail/code")));
        flags.push(ItemFlag::LastBackupFailed(match err {
            Some(e) => format!("{}: {}", s, e),
            None => s,
        }));
    }
    if state.eq_ignore_ascii_case("ProtectionError") {
        flags.push(ItemFlag::ProtectionError(state.clone()));
    }
    if state.eq_ignore_ascii_case("Protected") {
        if let Some(t) = when(json::str_at(item, &p("lastBackupTime")).as_deref()) {
            let hours = (now - t) / 3600;
            if hours > max_hours {
                flags.push(ItemFlag::Stale(hours, max_hours));
            }
        }
    }
    let health = json::str_at(item, &p("healthStatus")).or_else(|| json::str_at(item, &p("protectedItemHealthStatus")));
    if let Some(h) = health.filter(|h| {
        let l = h.to_lowercase();
        l == "actionrequired" || l == "unhealthy" || l == "notreachable"
    }) {
        flags.push(ItemFlag::Health(h));
    }
    flags
}

/// A Backup vault instance's problems, given its last backup job (from the
/// vault's jobs list, when read).
pub fn instance_flags(instance: &Value, last_backup: Option<&Value>) -> Vec<ItemFlag> {
    let p = |k: &str| format!("/properties/{}", k);
    let mut flags = Vec::new();
    let status = json::str_at(instance, &p("protectionStatus/status")).unwrap_or_default();
    let current = json::str_at(instance, &p("currentProtectionState")).unwrap_or_default();
    for s in [&status, &current] {
        let l = s.to_lowercase();
        if (l.contains("failed") || l == "protectionerror") && !flags.contains(&ItemFlag::ProtectionError(s.clone())) {
            let err = json::str_at(instance, &p("protectionStatus/errorDetails/message"))
                .or_else(|| json::str_at(instance, &p("protectionErrorDetails/message")));
            flags.push(ItemFlag::ProtectionError(match err {
                Some(e) => format!("{}: {}", s, e),
                None => s.clone(),
            }));
        }
    }
    if let Some(job) = last_backup {
        if let Some(s) = json::str_at(job, "/properties/status").filter(|s| failed_word(s)) {
            flags.push(ItemFlag::LastBackupFailed(s));
        }
    }
    flags
}

/// The newest backup job of one instance in a Backup vault's jobs.
pub fn last_backup_job<'a>(jobs: &'a [Value], instance_id: &str) -> Option<&'a Value> {
    jobs.iter()
        .filter(|j| {
            json::str_at(j, "/properties/backupInstanceId").is_some_and(|i| same_id(&i, instance_id))
                && json::str_at(j, "/properties/operationCategory").is_none_or(|c| c.eq_ignore_ascii_case("Backup"))
        })
        .max_by_key(|j| json::str_at(j, "/properties/startTime").unwrap_or_default())
}

/// The source resource of a protected item: `sourceResourceId`, or a VM
/// item's `virtualMachineId`.
pub fn item_source(item: &Value) -> Option<String> {
    json::arm_id(json::str_at(item, "/properties/sourceResourceId"))
        .or_else(|| json::arm_id(json::str_at(item, "/properties/virtualMachineId")))
}

/// The source resource of a Backup vault instance.
pub fn instance_source(instance: &Value) -> Option<String> {
    json::arm_id(json::str_at(instance, "/properties/dataSourceInfo/resourceID"))
}

fn item_name(item: &Value) -> String {
    json::str_at(item, "/properties/friendlyName").unwrap_or_else(|| json::text(item, "/name"))
}

// ── The reverse look-up: which vault protects a resource ──────────────

/// The lazy reads every section renders, keyed by vault id.
#[derive(Clone, Copy)]
pub struct BackupLazy<'a> {
    /// A Recovery Services vault's `backupProtectedItems`.
    pub items: &'a LazyMap<Vec<Value>>,
    /// A Backup vault's `backupInstances`.
    pub instances: &'a LazyMap<Vec<Value>>,
    /// Either kind's `backupPolicies`.
    pub policies: &'a LazyMap<Vec<Value>>,
    /// Failed jobs (Recovery Services) or recent jobs (Backup vault).
    pub jobs: &'a LazyMap<Vec<Value>>,
}

impl<'a> BackupLazy<'a> {
    fn loaded(map: &'a LazyMap<Vec<Value>>, vault: &str) -> Option<&'a [Value]> {
        match map.get(vault) {
            Some(Lazy::Loaded(v)) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// A vault's policy by id, when its policies are loaded.
    fn policy(&self, vault: &str, policy_id: Option<&str>) -> Option<&'a Value> {
        let id = policy_id?;
        Self::loaded(self.policies, vault)?
            .iter()
            .find(|p| json::str_at(p, "/id").is_some_and(|pid| same_id(&pid, id)))
    }
}

/// `Related` lines for any resource a warm vault read protects: "Backed up
/// by {vault}" with the vault's id. No call: only vaults whose protected
/// items or backup instances are already loaded know.
pub fn protection_of(resource_id: &str, lazy: &BackupLazy<'_>, now: i64) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut vaults: Vec<(&String, &Vec<Value>)> = lazy
        .items
        .iter()
        .filter_map(|(k, v)| match v {
            Lazy::Loaded(items) => Some((k, items)),
            _ => None,
        })
        .collect();
    vaults.sort_by(|a, b| a.0.cmp(b.0));
    for (vault, items) in vaults {
        for item in items.iter().filter(|i| item_source(i).is_some_and(|s| same_id(&s, resource_id))) {
            let status = json::str_at(item, "/properties/lastBackupStatus").unwrap_or_else(|| "-".into());
            let at = when(json::str_at(item, "/properties/lastBackupTime").as_deref())
                .map(|t| format!(" {}", ago(t, now)))
                .unwrap_or_default();
            out.push((
                format!(
                    "Backed up by {} · {} · last backup {}{}",
                    name_of_id(vault),
                    json::str_at(item, "/properties/policyName").unwrap_or_else(|| "no policy".into()),
                    status.to_lowercase(),
                    at
                ),
                vault.clone(),
            ));
        }
    }
    let mut bvs: Vec<(&String, &Vec<Value>)> = lazy
        .instances
        .iter()
        .filter_map(|(k, v)| match v {
            Lazy::Loaded(items) => Some((k, items)),
            _ => None,
        })
        .collect();
    bvs.sort_by(|a, b| a.0.cmp(b.0));
    for (vault, instances) in bvs {
        for i in instances.iter().filter(|i| instance_source(i).is_some_and(|s| same_id(&s, resource_id))) {
            out.push((
                format!(
                    "Backed up by {} · {}",
                    name_of_id(vault),
                    workload_label(&json::text(i, "/properties/dataSourceInfo/datasourceType"))
                ),
                vault.clone(),
            ));
        }
    }
    out
}

/// [`related_lines`] output with `extra` links inserted before its hint
/// footer (or in place of "No related resources"), each id once.
pub fn with_protection(mut lines: Vec<(String, String)>, extra: Vec<(String, String)>) -> Vec<(String, String)> {
    let extra: Vec<(String, String)> = extra
        .into_iter()
        .filter(|(_, id)| !lines.iter().any(|(l, existing)| existing.eq_ignore_ascii_case(id) && l.starts_with("Backed up")))
        .collect();
    if extra.is_empty() {
        return lines;
    }
    if lines.len() == 1 && lines[0].1 == "No related resources" {
        return related_lines(extra);
    }
    // The footer is a blank line then the ⏎ hint.
    let at = lines.iter().rposition(|(k, v)| k.is_empty() && v.is_empty()).unwrap_or(lines.len());
    let footer = lines.split_off(at);
    lines.extend(extra);
    lines.extend(footer);
    lines
}

// ── Schedules and retention ───────────────────────────────────────────

/// `2024-01-01T02:00:00Z` → `02:00`.
fn hhmm(t: &str) -> String {
    t.split_once('T').map(|(_, t)| t.get(..5).unwrap_or(t).to_string()).unwrap_or_else(|| t.to_string())
}

fn times(v: &Value, ptr: &str) -> String {
    let t: Vec<String> = json::strings_at(v, ptr).iter().map(|t| hhmm(t)).collect();
    json::join(&t)
}

/// A Backup Management Service schedule policy, one line.
pub fn schedule_text(s: &Value) -> String {
    let freq = json::str_at(s, "/scheduleRunFrequency").unwrap_or_default();
    if let Some(mins) = json::int_at(s, "/scheduleFrequencyInMins") {
        return format!("every {} min (log backups)", mins);
    }
    match freq.to_lowercase().as_str() {
        "hourly" => {
            let h = s.pointer("/hourlySchedule").cloned().unwrap_or(Value::Null);
            format!(
                "every {}h from {} for {}h",
                json::num(json::int_at(&h, "/interval")),
                hhmm(&json::text(&h, "/scheduleWindowStartTime")),
                json::num(json::int_at(&h, "/scheduleWindowDuration"))
            )
        }
        "weekly" => {
            let (days, at) = if s.pointer("/weeklySchedule").is_some() {
                (json::strings_at(s, "/weeklySchedule/scheduleRunDays"), times(s, "/weeklySchedule/scheduleRunTimes"))
            } else {
                (json::strings_at(s, "/scheduleRunDays"), times(s, "/scheduleRunTimes"))
            };
            format!("weekly on {} at {}", json::join(&days), at)
        }
        "daily" => {
            let at = if s.pointer("/dailySchedule").is_some() {
                times(s, "/dailySchedule/scheduleRunTimes")
            } else {
                times(s, "/scheduleRunTimes")
            };
            format!("daily at {}", at)
        }
        "" => "-".into(),
        other => other.to_string(),
    }
}

/// `{count} {Days|Weeks|Months|Years}` → `30 days`.
fn duration_text(d: &Value) -> Option<String> {
    let n = json::int_at(d, "/count")?;
    let unit = json::str_at(d, "/durationType").unwrap_or_default().to_lowercase();
    let unit = if n == 1 { unit.trim_end_matches('s').to_string() } else { unit };
    Some(format!("{} {}", n, unit))
}

/// A retention policy, one line: `daily 30 days · weekly 12 weeks · …`.
pub fn retention_text(r: &Value) -> String {
    if let Some(d) = r.pointer("/retentionDuration").and_then(duration_text) {
        return d;
    }
    let mut parts = Vec::new();
    for (label, key) in [("daily", "dailySchedule"), ("weekly", "weeklySchedule"), ("monthly", "monthlySchedule"), ("yearly", "yearlySchedule")] {
        if let Some(d) = r.pointer(&format!("/{}/retentionDuration", key)).and_then(duration_text) {
            parts.push(format!("{} {}", label, d));
        }
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" · ")
    }
}

/// `P30D` → `30 days`, `PT4H` → `4 hours`, `P1W` → `1 week`.
pub fn iso_duration(d: &str) -> String {
    let body = d.trim_start_matches('P');
    let (time, body) = match body.strip_prefix('T') {
        Some(b) => (true, b),
        None => (false, body),
    };
    let unit_at = body.len().saturating_sub(1);
    let (n, unit) = body.split_at(unit_at);
    let Ok(n) = n.parse::<i64>() else {
        return d.to_string();
    };
    let word = match (time, unit) {
        (false, "D") => "day",
        (false, "W") => "week",
        (false, "M") => "month",
        (false, "Y") => "year",
        (true, "H") => "hour",
        (true, "M") => "minute",
        _ => return d.to_string(),
    };
    format!("{} {}{}", n, word, if n == 1 { "" } else { "s" })
}

/// A job duration, `PT41M12.553S` → `41m 12s`, `P1DT2H` → `1d 2h`.
pub fn job_duration(d: &str) -> String {
    let mut out = Vec::new();
    let mut num = String::new();
    let mut in_time = false;
    for c in d.chars() {
        match c {
            'P' => {}
            'T' => in_time = true,
            '0'..='9' | '.' => num.push(c),
            unit => {
                let n = num.split('.').next().unwrap_or("0").to_string();
                num.clear();
                let u = match (in_time, unit) {
                    (false, 'D') => "d",
                    (true, 'H') => "h",
                    (true, 'M') => "m",
                    (true, 'S') => "s",
                    _ => return d.to_string(),
                };
                if n != "0" || out.is_empty() && u == "s" {
                    out.push(format!("{}{}", n, u));
                }
            }
        }
    }
    if out.is_empty() {
        d.to_string()
    } else {
        out.join(" ")
    }
}

/// A Data Protection repeating interval, `R/2024-01-01T02:00:00+00:00/P1D`
/// → `daily at 02:00`.
pub fn repeating_interval_text(r: &str) -> String {
    let parts: Vec<&str> = r.split('/').collect();
    let (start, period) = match parts.as_slice() {
        [_, start, period] => (*start, *period),
        _ => return r.to_string(),
    };
    let at = hhmm(start);
    match period {
        "P1D" => format!("daily at {}", at),
        "P1W" => format!("weekly from {} at {}", start.get(..10).unwrap_or(start), at),
        p if p.starts_with("PT") => format!("every {} from {}", iso_duration(p), at),
        p => format!("every {} from {}", iso_duration(p), start),
    }
}

// ── Recovery Services vault ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RecoveryVaultRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub redundancy: Option<String>,
    pub cross_region_restore: Option<String>,
    pub cross_subscription_restore: Option<String>,
    pub soft_delete: Option<String>,
    pub soft_delete_days: Option<i64>,
    pub enhanced_security: Option<String>,
    pub immutability: Option<String>,
    pub mua: Option<String>,
    pub cmk_key_uri: Option<String>,
    pub cmk_identity: Option<String>,
    pub cmk_system_identity: bool,
    pub infrastructure_encryption: Option<String>,
    pub public_network_access: Option<String>,
    pub pe_state_backup: Option<String>,
    pub private_endpoints: Vec<(String, String)>,
    pub alerts_job_failures: Option<String>,
    pub classic_alerts: Option<String>,
    pub secure_score: Option<String>,
    pub bcdr_level: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub move_state: Option<String>,
}

impl RecoveryVaultRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<RecoveryVaultRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let s = |k: &str| json::str_at(v, &p(k));
        Some(RecoveryVaultRow {
            sku: json::str_at(v, "/sku/name"),
            redundancy: s("redundancySettings/standardTierStorageRedundancy"),
            cross_region_restore: s("redundancySettings/crossRegionRestore"),
            cross_subscription_restore: s("restoreSettings/crossSubscriptionRestoreSettings/crossSubscriptionRestoreState"),
            soft_delete: s("securitySettings/softDeleteSettings/softDeleteState"),
            soft_delete_days: json::int_at(v, &p("securitySettings/softDeleteSettings/softDeleteRetentionPeriodInDays")),
            enhanced_security: s("securitySettings/softDeleteSettings/enhancedSecurityState"),
            immutability: s("securitySettings/immutabilitySettings/state"),
            mua: s("securitySettings/multiUserAuthorization"),
            cmk_key_uri: s("encryption/keyVaultProperties/keyUri"),
            cmk_identity: json::arm_id(s("encryption/kekIdentity/userAssignedIdentity")),
            cmk_system_identity: json::bool_at(v, &p("encryption/kekIdentity/useSystemAssignedIdentity")).unwrap_or(false),
            infrastructure_encryption: s("encryption/infrastructureEncryption"),
            public_network_access: s("publicNetworkAccess"),
            pe_state_backup: s("privateEndpointStateForBackup"),
            private_endpoints: private_endpoints(v),
            alerts_job_failures: s("monitoringSettings/azureMonitorAlertSettings/alertsForAllJobFailures"),
            classic_alerts: s("monitoringSettings/classicAlertSettings/alertsForCriticalOperations"),
            secure_score: s("secureScore"),
            bcdr_level: s("bcdrSecurityLevel"),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            move_state: s("moveState").filter(|m| !m.eq_ignore_ascii_case("Unknown")),
            base,
        })
    }

    /// Soft delete is off (`Disabled`); `Enabled` and `AlwaysON` are on.
    pub fn soft_delete_off(&self) -> bool {
        eq(self.soft_delete.as_deref(), "Disabled")
    }

    fn redundancy_text(&self) -> String {
        let r = self.redundancy.as_deref().map(redundancy_short).unwrap_or_else(|| "-".into());
        if eq(self.cross_region_restore.as_deref(), "Enabled") {
            format!("{} + cross-region restore", r)
        } else {
            r
        }
    }

    fn cmk_text(&self) -> String {
        match &self.cmk_key_uri {
            Some(k) => format!("customer-managed key {}", k),
            None => "platform-managed keys".into(),
        }
    }

    fn security_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Soft delete".into(), json::opt(self.soft_delete.clone())),
            ("  Retention".into(), self.soft_delete_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "-".into())),
            ("  Enhanced security".into(), json::opt(self.enhanced_security.clone())),
        ];
        if self.soft_delete_off() {
            lines.push((String::new(), "⚠ soft delete is off: deleted backup data is gone at once".into()));
        } else if eq(self.soft_delete.as_deref(), "AlwaysON") {
            lines.push((String::new(), "· always on: soft delete can no longer be turned off".into()));
        }
        lines.push((
            "Immutability".into(),
            match self.immutability.as_deref() {
                Some(s) if s.eq_ignore_ascii_case("Locked") => "Locked (recovery points can't be deleted before expiry; irreversible)".into(),
                Some(s) if s.eq_ignore_ascii_case("Unlocked") => "Unlocked (on, can still be turned off)".into(),
                other => json::opt(other.map(str::to_string)),
            },
        ));
        lines.push(("Multi-user authorization".into(), json::opt(self.mua.clone())));
        lines.push((String::new(), String::new()));
        lines.push(("Encryption".into(), self.cmk_text()));
        if self.cmk_key_uri.is_some() {
            let who = match (&self.cmk_identity, self.cmk_system_identity) {
                (Some(id), _) => name_of_id(id).to_string(),
                (None, true) => "system-assigned identity".into(),
                _ => "-".into(),
            };
            lines.push(("  Key read by".into(), who));
            if let Some(id) = &self.cmk_identity {
                lines.push((format!("  Identity {}", name_of_id(id)), id.clone()));
            }
        }
        lines.push(("Infrastructure encryption".into(), json::opt(self.infrastructure_encryption.clone())));
        lines.push((String::new(), String::new()));
        lines.push(("Public network access".into(), json::opt(self.public_network_access.clone())));
        lines.push(("Private endpoints for backup".into(), json::opt(self.pe_state_backup.clone())));
        for (pe, status) in &self.private_endpoints {
            lines.push((format!("  Private endpoint {} · {}", name_of_id(pe), status), pe.clone()));
        }
        lines.push((String::new(), String::new()));
        lines.push(("Storage redundancy".into(), json::opt(self.redundancy.clone())));
        lines.push(("Cross-region restore".into(), json::opt(self.cross_region_restore.clone())));
        lines.push(("Cross-subscription restore".into(), json::opt(self.cross_subscription_restore.clone())));
        lines.push(("Alerts for job failures".into(), json::opt(self.alerts_job_failures.clone())));
        lines.push(("Classic alerts (critical operations)".into(), json::opt(self.classic_alerts.clone())));
        lines.push(("Secure score".into(), json::opt(self.secure_score.clone())));
        lines.push(("BCDR security level".into(), json::opt(self.bcdr_level.clone())));
        lines
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for (pe, _) in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        let mut ids = self.user_identity_ids.clone();
        if let Some(c) = &self.cmk_identity {
            if !ids.iter().any(|i| i.eq_ignore_ascii_case(c)) {
                ids.push(c.clone());
            }
        }
        for id in ids {
            v.push((format!("Identity {}", name_of_id(&id)), id));
        }
        v
    }
}

impl Resource for RecoveryVaultRow {
    arm_row!("Recovery Services vault");
    /// `GRS + cross-region restore · soft delete AlwaysON · immutability Locked`.
    fn list_summary(&self) -> Option<String> {
        let mut parts = vec![
            self.redundancy_text(),
            format!("soft delete {}", json::opt(self.soft_delete.clone())),
        ];
        if let Some(i) = self.immutability.as_deref().filter(|i| !i.eq_ignore_ascii_case("Disabled")) {
            parts.push(format!("immutable ({})", i.to_lowercase()));
        }
        if !self.private_endpoints.is_empty() {
            parts.push(format!("{} PE", self.private_endpoints.len()));
        }
        Some(parts.join(" · "))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&RECOVERY_VAULT_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut d = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Redundancy".into(), self.redundancy_text()),
            ("Soft delete".into(), json::opt(self.soft_delete.clone())),
            ("Immutability".into(), json::opt(self.immutability.clone())),
            ("Multi-user authorization".into(), json::opt(self.mua.clone())),
            ("Encryption".into(), if self.cmk_key_uri.is_some() { "customer-managed key".into() } else { "platform-managed keys".into() }),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Private endpoints".into(), self.private_endpoints.len().to_string()),
            ("Alerts for job failures".into(), json::opt(self.alerts_job_failures.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ];
        if let Some(m) = &self.move_state {
            d.push(("Move state".into(), m.clone()));
        }
        d
    }
    fn related(&self) -> Vec<(String, String)> {
        RecoveryVaultRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az backup vault show --ids {}", shell_quote(&self.base.id)))
    }
}

/// One protected item, as lines: the header, the source (jumpable), the
/// policy, the latest recovery point and any warning.
fn protected_item_lines(item: &Value, flags: &[ItemFlag], now: i64) -> Vec<(String, String)> {
    let p = |k: &str| format!("/properties/{}", k);
    let workload = json::str_at(item, &p("workloadType"))
        .or_else(|| json::str_at(item, &p("backupManagementType")))
        .map(|w| workload_label(&w))
        .unwrap_or_else(|| "-".into());
    let mut lines = vec![(
        format!("{} · {}", item_name(item), workload),
        format!(
            "{} · last backup {} {}",
            json::text(item, &p("protectionState")),
            json::str_at(item, &p("lastBackupStatus")).unwrap_or_else(|| "-".into()).to_lowercase(),
            time_ago(json::str_at(item, &p("lastBackupTime")).as_deref(), now),
        ),
    )];
    if let Some(src) = item_source(item) {
        lines.push((format!("  Source {}", name_of_id(&src)), src));
    } else if let Some(c) = json::str_at(item, &p("containerName")).or_else(|| json::str_at(item, &p("computerName"))) {
        lines.push(("  Container".into(), c));
    }
    lines.push(("  Policy".into(), json::str_at(item, &p("policyName")).unwrap_or_else(|| "none".into())));
    let health = json::str_at(item, &p("healthStatus"))
        .or_else(|| json::str_at(item, &p("protectedItemHealthStatus")))
        .or_else(|| json::str_at(item, &p("protectionStatus")));
    let detail = json::arr(item, &p("healthDetails"))
        .first()
        .and_then(|d| json::str_at(d, "/title").or_else(|| json::str_at(d, "/message")))
        .map(|t| format!(" · {}", t))
        .unwrap_or_default();
    lines.push(("  Health".into(), format!("{}{}", json::opt(health), detail)));
    lines.push(("  Latest recovery point".into(), time_ago(json::str_at(item, &p("lastRecoveryPoint")).as_deref(), now)));
    if let Some(n) = json::int_at(item, &p("extendedInfo/recoveryPointCount")) {
        let oldest = json::str_at(item, &p("extendedInfo/oldestRecoveryPoint"));
        lines.push(("  Recovery points".into(), format!("{} · oldest {}", n, json::time(oldest))));
    }
    if json::bool_at(item, &p("isScheduledForDeferredDelete")) == Some(true) {
        lines.push((String::new(), format!("  ⚠ {}: soft-deleted, purged {}", item_name(item), json::time(json::str_at(item, &p("deferredDeleteTimeInUTC"))))));
    }
    for f in flags {
        lines.push((String::new(), format!("  ⚠ {}: {}", item_name(item), f.text())));
    }
    lines
}

/// A Recovery Services vault's Protected items: a count line, then each
/// item (problems first).
pub fn protected_items_rows(vault: &str, lazy: &BackupLazy<'_>, now: i64) -> Vec<(String, String)> {
    lazy_list_rows(lazy.items.get(vault), "Protected items", |items| {
        if items.is_empty() {
            return vec![(String::new(), "Nothing protected in this vault".into())];
        }
        let mut rows: Vec<(Vec<ItemFlag>, &Value)> = items
            .iter()
            .map(|i| {
                let policy = lazy.policy(vault, json::str_at(i, "/properties/policyId").as_deref());
                (item_flags(i, now, stale_hours(policy)), i)
            })
            .collect();
        rows.sort_by(|a, b| a.0.is_empty().cmp(&b.0.is_empty()).then_with(|| item_name(a.1).to_lowercase().cmp(&item_name(b.1).to_lowercase())));
        let failing = rows.iter().filter(|(f, _)| !f.is_empty()).count();
        let stopped = items
            .iter()
            .filter(|i| json::str_at(i, "/properties/protectionState").is_some_and(|s| s.to_lowercase().starts_with("protectionstopped")))
            .count();
        let mut head = format!("{}", items.len());
        if failing > 0 {
            head.push_str(&format!(" · {} {} attention", failing, if failing == 1 { "needs" } else { "need" }));
        }
        if stopped > 0 {
            head.push_str(&format!(" · {} protection stopped", stopped));
        }
        let mut lines = vec![("Items".into(), head)];
        for (flags, item) in rows {
            lines.push((String::new(), String::new()));
            lines.extend(protected_item_lines(item, &flags, now));
        }
        if lazy.policies.get(vault).is_none() {
            lines.push((String::new(), String::new()));
            lines.push((String::new(), format!("· stale = no backup for {}h (weekly policies {}h once Policies is read)", STALE_HOURS_DAILY, STALE_HOURS_WEEKLY)));
        }
        lines
    })
}

/// A Recovery Services vault's policies.
pub fn rsv_policy_rows(policies: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(policies, "Policies", |items| {
        if items.is_empty() {
            return vec![(String::new(), "No backup policies".into())];
        }
        let mut items: Vec<&Value> = items.iter().collect();
        items.sort_by_key(|p| json::text(p, "/name").to_lowercase());
        let mut lines = Vec::new();
        for pol in items {
            let p = |k: &str| format!("/properties/{}", k);
            let kind = json::str_at(pol, &p("backupManagementType")).unwrap_or_else(|| "-".into());
            let count = json::int_at(pol, &p("protectedItemsCount")).map(|n| format!(" · {} items", n)).unwrap_or_default();
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((json::text(pol, "/name"), format!("{}{}", workload_label(&kind), count)));
            if let Some(s) = pol.pointer(&p("schedulePolicy")) {
                let tz = json::str_at(pol, &p("timeZone")).map(|t| format!(" ({})", t)).unwrap_or_default();
                lines.push(("  Schedule".into(), format!("{}{}", schedule_text(s), tz)));
            }
            if let Some(r) = pol.pointer(&p("retentionPolicy")) {
                lines.push(("  Retention".into(), retention_text(r)));
            }
            if let Some(r) = pol.pointer(&p("vaultRetentionPolicy/vaultRetention")) {
                lines.push(("  Vault retention".into(), retention_text(r)));
            }
            if let Some(d) = json::int_at(pol, &p("instantRpRetentionRangeInDays")) {
                lines.push(("  Instant restore".into(), format!("{} days of snapshots", d)));
            }
            if let Some(t) = json::str_at(pol, &p("policyType")) {
                lines.push(("  Policy type".into(), if t.eq_ignore_ascii_case("V2") { "V2 (Enhanced)".into() } else { t }));
            }
            for sub in json::arr(pol, &p("subProtectionPolicy")) {
                let kind = json::text(&sub, "/policyType");
                let sched = sub.pointer("/schedulePolicy").map(schedule_text).unwrap_or_else(|| "-".into());
                let ret = sub.pointer("/retentionPolicy").map(retention_text).unwrap_or_else(|| "-".into());
                lines.push((format!("  {}", kind), format!("{} · keep {}", sched, ret)));
            }
        }
        lines
    })
}

/// One job, as a line pair (when, what · status · error).
fn job_line(j: &Value, name_ptr: &str) -> (String, String) {
    let p = |k: &str| format!("/properties/{}", k);
    let err = json::arr(j, &p("errorDetails"))
        .first()
        .map(|e| {
            let code = json::str_at(e, "/errorCode").or_else(|| json::str_at(e, "/code"));
            let msg = json::str_at(e, "/errorString").or_else(|| json::str_at(e, "/message"));
            match (code, msg) {
                (Some(c), Some(m)) => format!(" · {}: {}", c, m),
                (Some(c), None) => format!(" · {}", c),
                (None, Some(m)) => format!(" · {}", m),
                (None, None) => String::new(),
            }
        })
        .unwrap_or_default();
    let dur = json::str_at(j, &p("duration")).map(|d| format!(" · {}", job_duration(&d))).unwrap_or_default();
    (
        format!("{}  {}", json::time(json::str_at(j, &p("startTime"))), json::text(j, name_ptr)),
        format!("{} {}{}{}", json::text(j, &p("operation")), json::text(j, &p("status")).to_lowercase(), dur, err),
    )
}

fn newest_first(jobs: &[Value]) -> Vec<&Value> {
    let mut v: Vec<&Value> = jobs.iter().collect();
    v.sort_by_key(|j| std::cmp::Reverse(json::str_at(j, "/properties/startTime").unwrap_or_default()));
    v
}

/// A Recovery Services vault's failed jobs of the last week.
pub fn rsv_job_rows(jobs: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(jobs, "Failed jobs", |jobs| {
        if jobs.is_empty() {
            return vec![(String::new(), format!("No failed jobs in the last {} days", FAILED_JOBS_DAYS))];
        }
        let mut lines = vec![(format!("Failed in the last {} days", FAILED_JOBS_DAYS), jobs.len().to_string())];
        lines.extend(newest_first(jobs).into_iter().map(|j| job_line(j, "/properties/entityFriendlyName")));
        lines
    })
}

pub fn recovery_vault_section_lines(
    r: &RecoveryVaultRow,
    section: RecoveryVaultDetailSection,
    lazy: &BackupLazy<'_>,
    now: i64,
) -> Vec<(String, String)> {
    let id = &r.base.id;
    match section {
        RecoveryVaultDetailSection::Overview => overview_rows(r),
        RecoveryVaultDetailSection::Security => r.security_rows(),
        RecoveryVaultDetailSection::ProtectedItems => protected_items_rows(id, lazy, now),
        RecoveryVaultDetailSection::Policies => rsv_policy_rows(lazy.policies.get(id)),
        RecoveryVaultDetailSection::Jobs => rsv_job_rows(lazy.jobs.get(id)),
        RecoveryVaultDetailSection::Access => crate::azure::services::rendered_by_app(),
        RecoveryVaultDetailSection::Activity => crate::azure::services::rendered_by_app(),
        RecoveryVaultDetailSection::Related => {
            let mut rel = r.related();
            if let Some(items) = BackupLazy::loaded(lazy.items, id) {
                for src in items.iter().filter_map(item_source) {
                    if !rel.iter().any(|(_, e)| same_id(e, &src)) {
                        rel.push((format!("Protects {}", name_of_id(&src)), src));
                    }
                }
            }
            related_lines(rel)
        }
        RecoveryVaultDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Backup vault (Microsoft.DataProtection) ───────────────────────────

#[derive(Debug, Clone)]
pub struct BackupVaultRow {
    pub base: ArmBase,
    /// `(datastoreType, type)`: `VaultStore`, `GeoRedundant`.
    pub storage: Vec<(String, String)>,
    pub cross_region_restore: Option<String>,
    pub cross_subscription_restore: Option<String>,
    pub soft_delete: Option<String>,
    pub soft_delete_days: Option<f64>,
    pub immutability: Option<String>,
    pub encryption_state: Option<String>,
    pub cmk_key_uri: Option<String>,
    pub cmk_identity_type: Option<String>,
    pub cmk_identity: Option<String>,
    pub infrastructure_encryption: Option<String>,
    pub alerts_job_failures: Option<String>,
    pub resource_guard: Option<bool>,
    pub secure_score: Option<String>,
    pub bcdr_level: Option<String>,
    pub replicated_regions: Vec<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
}

impl BackupVaultRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<BackupVaultRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = |k: &str| format!("/properties/{}", k);
        let s = |k: &str| json::str_at(v, &p(k));
        Some(BackupVaultRow {
            storage: json::arr(v, &p("storageSettings"))
                .iter()
                .map(|st| (json::text(st, "/datastoreType"), json::text(st, "/type")))
                .collect(),
            cross_region_restore: s("featureSettings/crossRegionRestoreSettings/state"),
            cross_subscription_restore: s("featureSettings/crossSubscriptionRestoreSettings/state"),
            soft_delete: s("securitySettings/softDeleteSettings/state"),
            soft_delete_days: v.pointer(&p("securitySettings/softDeleteSettings/retentionDurationInDays")).and_then(|n| n.as_f64()),
            immutability: s("securitySettings/immutabilitySettings/state"),
            encryption_state: s("securitySettings/encryptionSettings/state"),
            cmk_key_uri: s("securitySettings/encryptionSettings/keyVaultProperties/keyUri"),
            cmk_identity_type: s("securitySettings/encryptionSettings/kekIdentity/identityType"),
            cmk_identity: json::arm_id(s("securitySettings/encryptionSettings/kekIdentity/identityId")),
            infrastructure_encryption: s("securitySettings/encryptionSettings/infrastructureEncryption"),
            alerts_job_failures: s("monitoringSettings/azureMonitorAlertSettings/alertsForAllJobFailures"),
            resource_guard: json::bool_at(v, &p("isVaultProtectedByResourceGuard")),
            secure_score: s("secureScore"),
            bcdr_level: s("bcdrSecurityLevel"),
            replicated_regions: json::strings_at(v, &p("replicatedRegions")),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            base,
        })
    }

    /// Soft delete is `Off` (`On` and `AlwaysOn` are on).
    pub fn soft_delete_off(&self) -> bool {
        eq(self.soft_delete.as_deref(), "Off")
    }

    /// Multi-user authorization: a resource guard protects the vault.
    pub fn mua_on(&self) -> bool {
        self.resource_guard == Some(true)
    }

    fn redundancy_text(&self) -> String {
        let r: Vec<String> = self.storage.iter().map(|(_, t)| redundancy_short(t)).collect();
        let r = json::join(&r);
        if eq(self.cross_region_restore.as_deref(), "Enabled") {
            format!("{} + cross-region restore", r)
        } else {
            r
        }
    }

    fn security_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Soft delete".into(), json::opt(self.soft_delete.clone())),
            ("  Retention".into(), self.soft_delete_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "-".into())),
        ];
        if self.soft_delete_off() {
            lines.push((String::new(), "⚠ soft delete is off: deleted backup data is gone at once".into()));
        }
        lines.push(("Immutability".into(), json::opt(self.immutability.clone())));
        lines.push((
            "Multi-user authorization".into(),
            match self.resource_guard {
                Some(true) => "on (a resource guard protects critical operations)".into(),
                Some(false) => "off".into(),
                None => "-".into(),
            },
        ));
        lines.push((String::new(), String::new()));
        match &self.cmk_key_uri {
            Some(k) => {
                lines.push(("Encryption".into(), format!("customer-managed key {}", k)));
                lines.push(("  State".into(), json::opt(self.encryption_state.clone())));
                lines.push(("  Key read by".into(), json::opt(self.cmk_identity_type.clone())));
                if let Some(id) = &self.cmk_identity {
                    lines.push((format!("  Identity {}", name_of_id(id)), id.clone()));
                }
            }
            None => lines.push(("Encryption".into(), "platform-managed keys".into())),
        }
        lines.push(("Infrastructure encryption".into(), json::opt(self.infrastructure_encryption.clone())));
        lines.push((String::new(), String::new()));
        for (store, kind) in &self.storage {
            lines.push((format!("Storage · {}", store), kind.clone()));
        }
        lines.push(("Cross-region restore".into(), json::opt(self.cross_region_restore.clone())));
        lines.push(("Cross-subscription restore".into(), json::opt(self.cross_subscription_restore.clone())));
        if !self.replicated_regions.is_empty() {
            lines.push(("Replicated regions".into(), json::join(&self.replicated_regions)));
        }
        lines.push(("Alerts for job failures".into(), json::opt(self.alerts_job_failures.clone())));
        lines.push(("Secure score".into(), json::opt(self.secure_score.clone())));
        lines.push(("BCDR security level".into(), json::opt(self.bcdr_level.clone())));
        lines
    }

    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        let mut ids = self.user_identity_ids.clone();
        if let Some(c) = &self.cmk_identity {
            if !ids.iter().any(|i| i.eq_ignore_ascii_case(c)) {
                ids.push(c.clone());
            }
        }
        for id in ids {
            v.push((format!("Identity {}", name_of_id(&id)), id));
        }
        v
    }
}

impl Resource for BackupVaultRow {
    arm_row!("Backup vault");
    /// `ZRS · soft delete On · immutable (unlocked)`.
    fn list_summary(&self) -> Option<String> {
        let mut parts = vec![self.redundancy_text(), format!("soft delete {}", json::opt(self.soft_delete.clone()))];
        if let Some(i) = self.immutability.as_deref().filter(|i| !i.eq_ignore_ascii_case("Disabled")) {
            parts.push(format!("immutable ({})", i.to_lowercase()));
        }
        if self.mua_on() {
            parts.push("MUA".into());
        }
        Some(parts.join(" · "))
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&BACKUP_VAULT_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Redundancy".into(), self.redundancy_text()),
            ("Soft delete".into(), json::opt(self.soft_delete.clone())),
            ("Immutability".into(), json::opt(self.immutability.clone())),
            ("Multi-user authorization".into(), json::yes_no(self.resource_guard)),
            ("Encryption".into(), if self.cmk_key_uri.is_some() { "customer-managed key".into() } else { "platform-managed keys".into() }),
            ("Alerts for job failures".into(), json::opt(self.alerts_job_failures.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        BackupVaultRow::related(self)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az dataprotection backup-vault show --ids {}", shell_quote(&self.base.id)))
    }
}

/// A Backup vault's instances: each with its source (jumpable), policy,
/// protection status and, from the jobs list, its last backup.
pub fn backup_instance_rows(vault: &str, lazy: &BackupLazy<'_>, now: i64) -> Vec<(String, String)> {
    let jobs = BackupLazy::loaded(lazy.jobs, vault);
    let jobs_state = lazy.jobs.get(vault);
    lazy_list_rows(lazy.instances.get(vault), "Backup instances", |items| {
        if items.is_empty() {
            return vec![(String::new(), "Nothing protected in this vault".into())];
        }
        let mut items: Vec<&Value> = items.iter().collect();
        items.sort_by_key(|i| item_name(i).to_lowercase());
        let mut lines = vec![("Instances".into(), items.len().to_string())];
        for i in items {
            let p = |k: &str| format!("/properties/{}", k);
            let last = jobs.and_then(|j| last_backup_job(j, &json::text(i, "/id")));
            let flags = instance_flags(i, last);
            lines.push((String::new(), String::new()));
            let current = json::text(i, &p("currentProtectionState"));
            let status = json::text(i, &p("protectionStatus/status"));
            lines.push((
                format!("{} · {}", item_name(i), workload_label(&json::text(i, &p("dataSourceInfo/datasourceType")))),
                if current.eq_ignore_ascii_case(&status) { current } else { format!("{} · {}", current, status) },
            ));
            if let Some(src) = instance_source(i) {
                lines.push((format!("  Source {}", name_of_id(&src)), src));
            }
            lines.push((
                "  Policy".into(),
                json::str_at(i, &p("policyInfo/policyId")).map(|id| name_of_id(&id).to_string()).unwrap_or_else(|| "-".into()),
            ));
            let policy = lazy.policy(vault, json::str_at(i, &p("policyInfo/policyId")).as_deref());
            let operational_only = policy.is_some_and(|pol| {
                !json::arr(pol, "/properties/policyRules")
                    .iter()
                    .any(|r| json::str_at(r, "/objectType").is_some_and(|k| k.eq_ignore_ascii_case("AzureBackupRule")))
            });
            let last_text = match (jobs_state, last) {
                (_, None) if operational_only => "continuous (operational tier: no scheduled backup jobs)".into(),
                (_, Some(j)) => format!(
                    "{} {}",
                    json::text(j, "/properties/status").to_lowercase(),
                    time_ago(json::str_at(j, "/properties/startTime").as_deref(), now)
                ),
                (Some(Lazy::Loaded(_)), None) => "no backup job in the vault's recent jobs".into(),
                (Some(Lazy::Error(_)), None) => "unknown (the jobs read failed)".into(),
                _ => "Loading…".into(),
            };
            lines.push(("  Last backup".into(), last_text));
            for f in flags {
                lines.push((String::new(), format!("  ⚠ {}: {}", item_name(i), f.text())));
            }
        }
        lines
    })
}

/// A Data Protection policy rule's one-line summary.
fn dpp_rule_line(rule: &Value) -> (String, String) {
    let name = json::text(rule, "/name");
    let kind = json::str_at(rule, "/objectType").unwrap_or_default();
    if kind.eq_ignore_ascii_case("AzureRetentionRule") {
        let default = if json::bool_at(rule, "/isDefault") == Some(true) { " (default)" } else { "" };
        let life: Vec<String> = json::arr(rule, "/lifecycles")
            .iter()
            .map(|l| {
                let keep = json::str_at(l, "/deleteAfter/duration").map(|d| iso_duration(&d)).unwrap_or_else(|| "-".into());
                let store = json::text(l, "/sourceDataStore/dataStoreType");
                let copies: Vec<String> =
                    json::arr(l, "/targetDataStoreCopySettings").iter().map(|c| json::text(c, "/dataStore/dataStoreType")).collect();
                if copies.is_empty() {
                    format!("{} in {}", keep, store)
                } else {
                    format!("{} in {} (copied to {})", keep, store, copies.join(", "))
                }
            })
            .collect();
        (format!("  Keep · {}{}", name, default), json::join(&life))
    } else {
        let sched: Vec<String> = json::strings_at(rule, "/trigger/schedule/repeatingTimeIntervals")
            .iter()
            .map(|r| repeating_interval_text(r))
            .collect();
        let tz = json::str_at(rule, "/trigger/schedule/timeZone").map(|t| format!(" ({})", t)).unwrap_or_default();
        let kind = json::str_at(rule, "/backupParameters/backupType").map(|b| format!(" · {}", b)).unwrap_or_default();
        let store = json::str_at(rule, "/dataStore/dataStoreType").map(|s| format!(" · to {}", s)).unwrap_or_default();
        (format!("  Backup · {}", name), format!("{}{}{}{}", json::join(&sched), tz, kind, store))
    }
}

/// A Backup vault's policies: data source types, backup and retention rules.
pub fn dpp_policy_rows(policies: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(policies, "Policies", |items| {
        if items.is_empty() {
            return vec![(String::new(), "No backup policies".into())];
        }
        let mut items: Vec<&Value> = items.iter().collect();
        items.sort_by_key(|p| json::text(p, "/name").to_lowercase());
        let mut lines = Vec::new();
        for pol in items {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            let types: Vec<String> = json::strings_at(pol, "/properties/datasourceTypes").iter().map(|t| workload_label(t)).collect();
            lines.push((json::text(pol, "/name"), json::join(&types)));
            let rules = json::arr(pol, "/properties/policyRules");
            if rules.is_empty() {
                lines.push(("  Rules".into(), "-".into()));
            }
            // Backup rules first, then retention.
            let mut rules: Vec<&Value> = rules.iter().collect();
            rules.sort_by_key(|r| json::str_at(r, "/objectType").is_some_and(|k| k.eq_ignore_ascii_case("AzureRetentionRule")));
            lines.extend(rules.into_iter().map(dpp_rule_line));
        }
        lines
    })
}

/// A Backup vault's recent jobs, newest first, with the failures counted.
pub fn dpp_job_rows(jobs: Option<&Lazy<Vec<Value>>>) -> Vec<(String, String)> {
    lazy_list_rows(jobs, "Jobs", |jobs| {
        if jobs.is_empty() {
            return vec![(String::new(), "No jobs".into())];
        }
        let failed = jobs
            .iter()
            .filter(|j| json::str_at(j, "/properties/status").is_some_and(|s| failed_word(&s)))
            .count();
        let mut lines = vec![(
            "Recent jobs".into(),
            format!("{}{}", jobs.len(), if failed > 0 { format!(" · {} failed", failed) } else { String::new() }),
        )];
        lines.extend(newest_first(jobs).into_iter().take(40).map(|j| job_line(j, "/properties/dataSourceName")));
        lines
    })
}

pub fn backup_vault_section_lines(
    r: &BackupVaultRow,
    section: BackupVaultDetailSection,
    lazy: &BackupLazy<'_>,
    now: i64,
) -> Vec<(String, String)> {
    let id = &r.base.id;
    match section {
        BackupVaultDetailSection::Overview => overview_rows(r),
        BackupVaultDetailSection::Security => r.security_rows(),
        BackupVaultDetailSection::Instances => backup_instance_rows(id, lazy, now),
        BackupVaultDetailSection::Policies => dpp_policy_rows(lazy.policies.get(id)),
        BackupVaultDetailSection::Jobs => dpp_job_rows(lazy.jobs.get(id)),
        BackupVaultDetailSection::Access => crate::azure::services::rendered_by_app(),
        BackupVaultDetailSection::Activity => crate::azure::services::rendered_by_app(),
        BackupVaultDetailSection::Related => {
            let mut rel = r.related();
            if let Some(items) = BackupLazy::loaded(lazy.instances, id) {
                for src in items.iter().filter_map(instance_source) {
                    if !rel.iter().any(|(_, e)| same_id(e, &src)) {
                        rel.push((format!("Protects {}", name_of_id(&src)), src));
                    }
                }
            }
            related_lines(rel)
        }
        BackupVaultDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct BackupService {
    scope: Scope,
}

impl BackupService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::BackupVaults => page
                .iter()
                .filter_map(|v| BackupVaultRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => page
                .iter()
                .filter_map(|v| RecoveryVaultRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
        }
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::BackupVaults => (BACKUP_VAULTS_PATH, DPP_API_VERSION, "Listing Backup vaults…"),
            _ => (RECOVERY_VAULTS_PATH, RSV_API_VERSION, "Listing Recovery Services vaults…"),
        }
    }

    pub fn api_version_for(id: &str) -> &'static str {
        if is_backup_vault(id) {
            DPP_API_VERSION
        } else {
            RSV_API_VERSION
        }
    }
}

#[async_trait]
impl AzureService for BackupService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Backup
    }

    fn name(&self) -> &str {
        "Backup"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, _) = Self::list_of(view);
        let page = self.scope.list(path, version).await?;
        Ok(Self::rows(view, &page, self.scope.tenant()))
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
            .stream(path, version, &[], service_type, label, &event_tx, |page| Self::rows(view, &page, tenant.as_deref()))
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, Self::api_version_for(id)).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::RecoveryVaults);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-bk";

    fn id(path: &str) -> String {
        format!("{}/providers/{}", RG, path)
    }

    fn has(lines: &[(String, String)], k: &str, v: &str) -> bool {
        lines.iter().any(|(a, b)| a.contains(k) && b.contains(v))
    }

    fn text(lines: &[(String, String)]) -> String {
        lines.iter().map(|(a, b)| format!("{a} | {b}\n")).collect()
    }

    // 2026-10-26T12:00:00Z
    const NOW: i64 = 1_793_016_000;

    fn rsv_json() -> Value {
        json!({
            "id": id("Microsoft.RecoveryServices/vaults/rsv-1"),
            "name": "rsv-1",
            "location": "westeurope",
            "sku": {"name": "RS0", "tier": "Standard"},
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                id("Microsoft.ManagedIdentity/userAssignedIdentities/id-backup"): {}}},
            "properties": {
                "provisioningState": "Succeeded",
                "publicNetworkAccess": "Disabled",
                "privateEndpointStateForBackup": "Enabled",
                "privateEndpointConnections": [{"id": id("Microsoft.RecoveryServices/vaults/rsv-1/privateEndpointConnections/c1"),
                    "properties": {"privateEndpoint": {"id": id("Microsoft.Network/privateEndpoints/pe-rsv")},
                        "privateLinkServiceConnectionState": {"status": "Approved"}, "groupIds": ["AzureBackup"]}}],
                "redundancySettings": {"standardTierStorageRedundancy": "GeoRedundant", "crossRegionRestore": "Enabled"},
                "securitySettings": {
                    "softDeleteSettings": {"softDeleteState": "AlwaysON", "softDeleteRetentionPeriodInDays": 14, "enhancedSecurityState": "AlwaysON"},
                    "immutabilitySettings": {"state": "Locked"},
                    "multiUserAuthorization": "Enabled"
                },
                "encryption": {"keyVaultProperties": {"keyUri": "https://kv-x.example/keys/k1"},
                    "kekIdentity": {"userAssignedIdentity": id("Microsoft.ManagedIdentity/userAssignedIdentities/id-backup")},
                    "infrastructureEncryption": "Enabled"},
                "monitoringSettings": {"azureMonitorAlertSettings": {"alertsForAllJobFailures": "Enabled"},
                    "classicAlertSettings": {"alertsForCriticalOperations": "Disabled"}}
            }
        })
    }

    fn vm(name: &str) -> String {
        id(&format!("Microsoft.Compute/virtualMachines/{}", name))
    }

    fn items() -> Vec<Value> {
        vec![
            json!({"id": id("Microsoft.RecoveryServices/vaults/rsv-1/backupFabrics/Azure/protectionContainers/c/protectedItems/vm;a"),
                "name": "VM;iaasvmcontainerv2;rg-bk;vm-ok",
                "properties": {"protectedItemType": "Microsoft.Compute/virtualMachines", "workloadType": "VM",
                    "friendlyName": "vm-ok", "virtualMachineId": vm("vm-ok"), "sourceResourceId": vm("vm-ok"),
                    "protectionState": "Protected", "healthStatus": "Passed", "lastBackupStatus": "Completed",
                    "lastBackupTime": "2026-10-26T02:05:00Z", "lastRecoveryPoint": "2026-10-26T02:10:00Z",
                    "policyId": id("Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/DefaultPolicy"), "policyName": "DefaultPolicy",
                    "extendedInfo": {"recoveryPointCount": 30, "oldestRecoveryPoint": "2026-09-26T02:10:00Z"}}}),
            json!({"id": id("Microsoft.RecoveryServices/vaults/rsv-1/backupFabrics/Azure/protectionContainers/c/protectedItems/vm;b"),
                "name": "VM;iaasvmcontainerv2;rg-bk;vm-bad",
                "properties": {"workloadType": "VM", "friendlyName": "vm-bad", "sourceResourceId": vm("vm-bad"),
                    "protectionState": "Protected", "healthStatus": "ActionRequired", "lastBackupStatus": "Failed",
                    "lastBackupTime": "2026-10-25T02:05:00Z", "lastRecoveryPoint": "2026-10-23T02:10:00Z",
                    "policyId": id("Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/DefaultPolicy"), "policyName": "DefaultPolicy"}}),
            json!({"id": id("Microsoft.RecoveryServices/vaults/rsv-1/backupFabrics/Azure/protectionContainers/c/protectedItems/vm;c"),
                "name": "VM;iaasvmcontainerv2;rg-bk;vm-old",
                "properties": {"workloadType": "VM", "friendlyName": "vm-old", "sourceResourceId": vm("vm-old"),
                    "protectionState": "Protected", "lastBackupStatus": "Completed",
                    "lastBackupTime": "2026-10-20T02:05:00Z",
                    "policyId": id("Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/weekly"), "policyName": "weekly"}}),
        ]
    }

    fn policies() -> Vec<Value> {
        vec![
            json!({"id": id("Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/DefaultPolicy"), "name": "DefaultPolicy",
                "properties": {"backupManagementType": "AzureIaasVM", "protectedItemsCount": 2, "instantRpRetentionRangeInDays": 2,
                    "timeZone": "UTC", "policyType": "V1",
                    "schedulePolicy": {"schedulePolicyType": "SimpleSchedulePolicy", "scheduleRunFrequency": "Daily", "scheduleRunTimes": ["2024-01-01T02:00:00Z"]},
                    "retentionPolicy": {"retentionPolicyType": "LongTermRetentionPolicy",
                        "dailySchedule": {"retentionTimes": ["2024-01-01T02:00:00Z"], "retentionDuration": {"count": 30, "durationType": "Days"}},
                        "weeklySchedule": {"daysOfTheWeek": ["Sunday"], "retentionDuration": {"count": 12, "durationType": "Weeks"}}}}}),
            json!({"id": id("Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/weekly"), "name": "weekly",
                "properties": {"backupManagementType": "AzureIaasVM", "protectedItemsCount": 1,
                    "schedulePolicy": {"schedulePolicyType": "SimpleSchedulePolicy", "scheduleRunFrequency": "Weekly", "scheduleRunDays": ["Sunday"], "scheduleRunTimes": ["2024-01-01T03:00:00Z"]},
                    "retentionPolicy": {"retentionPolicyType": "LongTermRetentionPolicy",
                        "weeklySchedule": {"daysOfTheWeek": ["Sunday"], "retentionDuration": {"count": 1, "durationType": "Weeks"}}}}}),
            json!({"id": id("Microsoft.RecoveryServices/vaults/rsv-1/backupPolicies/sql"), "name": "sql",
                "properties": {"backupManagementType": "AzureWorkload", "workLoadType": "SQLDataBase",
                    "subProtectionPolicy": [
                        {"policyType": "Full", "schedulePolicy": {"schedulePolicyType": "SimpleSchedulePolicy", "scheduleRunFrequency": "Daily", "scheduleRunTimes": ["2024-01-01T22:00:00Z"]},
                         "retentionPolicy": {"retentionPolicyType": "LongTermRetentionPolicy", "dailySchedule": {"retentionDuration": {"count": 30, "durationType": "Days"}}}},
                        {"policyType": "Log", "schedulePolicy": {"schedulePolicyType": "LogSchedulePolicy", "scheduleFrequencyInMins": 60},
                         "retentionPolicy": {"retentionPolicyType": "SimpleRetentionPolicy", "retentionDuration": {"count": 15, "durationType": "Days"}}}]}}),
        ]
    }

    struct Store {
        items: LazyMap<Vec<Value>>,
        instances: LazyMap<Vec<Value>>,
        policies: LazyMap<Vec<Value>>,
        jobs: LazyMap<Vec<Value>>,
    }

    impl Store {
        fn new() -> Self {
            Store { items: LazyMap::default(), instances: LazyMap::default(), policies: LazyMap::default(), jobs: LazyMap::default() }
        }
        fn lazy(&self) -> BackupLazy<'_> {
            BackupLazy { items: &self.items, instances: &self.instances, policies: &self.policies, jobs: &self.jobs }
        }
    }

    #[test]
    fn a_recovery_vault_parses_its_security_settings() {
        let r = RecoveryVaultRow::from_json(&rsv_json(), None).unwrap();
        assert_eq!(r.redundancy.as_deref(), Some("GeoRedundant"));
        assert_eq!(r.list_summary().unwrap(), "GRS + cross-region restore · soft delete AlwaysON · immutable (locked) · 1 PE");
        assert!(!r.soft_delete_off());
        let sec = r.security_rows();
        assert!(has(&sec, "Immutability", "Locked"));
        assert!(has(&sec, "Multi-user authorization", "Enabled"));
        assert!(has(&sec, "Encryption", "customer-managed key https://kv-x.example/keys/k1"));
        assert!(has(&sec, "Private endpoint pe-rsv · Approved", "/privateEndpoints/pe-rsv"));
        assert!(has(&sec, "Alerts for job failures", "Enabled"));
        let rel = Resource::related(&r);
        assert!(rel.iter().any(|(l, _)| l == "Private endpoint pe-rsv"));
        assert_eq!(rel.iter().filter(|(l, _)| l == "Identity id-backup").count(), 1, "CMK identity deduplicated");
        assert!(r.cli_command().unwrap().starts_with("az backup vault show --ids /subscriptions/0000/"));
        assert_eq!(r.state_label(), "");
    }

    #[test]
    fn soft_delete_off_is_flagged() {
        let mut v = rsv_json();
        v["properties"]["securitySettings"]["softDeleteSettings"]["softDeleteState"] = json!("Disabled");
        let r = RecoveryVaultRow::from_json(&v, None).unwrap();
        assert!(r.soft_delete_off());
        assert!(r.security_rows().iter().any(|(_, l)| l.contains("⚠ soft delete is off")));
    }

    #[test]
    fn section_labels_match_the_descriptors() {
        let labels: Vec<&str> = RECOVERY_VAULT_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Security", "Protected items", "Policies", "Failed jobs", "Access", "Activity", "Related", "Tags"]);
        let labels: Vec<&str> = BACKUP_VAULT_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Security", "Backup instances", "Policies", "Jobs", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn protected_items_put_failures_first_and_flag_them() {
        let vault = id("Microsoft.RecoveryServices/vaults/rsv-1");
        let mut s = Store::new();
        s.items.apply(vault.clone(), Ok(items()));
        let lines = protected_items_rows(&vault, &s.lazy(), NOW);
        let t = text(&lines);
        assert!(has(&lines, "Items", "3 · 2 need attention"), "{t}");
        // Before the policies are read, vm-old (weekly, 6 days) is stale on the daily threshold.
        let bad = lines.iter().position(|(l, _)| l.starts_with("vm-bad")).unwrap();
        let ok = lines.iter().position(|(l, _)| l.starts_with("vm-ok")).unwrap();
        assert!(bad < ok, "{t}");
        assert!(t.contains("⚠ vm-bad: last backup Failed"), "{t}");
        assert!(t.contains("⚠ vm-bad: health ActionRequired"), "{t}");
        assert!(has(&lines, "  Source vm-ok", &vm("vm-ok")));
        assert!(has(&lines, "vm-ok · Azure VM", "Protected · last backup completed 2026-10-26 02:05 (9h ago)"), "{t}");
        assert!(has(&lines, "  Recovery points", "30 · oldest 2026-09-26 02:10:00"));
        assert!(t.contains("⚠ vm-old: last backup 153h ago (more than 36h)"), "{t}");
        // With the policies read, the weekly policy's threshold applies.
        s.policies.apply(vault.clone(), Ok(policies()));
        let t = text(&protected_items_rows(&vault, &s.lazy(), NOW));
        assert!(!t.contains("vm-old: last backup"), "{t}");
        assert!(!t.contains("⚠ vm-ok"), "{t}");
    }

    #[test]
    fn item_flags_read_failure_staleness_and_health() {
        let i = items();
        assert!(item_flags(&i[0], NOW, 36).is_empty());
        assert_eq!(item_flags(&i[1], NOW, 36)[0], ItemFlag::LastBackupFailed("Failed".into()));
        assert_eq!(item_flags(&i[2], NOW, 36), vec![ItemFlag::Stale(153, 36)]);
        assert!(item_flags(&i[2], NOW, STALE_HOURS_WEEKLY).is_empty());
        // Stopped protection is never stale; "never backed up" is not a time.
        let stopped = json!({"properties": {"protectionState": "ProtectionStopped", "lastBackupTime": "2020-01-01T00:00:00Z"}});
        assert!(item_flags(&stopped, NOW, 36).is_empty());
        let never = json!({"properties": {"protectionState": "Protected", "lastBackupTime": "0001-01-01T00:00:00Z"}});
        assert!(item_flags(&never, NOW, 36).is_empty());
        let sql = json!({"properties": {"protectionState": "Protected", "lastBackupStatus": "Unhealthy",
            "lastBackupErrorDetail": {"code": "UserErrorSQLNoSysadminMembership", "message": "no sysadmin"},
            "protectedItemHealthStatus": "Unhealthy"}});
        let f = item_flags(&sql, NOW, 36);
        assert_eq!(f[0], ItemFlag::LastBackupFailed("Unhealthy: no sysadmin".into()));
        assert_eq!(f[1], ItemFlag::Health("Unhealthy".into()));
    }

    #[test]
    fn stale_threshold_follows_the_policy_schedule() {
        let p = policies();
        assert_eq!(stale_hours(None), STALE_HOURS_DAILY);
        assert_eq!(stale_hours(Some(&p[0])), STALE_HOURS_DAILY);
        assert_eq!(stale_hours(Some(&p[1])), STALE_HOURS_WEEKLY);
        assert_eq!(stale_hours(Some(&p[2])), STALE_HOURS_DAILY);
    }

    #[test]
    fn policies_render_schedule_retention_and_instant_restore() {
        let lines = rsv_policy_rows(Some(&Lazy::Loaded(policies())));
        let t = text(&lines);
        assert!(has(&lines, "DefaultPolicy", "Azure VM · 2 items"), "{t}");
        assert!(has(&lines, "  Schedule", "daily at 02:00 (UTC)"), "{t}");
        assert!(has(&lines, "  Retention", "daily 30 days · weekly 12 weeks"), "{t}");
        assert!(has(&lines, "  Instant restore", "2 days of snapshots"), "{t}");
        assert!(has(&lines, "  Schedule", "weekly on Sunday at 03:00"), "{t}");
        assert!(has(&lines, "  Retention", "weekly 1 week"), "{t}");
        assert!(has(&lines, "  Full", "daily at 22:00 · keep daily 30 days"), "{t}");
        assert!(has(&lines, "  Log", "every 60 min (log backups) · keep 15 days"), "{t}");
    }

    #[test]
    fn schedules_cover_hourly_and_v2() {
        let v2 = json!({"schedulePolicyType": "SimpleSchedulePolicyV2", "scheduleRunFrequency": "Hourly",
            "hourlySchedule": {"interval": 4, "scheduleWindowStartTime": "2024-01-01T08:00:00Z", "scheduleWindowDuration": 12}});
        assert_eq!(schedule_text(&v2), "every 4h from 08:00 for 12h");
        let daily = json!({"scheduleRunFrequency": "Daily", "dailySchedule": {"scheduleRunTimes": ["2024-01-01T01:30:00Z"]}});
        assert_eq!(schedule_text(&daily), "daily at 01:30");
    }

    #[test]
    fn failed_jobs_render_newest_first_with_the_error() {
        let jobs = vec![
            json!({"name": "j1", "properties": {"entityFriendlyName": "vm-bad", "operation": "Backup", "status": "Failed",
                "startTime": "2026-10-24T02:00:00Z", "duration": "PT5M3.1234S", "jobType": "AzureIaaSVMJob",
                "errorDetails": [{"errorCode": "UserErrorVmNotInDesirableState", "errorString": "VM is not in a state that allows backups."}]}}),
            json!({"name": "j2", "properties": {"entityFriendlyName": "vm-bad", "operation": "Backup", "status": "Failed",
                "startTime": "2026-10-25T02:00:00Z"}}),
        ];
        let lines = rsv_job_rows(Some(&Lazy::Loaded(jobs)));
        assert_eq!(lines[0], ("Failed in the last 7 days".into(), "2".into()));
        assert!(lines[1].0.starts_with("2026-10-25"));
        assert!(has(&lines, "2026-10-24 02:00:00  vm-bad", "Backup failed · 5m 3s · UserErrorVmNotInDesirableState: VM is not"));
        assert_eq!(job_duration("PT18M44.31S"), "18m 44s");
        assert_eq!(job_duration("P1DT2H0M5S"), "1d 2h 5s");
        assert_eq!(job_duration("PT0S"), "0s");
        assert_eq!(rsv_job_rows(Some(&Lazy::Loaded(vec![])))[0].1, "No failed jobs in the last 7 days");
    }

    #[test]
    fn the_job_filter_uses_the_service_time_format() {
        assert_eq!(job_filter_time(NOW), "2026-10-26 12:00:00 PM");
        assert_eq!(job_filter_time(NOW - 12 * 3600 + 5 * 60), "2026-10-26 12:05:00 AM");
        assert_eq!(job_filter_time(NOW + 3 * 3600), "2026-10-26 03:00:00 PM");
        assert_eq!(
            failed_jobs_filter(NOW),
            "status eq 'Failed' and startTime eq '2026-10-19 12:00:00 PM' and endTime eq '2026-10-26 12:00:00 PM'"
        );
    }

    fn bv_json() -> Value {
        json!({
            "id": id("Microsoft.DataProtection/backupVaults/bv-1"),
            "name": "bv-1",
            "location": "westeurope",
            "identity": {"type": "SystemAssigned", "principalId": "p"},
            "properties": {
                "provisioningState": "Succeeded",
                "storageSettings": [{"datastoreType": "VaultStore", "type": "ZoneRedundant"}],
                "featureSettings": {"crossRegionRestoreSettings": {"state": "Disabled"}, "crossSubscriptionRestoreSettings": {"state": "Enabled"}},
                "securitySettings": {"softDeleteSettings": {"state": "On", "retentionDurationInDays": 14.0},
                    "immutabilitySettings": {"state": "Unlocked"}},
                "monitoringSettings": {"azureMonitorAlertSettings": {"alertsForAllJobFailures": "Enabled"}},
                "isVaultProtectedByResourceGuard": false,
                "secureScore": "Adequate"
            }
        })
    }

    fn instances() -> Vec<Value> {
        let st = id("Microsoft.Storage/storageAccounts/st1");
        let pg = id("Microsoft.DBforPostgreSQL/flexibleServers/pg1");
        vec![
            json!({"id": id("Microsoft.DataProtection/backupVaults/bv-1/backupInstances/st1-blobs"), "name": "st1-blobs",
                "properties": {"friendlyName": "st1", "currentProtectionState": "ProtectionConfigured",
                    "protectionStatus": {"status": "ProtectionConfigured"},
                    "dataSourceInfo": {"resourceID": st, "datasourceType": "Microsoft.Storage/storageAccounts/blobServices", "resourceName": "st1"},
                    "policyInfo": {"policyId": id("Microsoft.DataProtection/backupVaults/bv-1/backupPolicies/blob-30d")}}}),
            json!({"id": id("Microsoft.DataProtection/backupVaults/bv-1/backupInstances/pg1"), "name": "pg1",
                "properties": {"friendlyName": "pg1", "currentProtectionState": "ProtectionConfigured",
                    "protectionStatus": {"status": "ProtectionConfigured"},
                    "dataSourceInfo": {"resourceID": pg, "datasourceType": "Microsoft.DBforPostgreSQL/flexibleServers"},
                    "policyInfo": {"policyId": id("Microsoft.DataProtection/backupVaults/bv-1/backupPolicies/pg-weekly")},
                    "datasourceAuthCredentials": {"objectType": "SecretStoreBasedAuthCredentials",
                        "secretStoreResource": {"secretStoreType": "AzureKeyVault", "uri": "https://kv/secrets/s", "value": "hunter2"}}}}),
        ]
    }

    #[test]
    fn a_backup_vault_parses_storage_and_security() {
        let r = BackupVaultRow::from_json(&bv_json(), None).unwrap();
        assert_eq!(r.list_summary().unwrap(), "ZRS · soft delete On · immutable (unlocked)");
        assert!(!r.soft_delete_off() && !r.mua_on());
        let sec = r.security_rows();
        assert!(has(&sec, "Storage · VaultStore", "ZoneRedundant"));
        assert!(has(&sec, "Multi-user authorization", "off"));
        assert!(has(&sec, "  Retention", "14 days"));
        assert!(r.cli_command().unwrap().starts_with("az dataprotection backup-vault show --ids "));
    }

    #[test]
    fn backup_instances_take_their_last_backup_from_the_jobs() {
        let vault = id("Microsoft.DataProtection/backupVaults/bv-1");
        let mut s = Store::new();
        s.instances.apply(vault.clone(), Ok(instances().iter().map(without_secrets).collect()));
        let t = text(&backup_instance_rows(&vault, &s.lazy(), NOW));
        assert!(t.contains("Last backup | Loading…"), "{t}");
        let pg_bi = id("Microsoft.DataProtection/backupVaults/bv-1/backupInstances/pg1");
        s.jobs.apply(
            vault.clone(),
            Ok(vec![
                json!({"properties": {"backupInstanceId": pg_bi, "operationCategory": "Backup", "status": "Completed",
                    "startTime": "2026-10-19T01:00:00Z", "dataSourceName": "pg1", "operation": "Backup"}}),
                json!({"properties": {"backupInstanceId": pg_bi, "operationCategory": "Backup", "status": "Failed",
                    "startTime": "2026-10-26T01:00:00Z", "dataSourceName": "pg1", "operation": "Backup",
                    "errorDetails": [{"code": "UserErrorMissingPermissions", "message": "the vault's identity can't read the server"}]}}),
            ]),
        );
        let lines = backup_instance_rows(&vault, &s.lazy(), NOW);
        let t = text(&lines);
        assert!(has(&lines, "pg1 · PostgreSQL flexible", "ProtectionConfigured"), "{t}");
        assert!(has(&lines, "  Last backup", "failed 2026-10-26 01:00 (11h ago)"), "{t}");
        assert!(t.contains("⚠ pg1: last backup Failed"), "{t}");
        assert!(has(&lines, "  Policy", "pg-weekly"));
        assert!(has(&lines, "  Source st1", "/storageAccounts/st1"));
        assert!(t.contains("st1 · Blobs") && t.contains("no backup job in the vault's recent jobs"), "{t}");
        // An operational-tier policy (retention only) schedules no jobs.
        s.policies.apply(
            vault.clone(),
            Ok(vec![json!({"id": id("Microsoft.DataProtection/backupVaults/bv-1/backupPolicies/blob-30d"), "name": "blob-30d",
                "properties": {"policyRules": [{"objectType": "AzureRetentionRule", "name": "Default"}]}})]),
        );
        let t = text(&backup_instance_rows(&vault, &s.lazy(), NOW));
        assert!(t.contains("continuous (operational tier"), "{t}");
        assert!(!t.contains("hunter2"));
        let jobs = text(&dpp_job_rows(s.jobs.get(&vault)));
        assert!(jobs.contains("Recent jobs | 2 · 1 failed"), "{jobs}");
        assert!(jobs.contains("UserErrorMissingPermissions: the vault's identity"), "{jobs}");
    }

    #[test]
    fn the_instance_credential_is_stripped() {
        let raw = serde_json::to_string(&instances()[1]).unwrap();
        assert!(raw.contains("hunter2"));
        let clean = serde_json::to_string(&without_secrets(&instances()[1])).unwrap();
        for (i, needle) in ["hunter2", "datasourceAuthCredentials", "secretStoreResource"].iter().enumerate() {
            assert!(!clean.contains(needle), "fixture value {i} left in the JSON");
        }
        assert!(clean.contains("dataSourceInfo"));
    }

    #[test]
    fn dpp_policies_render_rules() {
        let pol = json!({"id": id("Microsoft.DataProtection/backupVaults/bv-1/backupPolicies/pg-weekly"), "name": "pg-weekly",
            "properties": {"objectType": "BackupPolicy", "datasourceTypes": ["Microsoft.DBforPostgreSQL/flexibleServers"],
                "policyRules": [
                    {"objectType": "AzureRetentionRule", "name": "Default", "isDefault": true,
                     "lifecycles": [{"deleteAfter": {"objectType": "AbsoluteDeleteOption", "duration": "P90D"},
                        "sourceDataStore": {"dataStoreType": "VaultStore", "objectType": "DataStoreInfoBase"}}]},
                    {"objectType": "AzureBackupRule", "name": "BackupWeekly",
                     "backupParameters": {"objectType": "AzureBackupParams", "backupType": "Full"},
                     "dataStore": {"dataStoreType": "VaultStore"},
                     "trigger": {"objectType": "ScheduleBasedTriggerContext",
                        "schedule": {"repeatingTimeIntervals": ["R/2026-01-04T02:00:00+00:00/P1W"], "timeZone": "UTC"}}}]}});
        let lines = dpp_policy_rows(Some(&Lazy::Loaded(vec![pol])));
        let t = text(&lines);
        assert!(has(&lines, "pg-weekly", "PostgreSQL flexible"), "{t}");
        assert!(lines[1].0.starts_with("  Backup"), "backup rules first: {t}");
        assert!(has(&lines, "  Backup · BackupWeekly", "weekly from 2026-01-04 at 02:00 (UTC) · Full · to VaultStore"), "{t}");
        assert!(has(&lines, "  Keep · Default (default)", "90 days in VaultStore"), "{t}");
        assert_eq!(repeating_interval_text("R/2026-01-04T02:00:00+00:00/P1D"), "daily at 02:00");
        assert_eq!(repeating_interval_text("R/2026-01-04T02:00:00+00:00/PT4H"), "every 4 hours from 02:00");
        assert_eq!(iso_duration("P1W"), "1 week");
    }

    #[test]
    fn the_reverse_lookup_finds_the_protecting_vault() {
        let rsv = id("Microsoft.RecoveryServices/vaults/rsv-1");
        let bv = id("Microsoft.DataProtection/backupVaults/bv-1");
        let mut s = Store::new();
        assert!(protection_of(&vm("vm-bad"), &s.lazy(), NOW).is_empty());
        s.items.apply(rsv.clone(), Ok(items()));
        s.instances.apply(bv.clone(), Ok(instances()));
        let p = protection_of(&vm("vm-bad").to_uppercase(), &s.lazy(), NOW);
        assert_eq!(p, vec![("Backed up by rsv-1 · DefaultPolicy · last backup failed 33h ago".to_string(), rsv.clone())]);
        let p = protection_of(&id("Microsoft.Storage/storageAccounts/st1"), &s.lazy(), NOW);
        assert_eq!(p, vec![("Backed up by bv-1 · Blobs".to_string(), bv)]);
        // Spliced into a Related body before its hint, or replacing "none".
        let rel = related_lines(vec![("Subscription".into(), "/subscriptions/0000".into())]);
        let out = with_protection(rel, protection_of(&vm("vm-ok"), &s.lazy(), NOW));
        assert_eq!(out[1].1, rsv);
        assert!(out.last().unwrap().1.starts_with("⏎"));
        let out = with_protection(related_lines(vec![]), protection_of(&vm("vm-ok"), &s.lazy(), NOW));
        assert!(out[0].0.starts_with("Backed up by rsv-1") && out.last().unwrap().1.starts_with("⏎"));
    }

    #[test]
    fn a_vaults_related_lists_what_it_protects_once_read() {
        let r = RecoveryVaultRow::from_json(&rsv_json(), None).unwrap();
        let mut s = Store::new();
        let before = recovery_vault_section_lines(&r, RecoveryVaultDetailSection::Related, &s.lazy(), NOW);
        assert!(!before.iter().any(|(l, _)| l.starts_with("Protects")));
        s.items.apply(r.base.id.clone(), Ok(items()));
        let after = recovery_vault_section_lines(&r, RecoveryVaultDetailSection::Related, &s.lazy(), NOW);
        assert!(has(&after, "Protects vm-ok", &vm("vm-ok")));
        assert_eq!(after.iter().filter(|(l, _)| l.starts_with("Protects")).count(), 3);
    }

    #[test]
    fn lazy_failures_render_as_warnings() {
        let vault = id("Microsoft.RecoveryServices/vaults/rsv-1");
        let mut s = Store::new();
        s.items.apply(vault.clone(), Err("403 AuthorizationFailed: no".into()));
        let lines = protected_items_rows(&vault, &s.lazy(), NOW);
        assert!(lines.iter().any(|(_, l)| l.starts_with("⚠ 403")));
        assert_eq!(protected_items_rows(&id("Microsoft.RecoveryServices/vaults/x"), &s.lazy(), NOW)[0].1, "Loading…");
    }
}
