//! Azure Virtual Desktop (#198, SERVICES.md rule 46): the Virtual Desktop
//! tab, four subscription-wide lists of `Microsoft.DesktopVirtualization`.
//! Host pools (their session hosts lazy), application groups, workspaces
//! and scaling plans (their schedules lazy).
//!
//! A host pool's registration token is a secret: the GET leaves it out
//! (`retrieveRegistrationToken` and `listRegistrationTokens` are POSTs,
//! never sent), and it is stripped before the store keeps a body
//! regardless ([`without_secrets`]), with the Key Vault path of the pool's
//! SSO secret. A user session is personal data and is never listed;
//! sending it a message and disconnecting it are POSTs, logging it off a
//! DELETE.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::backup::ago;
use crate::azure::services::directory::iso_to_unix;
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows, related_rows_with, tag_rows, ArmBase,
    Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The stable version before the newest (azure-rest-api-specs, checked
/// 2026-11-08): 2026-04-16 only adds the RDP Shortpath UDP settings and
/// was published days ago.
pub const AVD_API_VERSION: &str = "2025-10-10";
const HOST_POOLS_PATH: &str = "/providers/Microsoft.DesktopVirtualization/hostPools";
const APP_GROUPS_PATH: &str = "/providers/Microsoft.DesktopVirtualization/applicationGroups";
const WORKSPACES_PATH: &str = "/providers/Microsoft.DesktopVirtualization/workspaces";
const SCALING_PLANS_PATH: &str = "/providers/Microsoft.DesktopVirtualization/scalingPlans";

/// The most session hosts a pool's read keeps (the counts cover them).
pub const MAX_SESSION_HOSTS: usize = 500;
/// How many the section lists, trouble first.
const HOSTS_SHOWN: usize = 50;

const NEVER_TOKEN: &str = "a registration token is never read; user sessions are never listed";

crate::sections! {
    pub enum HostPoolDetailSection,
    pub static HOST_POOL_SECTIONS = [
        Overview "Overview",
        SessionHosts "Session hosts" => crate::app::App::trigger_avd_session_hosts,
        Configuration "Configuration",
        Network "Network",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_avd_pool_related,
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum AppGroupDetailSection,
    pub static APP_GROUP_SECTIONS = [
        Overview "Overview",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum AvdWorkspaceDetailSection,
    pub static AVD_WORKSPACE_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ScalingPlanDetailSection,
    pub static SCALING_PLAN_SECTIONS = [
        Overview "Overview",
        Schedules "Schedules" => crate::app::App::trigger_avd_schedules,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Secrets out ───────────────────────────────────────────────────────

/// Removed wherever they sit: the registration token (in
/// `registrationInfo`) and the Key Vault path of the SSO secret.
const SECRET_FIELDS: &[&str] = &["token", "ssoClientSecretKeyVaultPath"];

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
/// for `e`.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

/// `{parent}/{child}` for the child lists.
pub fn child_path(parent_id: &str, child: &str) -> String {
    format!("{}/{}", parent_id.trim_end_matches('/'), child)
}

fn private_endpoints(v: &Value) -> Vec<(String, Option<String>)> {
    json::arr(v, "/properties/privateEndpointConnections")
        .iter()
        .filter_map(|c| {
            Some((
                json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
            ))
        })
        .collect()
}

fn private_endpoint_rows(endpoints: &[(String, Option<String>)]) -> Vec<(String, String)> {
    if endpoints.is_empty() {
        return vec![("Private endpoints".into(), "none".into())];
    }
    endpoints
        .iter()
        .map(|(pe, status)| {
            let status = json::opt(status.clone());
            let status = if status.eq_ignore_ascii_case("approved") { status } else { format!("⚠ {}", status) };
            (format!("Private endpoint · {} ({})", name_of_id(pe), status), pe.clone())
        })
        .collect()
}

/// ARM ids from an array of id strings (`applicationGroupReferences`).
fn id_strings(v: &Value, ptr: &str) -> Vec<String> {
    json::strings_at(v, ptr).into_iter().filter_map(|s| json::arm_id(Some(s))).collect()
}

fn none_if_empty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.trim().is_empty())
}

// ── Host pools ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HostPoolRow {
    pub base: ArmBase,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub pool_type: Option<String>,
    pub assignment_type: Option<String>,
    pub preferred_app_group_type: Option<String>,
    pub load_balancer: Option<String>,
    pub max_sessions: Option<i64>,
    pub validation: Option<bool>,
    pub start_vm_on_connect: Option<bool>,
    pub registration_expiry: Option<String>,
    pub agent_update: Option<String>,
    pub maintenance_time_zone: Option<String>,
    pub use_local_time: Option<bool>,
    /// `Saturday 02:00` for each maintenance window.
    pub maintenance_windows: Vec<String>,
    pub custom_rdp: Option<String>,
    pub vm_template: Option<Value>,
    pub public_network_access: Option<String>,
    pub private_endpoints: Vec<(String, Option<String>)>,
    pub app_group_ids: Vec<String>,
    pub sso_secret_type: Option<String>,
}

impl HostPoolRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<HostPoolRow> {
        let v = &without_secrets(raw);
        let p = |f: &str| format!("/properties/{}", f);
        Some(HostPoolRow {
            friendly_name: none_if_empty(json::str_at(v, &p("friendlyName"))),
            description: none_if_empty(json::str_at(v, &p("description"))),
            pool_type: json::str_at(v, &p("hostPoolType")),
            assignment_type: none_if_empty(json::str_at(v, &p("personalDesktopAssignmentType"))),
            preferred_app_group_type: json::str_at(v, &p("preferredAppGroupType")),
            load_balancer: json::str_at(v, &p("loadBalancerType")),
            max_sessions: json::int_at(v, &p("maxSessionLimit")),
            validation: json::bool_at(v, &p("validationEnvironment")),
            start_vm_on_connect: json::bool_at(v, &p("startVMOnConnect")),
            registration_expiry: none_if_empty(json::str_at(v, &p("registrationInfo/expirationTime"))),
            agent_update: json::str_at(v, &p("agentUpdate/type")),
            maintenance_time_zone: none_if_empty(json::str_at(v, &p("agentUpdate/maintenanceWindowTimeZone"))),
            use_local_time: json::bool_at(v, &p("agentUpdate/useSessionHostLocalTime")),
            maintenance_windows: json::arr(v, &p("agentUpdate/maintenanceWindows"))
                .iter()
                .map(|w| format!("{} {:02}:00", json::text(w, "/dayOfWeek"), json::int_at(w, "/hour").unwrap_or(0)))
                .collect(),
            custom_rdp: none_if_empty(json::str_at(v, &p("customRdpProperty"))),
            vm_template: json::str_at(v, &p("vmTemplate")).and_then(|t| serde_json::from_str(&t).ok()),
            public_network_access: json::str_at(v, &p("publicNetworkAccess")),
            private_endpoints: private_endpoints(v),
            app_group_ids: id_strings(v, &p("applicationGroupReferences")),
            sso_secret_type: json::str_at(v, &p("ssoSecretType")),
            base: ArmBase::from_json(v, tenant)?,
        })
    }

    pub fn is_personal(&self) -> bool {
        self.pool_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("personal"))
    }

    /// `Automatic` or `Direct`; a personal pool with neither assigns no
    /// desktops on its own.
    pub fn assignment_text(&self) -> String {
        match (&self.assignment_type, self.is_personal()) {
            (Some(a), _) => a.clone(),
            (None, true) => "⚠ none (users get no desktop until one is assigned)".into(),
            (None, false) => "-".into(),
        }
    }

    fn type_text(&self) -> String {
        json::opt(self.pool_type.clone())
    }

    fn registration_text(&self, now: i64) -> String {
        match self.registration_expiry.as_deref().and_then(|e| Some((e, iso_to_unix(e)?))) {
            Some((_, t)) if t < now => format!("expired {} ({})", json::unix_to_ymdhm(t), ago(t, now)),
            Some((_, t)) => format!("valid until {} (hosts can register)", json::unix_to_ymdhm(t)),
            None => "none".into(),
        }
    }

    fn agent_update_text(&self) -> String {
        match self.agent_update.as_deref() {
            Some(t) if t.eq_ignore_ascii_case("scheduled") => {
                let zone = if self.use_local_time == Some(true) {
                    "each host's local time".to_string()
                } else {
                    json::opt(self.maintenance_time_zone.clone())
                };
                format!("scheduled: {} ({})", json::join(&self.maintenance_windows), zone)
            }
            Some(t) if t.eq_ignore_ascii_case("default") => "default (whenever an update is available)".into(),
            other => json::opt(other.map(str::to_string)),
        }
    }

    /// The image, size and name prefix from the VM template, when the
    /// pool was made with one.
    fn template_rows(&self) -> Vec<(String, String)> {
        let Some(t) = &self.vm_template else { return Vec::new() };
        let image = match (json::str_at(t, "/galleryImageOffer"), json::str_at(t, "/galleryImageSKU")) {
            (Some(offer), Some(sku)) => Some(format!("{} {}", offer, sku)),
            _ => json::str_at(t, "/customImageId").map(|id| name_of_id(&id).to_string()),
        };
        let mut lines = Vec::new();
        if let Some(prefix) = json::str_at(t, "/namePrefix") {
            lines.push(("VM name prefix".into(), prefix));
        }
        if let Some(size) = json::str_at(t, "/vmSize/id").or_else(|| json::str_at(t, "/vmSize")) {
            lines.push(("VM size".into(), size));
        }
        if let Some(image) = image {
            lines.push(("VM image".into(), image));
        }
        lines
    }

    fn configuration_rows(&self, now: i64) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Type".into(), self.type_text()),
            ("Preferred app group type".into(), json::opt(self.preferred_app_group_type.clone())),
        ];
        if self.is_personal() {
            lines.push(("Assignment type".into(), self.assignment_text()));
        } else {
            lines.push(("Load balancing".into(), json::opt(self.load_balancer.clone())));
            lines.push(("Max sessions per host".into(), json::num(self.max_sessions)));
        }
        lines.extend([
            ("Start VM on connect".into(), json::yes_no(self.start_vm_on_connect)),
            ("Validation environment".into(), json::yes_no(self.validation)),
            ("Registration token".into(), self.registration_text(now)),
            ("Agent updates".into(), self.agent_update_text()),
        ]);
        lines.extend(self.template_rows());
        if let Some(sso) = &self.sso_secret_type {
            lines.push(("SSO secret type".into(), sso.clone()));
        }
        match &self.custom_rdp {
            Some(rdp) => {
                for prop in rdp.split(';').map(str::trim).filter(|p| !p.is_empty()) {
                    lines.push(("RDP property".into(), prop.to_string()));
                }
            }
            None => lines.push(("RDP properties".into(), "defaults".into())),
        }
        lines.push((String::new(), String::new()));
        lines.push((String::new(), NEVER_TOKEN.into()));
        lines
    }

    fn network_rows(&self) -> Vec<(String, String)> {
        let access = match self.public_network_access.as_deref() {
            Some("EnabledForSessionHostsOnly") => "session hosts only (clients connect privately)".to_string(),
            Some("EnabledForClientsOnly") => "clients only (session hosts connect privately)".to_string(),
            other => json::opt(other.map(str::to_string)),
        };
        let mut lines = vec![("Public network access".into(), access)];
        lines.extend(private_endpoint_rows(&self.private_endpoints));
        lines
    }

    fn read_command(&self) -> String {
        format!("az desktopvirtualization hostpool show --ids {}", shell_quote(&self.base.id))
    }
}

impl Resource for HostPoolRow {
    arm_row!("Host pool");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&HOST_POOL_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let kind = self.type_text();
        Some(if self.is_personal() {
            format!("{} · {}", kind, self.assignment_type.clone().unwrap_or_else(|| "no assignment".into()))
        } else {
            match (&self.load_balancer, self.max_sessions) {
                (Some(lb), Some(n)) => format!("{} · {} · max {}", kind, lb, n),
                (Some(lb), None) => format!("{} · {}", kind, lb),
                _ => kind,
            }
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Friendly name".into(), json::opt(self.friendly_name.clone())),
            ("Type".into(), self.type_text()),
            ("Start VM on connect".into(), json::yes_no(self.start_vm_on_connect)),
            ("Validation environment".into(), json::yes_no(self.validation)),
            ("App groups".into(), self.app_group_ids.len().to_string()),
            ("Description".into(), json::opt(self.description.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for id in &self.app_group_ids {
            v.push((format!("App group {}", name_of_id(id)), id.clone()));
        }
        for (pe, _) in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(self.read_command())
    }
}

// ── Session hosts (lazy, per pool) ────────────────────────────────────

/// One session host from `{pool}/sessionHosts`.
#[derive(Debug, Clone)]
pub struct SessionHost {
    /// The host name, without the pool's `{pool}/` prefix.
    pub name: String,
    pub status: Option<String>,
    pub allow_new_sessions: Option<bool>,
    pub sessions: Option<i64>,
    pub assigned_user: Option<String>,
    pub last_heartbeat: Option<String>,
    pub agent_version: Option<String>,
    pub os_version: Option<String>,
    pub update_state: Option<String>,
    pub update_error: Option<String>,
    /// The VM (or Arc machine) behind the host.
    pub vm_id: Option<String>,
    /// `(check, message)` of each failed health check.
    pub failed_checks: Vec<(String, String)>,
}

impl SessionHost {
    pub fn from_json(v: &Value) -> SessionHost {
        let p = |f: &str| format!("/properties/{}", f);
        let name = json::text(v, "/name");
        SessionHost {
            name: name.rsplit('/').next().unwrap_or(&name).to_string(),
            status: json::str_at(v, &p("status")),
            allow_new_sessions: json::bool_at(v, &p("allowNewSession")),
            sessions: json::int_at(v, &p("sessions")),
            assigned_user: none_if_empty(json::str_at(v, &p("assignedUser"))),
            last_heartbeat: json::str_at(v, &p("lastHeartBeat")),
            agent_version: json::str_at(v, &p("agentVersion")),
            os_version: json::str_at(v, &p("osVersion")),
            update_state: json::str_at(v, &p("updateState")),
            update_error: none_if_empty(json::str_at(v, &p("updateErrorMessage"))),
            vm_id: json::arm_id(json::str_at(v, &p("resourceId"))),
            failed_checks: json::arr(v, &p("sessionHostHealthCheckResults"))
                .iter()
                .filter(|c| json::str_at(c, "/healthCheckResult").as_deref() == Some("HealthCheckFailed"))
                .map(|c| (json::text(c, "/healthCheckName"), json::text(c, "/additionalFailureDetails/message")))
                .collect(),
        }
    }

    fn status_is(&self, any: &[&str]) -> bool {
        self.status.as_deref().is_some_and(|s| any.iter().any(|a| s.eq_ignore_ascii_case(a)))
    }

    /// The broker sends new sessions here: `Available`, and the states
    /// Learn says still load balance (`NeedsAssistance` fails only
    /// non-fatal checks; `UpgradeFailed`, `Upgrading`), unless drained.
    pub fn takes_new_sessions(&self) -> bool {
        self.status_is(&["Available", "NeedsAssistance", "UpgradeFailed", "Upgrading"]) && self.allow_new_sessions != Some(false)
    }

    /// Needs someone: anything but `Available`, except `Shutdown` (what a
    /// scaling plan or an idle personal desktop leaves) and `Upgrading`.
    pub fn is_trouble(&self) -> bool {
        !self.status_is(&["Available", "Shutdown", "Upgrading"])
    }

    pub fn update_failed(&self) -> bool {
        self.update_state.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("failed"))
            || self.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("upgradefailed"))
    }

    fn status_text(&self) -> String {
        let s = json::opt(self.status.clone());
        if self.is_trouble() {
            format!("⚠ {}", s)
        } else {
            s
        }
    }
}

/// `(major, minor, build, revision)` of an agent version
/// (`1.0.11388.1700`), for comparing hosts.
pub fn agent_version_key(v: &str) -> Option<Vec<u64>> {
    v.split('.').map(|p| p.trim().parse().ok()).collect()
}

/// The Session hosts body: the counts, then each host (trouble first)
/// with its VM as a jump, status, drain mode, sessions, heartbeat, agent
/// and the health checks that failed.
pub fn session_host_rows(items: &[Value], now: i64) -> Vec<(String, String)> {
    let mut hosts: Vec<SessionHost> = items.iter().map(SessionHost::from_json).collect();
    if hosts.is_empty() {
        return vec![(String::new(), "No session hosts (none has registered with the pool)".into())];
    }
    hosts.sort_by_key(|h| (!h.is_trouble(), h.name.to_lowercase()));
    let open = hosts.iter().filter(|h| h.takes_new_sessions()).count();
    let sessions: i64 = hosts.iter().filter_map(|h| h.sessions).sum();
    let trouble = hosts.iter().filter(|h| h.is_trouble()).count();
    let mut summary = format!("{} · {} taking new sessions · {} sessions", hosts.len(), open, sessions);
    if hosts.len() >= MAX_SESSION_HOSTS {
        summary = format!("the first {} · {} taking new sessions · {} sessions", MAX_SESSION_HOSTS, open, sessions);
    }
    let mut lines = vec![("Session hosts".into(), summary)];
    if open == 0 {
        lines.push(("Taking new sessions".into(), "⚠ none: new connections fail".into()));
    }
    if trouble > 0 {
        lines.push(("Need attention".into(), format!("⚠ {}", trouble)));
    }
    for h in hosts.iter().take(HOSTS_SHOWN) {
        lines.push((String::new(), String::new()));
        lines.push((h.name.clone(), h.vm_id.clone().unwrap_or_default()));
        lines.push(("  Status".into(), h.status_text()));
        lines.push((
            "  New sessions".into(),
            match h.allow_new_sessions {
                Some(false) => "not allowed (drain mode)".into(),
                other => json::yes_no(other),
            },
        ));
        lines.push(("  Sessions".into(), json::num(h.sessions)));
        if let Some(u) = &h.assigned_user {
            lines.push(("  Assigned user".into(), u.clone()));
        }
        let heartbeat = match h.last_heartbeat.as_deref().and_then(iso_to_unix) {
            Some(t) => format!("{} ({})", json::unix_to_ymdhm(t), ago(t, now)),
            None => "-".into(),
        };
        lines.push(("  Last heartbeat".into(), heartbeat));
        let agent = json::opt(h.agent_version.clone());
        lines.push((
            "  Agent".into(),
            if h.update_failed() {
                format!("⚠ {} (update failed{})", agent, h.update_error.as_ref().map(|e| format!(": {}", e)).unwrap_or_default())
            } else {
                agent
            },
        ));
        lines.push(("  OS version".into(), json::opt(h.os_version.clone())));
        if h.failed_checks.is_empty() {
            lines.push(("  Health checks".into(), "passed".into()));
        }
        for (check, message) in &h.failed_checks {
            lines.push((format!("  ⚠ {}", check), message.clone()));
        }
    }
    if hosts.len() > HOSTS_SHOWN {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("… {} more hosts not shown", hosts.len() - HOSTS_SHOWN)));
    }
    lines
}

/// The VMs behind a pool's session hosts, for Related.
fn session_host_vms(items: &[Value]) -> Vec<(String, String)> {
    items
        .iter()
        .map(SessionHost::from_json)
        .filter_map(|h| Some((format!("Session host {}", h.name), h.vm_id?)))
        .collect()
}

/// Every pool whose session hosts read this session names `vm_id`: what
/// a VM's Related says ("session host in pool X"), with no call.
pub fn pools_hosting<'a>(
    vm_id: &str,
    reads: impl Iterator<Item = (&'a String, &'a Lazy<Vec<Value>>)>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (pool, lazy) in reads {
        let Lazy::Loaded(items) = lazy else { continue };
        if items
            .iter()
            .any(|h| json::str_at(h, "/properties/resourceId").is_some_and(|id| id.eq_ignore_ascii_case(vm_id)))
        {
            out.push((format!("Session host in pool {}", name_of_id(pool)), pool.clone()));
        }
    }
    out.sort();
    out
}

// ── Application groups ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AppGroupRow {
    pub base: ArmBase,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub group_type: Option<String>,
    pub host_pool: Option<String>,
    pub workspace: Option<String>,
    pub show_in_feed: Option<bool>,
}

impl AppGroupRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<AppGroupRow> {
        let v = &without_secrets(raw);
        let p = |f: &str| format!("/properties/{}", f);
        Some(AppGroupRow {
            friendly_name: none_if_empty(json::str_at(v, &p("friendlyName"))),
            description: none_if_empty(json::str_at(v, &p("description"))),
            group_type: json::str_at(v, &p("applicationGroupType")),
            host_pool: json::arm_id(json::str_at(v, &p("hostPoolArmPath"))),
            workspace: json::arm_id(json::str_at(v, &p("workspaceArmPath"))),
            show_in_feed: json::bool_at(v, &p("showInFeed")),
            base: ArmBase::from_json(v, tenant)?,
        })
    }

    /// No workspace publishes it: its users see nothing in their feed.
    pub fn is_unpublished(&self) -> bool {
        self.workspace.is_none()
    }
}

impl Resource for AppGroupRow {
    arm_row!("Application group");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&APP_GROUP_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let kind = json::opt(self.group_type.clone());
        Some(match &self.host_pool {
            Some(hp) => format!("{} · {}", kind, name_of_id(hp)),
            None => kind,
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Friendly name".into(), json::opt(self.friendly_name.clone())),
            ("Type".into(), json::opt(self.group_type.clone())),
        ];
        match &self.host_pool {
            Some(hp) => lines.push((format!("Host pool · {}", name_of_id(hp)), hp.clone())),
            None => lines.push(("Host pool".into(), "-".into())),
        }
        match &self.workspace {
            Some(ws) => lines.push((format!("Workspace · {}", name_of_id(ws)), ws.clone())),
            None => lines.push(("Workspace".into(), "⚠ none: no workspace publishes it, so its users see nothing".into())),
        }
        if self.show_in_feed.is_some() {
            lines.push(("Shown in feed".into(), json::yes_no(self.show_in_feed)));
        }
        lines.push(("Description".into(), json::opt(self.description.clone())));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(hp) = &self.host_pool {
            v.push((format!("Host pool {}", name_of_id(hp)), hp.clone()));
        }
        if let Some(ws) = &self.workspace {
            v.push((format!("Workspace {}", name_of_id(ws)), ws.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az desktopvirtualization applicationgroup show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Workspaces ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AvdWorkspaceRow {
    pub base: ArmBase,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub app_group_ids: Vec<String>,
    pub public_network_access: Option<String>,
    pub private_endpoints: Vec<(String, Option<String>)>,
}

impl AvdWorkspaceRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<AvdWorkspaceRow> {
        let v = &without_secrets(raw);
        let p = |f: &str| format!("/properties/{}", f);
        Some(AvdWorkspaceRow {
            friendly_name: none_if_empty(json::str_at(v, &p("friendlyName"))),
            description: none_if_empty(json::str_at(v, &p("description"))),
            app_group_ids: id_strings(v, &p("applicationGroupReferences")),
            public_network_access: json::str_at(v, &p("publicNetworkAccess")),
            private_endpoints: private_endpoints(v),
            base: ArmBase::from_json(v, tenant)?,
        })
    }

    fn network_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Public network access".into(), json::opt(self.public_network_access.clone()))];
        lines.extend(private_endpoint_rows(&self.private_endpoints));
        lines
    }
}

impl Resource for AvdWorkspaceRow {
    arm_row!("AVD workspace");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&AVD_WORKSPACE_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        Some(match self.app_group_ids.len() {
            1 => "1 app group".into(),
            n => format!("{} app groups", n),
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Friendly name".into(), json::opt(self.friendly_name.clone())),
        ];
        if self.app_group_ids.is_empty() {
            lines.push(("App groups".into(), "none: the workspace publishes nothing".into()));
        }
        for id in &self.app_group_ids {
            lines.push((format!("App group · {}", name_of_id(id)), id.clone()));
        }
        lines.push(("Public network access".into(), json::opt(self.public_network_access.clone())));
        lines.push(("Description".into(), json::opt(self.description.clone())));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for id in &self.app_group_ids {
            v.push((format!("App group {}", name_of_id(id)), id.clone()));
        }
        for (pe, _) in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az desktopvirtualization workspace show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Scaling plans ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScalingPlanRow {
    pub base: ArmBase,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub time_zone: Option<String>,
    pub pool_type: Option<String>,
    pub exclusion_tag: Option<String>,
    /// `(host pool id, scaling enabled)` for each pool the plan names.
    pub host_pools: Vec<(String, Option<bool>)>,
}

impl ScalingPlanRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ScalingPlanRow> {
        let v = &without_secrets(raw);
        let p = |f: &str| format!("/properties/{}", f);
        Some(ScalingPlanRow {
            friendly_name: none_if_empty(json::str_at(v, &p("friendlyName"))),
            description: none_if_empty(json::str_at(v, &p("description"))),
            time_zone: json::str_at(v, &p("timeZone")),
            pool_type: json::str_at(v, &p("hostPoolType")),
            exclusion_tag: none_if_empty(json::str_at(v, &p("exclusionTag"))),
            host_pools: json::arr(v, &p("hostPoolReferences"))
                .iter()
                .filter_map(|r| {
                    Some((json::arm_id(json::str_at(r, "/hostPoolArmPath"))?, json::bool_at(r, "/scalingPlanEnabled")))
                })
                .collect(),
            base: ArmBase::from_json(v, tenant)?,
        })
    }

    pub fn is_personal(&self) -> bool {
        self.pool_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("personal"))
    }

    /// `pooledSchedules` or `personalSchedules`: the child list the
    /// plan's pool type keeps its schedules in.
    pub fn schedules_child(&self) -> &'static str {
        if self.is_personal() {
            "personalSchedules"
        } else {
            "pooledSchedules"
        }
    }

    /// Whether the plan scales `pool` (named and enabled).
    pub fn scales(&self, pool: &str) -> Option<bool> {
        self.host_pools.iter().find(|(id, _)| id.eq_ignore_ascii_case(pool)).map(|(_, on)| *on != Some(false))
    }
}

impl Resource for ScalingPlanRow {
    arm_row!("Scaling plan");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SCALING_PLAN_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let pools = match self.host_pools.len() {
            1 => "1 host pool".to_string(),
            n => format!("{} host pools", n),
        };
        Some(format!("{} · {}", json::opt(self.pool_type.clone()), pools))
    }
    fn details(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Friendly name".into(), json::opt(self.friendly_name.clone())),
            ("Host pool type".into(), json::opt(self.pool_type.clone())),
            ("Time zone".into(), json::opt(self.time_zone.clone())),
            ("Exclusion tag".into(), json::opt(self.exclusion_tag.clone())),
        ];
        if self.host_pools.is_empty() {
            lines.push(("Host pools".into(), "none: the plan scales nothing".into()));
        }
        for (id, enabled) in &self.host_pools {
            let label = match enabled {
                Some(false) => format!("Host pool · {} (scaling off)", name_of_id(id)),
                _ => format!("Host pool · {}", name_of_id(id)),
            };
            lines.push((label, id.clone()));
        }
        lines.push(("Description".into(), json::opt(self.description.clone())));
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for (id, _) in &self.host_pools {
            v.push((format!("Host pool {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        // No `az desktopvirtualization` group for scaling plans.
        Some(format!("az resource show --ids {}", shell_quote(&self.base.id)))
    }
}

/// `06:30`, or `-`.
fn clock(s: &Value, field: &str) -> String {
    match (json::int_at(s, &format!("/properties/{}/hour", field)), json::int_at(s, &format!("/properties/{}/minute", field))) {
        (Some(h), m) => format!("{:02}:{:02}", h, m.unwrap_or(0)),
        _ => "-".into(),
    }
}

fn pct(s: &Value, field: &str) -> String {
    json::int_at(s, &format!("/properties/{}", field)).map(|n| format!("{}%", n)).unwrap_or_else(|| "-".into())
}

/// `deallocate after 30 min`, `none`.
fn session_action(s: &Value, phase: &str, event: &str) -> String {
    let p = |f: &str| format!("/properties/{}{}", phase, f);
    let action = json::str_at(s, &p(&format!("ActionOn{}", event))).unwrap_or_else(|| "None".into());
    if action.eq_ignore_ascii_case("none") {
        return "none".into();
    }
    match json::int_at(s, &p(&format!("MinutesToWaitOn{}", event))) {
        Some(m) => format!("{} after {} min", action.to_lowercase(), m),
        None => action.to_lowercase(),
    }
}

/// The Schedules body: each schedule's days, then its four phases with
/// what each does (load balancing and capacity for a pooled plan; start
/// and disconnect / log-off actions for a personal one).
pub fn schedule_rows(items: &[Value], plan: &ScalingPlanRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No schedules: the plan never scales".into()));
    }
    let mut schedules: Vec<&Value> = items.iter().collect();
    schedules.sort_by_key(|s| json::text(s, "/name").to_lowercase());
    for s in schedules {
        let name = json::text(s, "/name");
        lines.push((String::new(), String::new()));
        lines.push((name.rsplit('/').next().unwrap_or(&name).to_string(), String::new()));
        lines.push(("  Days".into(), json::join(&json::strings_at(s, "/properties/daysOfWeek"))));
        for (label, phase) in [("Ramp-up", "rampUp"), ("Peak", "peak"), ("Ramp-down", "rampDown"), ("Off-peak", "offPeak")] {
            let start = clock(s, &format!("{}StartTime", phase));
            let detail = if plan.is_personal() {
                let mut parts = Vec::new();
                if let Some(auto) = json::str_at(s, &format!("/properties/{}AutoStartHosts", phase)) {
                    parts.push(format!("start {}", auto));
                }
                if let Some(svc) = json::str_at(s, &format!("/properties/{}StartVMOnConnect", phase)) {
                    parts.push(format!("start VM on connect {}", svc.to_lowercase()));
                }
                parts.push(format!("disconnect: {}", session_action(s, phase, "Disconnect")));
                parts.push(format!("log off: {}", session_action(s, phase, "Logoff")));
                parts.join(" · ")
            } else {
                let mut parts = vec![json::text(s, &format!("/properties/{}LoadBalancingAlgorithm", phase))];
                if s.pointer(&format!("/properties/{}MinimumHostsPct", phase)).is_some() {
                    parts.push(format!("min hosts {}", pct(s, &format!("{}MinimumHostsPct", phase))));
                }
                if s.pointer(&format!("/properties/{}CapacityThresholdPct", phase)).is_some() {
                    parts.push(format!("capacity {}", pct(s, &format!("{}CapacityThresholdPct", phase))));
                }
                parts.join(" · ")
            };
            lines.push((format!("  {}", label), format!("{} · {}", start, detail)));
        }
        if !plan.is_personal() {
            let force = json::bool_at(s, "/properties/rampDownForceLogoffUsers");
            let stop = json::text(s, "/properties/rampDownStopHostsWhen");
            let users = match (force, json::int_at(s, "/properties/rampDownWaitTimeMinutes")) {
                (Some(true), Some(m)) => format!("logged off after {} min", m),
                (Some(true), None) => "logged off".into(),
                _ => "not logged off".into(),
            };
            lines.push(("  Ramp-down users".into(), format!("{} · hosts stop at {}", users, stop)));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push(("Time zone".into(), json::opt(plan.time_zone.clone())));
    lines
}

// ── Sections ──────────────────────────────────────────────────────────

/// Every lazy read the AVD sections draw on.
#[derive(Default, Clone, Copy)]
pub struct AvdLazy<'a> {
    pub session_hosts: Option<&'a Lazy<Vec<Value>>>,
    pub schedules: Option<&'a Lazy<Vec<Value>>>,
    /// The scaling plans list, for a pool's Related (`None` while cold).
    pub scaling_plans: Option<&'a [Box<dyn Resource>]>,
}

/// Body lines for one section of an AVD row; `None` for another type.
pub fn avd_section_lines(r: &dyn Resource, idx: usize, lazy: AvdLazy, now: i64) -> Option<Vec<(String, String)>> {
    let any = r.as_any();
    if let Some(x) = any.downcast_ref::<HostPoolRow>() {
        use HostPoolDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::SessionHosts => lazy_list_rows(lazy.session_hosts, "Session hosts", |items| session_host_rows(items, now)),
            S::Configuration => x.configuration_rows(now),
            S::Network => x.network_rows(),
            S::Access | S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => {
                let mut extra = Vec::new();
                for plan in lazy.scaling_plans.unwrap_or_default() {
                    let Some(p) = plan.as_any().downcast_ref::<ScalingPlanRow>() else { continue };
                    match p.scales(&x.base.id) {
                        Some(true) => extra.push((format!("Scaling plan {}", p.base.name), p.base.id.clone())),
                        Some(false) => extra.push((format!("Scaling plan {} (scaling off)", p.base.name), p.base.id.clone())),
                        None => {}
                    }
                }
                if let Some(Lazy::Loaded(items)) = lazy.session_hosts {
                    extra.extend(session_host_vms(items));
                }
                related_rows_with(x, extra)
            }
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<AppGroupRow>() {
        use AppGroupDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Access | S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_rows(x),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = any.downcast_ref::<AvdWorkspaceRow>() {
        use AvdWorkspaceDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Network => x.network_rows(),
            S::Access | S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_rows(x),
            S::Tags => tag_rows(x.tags()),
        });
    }
    let x = any.downcast_ref::<ScalingPlanRow>()?;
    use ScalingPlanDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Schedules => lazy_list_rows(lazy.schedules, "Schedules", |items| schedule_rows(items, x)),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => related_rows(x),
        S::Tags => tag_rows(x.tags()),
    })
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct VirtualDesktopService {
    scope: Scope,
}

impl VirtualDesktopService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<R: Resource + 'static>(rows: impl Iterator<Item = R>) -> Vec<Box<dyn Resource>> {
        rows.map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::AvdApplicationGroups => Self::boxed(page.iter().filter_map(|v| AppGroupRow::from_json(v, tenant))),
            JumpView::AvdWorkspaces => Self::boxed(page.iter().filter_map(|v| AvdWorkspaceRow::from_json(v, tenant))),
            JumpView::ScalingPlans => Self::boxed(page.iter().filter_map(|v| ScalingPlanRow::from_json(v, tenant))),
            _ => Self::boxed(page.iter().filter_map(|v| HostPoolRow::from_json(v, tenant))),
        }
    }

    fn path_of(view: JumpView) -> (&'static str, &'static str) {
        match view {
            JumpView::AvdApplicationGroups => (APP_GROUPS_PATH, "Listing application groups…"),
            JumpView::AvdWorkspaces => (WORKSPACES_PATH, "Listing AVD workspaces…"),
            JumpView::ScalingPlans => (SCALING_PLANS_PATH, "Listing scaling plans…"),
            _ => (HOST_POOLS_PATH, "Listing host pools…"),
        }
    }
}

#[async_trait]
impl AzureService for VirtualDesktopService {
    fn service_type(&self) -> ServiceType {
        ServiceType::VirtualDesktop
    }

    fn name(&self) -> &str {
        "Virtual Desktop"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, _) = Self::path_of(view);
        let page = self.scope.list(path, AVD_API_VERSION).await?;
        Ok(Self::rows(view, &page, self.scope.tenant()))
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let (path, message) = Self::path_of(view);
        let r = self
            .scope
            .stream(path, AVD_API_VERSION, &[], service_type, message, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::HostPools);
        let v = self.scope.get(id, AVD_API_VERSION).await?;
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-avd";
    /// 2026-11-07T00:00:00Z.
    const NOW: i64 = 1_794_009_600;

    fn dv(path: &str) -> String {
        format!("{}/providers/Microsoft.DesktopVirtualization/{}", RG, path)
    }

    fn vm(name: &str) -> String {
        format!("{}/providers/Microsoft.Compute/virtualMachines/{}", RG, name)
    }

    fn pool(kind: &str, assignment: Option<&str>) -> HostPoolRow {
        HostPoolRow::from_json(
            &json!({
                "id": dv("hostPools/hp-1"), "name": "hp-1", "location": "westeurope",
                "properties": {
                    "hostPoolType": kind, "personalDesktopAssignmentType": assignment,
                    "loadBalancerType": "BreadthFirst", "maxSessionLimit": 12, "preferredAppGroupType": "Desktop",
                    "startVMOnConnect": true, "validationEnvironment": false,
                    "registrationInfo": {"expirationTime": "2026-11-01T00:00:00Z", "token": "planted", "registrationTokenOperation": "Update"},
                    "ssoClientSecretKeyVaultPath": "https://kv.example/secrets/planted",
                    "agentUpdate": {"type": "Scheduled", "maintenanceWindowTimeZone": "W. Europe Standard Time",
                        "maintenanceWindows": [{"dayOfWeek": "Saturday", "hour": 2}]},
                    "customRdpProperty": "drivestoredirect:s:;audiomode:i:0;",
                    "vmTemplate": "{\"namePrefix\":\"avd\",\"vmSize\":{\"id\":\"Standard_D4s_v5\"},\"galleryImageOffer\":\"windows-11\",\"galleryImageSKU\":\"win11-24h2-avd\"}",
                    "publicNetworkAccess": "EnabledForClientsOnly",
                    "applicationGroupReferences": [dv("applicationGroups/dag-1")]
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

    fn host(name: &str, status: &str, agent: &str, failed: Option<&str>) -> Value {
        let checks: Vec<Value> = match failed {
            Some(c) => vec![json!({"healthCheckName": c, "healthCheckResult": "HealthCheckFailed",
                "additionalFailureDetails": {"message": "a required URL is blocked"}})],
            None => vec![json!({"healthCheckName": "DomainJoinedCheck", "healthCheckResult": "HealthCheckSucceeded"})],
        };
        json!({"name": format!("hp-1/{}", name), "properties": {
            "status": status, "allowNewSession": status != "Shutdown", "sessions": 2, "agentVersion": agent,
            "lastHeartBeat": "2026-11-06T23:00:00Z", "osVersion": "10.0.26100", "updateState": "Succeeded",
            "resourceId": vm(name.split('.').next().unwrap()), "sessionHostHealthCheckResults": checks
        }})
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels = |d: &crate::sections::SectionDescriptor| d.sections.iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(
            labels(&HOST_POOL_SECTIONS),
            ["Overview", "Session hosts", "Configuration", "Network", "Access", "Activity", "Related", "Tags"]
        );
        assert_eq!(labels(&APP_GROUP_SECTIONS), ["Overview", "Access", "Activity", "Related", "Tags"]);
        assert_eq!(labels(&AVD_WORKSPACE_SECTIONS), ["Overview", "Network", "Access", "Activity", "Related", "Tags"]);
        assert_eq!(labels(&SCALING_PLAN_SECTIONS), ["Overview", "Schedules", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn the_registration_token_and_sso_secret_path_never_reach_the_store() {
        let row = pool("Pooled", None);
        assert!(!row.base.raw.contains("planted"), "a planted value survived the scrub");
        assert!(row.base.raw.contains("expirationTime"));
    }

    #[test]
    fn a_pooled_pool_reads_its_configuration_and_the_ids_command() {
        let row = pool("Pooled", None);
        assert_eq!(row.list_summary().as_deref(), Some("Pooled · BreadthFirst · max 12"));
        assert_eq!(row.cli_command(), Some(format!("az desktopvirtualization hostpool show --ids {}", dv("hostPools/hp-1"))));
        let config = row.configuration_rows(NOW);
        assert_eq!(get(&config, "Registration token"), Some("expired 2026-11-01 00:00 (6d ago)"));
        assert_eq!(get(&config, "Agent updates"), Some("scheduled: Saturday 02:00 (W. Europe Standard Time)"));
        assert_eq!(get(&config, "VM image"), Some("windows-11 win11-24h2-avd"));
        assert_eq!(get(&config, "VM size"), Some("Standard_D4s_v5"));
        assert_eq!(all(&config, "RDP property"), ["drivestoredirect:s:", "audiomode:i:0"]);
        assert_eq!(get(&config, "Assignment type"), None, "a pooled pool has none");
        assert_eq!(get(&row.network_rows(), "Public network access"), Some("clients only (session hosts connect privately)"));
        assert!(row.related().iter().any(|(l, id)| l == "App group dag-1" && id == &dv("applicationGroups/dag-1")));
    }

    #[test]
    fn a_personal_pool_without_an_assignment_type_is_flagged() {
        let row = pool("Personal", None);
        assert_eq!(row.list_summary().as_deref(), Some("Personal · no assignment"));
        assert!(get(&row.configuration_rows(NOW), "Assignment type").unwrap().starts_with("⚠ none"));
        assert_eq!(pool("Personal", Some("Automatic")).assignment_text(), "Automatic");
    }

    #[test]
    fn session_hosts_list_trouble_first_with_their_vm_and_failed_checks() {
        let items = vec![
            host("avd-0.contoso.com", "Available", "1.0.11388.1700", None),
            host("avd-1.contoso.com", "NeedsAssistance", "1.0.9742.1100", Some("UrlsAccessibleCheck")),
            host("avd-2.contoso.com", "Shutdown", "1.0.11388.1700", None),
        ];
        let lines = session_host_rows(&items, NOW);
        assert_eq!(get(&lines, "Session hosts"), Some("3 · 2 taking new sessions · 6 sessions"));
        assert_eq!(get(&lines, "Need attention"), Some("⚠ 1"));
        assert_eq!(all(&lines, "  Status"), ["⚠ NeedsAssistance", "Available", "Shutdown"]);
        assert_eq!(get(&lines, "avd-1.contoso.com"), Some(vm("avd-1").as_str()), "the host line jumps to its VM");
        assert_eq!(get(&lines, "  ⚠ UrlsAccessibleCheck"), Some("a required URL is blocked"));
        assert_eq!(all(&lines, "  New sessions"), ["yes", "yes", "not allowed (drain mode)"]);
        assert_eq!(all(&lines, "  Last heartbeat")[0], "2026-11-06 23:00 (1h ago)");

        let none = session_host_rows(&[host("avd-2.contoso.com", "Shutdown", "1", None)], NOW);
        assert_eq!(get(&none, "Taking new sessions"), Some("⚠ none: new connections fail"));
        assert!(session_host_rows(&[], NOW)[0].1.starts_with("No session hosts"));
    }

    #[test]
    fn a_vm_names_the_pool_whose_hosts_it_is_and_a_pool_names_its_scaling_plan() {
        let pool_id = dv("hostPools/hp-1");
        let read = Lazy::Loaded(vec![host("avd-0.contoso.com", "Available", "1", None)]);
        let reads = [(pool_id.clone(), read)];
        let found = pools_hosting(&vm("avd-0"), reads.iter().map(|(k, v)| (k, v)));
        assert_eq!(found, vec![("Session host in pool hp-1".to_string(), pool_id.clone())]);
        assert!(pools_hosting(&vm("other"), reads.iter().map(|(k, v)| (k, v))).is_empty());

        let plan = ScalingPlanRow::from_json(
            &json!({"id": dv("scalingPlans/sp-1"), "name": "sp-1", "location": "westeurope",
                "properties": {"hostPoolType": "Pooled", "hostPoolReferences": [{"hostPoolArmPath": pool_id, "scalingPlanEnabled": true}]}}),
            None,
        )
        .unwrap();
        let plans: Vec<Box<dyn Resource>> = vec![Box::new(plan)];
        let row = pool("Pooled", None);
        let lazy = AvdLazy { session_hosts: Some(&reads[0].1), scaling_plans: Some(&plans), ..Default::default() };
        let related = avd_section_lines(&row, HostPoolDetailSection::Related as usize, lazy, NOW).unwrap();
        assert!(related.iter().any(|(l, id)| l == "Scaling plan sp-1" && id == &dv("scalingPlans/sp-1")));
        assert!(related.iter().any(|(l, id)| l == "Session host avd-0.contoso.com" && id == &vm("avd-0")));
    }

    #[test]
    fn an_app_group_outside_a_workspace_is_unpublished() {
        let group = |ws: Option<String>| {
            AppGroupRow::from_json(
                &json!({"id": dv("applicationGroups/dag-1"), "name": "dag-1", "location": "westeurope",
                    "properties": {"applicationGroupType": "Desktop", "hostPoolArmPath": dv("hostPools/hp-1"), "workspaceArmPath": ws}}),
                None,
            )
            .unwrap()
        };
        let lone = group(None);
        assert!(lone.is_unpublished());
        assert_eq!(lone.list_summary().as_deref(), Some("Desktop · hp-1"));
        assert!(get(&lone.details(), "Workspace").unwrap().starts_with("⚠ none"));
        let published = group(Some(dv("workspaces/ws-1")));
        assert!(!published.is_unpublished());
        assert!(published.related().iter().any(|(l, _)| l == "Workspace ws-1"));
        assert!(published.related().iter().any(|(l, _)| l == "Host pool hp-1"));
    }

    #[test]
    fn a_workspace_lists_its_app_groups_and_endpoints() {
        let ws = AvdWorkspaceRow::from_json(
            &json!({"id": dv("workspaces/ws-1"), "name": "ws-1", "location": "westeurope",
                "properties": {"publicNetworkAccess": "Enabled", "applicationGroupReferences": [dv("applicationGroups/dag-1"), dv("applicationGroups/rag-1")],
                    "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-ws", RG)},
                        "privateLinkServiceConnectionState": {"status": "Pending"}}}]}}),
            None,
        )
        .unwrap();
        assert_eq!(ws.list_summary().as_deref(), Some("2 app groups"));
        assert!(ws.network_rows().iter().any(|(l, _)| l == "Private endpoint · pe-ws (⚠ Pending)"));
        assert_eq!(ws.related().iter().filter(|(l, _)| l.starts_with("App group")).count(), 2);
    }

    #[test]
    fn schedules_render_each_phase_for_pooled_and_personal_plans() {
        let plan = |kind: &str| {
            ScalingPlanRow::from_json(
                &json!({"id": dv("scalingPlans/sp-1"), "name": "sp-1", "location": "westeurope",
                    "properties": {"hostPoolType": kind, "timeZone": "W. Europe Standard Time"}}),
                None,
            )
            .unwrap()
        };
        let pooled = plan("Pooled");
        assert_eq!(pooled.schedules_child(), "pooledSchedules");
        let s = json!({"name": "sp-1/weekdays", "properties": {
            "daysOfWeek": ["Monday", "Friday"], "rampUpStartTime": {"hour": 7, "minute": 0},
            "rampUpLoadBalancingAlgorithm": "BreadthFirst", "rampUpMinimumHostsPct": 20, "rampUpCapacityThresholdPct": 60,
            "peakStartTime": {"hour": 9, "minute": 30}, "peakLoadBalancingAlgorithm": "DepthFirst",
            "rampDownStartTime": {"hour": 18, "minute": 0}, "rampDownLoadBalancingAlgorithm": "DepthFirst",
            "rampDownForceLogoffUsers": true, "rampDownWaitTimeMinutes": 30, "rampDownStopHostsWhen": "ZeroSessions",
            "offPeakStartTime": {"hour": 20, "minute": 0}, "offPeakLoadBalancingAlgorithm": "DepthFirst"}});
        let lines = schedule_rows(&[s], &pooled);
        assert!(lines.iter().any(|(k, _)| k == "weekdays"));
        assert_eq!(get(&lines, "  Days"), Some("Monday, Friday"));
        assert_eq!(get(&lines, "  Ramp-up"), Some("07:00 · BreadthFirst · min hosts 20% · capacity 60%"));
        assert_eq!(get(&lines, "  Peak"), Some("09:30 · DepthFirst"));
        assert_eq!(get(&lines, "  Ramp-down users"), Some("logged off after 30 min · hosts stop at ZeroSessions"));

        let personal = plan("Personal");
        assert_eq!(personal.schedules_child(), "personalSchedules");
        let s = json!({"name": "nights", "properties": {"daysOfWeek": ["Monday"], "rampUpStartTime": {"hour": 8},
            "rampUpAutoStartHosts": "WithAssignedUser", "rampUpStartVMOnConnect": "Enable",
            "rampUpActionOnDisconnect": "Deallocate", "rampUpMinutesToWaitOnDisconnect": 30, "rampUpActionOnLogoff": "None"}});
        let lines = schedule_rows(&[s], &personal);
        assert_eq!(
            get(&lines, "  Ramp-up"),
            Some("08:00 · start WithAssignedUser · start VM on connect enable · disconnect: deallocate after 30 min · log off: none")
        );
        assert!(schedule_rows(&[], &personal)[0].1.starts_with("No schedules"));
    }

    #[test]
    fn agent_versions_compare_by_every_part() {
        assert!(agent_version_key("1.0.11388.1700") > agent_version_key("1.0.9742.1100"));
        assert_eq!(agent_version_key("1.0.x"), None);
    }
}
