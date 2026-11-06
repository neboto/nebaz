//! Container Instances (#197, SERVICES.md rule 39): the Container Apps
//! tab's Container groups sub-tab, one subscription-wide list of
//! `Microsoft.ContainerInstance/containerGroups`. The list body carries
//! each group's containers but not their runtime state, so the Containers
//! section is a lazy `GET` of the group itself, whose body adds the
//! group's and every container's instance view.
//!
//! The bodies carry credentials, removed before a row or the lazy body
//! keeps them ([`without_secrets`]): an environment variable's `value`
//! and `secureValue` (env vars render by name), a registry `password`, an
//! Azure Files `storageAccountKey`, a secret volume's files, a config
//! map's values, the Log Analytics `workspaceKey`, an extension's
//! `protectedSettings`. A container's logs (`{group}/containers/{c}/logs`)
//! are a GET, but they are the workload's output, never fetched; the
//! guard names the path. `exec` and `attach` are POSTs.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::ServiceType;
use crate::azure::services::{
    arm_row, error_rows, finish_stream, json, overview_rows, related_rows_with, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version with months behind it (azure-rest-api-specs,
/// added 2026-07-09, checked 2026-11-07).
pub const ACI_API_VERSION: &str = "2026-07-01";
const GROUPS_PATH: &str = "/providers/Microsoft.ContainerInstance/containerGroups";

const NEVER_LOGS: &str = "metadata from ARM; logs and environment values are never fetched";

/// How many of the latest events a container or the group shows.
const EVENTS_SHOWN: usize = 3;

crate::sections! {
    pub enum ContainerGroupDetailSection,
    pub static CONTAINER_GROUP_SECTIONS = [
        Overview "Overview",
        Containers "Containers" => crate::app::App::trigger_aci_instance_view,
        Network "Network",
        Configuration "Configuration",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Credentials out ───────────────────────────────────────────────────

/// Keys removed wherever they sit under `properties`.
const SECRET_FIELDS: &[&str] = &["password", "storageAccountKey", "workspaceKey", "protectedSettings"];

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            for (k, child) in map.iter_mut() {
                match (k.as_str(), &mut *child) {
                    ("environmentVariables", Value::Array(items)) => {
                        for item in items.iter_mut().filter_map(Value::as_object_mut) {
                            // Kept as a flag: the name is what renders. ARM
                            // returns a secure variable as a bare name.
                            let had_value = item.remove("value").is_some();
                            let secure = item.remove("secureValue").is_some() || !had_value;
                            if secure {
                                item.insert("secure".into(), Value::Bool(true));
                            }
                        }
                    }
                    // A secret volume's files and a config map's pairs:
                    // the names stay, the contents go.
                    ("secret" | "keyValuePairs", Value::Object(files)) => {
                        files.values_mut().for_each(|f| *f = Value::Null);
                    }
                    _ => {}
                }
                scrub(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every credential under `properties` removed: what a row
/// parses and keeps for `e`, and what the lazy instance view stores.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(p) = v.get_mut("properties") {
        scrub(p);
    }
    v
}

// ── The row ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContainerGroupRow {
    pub base: ArmBase,
    pub os_type: Option<String>,
    pub restart_policy: Option<String>,
    pub sku: Option<String>,
    pub priority: Option<String>,
    pub ip_type: Option<String>,
    pub ip: Option<String>,
    pub ports: Vec<String>,
    pub dns_label: Option<String>,
    pub dns_label_scope: Option<String>,
    pub fqdn: Option<String>,
    pub subnet_ids: Vec<String>,
    pub dns_servers: Vec<String>,
    /// Scrubbed container objects, as the list body gives them.
    pub containers: Vec<Value>,
    pub init_containers: Vec<Value>,
    /// `(server, who)`: the username or the identity that pulls.
    pub registries: Vec<(String, String)>,
    pub volumes: Vec<Value>,
    pub secret_references: Vec<String>,
    pub log_workspace: Option<String>,
    pub log_type: Option<String>,
    pub encryption_key: Option<String>,
    pub confidential: bool,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub profile_id: Option<String>,
    pub standby_pool_id: Option<String>,
    /// The group's `instanceView.state`: on a `GET` body, not the list's.
    pub group_state: Option<String>,
}

impl ContainerGroupRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ContainerGroupRow> {
        let v = &without_secrets(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        Some(ContainerGroupRow {
            os_type: json::str_at(v, &p("osType")),
            restart_policy: json::str_at(v, &p("restartPolicy")),
            sku: json::str_at(v, &p("sku")),
            priority: json::str_at(v, &p("priority")),
            ip_type: json::str_at(v, &p("ipAddress/type")),
            ip: json::str_at(v, &p("ipAddress/ip")),
            ports: json::arr(v, &p("ipAddress/ports")).iter().map(port_text).collect(),
            dns_label: json::str_at(v, &p("ipAddress/dnsNameLabel")),
            dns_label_scope: json::str_at(v, &p("ipAddress/autoGeneratedDomainNameLabelScope")),
            fqdn: json::str_at(v, &p("ipAddress/fqdn")),
            subnet_ids: json::ids_at(v, &p("subnetIds")).into_iter().filter_map(|id| json::arm_id(Some(id))).collect(),
            dns_servers: json::strings_at(v, &p("dnsConfig/nameServers")),
            containers: json::arr(v, &p("containers")),
            init_containers: json::arr(v, &p("initContainers")),
            registries: json::arr(v, &p("imageRegistryCredentials"))
                .iter()
                .filter_map(|r| {
                    let server = json::str_at(r, "/server")?;
                    let who = match (json::str_at(r, "/identity"), json::str_at(r, "/username")) {
                        (Some(id), _) => format!("identity {}", name_of_id(&id)),
                        (None, Some(user)) => format!("user {}", user),
                        (None, None) => "-".into(),
                    };
                    Some((server, who))
                })
                .collect(),
            volumes: json::arr(v, &p("volumes")),
            secret_references: json::arr(v, &p("secretReferences")).iter().filter_map(|s| json::str_at(s, "/name")).collect(),
            log_workspace: json::str_at(v, &p("diagnostics/logAnalytics/workspaceId")),
            log_type: json::str_at(v, &p("diagnostics/logAnalytics/logType")),
            encryption_key: json::str_at(v, &p("encryptionProperties/keyName")),
            confidential: v.pointer(&p("confidentialComputeProperties")).is_some_and(|c| !c.is_null()),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            profile_id: json::arm_id(json::str_at(v, &p("containerGroupProfile/id"))),
            standby_pool_id: json::arm_id(json::str_at(v, &p("standbyPoolProfile/id"))),
            group_state: json::str_at(v, &p("instanceView/state")),
            base,
        })
    }

    /// Provisioning first, then the group's own state when the body has
    /// it: `Succeeded` is a run that finished (restart policy `Never` or
    /// `OnFailure`), `Failed` one that did not.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.group_state.as_deref().map(|s| (group_state_bucket(s), s));
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// Requested CPU and memory over every main container.
    fn requested(&self) -> (f64, f64) {
        self.containers.iter().fold((0.0, 0.0), |(c, m), x| {
            let r = "/properties/resources/requests";
            (
                c + x.pointer(&format!("{}/cpu", r)).and_then(Value::as_f64).unwrap_or(0.0),
                m + x.pointer(&format!("{}/memoryInGB", r)).and_then(Value::as_f64).unwrap_or(0.0),
            )
        })
    }

    fn network_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("IP address".into(), match (&self.ip_type, &self.ip) {
                (Some(t), Some(ip)) => format!("{} · {}", ip, t),
                (Some(t), None) => t.clone(),
                (None, _) => "none".into(),
            }),
        ];
        if !self.ports.is_empty() {
            lines.push(("Ports".into(), json::join(&self.ports)));
        }
        if let Some(label) = &self.dns_label {
            let scope = self.dns_label_scope.as_deref().map(|s| format!(" (reuse: {})", s)).unwrap_or_default();
            lines.push(("DNS label".into(), format!("{}{}", label, scope)));
        }
        if let Some(fqdn) = &self.fqdn {
            lines.push(("FQDN".into(), fqdn.clone()));
        }
        for id in &self.subnet_ids {
            lines.push((format!("Subnet · {}", subnet_name(id)), id.clone()));
        }
        if !self.dns_servers.is_empty() {
            lines.push(("DNS servers".into(), json::join(&self.dns_servers)));
        }
        lines
    }

    /// Settings, then what the group pulls and mounts, then identity.
    /// `registry_ids` resolves a server to its warm ACR row.
    fn configuration_rows(&self, registry_ids: &[(String, String)]) -> Vec<(String, String)> {
        let mut lines = vec![
            ("OS".into(), json::opt(self.os_type.clone())),
            ("Restart policy".into(), json::opt(self.restart_policy.clone())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Priority".into(), json::opt(self.priority.clone())),
        ];
        if self.confidential {
            lines.push(("Confidential".into(), "yes (confidential compute policy set)".into()));
        }
        lines.push(("Log Analytics".into(), match (&self.log_workspace, &self.log_type) {
            (Some(ws), Some(t)) => format!("{} · {}", ws, t),
            (Some(ws), None) => ws.clone(),
            _ => "-".into(),
        }));
        if let Some(key) = &self.encryption_key {
            lines.push(("Encryption key".into(), key.clone()));
        }
        lines.push((String::new(), String::new()));
        if self.registries.is_empty() {
            lines.push(("Registries".into(), "none (public images)".into()));
        }
        for (server, who) in &self.registries {
            // A warm ACR row makes the line a jump; else the server is text.
            match registry_ids.iter().find(|(s, _)| s.eq_ignore_ascii_case(server)) {
                Some((_, id)) => lines.push((format!("Registry · {} ({})", server, who), id.clone())),
                None => lines.push((format!("Registry · {}", server), who.clone())),
            }
        }
        for vol in &self.volumes {
            lines.push((format!("Volume · {}", json::text(vol, "/name")), volume_text(vol)));
        }
        if !self.secret_references.is_empty() {
            lines.push(("Secret references".into(), json::join(&self.secret_references)));
        }
        lines.push((String::new(), String::new()));
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        for id in &self.user_identity_ids {
            lines.push((format!("User identity · {}", name_of_id(id)), id.clone()));
        }
        lines
    }
}

fn group_state_bucket(s: &str) -> ResourceState {
    match s.to_lowercase().as_str() {
        "running" => ResourceState::Running,
        "pending" | "repairing" => ResourceState::Pending,
        "stopped" | "succeeded" => ResourceState::Stopped,
        "failed" => ResourceState::Unavailable,
        other => ResourceState::Unknown(other.to_string()),
    }
}

/// `80/TCP`; a container port has no protocol unless one is set.
fn port_text(p: &Value) -> String {
    let port = json::int_at(p, "/port").map(|n| n.to_string()).unwrap_or_else(|| "-".into());
    match json::str_at(p, "/protocol") {
        Some(proto) => format!("{}/{}", port, proto),
        None => port,
    }
}

/// `vnet/subnet` from a subnet id, the name the Subnets sub-tab shows.
fn subnet_name(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    match parts.iter().position(|p| p.eq_ignore_ascii_case("virtualNetworks")) {
        Some(i) if parts.len() > i + 3 => format!("{}/{}", parts[i + 1], parts[i + 3]),
        _ => name_of_id(id).to_string(),
    }
}

/// What backs a volume, without its contents.
fn volume_text(v: &Value) -> String {
    if let Some(f) = v.get("azureFile") {
        let ro = if json::bool_at(f, "/readOnly") == Some(true) { " (read-only)" } else { "" };
        return format!("Azure Files {} on {}{}", json::text(f, "/shareName"), json::text(f, "/storageAccountName"), ro);
    }
    if v.get("emptyDir").is_some() {
        return "empty directory".into();
    }
    if let Some(files) = v.get("secret").and_then(Value::as_object) {
        let names: Vec<String> = files.keys().cloned().collect();
        return format!("secret files: {}", json::join(&names));
    }
    if let Some(g) = v.get("gitRepo") {
        return format!("git {}", json::text(g, "/repository"));
    }
    "-".into()
}

impl Resource for ContainerGroupRow {
    arm_row!("Container group");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CONTAINER_GROUP_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let (cpu, mem) = self.requested();
        let n = self.containers.len();
        Some(format!(
            "{} · {} container{} · {} CPU · {} GB",
            self.os_type.as_deref().unwrap_or("-"),
            n,
            if n == 1 { "" } else { "s" },
            cpu,
            mem
        ))
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("OS".into(), json::opt(self.os_type.clone())),
            ("Restart policy".into(), json::opt(self.restart_policy.clone())),
            ("Containers".into(), self.containers.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for id in &self.subnet_ids {
            v.push((format!("Subnet {}", subnet_name(id)), id.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        if let Some(id) = &self.profile_id {
            v.push((format!("Container group profile {}", name_of_id(id)), id.clone()));
        }
        if let Some(id) = &self.standby_pool_id {
            v.push((format!("Standby pool {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az container show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Containers ────────────────────────────────────────────────────────

/// One container's lines: the spec, then its live state when `live`.
fn container_rows(c: &Value, prefix: &str, live: bool) -> Vec<(String, String)> {
    let p = |f: &str| format!("/properties/{}", f);
    let mut lines = vec![
        (String::new(), String::new()),
        (format!("{}{}", prefix, json::text(c, "/name")), String::new()),
        ("  Image".into(), json::text(c, &p("image"))),
    ];
    let req = |f: &str| c.pointer(&p(&format!("resources/requests/{}", f))).and_then(Value::as_f64);
    let lim = |f: &str| c.pointer(&p(&format!("resources/limits/{}", f))).and_then(Value::as_f64);
    let mut res = format!("{} CPU · {} GB", fmt_num(req("cpu")), fmt_num(req("memoryInGB")));
    if lim("cpu").is_some() || lim("memoryInGB").is_some() {
        res.push_str(&format!(" (limit {} CPU · {} GB)", fmt_num(lim("cpu")), fmt_num(lim("memoryInGB"))));
    }
    if let Some(gpu) = c.pointer(&p("resources/requests/gpu")) {
        res.push_str(&format!(" · {} × {} GPU", json::text(gpu, "/count"), json::text(gpu, "/sku")));
    }
    lines.push(("  Resources".into(), res));
    let ports: Vec<String> = json::arr(c, &p("ports")).iter().map(port_text).collect();
    if !ports.is_empty() {
        lines.push(("  Ports".into(), json::join(&ports)));
    }
    let command = json::strings_at(c, &p("command"));
    if !command.is_empty() {
        lines.push(("  Command".into(), command.join(" ")));
    }
    let env: Vec<String> = json::arr(c, &p("environmentVariables"))
        .iter()
        .filter_map(|e| {
            let name = json::str_at(e, "/name")?;
            Some(if json::bool_at(e, "/secure") == Some(true) { format!("{} (secure)", name) } else { name })
        })
        .collect();
    if !env.is_empty() {
        lines.push(("  Environment".into(), format!("{} · values not shown", json::join(&env))));
    }
    for m in json::arr(c, &p("volumeMounts")) {
        let ro = if json::bool_at(&m, "/readOnly") == Some(true) { " (read-only)" } else { "" };
        lines.push((format!("  Mount · {}", json::text(&m, "/name")), format!("{}{}", json::text(&m, "/mountPath"), ro)));
    }
    let probes: Vec<&str> = [("livenessProbe", "liveness"), ("readinessProbe", "readiness")]
        .iter()
        .filter(|(k, _)| c.pointer(&p(k)).is_some())
        .map(|(_, l)| *l)
        .collect();
    if !probes.is_empty() {
        lines.push(("  Probes".into(), probes.join(", ")));
    }
    if live {
        lines.extend(container_state_rows(c));
    }
    lines
}

/// A container's instance view: the current state (`⚠` when it is
/// waiting with a reason or ended with a non-zero exit), the restarts,
/// the previous state and the latest events.
fn container_state_rows(c: &Value) -> Vec<(String, String)> {
    let iv = "/properties/instanceView";
    let Some(view) = c.pointer(iv) else {
        return vec![("  State".into(), "- (no instance view)".into())];
    };
    let mut lines = vec![("  State".into(), state_text(view.get("currentState")))];
    if let Some(n) = json::int_at(view, "/restartCount") {
        lines.push(("  Restarts".into(), n.to_string()));
    }
    if view.get("previousState").is_some_and(|s| !s.is_null()) {
        lines.push(("  Previous".into(), state_text(view.get("previousState"))));
    }
    lines.extend(event_rows(view, "  "));
    lines
}

/// `running since …`, `⚠ waiting · CrashLoopBackOff`, `⚠ terminated ·
/// exit 1 · Error`.
fn state_text(s: Option<&Value>) -> String {
    let Some(s) = s.filter(|s| !s.is_null()) else {
        return "-".into();
    };
    let state = json::str_at(s, "/state").unwrap_or_default().to_lowercase();
    let detail = json::str_at(s, "/detailStatus").filter(|d| !d.is_empty());
    let exit = json::int_at(s, "/exitCode");
    let trouble = (state == "waiting" && detail.is_some()) || (state == "terminated" && exit.is_some_and(|e| e != 0));
    let mut parts = vec![if trouble { format!("⚠ {}", state) } else { state.clone() }];
    if let Some(e) = exit {
        parts.push(format!("exit {}", e));
    }
    if let Some(d) = detail {
        parts.push(d);
    }
    let mut text = parts.join(" · ");
    match state.as_str() {
        "running" => text.push_str(&format!(" since {}", json::time(json::str_at(s, "/startTime")))),
        "terminated" => text.push_str(&format!(" at {}", json::time(json::str_at(s, "/finishTime")))),
        _ => {}
    }
    text
}

/// The latest events of an instance view, newest first.
fn event_rows(view: &Value, indent: &str) -> Vec<(String, String)> {
    let mut events = json::arr(view, "/events");
    events.sort_by_key(|e| std::cmp::Reverse(json::str_at(e, "/lastTimestamp")));
    events
        .iter()
        .take(EVENTS_SHOWN)
        .map(|e| {
            let count = json::int_at(e, "/count").filter(|n| *n > 1).map(|n| format!(" ×{}", n)).unwrap_or_default();
            (
                format!("{}Event · {}{}", indent, json::text(e, "/name"), count),
                format!("{} · {}", json::time(json::str_at(e, "/lastTimestamp")), json::text(e, "/message")),
            )
        })
        .collect()
}

fn fmt_num(n: Option<f64>) -> String {
    n.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}

/// The Containers section: the group's state and events from the lazy
/// `GET`, then each init and main container. While the `GET` is out (or
/// failed) the list body's spec still renders, without live state.
pub fn containers_rows(r: &ContainerGroupRow, live: Option<&Lazy<Value>>) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let body = match live {
        Some(Lazy::Loaded(v)) => Some(v),
        Some(Lazy::Error(e)) => {
            lines.extend(error_rows(e));
            None
        }
        None | Some(Lazy::Loading) => {
            lines.push(("Live state".into(), "Loading…".into()));
            None
        }
    };
    let (init, main) = match body {
        Some(v) => {
            lines.push(("Group state".into(), json::text(v, "/properties/instanceView/state")));
            lines.extend(event_rows(v.pointer("/properties/instanceView").unwrap_or(&Value::Null), ""));
            (json::arr(v, "/properties/initContainers"), json::arr(v, "/properties/containers"))
        }
        None => (r.init_containers.clone(), r.containers.clone()),
    };
    for c in &init {
        lines.extend(container_rows(c, "Init container · ", body.is_some()));
    }
    for c in &main {
        lines.extend(container_rows(c, "", body.is_some()));
    }
    if main.is_empty() {
        lines.push((String::new(), "No containers".into()));
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), NEVER_LOGS.into()));
    lines
}

/// Body lines for one section of a container group; `None` for another
/// type. `live` is the lazy `GET` of the group; `registry_ids` pairs a
/// login server with its ACR row's id, from the warm registries list.
pub fn container_group_section_lines(
    r: &dyn Resource,
    idx: usize,
    live: Option<&Lazy<Value>>,
    registry_ids: &[(String, String)],
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<ContainerGroupRow>()?;
    use ContainerGroupDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Containers => containers_rows(x, live),
        S::Network => x.network_rows(),
        S::Configuration => x.configuration_rows(registry_ids),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let extra = x
                .registries
                .iter()
                .filter_map(|(server, _)| registry_ids.iter().find(|(s, _)| s.eq_ignore_ascii_case(server)))
                .map(|(_, id)| (format!("Registry {}", name_of_id(id)), id.clone()))
                .collect();
            related_rows_with(x, extra)
        }
        S::Tags => tag_rows(x.tags()),
    })
}

fn rows(page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
    page.iter()
        .filter_map(|v| ContainerGroupRow::from_json(v, tenant))
        .map(|r| Box::new(r) as Box<dyn Resource>)
        .collect()
}

// ── Provider (the Container Apps tab delegates its Container groups) ──

pub struct ContainerInstanceLists<'a> {
    pub scope: &'a Scope,
}

impl ContainerInstanceLists<'_> {
    pub async fn list(&self) -> Result<Vec<Box<dyn Resource>>> {
        let page = self.scope.list(GROUPS_PATH, ACI_API_VERSION).await?;
        Ok(rows(&page, self.scope.tenant()))
    }

    pub async fn stream(&self, event_tx: &mpsc::UnboundedSender<Event>, service_type: ServiceType) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        let r = self
            .scope
            .stream(GROUPS_PATH, ACI_API_VERSION, &[], service_type, "Listing container groups…", event_tx, |page| {
                rows(&page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, event_tx)
    }

    pub async fn get(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, ACI_API_VERSION).await?;
        rows(std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-jobs";

    fn group_id(name: &str) -> String {
        format!("{}/providers/Microsoft.ContainerInstance/containerGroups/{}", RG, name)
    }

    fn subnet_id() -> String {
        format!("{}/providers/Microsoft.Network/virtualNetworks/vnet-jobs/subnets/snet-aci", RG)
    }

    fn body(instance_view: bool) -> Value {
        let mut c = json!({
            "name": "agent",
            "properties": {
                "image": "acrjobs.registry.example/agent:1.4",
                "command": ["/bin/agent", "--once"],
                "ports": [{"port": 8080}],
                "resources": {"requests": {"cpu": 1.0, "memoryInGB": 1.5}, "limits": {"cpu": 2.0, "memoryInGB": 3.0}},
                "environmentVariables": [
                    {"name": "POOL", "value": "linux-prod"},
                    {"name": "AGENT_TOKEN", "secureValue": "hunter2"}
                ],
                "volumeMounts": [{"name": "work", "mountPath": "/work", "readOnly": false}],
                "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}}
            }
        });
        let mut v = json!({
            "id": group_id("cg-agents"), "name": "cg-agents", "location": "westeurope",
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-agents", RG): {}
            }},
            "properties": {
                "provisioningState": "Succeeded", "osType": "Linux", "restartPolicy": "Always",
                "sku": "Standard", "priority": "Regular",
                "ipAddress": {"type": "Private", "ip": "10.4.0.5", "ports": [{"port": 8080, "protocol": "TCP"}]},
                "subnetIds": [{"id": subnet_id()}],
                "imageRegistryCredentials": [{"server": "acrjobs.registry.example", "username": "acrjobs", "password": "pw"}],
                "volumes": [
                    {"name": "work", "azureFile": {"shareName": "work", "storageAccountName": "stjobs", "storageAccountKey": "k=="}},
                    {"name": "certs", "secret": {"tls.crt": "QUJD", "tls.key": "REVG"}}
                ],
                "diagnostics": {"logAnalytics": {"workspaceId": "ws-guid", "workspaceKey": "wk==", "logType": "ContainerInsights"}},
                "containers": []
            }
        });
        if instance_view {
            c["properties"]["instanceView"] = json!({
                "restartCount": 12,
                "currentState": {"state": "Waiting", "detailStatus": "CrashLoopBackOff: Back-off restarting failed"},
                "previousState": {"state": "Terminated", "exitCode": 1, "detailStatus": "Error", "finishTime": "2026-11-06T22:01:00Z"},
                "events": [
                    {"name": "Pulled", "count": 1, "lastTimestamp": "2026-11-06T21:00:00Z", "message": "pulled"},
                    {"name": "BackOff", "count": 40, "lastTimestamp": "2026-11-06T22:02:00Z", "message": "Back-off restarting"}
                ]
            });
            v["properties"]["instanceView"] = json!({"state": "Running", "events": []});
        }
        v["properties"]["containers"] = json!([c]);
        v
    }

    fn row() -> ContainerGroupRow {
        ContainerGroupRow::from_json(&body(false), Some("t-1")).unwrap()
    }

    fn get<'a>(lines: &'a [(String, String)], key: &str) -> Option<&'a str> {
        lines.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = CONTAINER_GROUP_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Containers", "Network", "Configuration", "Access", "Activity", "Related", "Tags"]
        );
    }

    #[test]
    fn no_credential_survives_the_row() {
        let r = row();
        let planted = ["hunter2", "linux-prod", "\"pw\"", "k==", "QUJD", "REVG", "wk=="];
        let kept: Vec<usize> = (0..planted.len()).filter(|&i| r.base.raw.contains(planted[i])).collect();
        assert!(kept.is_empty(), "planted values {kept:?} (by index) survive in the raw body");
        assert!(r.base.raw.contains("AGENT_TOKEN") && r.base.raw.contains("tls.crt"), "names stay");
        let lines = containers_rows(&r, None);
        assert_eq!(get(&lines, "  Environment"), Some("POOL, AGENT_TOKEN (secure) · values not shown"));
    }

    #[test]
    fn a_group_reads_its_network_configuration_and_the_ids_command() {
        let r = row();
        assert_eq!(r.state(), ResourceState::stateless(), "the list body has no instance view: provisioning only");
        assert_eq!(r.list_summary().as_deref(), Some("Linux · 1 container · 1 CPU · 1.5 GB"));
        assert_eq!(r.cli_command(), Some(format!("az container show --ids {}", group_id("cg-agents"))));

        let net = r.network_rows();
        assert_eq!(get(&net, "IP address"), Some("10.4.0.5 · Private"));
        assert_eq!(get(&net, "Subnet · vnet-jobs/snet-aci"), Some(subnet_id().as_str()));

        let acr = format!("{}/providers/Microsoft.ContainerRegistry/registries/acrjobs", RG);
        let warm = vec![("ACRJOBS.registry.example".to_string(), acr.clone())];
        let cfg = r.configuration_rows(&warm);
        assert_eq!(get(&cfg, "Registry · acrjobs.registry.example (user acrjobs)"), Some(acr.as_str()));
        assert_eq!(get(&cfg, "Volume · work"), Some("Azure Files work on stjobs"));
        assert_eq!(get(&cfg, "Volume · certs"), Some("secret files: tls.crt, tls.key"));
        assert_eq!(get(&cfg, "Log Analytics"), Some("ws-guid · ContainerInsights"));
        let cold = r.configuration_rows(&[]);
        assert_eq!(get(&cold, "Registry · acrjobs.registry.example"), Some("user acrjobs"), "no warm ACR: text");

        let related = container_group_section_lines(&r, ContainerGroupDetailSection::Related as usize, None, &warm).unwrap();
        for want in ["Subnet vnet-jobs/snet-aci", "Identity id-agents", "Registry acrjobs"] {
            assert!(related.iter().any(|(l, _)| l == want), "{want} in {related:?}");
        }
    }

    #[test]
    fn the_containers_section_shows_the_spec_then_the_live_state() {
        let r = row();
        let loading = containers_rows(&r, Some(&Lazy::Loading));
        assert_eq!(loading[0], ("Live state".to_string(), "Loading…".to_string()));
        assert_eq!(get(&loading, "  Image"), Some("acrjobs.registry.example/agent:1.4"));
        assert_eq!(get(&loading, "  Resources"), Some("1 CPU · 1.5 GB (limit 2 CPU · 3 GB)"));
        assert!(get(&loading, "  State").is_none(), "no live state from the list body");

        let failed = containers_rows(&r, Some(&Lazy::Error("403 AuthorizationFailed".into())));
        assert!(failed.iter().any(|(_, v)| v.contains("403")));
        assert_eq!(get(&failed, "  Image"), Some("acrjobs.registry.example/agent:1.4"), "the spec still renders");

        let live = Lazy::Loaded(without_secrets(&body(true)));
        let lines = containers_rows(&r, Some(&live));
        assert_eq!(get(&lines, "Group state"), Some("Running"));
        assert_eq!(get(&lines, "  State"), Some("⚠ waiting · CrashLoopBackOff: Back-off restarting failed"));
        assert_eq!(get(&lines, "  Restarts"), Some("12"));
        assert_eq!(get(&lines, "  Previous"), Some("⚠ terminated · exit 1 · Error at 2026-11-06 22:01:00"));
        let events: Vec<&str> = lines.iter().filter(|(k, _)| k.starts_with("  Event")).map(|(k, _)| k.as_str()).collect();
        assert_eq!(events, ["  Event · BackOff ×40", "  Event · Pulled"], "newest first");
        assert_eq!(lines.last().unwrap().1, NEVER_LOGS);
    }

    #[test]
    fn a_get_body_puts_the_group_state_on_the_ladder() {
        let r = ContainerGroupRow::from_json(&body(true), None).unwrap();
        assert_eq!((r.state(), r.state_label()), (ResourceState::Running, "running".to_string()));
        assert_eq!(group_state_bucket("Succeeded"), ResourceState::Stopped);
        assert_eq!(group_state_bucket("Failed"), ResourceState::Unavailable);
        assert_eq!(group_state_bucket("Pending"), ResourceState::Pending);
    }
}
