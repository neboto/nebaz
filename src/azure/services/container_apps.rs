//! The Container Apps service (issue #26): apps, their environments and
//! jobs (`Microsoft.App`), three subscription-wide lists. An app's
//! Revisions and its Auth (Easy Auth) settings are lazy sections, one call
//! per app each; a job's Executions is one, one call per job.
//!
//! The list bodies carry credentials: a secret's `value` (when the caller
//! may read it), a container env var's literal `value`, an environment's
//! Log Analytics shared key, Dapr App Insights key and connection string,
//! custom-domain certificate blob and password, an OpenTelemetry
//! destination's API key and headers. They are removed from the JSON
//! before the row keeps it ([`without_secrets`]), so no section, search
//! or raw view (`e`) can show them: env vars render as a name and whether
//! the value is a secret reference, secrets as names. `listSecrets` is a
//! POST nebaz never sends, and the guard names the `az` commands that
//! would print secret values.
//!
//! An app's FQDN (the environment's default domain) is data plane: shown
//! as text, never requested.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable version (checked against azure-rest-api-specs,
/// 2026-10-23; released there 2026-09-03). The live check confirms it.
pub const ACA_API_VERSION: &str = "2026-07-01";
const APPS_PATH: &str = "/providers/Microsoft.App/containerApps";
const ENVIRONMENTS_PATH: &str = "/providers/Microsoft.App/managedEnvironments";
const JOBS_PATH: &str = "/providers/Microsoft.App/jobs";

const NEVER_VALUES: &str = "names only; secret and env var values are never fetched or shown";

crate::sections! {
    pub enum ContainerAppDetailSection,
    pub static CONTAINER_APP_SECTIONS = [
        Overview "Overview",
        Ingress "Ingress",
        Scale "Scale",
        Containers "Containers",
        Revisions "Revisions" => crate::app::App::trigger_aca_revisions,
        Auth "Auth" => crate::app::App::trigger_aca_auth,
        Identity "Identity",
        Secrets "Secrets",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum EnvironmentDetailSection,
    pub static ENVIRONMENT_SECTIONS = [
        Overview "Overview",
        Network "Network",
        WorkloadProfiles "Workload profiles",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum JobDetailSection,
    pub static JOB_SECTIONS = [
        Overview "Overview",
        Trigger "Trigger",
        Executions "Executions" => crate::app::App::trigger_aca_job_executions,
        Containers "Containers",
        Identity "Identity",
        Secrets "Secrets",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Credentials out of the JSON ───────────────────────────────────────

/// Property names that hold a credential wherever they sit under
/// `properties` (environment: `daprAIInstrumentationKey`,
/// `daprAIConnectionString`, Log Analytics `sharedKey`, App Insights
/// `connectionString`, the custom-domain `certificateValue` and
/// `certificatePassword`, a Datadog destination's `key`; a registry
/// `password` should one ever appear inline).
const SECRET_FIELDS: &[&str] = &[
    "daprAIInstrumentationKey",
    "daprAIConnectionString",
    "sharedKey",
    "connectionString",
    "certificateValue",
    "certificatePassword",
    "password",
    "key",
];

/// Arrays whose items carry a literal `value` that may be a secret: an
/// app's or job's `secrets`, a container's `env`, an OTLP destination's
/// `headers`. The item keeps its name (and `secretRef`), loses `value`.
const VALUE_ARRAYS: &[&str] = &["secrets", "env", "headers"];

fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !SECRET_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(k)));
            for (k, child) in map.iter_mut() {
                if VALUE_ARRAYS.contains(&k.as_str()) {
                    if let Value::Array(items) = child {
                        for item in items.iter_mut().filter_map(Value::as_object_mut) {
                            item.remove("value");
                        }
                    }
                }
                scrub(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// The body with every credential under `properties` removed: what a row
/// parses and keeps for `e`. Tags and the envelope are untouched.
pub fn without_secrets(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(p) = v.get_mut("properties") {
        scrub(p);
    }
    v
}

/// The envelope of a scrubbed body. `Microsoft.App` returns a display-name
/// location (`East US`); stored as `eastus` so `R` matches.
fn base_of(v: &Value, tenant: Option<&str>) -> Option<ArmBase> {
    let mut base = ArmBase::from_json(v, tenant)?;
    base.location = base.location.replace(' ', "");
    Some(base)
}

// ── What apps and jobs share ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub id: String,
    pub client_id: Option<String>,
    pub principal_id: Option<String>,
}

/// The parts of an app and a job that have the same shape: environment,
/// identity, secrets, registries and the container template.
#[derive(Debug, Clone)]
pub struct Workload {
    pub environment_id: Option<String>,
    pub workload_profile: Option<String>,
    pub identity_type: Option<String>,
    pub principal_id: Option<String>,
    pub user_identities: Vec<UserIdentity>,
    /// `(identity, lifecycle)`: which identity is available to init
    /// containers, main containers or both.
    pub identity_settings: Vec<(String, String)>,
    /// Scrubbed: name, `keyVaultUrl`, `identity`; never `value`.
    pub secrets: Vec<Value>,
    pub registries: Vec<Value>,
    pub containers: Vec<Value>,
    pub init_containers: Vec<Value>,
    pub outbound_ips: Vec<String>,
}

impl Workload {
    /// From a scrubbed body; both types put the configuration and the
    /// template at the same paths.
    fn from_json(v: &Value) -> Workload {
        let c = "/properties/configuration";
        let t = "/properties/template";
        let mut user_identities: Vec<UserIdentity> = v
            .pointer("/identity/userAssignedIdentities")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(id, u)| UserIdentity {
                        id: id.clone(),
                        client_id: json::str_at(u, "/clientId"),
                        principal_id: json::str_at(u, "/principalId"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        user_identities.sort_by(|a, b| a.id.cmp(&b.id));
        Workload {
            environment_id: json::arm_id(
                json::str_at(v, "/properties/environmentId")
                    .or_else(|| json::str_at(v, "/properties/managedEnvironmentId")),
            ),
            workload_profile: json::str_at(v, "/properties/workloadProfileName").filter(|s| !s.is_empty()),
            identity_type: json::str_at(v, "/identity/type"),
            principal_id: json::str_at(v, "/identity/principalId"),
            user_identities,
            identity_settings: json::arr(v, &format!("{}/identitySettings", c))
                .iter()
                .map(|s| (json::text(s, "/identity"), json::text(s, "/lifecycle")))
                .collect(),
            secrets: json::arr(v, &format!("{}/secrets", c)),
            registries: json::arr(v, &format!("{}/registries", c)),
            containers: json::arr(v, &format!("{}/containers", t)),
            init_containers: json::arr(v, &format!("{}/initContainers", t)),
            outbound_ips: json::strings_at(v, "/properties/outboundIpAddresses"),
        }
    }

    fn environment_name(&self) -> &str {
        self.environment_id.as_deref().map(name_of_id).unwrap_or("-")
    }

    /// Every image, for search.
    fn images(&self) -> String {
        self.init_containers
            .iter()
            .chain(&self.containers)
            .filter_map(|c| json::str_at(c, "/image"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The registry identities that are ARM ids (not `system`).
    fn registry_identity_ids(&self) -> Vec<String> {
        self.registries
            .iter()
            .filter_map(|r| json::arm_id(json::str_at(r, "/identity")))
            .collect()
    }

    /// Environment, user-assigned identities, then registry identities
    /// the identity block does not already list.
    fn related(&self, id: &str) -> Vec<(String, String)> {
        let mut v = scope_related(id);
        if let Some(env) = &self.environment_id {
            v.push((format!("Environment {}", name_of_id(env)), env.clone()));
        }
        for u in &self.user_identities {
            v.push((format!("Identity {}", name_of_id(&u.id)), u.id.clone()));
        }
        for rid in self.registry_identity_ids() {
            if !v.iter().any(|(_, existing)| existing.eq_ignore_ascii_case(&rid)) {
                v.push((format!("Registry identity {}", name_of_id(&rid)), rid));
            }
        }
        v
    }

    /// The Identity section: system-assigned principal, each
    /// user-assigned identity (Enter jumps to its Identity row) with its
    /// client and principal ids, and the lifecycle settings.
    fn identity_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("Type".into(), json::opt(self.identity_type.clone()))];
        let system = self
            .identity_type
            .as_deref()
            .is_some_and(|t| t.to_lowercase().contains("systemassigned"));
        if system {
            lines.push(("System-assigned principal".into(), json::opt(self.principal_id.clone())));
        }
        for u in &self.user_identities {
            lines.push((String::new(), String::new()));
            lines.push((format!("User-assigned · {}", name_of_id(&u.id)), u.id.clone()));
            lines.push(("  Client id".into(), json::opt(u.client_id.clone())));
            lines.push(("  Principal id".into(), json::opt(u.principal_id.clone())));
        }
        if !system && self.user_identities.is_empty() {
            lines.push((String::new(), "· no managed identity".into()));
        }
        if !self.identity_settings.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Available to".into(), String::new()));
            for (identity, lifecycle) in &self.identity_settings {
                let who = match identity.as_str() {
                    s if s.eq_ignore_ascii_case("system") => "system-assigned".to_string(),
                    s => name_of_id(s).to_string(),
                };
                lines.push((format!("  {}", who), lifecycle_label(lifecycle)));
            }
        }
        let registry: Vec<String> = self
            .registries
            .iter()
            .filter_map(|r| json::str_at(r, "/identity").map(|i| (json::text(r, "/server"), i)))
            .map(|(server, i)| format!("{} → {}", server, if i.eq_ignore_ascii_case("system") { "system-assigned" } else { name_of_id(&i) }))
            .collect();
        if !registry.is_empty() {
            lines.push((String::new(), String::new()));
            lines.push(("Image pulls".into(), json::join(&registry)));
        }
        lines
    }

    /// The Secrets section: secret names (stored, or a Key Vault
    /// reference with the identity that reads it) and registry
    /// credentials (identity, or a username and the name of the secret
    /// holding the password).
    fn secret_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![(String::new(), NEVER_VALUES.into())];
        lines.push((String::new(), String::new()));
        lines.push(("Secrets".into(), if self.secrets.is_empty() { "-".into() } else { String::new() }));
        for s in &self.secrets {
            let at = match json::str_at(s, "/keyVaultUrl").filter(|u| !u.is_empty()) {
                Some(url) => {
                    let via = json::str_at(s, "/identity")
                        .map(|i| match i.as_str() {
                            i if i.eq_ignore_ascii_case("system") => " · via system-assigned".to_string(),
                            i => format!(" · via {}", name_of_id(i)),
                        })
                        .unwrap_or_default();
                    format!("Key Vault reference {}{}", url, via)
                }
                None => "stored in the resource".into(),
            };
            lines.push((format!("  {}", json::text(s, "/name")), at));
        }
        lines.push((String::new(), String::new()));
        lines.push(("Registries".into(), if self.registries.is_empty() { "-".into() } else { String::new() }));
        for r in &self.registries {
            let server = json::text(r, "/server");
            match (json::str_at(r, "/identity"), json::str_at(r, "/username")) {
                (Some(i), _) if i.eq_ignore_ascii_case("system") => {
                    lines.push((format!("  {}", server), "managed identity · system-assigned".into()))
                }
                // A user-assigned id: the value is the ARM id, Enter jumps.
                (Some(i), _) => lines.push((format!("  {} · managed identity", server), i)),
                (None, Some(user)) => lines.push((
                    format!("  {}", server),
                    format!("username {} · password in secret {}", user, json::text(r, "/passwordSecretRef")),
                )),
                (None, None) => lines.push((format!("  {}", server), "anonymous".into())),
            }
        }
        lines
    }

    /// The Containers section: init containers first, then the app's;
    /// image, resources, probes, env var **names** (a secret reference
    /// is named, a literal value never shown) and volume mounts.
    fn container_rows(&self) -> Vec<(String, String)> {
        let mut lines = Vec::new();
        if self.containers.is_empty() && self.init_containers.is_empty() {
            lines.push((String::new(), "No containers".into()));
        }
        let all = self.init_containers.iter().map(|c| (c, true)).chain(self.containers.iter().map(|c| (c, false)));
        for (c, init) in all {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            let name = json::text(c, "/name");
            lines.push((if init { format!("{} (init)", name) } else { name }, String::new()));
            lines.push(("  Image".into(), json::text(c, "/image")));
            lines.push((
                "  Resources".into(),
                format!(
                    "{} CPU · {} memory",
                    json::text(c, "/resources/cpu"),
                    json::text(c, "/resources/memory")
                ),
            ));
            for p in json::arr(c, "/probes") {
                lines.push((format!("  Probe · {}", json::text(&p, "/type").to_lowercase()), probe_text(&p)));
            }
            let env = json::arr(c, "/env");
            if !env.is_empty() {
                lines.push(("  Env".into(), format!("{} variables (values never shown)", env.len())));
            }
            for e in &env {
                let what = match json::str_at(e, "/secretRef") {
                    Some(r) => format!("secret ref · {}", r),
                    None => "value".into(),
                };
                lines.push((format!("    {}", json::text(e, "/name")), what));
            }
            for m in json::arr(c, "/volumeMounts") {
                lines.push((
                    format!("  Mount · {}", json::text(&m, "/volumeName")),
                    json::text(&m, "/mountPath"),
                ));
            }
        }
        lines
    }
}

fn lifecycle_label(lifecycle: &str) -> String {
    match lifecycle.to_lowercase().as_str() {
        "init" => "init containers".into(),
        "main" => "app containers".into(),
        "all" => "init and app containers".into(),
        "none" => "no containers (control plane only)".into(),
        _ => lifecycle.to_string(),
    }
}

/// `http GET /healthz :8080 · every 10s` / `tcp :5432 · every 10s`.
fn probe_text(p: &Value) -> String {
    let target = if p.pointer("/httpGet").is_some() {
        format!(
            "{} {} :{}",
            json::str_at(p, "/httpGet/scheme").unwrap_or_else(|| "http".into()).to_lowercase(),
            json::text(p, "/httpGet/path"),
            json::text(p, "/httpGet/port")
        )
    } else if p.pointer("/tcpSocket").is_some() {
        format!("tcp :{}", json::text(p, "/tcpSocket/port"))
    } else {
        "-".into()
    };
    match json::int_at(p, "/periodSeconds") {
        Some(s) => format!("{} · every {}s", target, s),
        None => target,
    }
}

/// One scale rule: its kind (`http`, `tcp`, `azure-queue`, or a custom
/// KEDA scaler's type), then metadata, auth (trigger parameter → the
/// secret's **name**) and identity.
fn rule_rows(name: &str, kind: &str, body: &Value) -> Vec<(String, String)> {
    let mut lines = vec![(format!("  {}", name), kind.to_string())];
    if let Some(meta) = body.pointer("/metadata").and_then(Value::as_object) {
        let mut meta: Vec<_> = meta.iter().collect();
        meta.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in meta {
            let v = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
            lines.push((format!("    {}", k), v));
        }
    }
    for (k, ptr) in [("queue", "/queueName"), ("account", "/accountName"), ("queue length", "/queueLength")] {
        if let Some(v) = json::str_at(body, ptr) {
            lines.push((format!("    {}", k), v));
        }
    }
    for a in json::arr(body, "/auth") {
        lines.push((
            format!("    auth {}", json::text(&a, "/triggerParameter")),
            format!("secret {}", json::text(&a, "/secretRef")),
        ));
    }
    if let Some(i) = json::str_at(body, "/identity") {
        lines.push(("    identity".into(), i));
    }
    lines
}

/// An app scale rule names its kind by which key it carries.
fn app_rule_rows(rule: &Value) -> Vec<(String, String)> {
    let name = json::text(rule, "/name");
    for (key, kind) in [("http", "http"), ("tcp", "tcp"), ("azureQueue", "azure-queue")] {
        if let Some(body) = rule.get(key) {
            return rule_rows(&name, kind, body);
        }
    }
    match rule.get("custom") {
        Some(body) => rule_rows(&name, &json::text(body, "/type"), body),
        None => rule_rows(&name, "-", &Value::Null),
    }
}

// ── Container app ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContainerAppRow {
    pub base: ArmBase,
    pub workload: Workload,
    pub running_status: Option<String>,
    pub revisions_mode: Option<String>,
    pub latest_revision: Option<String>,
    pub latest_ready_revision: Option<String>,
    pub max_inactive_revisions: Option<i64>,
    /// `configuration.ingress`; `None` when ingress is off.
    pub ingress: Option<Value>,
    /// `template.scale`.
    pub scale: Value,
    pub dapr_enabled: Option<bool>,
    pub dapr_app_id: Option<String>,
    /// Express environments only: the app's own egress subnet.
    pub outbound_subnet_id: Option<String>,
}

impl ContainerAppRow {
    /// Parses an app with its credentials stripped first, so the kept
    /// raw JSON never holds them.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ContainerAppRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        let p = "/properties";
        let c = "/properties/configuration";
        Some(ContainerAppRow {
            workload: Workload::from_json(v),
            running_status: json::str_at(v, &format!("{}/runningStatus", p)),
            revisions_mode: json::str_at(v, &format!("{}/activeRevisionsMode", c)),
            latest_revision: json::str_at(v, &format!("{}/latestRevisionName", p)),
            latest_ready_revision: json::str_at(v, &format!("{}/latestReadyRevisionName", p)),
            max_inactive_revisions: json::int_at(v, &format!("{}/maxInactiveRevisions", c)),
            ingress: v.pointer(&format!("{}/ingress", c)).filter(|i| i.is_object()).cloned(),
            scale: v.pointer("/properties/template/scale").cloned().unwrap_or(Value::Null),
            dapr_enabled: json::bool_at(v, &format!("{}/dapr/enabled", c)),
            dapr_app_id: json::str_at(v, &format!("{}/dapr/appId", c)),
            outbound_subnet_id: json::arm_id(json::str_at(v, &format!("{}/networking/outboundVnetSubnetId", p))),
            base,
        })
    }

    fn fqdn(&self) -> Option<String> {
        self.ingress.as_ref().and_then(|i| json::str_at(i, "/fqdn")).filter(|s| !s.is_empty())
    }

    fn exposure(&self) -> &'static str {
        match self.ingress.as_ref().and_then(|i| json::bool_at(i, "/external")) {
            None if self.ingress.is_none() => "disabled",
            Some(true) => "external",
            Some(false) | None => "internal",
        }
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.running_status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "running" => ResourceState::Running,
                "ready" => ResourceState::Available,
                "stopped" | "suspended" => ResourceState::Stopped,
                _ => ResourceState::Pending,
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    /// `-n {name} -g {rg} --subscription {sub}`: `az containerapp
    /// revision list` takes no `--ids` (`id_part=None` on its name).
    fn name_args(&self) -> Option<String> {
        Some(format!(
            "-n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for ContainerAppRow {
    arm_row!("Container app");
    /// `1–5 replicas`, from `template.scale` (the running status is the
    /// state column already). Azure's defaults fill a missing bound.
    fn list_summary(&self) -> Option<String> {
        let min = self.scale.pointer("/minReplicas").and_then(|v| v.as_i64());
        let max = self.scale.pointer("/maxReplicas").and_then(|v| v.as_i64());
        if min.is_none() && max.is_none() {
            return None;
        }
        Some(format!("{}–{} replicas", min.unwrap_or(0), max.unwrap_or(10)))
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&CONTAINER_APP_SECTIONS)
    }
    /// The FQDN and custom domains are searchable: a hostname from a
    /// connector's config finds its app.
    fn search_text(&self) -> String {
        let domains: Vec<String> = self
            .ingress
            .as_ref()
            .map(|i| json::arr(i, "/customDomains").iter().filter_map(|d| json::str_at(d, "/name")).collect())
            .unwrap_or_default();
        format!(
            "{} {} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.workload.environment_name(),
            self.fqdn().unwrap_or_default(),
            domains.join(" "),
            self.workload.images(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let dapr = match (self.dapr_enabled, &self.dapr_app_id) {
            (Some(true), Some(id)) => format!("yes · app id {}", id),
            (b, _) => json::yes_no(b),
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Environment".into(), self.workload.environment_name().to_string()),
            ("Workload profile".into(), json::opt(self.workload.workload_profile.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Running status".into(), json::opt(self.running_status.clone())),
            ("Ingress".into(), self.exposure().into()),
            ("FQDN".into(), json::opt(self.fqdn())),
            ("Revisions mode".into(), json::opt(self.revisions_mode.clone())),
            ("Latest revision".into(), json::opt(self.latest_revision.clone())),
            ("Latest ready revision".into(), json::opt(self.latest_ready_revision.clone())),
            ("Max inactive revisions".into(), json::num(self.max_inactive_revisions)),
            ("Identity".into(), json::opt(self.workload.identity_type.clone())),
            ("Dapr".into(), dapr),
            ("Outbound IPs".into(), json::join(&self.workload.outbound_ips)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = self.workload.related(&self.base.id);
        if let Some(s) = &self.outbound_subnet_id {
            v.push((format!("Outbound subnet {}", name_of_id(s)), s.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az containerapp show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn container_app_section_lines(
    r: &ContainerAppRow,
    section: ContainerAppDetailSection,
    revisions: Option<&Lazy<Vec<Value>>>,
    auth: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        ContainerAppDetailSection::Overview => overview_rows(r),
        ContainerAppDetailSection::Ingress => ingress_rows(r),
        ContainerAppDetailSection::Scale => scale_rows(&r.scale),
        ContainerAppDetailSection::Containers => r.workload.container_rows(),
        ContainerAppDetailSection::Revisions => lazy_list_rows(revisions, "Revisions", |items| revision_rows(items, r)),
        ContainerAppDetailSection::Auth => lazy_list_rows(auth, "Auth", |items| auth_rows(items, r)),
        ContainerAppDetailSection::Identity => r.workload.identity_rows(),
        ContainerAppDetailSection::Secrets => r.workload.secret_rows(),
        ContainerAppDetailSection::Access => crate::azure::services::rendered_by_app(),
        ContainerAppDetailSection::Activity => crate::azure::services::rendered_by_app(),
        ContainerAppDetailSection::Related => related_rows(r),
        ContainerAppDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Ingress section: who can reach the app and how. Exposure,
/// transport and ports; HTTP allowed or redirected; client certificates;
/// IP restrictions (all allow or all deny: the platform refuses a mix);
/// CORS; the traffic split; custom domains with their certificates.
fn ingress_rows(r: &ContainerAppRow) -> Vec<(String, String)> {
    let Some(i) = &r.ingress else {
        return vec![
            ("Ingress".into(), "disabled".into()),
            (String::new(), "· the app accepts no inbound HTTP or TCP traffic".into()),
        ];
    };
    let exposure = match json::bool_at(i, "/external") {
        Some(true) => "external · from outside the environment (the internet, or only the VNet when the environment is internal)",
        _ => "internal · only from apps in the same environment",
    };
    let insecure = match json::bool_at(i, "/allowInsecure") {
        Some(true) => "yes · ⚠ plain HTTP is served, not redirected".to_string(),
        Some(false) => "no · HTTP redirects to HTTPS".to_string(),
        None => "-".to_string(),
    };
    let client_cert = match json::str_at(i, "/clientCertificateMode") {
        Some(m) if m.eq_ignore_ascii_case("require") => "require · mTLS: a client certificate is mandatory".to_string(),
        Some(m) if m.eq_ignore_ascii_case("accept") => "accept · forwarded when presented, not required".to_string(),
        Some(m) => m,
        None => "- (ignore)".to_string(),
    };
    let mut lines = vec![
        ("Exposure".into(), exposure.to_string()),
        ("FQDN".into(), json::text(i, "/fqdn")),
        ("Transport".into(), json::text(i, "/transport")),
        ("Target port".into(), json::text(i, "/targetPort")),
    ];
    if let Some(p) = json::int_at(i, "/exposedPort").filter(|p| *p != 0) {
        lines.push(("Exposed port".into(), p.to_string()));
    }
    lines.push(("Allow insecure (HTTP)".into(), insecure));
    lines.push(("Client certificates".into(), client_cert));
    lines.push(("Sticky sessions".into(), json::text(i, "/stickySessions/affinity")));
    for m in json::arr(i, "/additionalPortMappings") {
        let ext = if json::bool_at(&m, "/external") == Some(true) { "external" } else { "internal" };
        lines.push((
            format!("Extra port {}", json::text(&m, "/targetPort")),
            format!("{} · exposed {}", ext, json::text(&m, "/exposedPort")),
        ));
    }

    let rules = json::arr(i, "/ipSecurityRestrictions");
    lines.push((String::new(), String::new()));
    if rules.is_empty() {
        lines.push(("IP restrictions".into(), "none · every source address allowed".into()));
    } else {
        let all_allow = rules.iter().all(|r| json::text(r, "/action").eq_ignore_ascii_case("allow"));
        lines.push((
            "IP restrictions".into(),
            if all_allow {
                format!("{} allow rules · every other address is denied", rules.len())
            } else {
                format!("{} deny rules · every other address is allowed", rules.len())
            },
        ));
    }
    for rule in &rules {
        lines.push((
            format!("  {} {}", json::text(rule, "/action").to_lowercase(), json::text(rule, "/name")),
            json::text(rule, "/ipAddressRange"),
        ));
        if let Some(d) = json::str_at(rule, "/description").filter(|d| !d.is_empty()) {
            lines.push((String::new(), format!("    {}", d)));
        }
    }

    lines.push((String::new(), String::new()));
    match i.pointer("/corsPolicy").filter(|c| c.is_object()) {
        None => lines.push(("CORS".into(), "none · browsers get no CORS headers".into())),
        Some(c) => {
            lines.push(("CORS".into(), String::new()));
            lines.push(("  Allowed origins".into(), json::join(&json::strings_at(c, "/allowedOrigins"))));
            lines.push(("  Allowed methods".into(), json::join(&json::strings_at(c, "/allowedMethods"))));
            lines.push(("  Allowed headers".into(), json::join(&json::strings_at(c, "/allowedHeaders"))));
            lines.push(("  Expose headers".into(), json::join(&json::strings_at(c, "/exposeHeaders"))));
            lines.push(("  Max age".into(), json::text(c, "/maxAge")));
            lines.push(("  Allow credentials".into(), json::yes_no(json::bool_at(c, "/allowCredentials"))));
        }
    }

    let traffic = json::arr(i, "/traffic");
    lines.push((String::new(), String::new()));
    lines.push(("Traffic".into(), if traffic.is_empty() { "-".into() } else { String::new() }));
    for t in &traffic {
        let target = match json::str_at(t, "/revisionName") {
            Some(name) => name,
            None if json::bool_at(t, "/latestRevision") == Some(true) => "latest revision".into(),
            None => "-".into(),
        };
        let label = json::str_at(t, "/label").map(|l| format!(" ({})", l)).unwrap_or_default();
        let weight = json::int_at(t, "/weight").map(|w| format!("{}%", w)).unwrap_or_else(|| "-".into());
        lines.push((format!("  {}{}", target, label), weight));
    }

    let domains = json::arr(i, "/customDomains");
    lines.push((String::new(), String::new()));
    lines.push((
        "Custom domains".into(),
        if domains.is_empty() { "none · the generated FQDN only".into() } else { String::new() },
    ));
    for d in &domains {
        lines.push((format!("  {}", json::text(d, "/name")), json::text(d, "/bindingType")));
        if let Some(cert) = json::arm_id(json::str_at(d, "/certificateId")) {
            lines.push(("    Certificate".into(), cert));
        }
    }

    if let Some(env) = &r.workload.environment_id {
        lines.push((String::new(), String::new()));
        lines.push((format!("Environment · {}", name_of_id(env)), env.clone()));
        lines.push((String::new(), "· whether the environment is VNet-internal is in its Network section".into()));
    }
    lines
}

/// The Scale section from `template.scale`.
fn scale_rows(s: &Value) -> Vec<(String, String)> {
    let mut lines = vec![
        ("Min replicas".into(), json::text(s, "/minReplicas")),
        ("Max replicas".into(), json::text(s, "/maxReplicas")),
    ];
    if let Some(c) = json::int_at(s, "/cooldownPeriod") {
        lines.push(("Cooldown".into(), format!("{}s", c)));
    }
    if let Some(p) = json::int_at(s, "/pollingInterval") {
        lines.push(("Polling interval".into(), format!("{}s", p)));
    }
    let rules = json::arr(s, "/rules");
    lines.push((String::new(), String::new()));
    lines.push((
        "Rules".into(),
        if rules.is_empty() { "none declared".into() } else { String::new() },
    ));
    for rule in &rules {
        lines.extend(app_rule_rows(rule));
    }
    lines
}

/// The Revisions section body from `GET {app}/revisions`: active first,
/// then newest first. Never the revision's template (it carries env).
pub fn revision_rows(items: &[Value], r: &ContainerAppRow) -> Vec<(String, String)> {
    let mut items: Vec<&Value> = items.iter().collect();
    items.sort_by(|a, b| {
        let active = |v: &Value| json::bool_at(v, "/properties/active") == Some(true);
        active(b)
            .cmp(&active(a))
            .then_with(|| json::text(b, "/properties/createdTime").cmp(&json::text(a, "/properties/createdTime")))
    });
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No revisions".into()));
    }
    for rev in items {
        let p = "/properties";
        let name = json::text(rev, "/name");
        let latest = if r.latest_revision.as_deref() == Some(name.as_str()) { " (latest)" } else { "" };
        lines.push((String::new(), String::new()));
        lines.push((format!("{}{}", name, latest), String::new()));
        lines.push(("  Active".into(), json::yes_no(json::bool_at(rev, &format!("{}/active", p)))));
        lines.push((
            "  Traffic".into(),
            json::int_at(rev, &format!("{}/trafficWeight", p)).map(|w| format!("{}%", w)).unwrap_or_else(|| "-".into()),
        ));
        lines.push(("  Replicas".into(), json::text(rev, &format!("{}/replicas", p))));
        lines.push(("  Health".into(), json::text(rev, &format!("{}/healthState", p))));
        lines.push(("  Running".into(), json::text(rev, &format!("{}/runningState", p))));
        lines.push(("  Created".into(), json::time(json::str_at(rev, &format!("{}/createdTime", p)))));
        lines.push(("  Last active".into(), json::time(json::str_at(rev, &format!("{}/lastActiveTime", p)))));
        if let Some(e) = json::str_at(rev, &format!("{}/provisioningError", p)).filter(|e| !e.is_empty()) {
            lines.push(("  ⚠ Error".into(), e));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az containerapp revision list {} --all", r.name_args().unwrap_or_default()),
    ));
    lines
}

/// The identity providers an auth config can carry, with the field that
/// names the client (never a secret: those are setting *names*).
const AUTH_PROVIDERS: &[(&str, &str, &str)] = &[
    ("azureActiveDirectory", "Microsoft Entra ID", "/registration/clientId"),
    ("facebook", "Facebook", "/registration/appId"),
    ("gitHub", "GitHub", "/registration/clientId"),
    ("google", "Google", "/registration/clientId"),
    ("twitter", "Twitter", "/registration/consumerKey"),
    ("apple", "Apple", "/registration/clientId"),
    ("azureStaticWebApps", "Static Web Apps", "/registration/clientId"),
];

/// The Auth section body from `GET {app}/authConfigs` (built-in
/// authentication, "Easy Auth"): whether it is on, what an anonymous
/// caller gets, and per provider the client id and, for Entra ID, the
/// issuer, audiences and allowed client applications. Client secrets are
/// app secrets named by `clientSecretSettingName`; only the name shows.
pub fn auth_rows(items: &[Value], r: &ContainerAppRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No auth config · built-in authentication is off".into()));
    }
    for cfg in items {
        let p = |k: &str| format!("/properties/{}", k);
        if items.len() > 1 {
            lines.push((json::text(cfg, "/name"), String::new()));
        }
        let platform = match (json::bool_at(cfg, &p("platform/enabled")), json::str_at(cfg, &p("platform/runtimeVersion"))) {
            (Some(true), Some(v)) => format!("enabled · runtime {}", v),
            (Some(true), None) => "enabled".into(),
            (Some(false), _) => "disabled".into(),
            (None, _) => "-".into(),
        };
        lines.push(("Built-in auth".into(), platform));
        lines.push((
            "Unauthenticated requests".into(),
            json::text(cfg, &p("globalValidation/unauthenticatedClientAction")),
        ));
        lines.push(("Redirect provider".into(), json::text(cfg, &p("globalValidation/redirectToProvider"))));
        lines.push((
            "Excluded paths".into(),
            json::join(&json::strings_at(cfg, &p("globalValidation/excludedPaths"))),
        ));
        lines.push(("Require HTTPS".into(), json::yes_no(json::bool_at(cfg, &p("httpSettings/requireHttps")))));
        lines.push(("Token store".into(), json::yes_no(json::bool_at(cfg, &p("login/tokenStore/enabled")))));

        let providers = cfg.pointer(&p("identityProviders"));
        for (key, label, client) in AUTH_PROVIDERS {
            let Some(prov) = providers.and_then(|ps| ps.get(*key)) else {
                continue;
            };
            lines.push((String::new(), String::new()));
            let enabled = json::bool_at(prov, "/enabled").map(|b| if b { "enabled" } else { "disabled" }).unwrap_or("configured");
            lines.push((label.to_string(), enabled.into()));
            lines.push(("  Client id".into(), json::text(prov, client)));
            if *key == "azureActiveDirectory" {
                let v = "/validation";
                lines.push(("  Issuer".into(), json::text(prov, "/registration/openIdIssuer")));
                lines.push((
                    "  Client secret setting".into(),
                    json::text(prov, "/registration/clientSecretSettingName"),
                ));
                lines.push(("  Allowed audiences".into(), json::join(&json::strings_at(prov, &format!("{}/allowedAudiences", v)))));
                lines.push((
                    "  Allowed client apps".into(),
                    json::join(&json::strings_at(prov, &format!("{}/defaultAuthorizationPolicy/allowedApplications", v))),
                ));
                lines.push((
                    "  Allowed identities".into(),
                    json::join(&json::strings_at(prov, &format!("{}/defaultAuthorizationPolicy/allowedPrincipals/identities", v))),
                ));
                lines.push((
                    "  JWT client apps".into(),
                    json::join(&json::strings_at(prov, &format!("{}/jwtClaimChecks/allowedClientApplications", v))),
                ));
                lines.push((
                    "  JWT groups".into(),
                    json::join(&json::strings_at(prov, &format!("{}/jwtClaimChecks/allowedGroups", v))),
                ));
            }
        }
        if let Some(custom) = providers.and_then(|ps| ps.get("customOpenIdConnectProviders")).and_then(Value::as_object) {
            for (name, prov) in custom {
                lines.push((String::new(), String::new()));
                let enabled = json::bool_at(prov, "/enabled").map(|b| if b { "enabled" } else { "disabled" }).unwrap_or("configured");
                lines.push((format!("OpenID Connect · {}", name), enabled.into()));
                lines.push(("  Client id".into(), json::text(prov, "/registration/clientId")));
                lines.push((
                    "  Client secret setting".into(),
                    json::text(prov, "/registration/clientCredential/clientSecretSettingName"),
                ));
            }
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "· client secrets are app secrets: their names show, never values".into()));
    lines.push((
        "Read command".into(),
        format!("az containerapp auth show --ids {}", shell_quote(&r.base.id)),
    ));
    lines
}

/// The ARM path of an app's child list (`revisions`, `authConfigs`).
pub fn container_app_child_path(app_id: &str, child: &str) -> String {
    format!("{}/{}", app_id.trim_end_matches('/'), child)
}

// ── Managed environment ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WorkloadProfile {
    pub name: String,
    pub kind: String,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct EnvironmentRow {
    pub base: ArmBase,
    pub mode: Option<String>,
    /// The apps' domain (data plane): text only, never requested.
    pub default_domain: Option<String>,
    pub static_ip: Option<String>,
    pub zone_redundant: Option<bool>,
    pub public_network_access: Option<String>,
    pub internal: Option<bool>,
    pub infrastructure_subnet_id: Option<String>,
    pub docker_bridge_cidr: Option<String>,
    pub platform_reserved_cidr: Option<String>,
    pub platform_reserved_dns_ip: Option<String>,
    pub infrastructure_resource_group: Option<String>,
    pub dns_suffix: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_thumbprint: Option<String>,
    pub cert_expiry: Option<String>,
    /// A Key Vault secret URL, not an ARM id.
    pub cert_key_vault_url: Option<String>,
    pub cert_key_vault_identity: Option<String>,
    pub mtls: Option<bool>,
    pub peer_encryption: Option<bool>,
    pub ingress_config: Value,
    pub log_destination: Option<String>,
    /// The Log Analytics workspace's customer id (a GUID, not an ARM id):
    /// the workspace row is searchable by it.
    pub log_customer_id: Option<String>,
    pub workload_profiles: Vec<WorkloadProfile>,
    pub dapr_version: Option<String>,
    pub keda_version: Option<String>,
    pub deployment_errors: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub private_endpoint_ids: Vec<String>,
}

impl EnvironmentRow {
    /// Parses an environment with its credentials stripped first (shared
    /// key, Dapr App Insights key and connection string, certificate blob
    /// and password).
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<EnvironmentRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        let p = "/properties";
        let n = format!("{}/vnetConfiguration", p);
        let d = format!("{}/customDomainConfiguration", p);
        Some(EnvironmentRow {
            mode: json::str_at(v, &format!("{}/environmentMode", p)).or_else(|| json::str_at(v, "/kind")),
            default_domain: json::str_at(v, &format!("{}/defaultDomain", p)),
            static_ip: json::str_at(v, &format!("{}/staticIp", p)),
            zone_redundant: json::bool_at(v, &format!("{}/zoneRedundant", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            internal: json::bool_at(v, &format!("{}/internal", n)),
            infrastructure_subnet_id: json::arm_id(json::str_at(v, &format!("{}/infrastructureSubnetId", n))),
            docker_bridge_cidr: json::str_at(v, &format!("{}/dockerBridgeCidr", n)),
            platform_reserved_cidr: json::str_at(v, &format!("{}/platformReservedCidr", n)),
            platform_reserved_dns_ip: json::str_at(v, &format!("{}/platformReservedDnsIP", n)),
            infrastructure_resource_group: json::str_at(v, &format!("{}/infrastructureResourceGroup", p))
                .filter(|s| !s.is_empty()),
            dns_suffix: json::str_at(v, &format!("{}/dnsSuffix", d)).filter(|s| !s.is_empty()),
            cert_subject: json::str_at(v, &format!("{}/subjectName", d)),
            cert_thumbprint: json::str_at(v, &format!("{}/thumbprint", d)),
            cert_expiry: json::str_at(v, &format!("{}/expirationDate", d)),
            cert_key_vault_url: json::str_at(v, &format!("{}/certificateKeyVaultProperties/keyVaultUrl", d))
                .filter(|s| !s.is_empty()),
            cert_key_vault_identity: json::str_at(v, &format!("{}/certificateKeyVaultProperties/identity", d)),
            mtls: json::bool_at(v, &format!("{}/peerAuthentication/mtls/enabled", p)),
            peer_encryption: json::bool_at(v, &format!("{}/peerTrafficConfiguration/encryption/enabled", p)),
            ingress_config: v.pointer(&format!("{}/ingressConfiguration", p)).cloned().unwrap_or(Value::Null),
            log_destination: json::str_at(v, &format!("{}/appLogsConfiguration/destination", p)),
            log_customer_id: json::str_at(v, &format!("{}/appLogsConfiguration/logAnalyticsConfiguration/customerId", p)),
            workload_profiles: json::arr(v, &format!("{}/workloadProfiles", p))
                .iter()
                .map(|w| WorkloadProfile {
                    name: json::text(w, "/name"),
                    kind: json::text(w, "/workloadProfileType"),
                    min: json::int_at(w, "/minimumCount"),
                    max: json::int_at(w, "/maximumCount"),
                })
                .collect(),
            dapr_version: json::str_at(v, &format!("{}/daprConfiguration/version", p)),
            keda_version: json::str_at(v, &format!("{}/kedaConfiguration/version", p)),
            deployment_errors: json::str_at(v, &format!("{}/deploymentErrors", p)).filter(|s| !s.is_empty()),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            private_endpoint_ids: json::arr(v, &format!("{}/privateEndpointConnections", p))
                .iter()
                .filter_map(|c| json::arm_id(json::id_at(c, "/properties/privateEndpoint")))
                .collect(),
            base,
        })
    }

    /// The managed resource group the platform creates for the
    /// environment's infrastructure, as an ARM id.
    fn infrastructure_rg_id(&self) -> Option<String> {
        let rg = self.infrastructure_resource_group.as_ref()?;
        Some(format!("/subscriptions/{}/resourceGroups/{}", subscription_of(&self.base.id)?, rg))
    }

    fn internal_label(&self) -> String {
        match (self.internal, &self.infrastructure_subnet_id) {
            (Some(true), _) => "yes · the static IP is private, inside the VNet".into(),
            (_, Some(_)) => "no · a public static IP, outbound through the VNet".into(),
            _ => "no · Azure-managed network, public static IP".into(),
        }
    }
}

impl Resource for EnvironmentRow {
    arm_row!("Container Apps environment");
    /// Internal (VNet-only ingress) or external.
    fn list_summary(&self) -> Option<String> {
        self.internal.map(|i| if i { "internal" } else { "external" }.to_string())
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ENVIRONMENT_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.default_domain.clone()),
            json::opt(self.static_ip.clone()),
            json::opt(self.dns_suffix.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let logs = match (&self.log_destination, &self.log_customer_id) {
            (Some(d), Some(id)) => format!("{} · workspace {}", d, id),
            (Some(d), None) => d.clone(),
            (None, _) => "none".into(),
        };
        let mut lines = vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Mode".into(), json::opt(self.mode.clone())),
            ("Default domain".into(), json::opt(self.default_domain.clone())),
            ("Static IP".into(), json::opt(self.static_ip.clone())),
            ("Internal only".into(), self.internal_label()),
            ("Zone redundant".into(), json::yes_no(self.zone_redundant)),
            ("Workload profiles".into(), self.workload_profiles.len().to_string()),
            ("Logs".into(), logs),
            ("Dapr / KEDA".into(), format!("{} / {}", json::opt(self.dapr_version.clone()), json::opt(self.keda_version.clone()))),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ];
        if let Some(e) = &self.deployment_errors {
            lines.push(("⚠ Deployment errors".into(), e.clone()));
        }
        lines
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(s) = &self.infrastructure_subnet_id {
            v.push((format!("Infrastructure subnet {}", name_of_id(s)), s.clone()));
        }
        if let Some(rg) = self.infrastructure_rg_id() {
            v.push((format!("Infrastructure resource group {}", name_of_id(&rg)), rg));
        }
        for pe in &self.private_endpoint_ids {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az containerapp env show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn environment_section_lines(r: &EnvironmentRow, section: EnvironmentDetailSection) -> Vec<(String, String)> {
    match section {
        EnvironmentDetailSection::Overview => {
            let mut lines = overview_rows(r);
            if r.log_customer_id.is_some() {
                lines.push((String::new(), "· the workspace is a customer id, not an ARM id: search @law for it".into()));
            }
            lines
        }
        EnvironmentDetailSection::Network => network_rows(r),
        EnvironmentDetailSection::WorkloadProfiles => {
            if r.workload_profiles.is_empty() {
                return vec![(String::new(), "No workload profiles · a Consumption-only environment".into())];
            }
            r.workload_profiles
                .iter()
                .map(|w| {
                    let count = match (w.min, w.max) {
                        (Some(min), Some(max)) => format!(" · {}–{} nodes", min, max),
                        _ => String::new(),
                    };
                    (w.name.clone(), format!("{}{}", w.kind, count))
                })
                .collect()
        }
        EnvironmentDetailSection::Access => crate::azure::services::rendered_by_app(),
        EnvironmentDetailSection::Activity => crate::azure::services::rendered_by_app(),
        EnvironmentDetailSection::Related => related_rows(r),
        EnvironmentDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The Network section: how the environment's apps are reached and from
/// where. VNet integration and internal-only, the static IP and default
/// domain (the private DNS a VNet caller needs), reserved ranges, the
/// custom DNS suffix and its certificate, peer mTLS and encryption, the
/// ingress tier and private endpoints.
fn network_rows(r: &EnvironmentRow) -> Vec<(String, String)> {
    let mut lines = vec![
        ("Public network access".into(), json::opt(r.public_network_access.clone())),
        ("Internal only".into(), r.internal_label()),
        ("Static IP".into(), json::opt(r.static_ip.clone())),
        ("Default domain".into(), json::opt(r.default_domain.clone())),
    ];
    match &r.infrastructure_subnet_id {
        // The value is the ARM id: Enter jumps to the subnet.
        Some(s) => lines.push((format!("Infrastructure subnet · {}", name_of_id(s)), s.clone())),
        None => lines.push(("Infrastructure subnet".into(), "- (no VNet integration)".into())),
    }
    lines.push(("Docker bridge CIDR".into(), json::opt(r.docker_bridge_cidr.clone())));
    lines.push(("Platform reserved CIDR".into(), json::opt(r.platform_reserved_cidr.clone())));
    lines.push(("Platform reserved DNS IP".into(), json::opt(r.platform_reserved_dns_ip.clone())));
    if r.internal == Some(true) {
        if let (Some(domain), Some(ip)) = (&r.default_domain, &r.static_ip) {
            lines.push((
                String::new(),
                format!("· VNet callers need private DNS: *.{} → {}", domain, ip),
            ));
        }
    }

    lines.push((String::new(), String::new()));
    lines.push(("Custom DNS suffix".into(), json::opt(r.dns_suffix.clone())));
    if r.dns_suffix.is_some() {
        lines.push(("  Certificate".into(), json::opt(r.cert_subject.clone())));
        lines.push(("  Thumbprint".into(), json::opt(r.cert_thumbprint.clone())));
        lines.push(("  Expires".into(), json::time(r.cert_expiry.clone())));
        if let Some(url) = &r.cert_key_vault_url {
            lines.push(("  From Key Vault".into(), url.clone()));
            if let Some(i) = &r.cert_key_vault_identity {
                lines.push(("  Read by".into(), i.clone()));
            }
        }
    }

    lines.push((String::new(), String::new()));
    lines.push(("Peer mTLS".into(), json::yes_no(r.mtls)));
    lines.push(("Peer traffic encryption".into(), json::yes_no(r.peer_encryption)));
    let ic = &r.ingress_config;
    if ic.is_object() {
        lines.push((String::new(), String::new()));
        lines.push(("Ingress".into(), String::new()));
        lines.push(("  Workload profile".into(), json::text(ic, "/workloadProfileName")));
        lines.push(("  Header count limit".into(), json::text(ic, "/headerCountLimit")));
        lines.push((
            "  Request idle timeout".into(),
            json::int_at(ic, "/requestIdleTimeout").map(|m| format!("{} min", m)).unwrap_or_else(|| "-".into()),
        ));
        lines.push((
            "  Termination grace".into(),
            json::int_at(ic, "/terminationGracePeriodSeconds").map(|s| format!("{}s", s)).unwrap_or_else(|| "-".into()),
        ));
    }
    if !r.private_endpoint_ids.is_empty() {
        lines.push((String::new(), String::new()));
    }
    for pe in &r.private_endpoint_ids {
        lines.push((format!("Private endpoint · {}", name_of_id(pe)), pe.clone()));
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "· each app's exposure and IP restrictions are in its Ingress section".into()));
    lines
}

// ── Job ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct JobRow {
    pub base: ArmBase,
    pub workload: Workload,
    pub running_state: Option<String>,
    pub trigger_type: Option<String>,
    pub replica_timeout: Option<i64>,
    pub retry_limit: Option<i64>,
    /// `configuration`, for the trigger config the type picks.
    pub configuration: Value,
}

impl JobRow {
    /// Parses a job with its credentials stripped first.
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<JobRow> {
        let v = &without_secrets(v);
        let base = base_of(v, tenant)?;
        let c = "/properties/configuration";
        Some(JobRow {
            workload: Workload::from_json(v),
            running_state: json::str_at(v, "/properties/runningState"),
            trigger_type: json::str_at(v, &format!("{}/triggerType", c)),
            replica_timeout: json::int_at(v, &format!("{}/replicaTimeout", c)),
            retry_limit: json::int_at(v, &format!("{}/replicaRetryLimit", c)),
            configuration: v.pointer(c).cloned().unwrap_or(Value::Null),
            base,
        })
    }

    /// The trigger's own config block: `scheduleTriggerConfig` and so on.
    fn trigger_config(&self) -> Option<&Value> {
        let key = match self.trigger_type.as_deref()?.to_lowercase().as_str() {
            "schedule" => "scheduleTriggerConfig",
            "event" => "eventTriggerConfig",
            "manual" => "manualTriggerConfig",
            _ => return None,
        };
        self.configuration.get(key).filter(|v| v.is_object())
    }

    fn cron(&self) -> Option<String> {
        self.trigger_config().and_then(|t| json::str_at(t, "/cronExpression"))
    }

    /// `-n {job} -g {rg} --subscription {sub}`: `job execution list`
    /// takes no `--ids`.
    fn name_args(&self) -> Option<String> {
        Some(format!(
            "-n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

impl Resource for JobRow {
    arm_row!("Container Apps job");
    /// The trigger: `Manual`, `Schedule` or `Event`.
    fn list_summary(&self) -> Option<String> {
        self.trigger_type.clone()
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&JOB_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            self.workload.environment_name(),
            json::opt(self.trigger_type.clone()),
            self.workload.images(),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        let trigger = match (&self.trigger_type, self.cron()) {
            (Some(t), Some(cron)) => format!("{} · {}", t, cron),
            (t, _) => json::opt(t.clone()),
        };
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Environment".into(), self.workload.environment_name().to_string()),
            ("Workload profile".into(), json::opt(self.workload.workload_profile.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Running state".into(), json::opt(self.running_state.clone())),
            ("Trigger".into(), trigger),
            ("Identity".into(), json::opt(self.workload.identity_type.clone())),
            ("Outbound IPs".into(), json::join(&self.workload.outbound_ips)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        self.workload.related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az containerapp job show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn job_section_lines(
    r: &JobRow,
    section: JobDetailSection,
    executions: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        JobDetailSection::Overview => overview_rows(r),
        JobDetailSection::Trigger => trigger_rows(r),
        JobDetailSection::Executions => lazy_list_rows(executions, "Executions", |items| execution_rows(items, r)),
        JobDetailSection::Containers => r.workload.container_rows(),
        JobDetailSection::Identity => r.workload.identity_rows(),
        JobDetailSection::Secrets => r.workload.secret_rows(),
        JobDetailSection::Access => crate::azure::services::rendered_by_app(),
        JobDetailSection::Activity => crate::azure::services::rendered_by_app(),
        JobDetailSection::Related => related_rows(r),
        JobDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// How many executions the section shows: the newest. `GET {job}/executions`
/// returns the platform's recent history in one page.
const EXECUTIONS_SHOWN: usize = 20;

/// The Executions section body from `GET {job}/executions`: newest first,
/// each with its status, start and end. A failed one is marked `⚠`.
/// Never the execution's template (it carries env).
pub fn execution_rows(items: &[Value], r: &JobRow) -> Vec<(String, String)> {
    let mut items: Vec<&Value> = items.iter().collect();
    items.sort_by_key(|a| std::cmp::Reverse(json::text(a, "/properties/startTime")));
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No executions".into()));
    }
    for ex in items.iter().take(EXECUTIONS_SHOWN) {
        let status = json::text(ex, "/properties/status");
        let failed = matches!(status.to_ascii_lowercase().as_str(), "failed" | "degraded");
        let status = if failed { format!("⚠ {}", status) } else { status };
        lines.push((String::new(), String::new()));
        lines.push((json::text(ex, "/name"), status));
        lines.push(("  Started".into(), json::time(json::str_at(ex, "/properties/startTime"))));
        lines.push(("  Ended".into(), json::time(json::str_at(ex, "/properties/endTime"))));
    }
    if items.len() > EXECUTIONS_SHOWN {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("· {} older not shown", items.len() - EXECUTIONS_SHOWN)));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!("az containerapp job execution list {}", r.name_args().unwrap_or_default()),
    ));
    lines
}

/// The Trigger section: manual, scheduled (cron) or event-driven (KEDA
/// rules), with parallelism, completions, retries and the timeout.
fn trigger_rows(r: &JobRow) -> Vec<(String, String)> {
    let mut lines = vec![("Trigger".into(), json::opt(r.trigger_type.clone()))];
    if let Some(t) = r.trigger_config() {
        if let Some(cron) = json::str_at(t, "/cronExpression") {
            lines.push(("Cron".into(), format!("{} (UTC)", cron)));
        }
        lines.push(("Parallelism".into(), json::text(t, "/parallelism")));
        lines.push(("Completions".into(), json::text(t, "/replicaCompletionCount")));
        if let Some(s) = t.pointer("/scale") {
            lines.push(("Polling interval".into(), json::int_at(s, "/pollingInterval").map(|p| format!("{}s", p)).unwrap_or_else(|| "-".into())));
            lines.push(("Executions".into(), format!("{} – {}", json::text(s, "/minExecutions"), json::text(s, "/maxExecutions"))));
            let rules = json::arr(s, "/rules");
            lines.push((String::new(), String::new()));
            lines.push(("Rules".into(), if rules.is_empty() { "none declared".into() } else { String::new() }));
            for rule in &rules {
                lines.extend(rule_rows(&json::text(rule, "/name"), &json::text(rule, "/type"), rule));
            }
            lines.push((String::new(), String::new()));
        }
    }
    lines.push((
        "Replica timeout".into(),
        r.replica_timeout.map(|s| format!("{}s", s)).unwrap_or_else(|| "-".into()),
    ));
    lines.push(("Retry limit".into(), json::num(r.retry_limit)));
    lines
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct ContainerAppsService {
    scope: Scope,
}

impl ContainerAppsService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// One page of a sub-tab, parsed as that sub-tab's row type.
    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::ContainerAppEnvironments => page
                .iter()
                .filter_map(|v| EnvironmentRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            JumpView::ContainerAppJobs => page
                .iter()
                .filter_map(|v| JobRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
            _ => page
                .iter()
                .filter_map(|v| ContainerAppRow::from_json(v, tenant))
                .map(|r| Box::new(r) as Box<dyn Resource>)
                .collect(),
        }
    }

    fn list_of(view: JumpView) -> (&'static str, &'static str) {
        match view {
            JumpView::ContainerAppEnvironments => (ENVIRONMENTS_PATH, "Listing Container Apps environments…"),
            JumpView::ContainerAppJobs => (JOBS_PATH, "Listing Container Apps jobs…"),
            _ => (APPS_PATH, "Listing container apps…"),
        }
    }
}

#[async_trait]
impl AzureService for ContainerAppsService {
    fn service_type(&self) -> ServiceType {
        ServiceType::ContainerApps
    }

    fn name(&self) -> &str {
        "Container Apps"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, _) = Self::list_of(view);
        Ok(Self::rows(view, &self.scope.list(path, ACA_API_VERSION).await?, self.scope.tenant()))
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
            .stream(path, ACA_API_VERSION, &[], service_type, label, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let v = self.scope.get(id, ACA_API_VERSION).await?;
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::ContainerApps);
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-aca";

    #[test]
    fn list_summaries_show_replicas_exposure_and_trigger() {
        let app = ContainerAppRow::from_json(&app_json(), None).unwrap();
        assert_eq!(app.list_summary().as_deref(), Some("1–5 replicas"));
        let env = EnvironmentRow::from_json(&env_json(), None).unwrap();
        assert_eq!(env.list_summary().as_deref(), Some("internal"));
        let job = JobRow::from_json(&job_json(), None).unwrap();
        assert_eq!(job.list_summary().as_deref(), Some("Schedule"));
    }

    fn app_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.App/containerApps/api", RG),
            "name": "api",
            "location": "Australia East",
            "identity": {
                "type": "SystemAssigned,UserAssigned",
                "principalId": "p-system",
                "userAssignedIdentities": {
                    format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-api", RG):
                        {"clientId": "c-api", "principalId": "p-api"}
                }
            },
            "properties": {
                "provisioningState": "Succeeded",
                "runningStatus": "Running",
                "environmentId": format!("{}/providers/Microsoft.App/managedEnvironments/cae-prod", RG),
                "workloadProfileName": "Consumption",
                "latestRevisionName": "api--v2",
                "latestReadyRevisionName": "api--v2",
                "outboundIpAddresses": ["20.1.1.1"],
                "configuration": {
                    "activeRevisionsMode": "Multiple",
                    "secrets": [
                        {"name": "db-password", "value": "hunter2-secret"},
                        {"name": "kv-ref", "keyVaultUrl": "https://kv.example/secrets/x", "identity": "system"}
                    ],
                    "registries": [
                        {"server": "acrprod.example", "identity": format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-pull", RG)},
                        {"server": "docker.example", "username": "bot", "passwordSecretRef": "reg-pass"}
                    ],
                    "ingress": {
                        "external": true,
                        "fqdn": "api.happy.australiaeast.example",
                        "targetPort": 8080,
                        "transport": "auto",
                        "allowInsecure": false,
                        "clientCertificateMode": "require",
                        "ipSecurityRestrictions": [
                            {"name": "powerplatform", "action": "Allow", "ipAddressRange": "203.0.113.0/24", "description": "PP connector"}
                        ],
                        "corsPolicy": {"allowedOrigins": ["https://make.example"], "allowCredentials": true},
                        "traffic": [{"latestRevision": true, "weight": 80}, {"revisionName": "api--v1", "label": "blue", "weight": 20}],
                        "customDomains": [{"name": "api.contoso.example", "bindingType": "SniEnabled",
                            "certificateId": format!("{}/providers/Microsoft.App/managedEnvironments/cae-prod/certificates/c1", RG)}]
                    },
                    "dapr": {"enabled": false}
                },
                "template": {
                    "containers": [{
                        "name": "api",
                        "image": "acrprod.example/api:2",
                        "resources": {"cpu": 0.5, "memory": "1Gi"},
                        "env": [
                            {"name": "DB_PASSWORD", "secretRef": "db-password"},
                            {"name": "API_TOKEN", "value": "literal-secret-token"}
                        ],
                        "probes": [{"type": "Liveness", "httpGet": {"path": "/healthz", "port": 8080}, "periodSeconds": 10}]
                    }],
                    "scale": {"minReplicas": 1, "maxReplicas": 5, "rules": [
                        {"name": "http", "http": {"metadata": {"concurrentRequests": "50"}}},
                        {"name": "queue", "azureQueue": {"queueName": "jobs", "queueLength": 10,
                            "auth": [{"secretRef": "queue-conn", "triggerParameter": "connection"}]}}
                    ]}
                }
            }
        })
    }

    fn env_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.App/managedEnvironments/cae-prod", RG),
            "name": "cae-prod",
            "location": "Australia East",
            "properties": {
                "provisioningState": "Succeeded",
                "environmentMode": "WorkloadProfiles",
                "defaultDomain": "happy.australiaeast.example",
                "staticIp": "10.0.16.4",
                "zoneRedundant": true,
                "publicNetworkAccess": "Disabled",
                "infrastructureResourceGroup": "ME_cae-prod",
                "daprAIInstrumentationKey": "dapr-ikey-secret",
                "daprAIConnectionString": "InstrumentationKey=dapr-secret",
                "vnetConfiguration": {
                    "internal": true,
                    "infrastructureSubnetId": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/aca", RG),
                    "platformReservedCidr": "10.1.0.0/16",
                    "platformReservedDnsIP": "10.1.0.2"
                },
                "appLogsConfiguration": {"destination": "log-analytics",
                    "logAnalyticsConfiguration": {"customerId": "cust-1", "sharedKey": "shared-key-secret"}},
                "appInsightsConfiguration": {"connectionString": "InstrumentationKey=appi-secret"},
                "customDomainConfiguration": {"dnsSuffix": "apps.contoso.example", "subjectName": "CN=*.apps.contoso.example",
                    "certificateValue": "cert-blob-secret", "certificatePassword": "cert-pass-secret",
                    "expirationDate": "2027-01-01T00:00:00Z"},
                "peerAuthentication": {"mtls": {"enabled": true}},
                "peerTrafficConfiguration": {"encryption": {"enabled": true}},
                "workloadProfiles": [{"name": "Consumption", "workloadProfileType": "Consumption"},
                    {"name": "d4", "workloadProfileType": "D4", "minimumCount": 1, "maximumCount": 3}],
                "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": format!("{}/providers/Microsoft.Network/privateEndpoints/pe-cae", RG)}}}]
            }
        })
    }

    fn job_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.App/jobs/nightly", RG),
            "name": "nightly",
            "location": "australiaeast",
            "properties": {
                "provisioningState": "Succeeded",
                "runningState": "Ready",
                "environmentId": format!("{}/providers/Microsoft.App/managedEnvironments/cae-prod", RG),
                "configuration": {
                    "triggerType": "Schedule",
                    "replicaTimeout": 1800,
                    "replicaRetryLimit": 2,
                    "scheduleTriggerConfig": {"cronExpression": "0 2 * * *", "parallelism": 1, "replicaCompletionCount": 1},
                    "secrets": [{"name": "sb", "value": "job-secret-value"}]
                },
                "template": {"containers": [{"name": "run", "image": "acrprod.example/job:1",
                    "env": [{"name": "MODE", "value": "job-literal-secret"}]}]}
            }
        })
    }

    /// Every section body, search text and the raw JSON, concatenated.
    fn everything(r: &dyn Resource, sections: Vec<Vec<(String, String)>>) -> String {
        sections
            .into_iter()
            .flatten()
            .map(|(k, v)| format!("{k}{v}"))
            .collect::<String>()
            + &r.search_text()
            + &r.raw_content().unwrap()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        for desc in [&CONTAINER_APP_SECTIONS, &ENVIRONMENT_SECTIONS, &JOB_SECTIONS] {
            let labels: Vec<&str> = desc.sections.iter().map(|s| s.label).collect();
            assert_eq!(labels.first(), Some(&"Overview"));
            assert_eq!(&labels[labels.len() - 4..], ["Access", "Activity", "Related", "Tags"]);
        }
    }

    #[test]
    fn app_row_reads_state_overview_and_related() {
        let row = ContainerAppRow::from_json(&app_json(), None).unwrap();
        assert_eq!(row.base.location, "australiaeast");
        assert_eq!(row.state(), ResourceState::Running);
        assert_eq!(row.state_label(), "running");
        assert!(row.details().iter().any(|(k, v)| k == "Environment" && v == "cae-prod"));
        assert!(row.details().iter().any(|(k, v)| k == "Ingress" && v == "external"));
        assert!(row.search_text().contains("api.contoso.example"));
        assert!(row.search_text().contains("acrprod.example/api:2"));
        let related = row.related();
        let labels: Vec<&str> = related.iter().map(|(l, _)| l.as_str()).collect();
        for want in ["Environment cae-prod", "Identity id-api", "Registry identity id-pull"] {
            assert!(labels.contains(&want), "{want} in {labels:?}");
        }
        let (_, env) = related.iter().find(|(l, _)| l == "Environment cae-prod").unwrap();
        assert_eq!(JumpView::for_arm_id(env), Some(JumpView::ContainerAppEnvironments));
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az containerapp show --ids /subscriptions/0000/resourceGroups/rg-aca/providers/Microsoft.App/containerApps/api")
        );
    }

    #[test]
    fn ingress_shows_exposure_restrictions_cors_traffic_and_domains() {
        let row = ContainerAppRow::from_json(&app_json(), None).unwrap();
        let lines = container_app_section_lines(&row, ContainerAppDetailSection::Ingress, None, None);
        let has = |k: &str, v: &str| lines.iter().any(|(a, b)| a == k && b.starts_with(v));
        assert!(has("Exposure", "external"));
        assert!(has("Allow insecure (HTTP)", "no"));
        assert!(has("Client certificates", "require"));
        assert!(has("IP restrictions", "1 allow rules · every other address is denied"));
        assert!(has("  allow powerplatform", "203.0.113.0/24"));
        assert!(has("  Allowed origins", "https://make.example"));
        assert!(has("  Allow credentials", "yes"));
        assert!(has("  latest revision", "80%"));
        assert!(has("  api--v1 (blue)", "20%"));
        assert!(has("  api.contoso.example", "SniEnabled"));

        let mut off = app_json();
        off["properties"]["configuration"].as_object_mut().unwrap().remove("ingress");
        let row = ContainerAppRow::from_json(&off, None).unwrap();
        let lines = container_app_section_lines(&row, ContainerAppDetailSection::Ingress, None, None);
        assert_eq!(lines[0], ("Ingress".to_string(), "disabled".to_string()));
    }

    #[test]
    fn scale_and_containers_name_secrets_but_never_values() {
        let row = ContainerAppRow::from_json(&app_json(), None).unwrap();
        let scale = container_app_section_lines(&row, ContainerAppDetailSection::Scale, None, None);
        assert!(scale.iter().any(|(k, v)| k == "  queue" && v == "azure-queue"));
        assert!(scale.iter().any(|(k, v)| k == "    auth connection" && v == "secret queue-conn"));
        let containers = container_app_section_lines(&row, ContainerAppDetailSection::Containers, None, None);
        assert!(containers.iter().any(|(k, v)| k == "    DB_PASSWORD" && v == "secret ref · db-password"));
        assert!(containers.iter().any(|(k, v)| k == "    API_TOKEN" && v == "value"));
        assert!(containers.iter().any(|(k, v)| k == "  Probe · liveness" && v == "http /healthz :8080 · every 10s"));
        let secrets = container_app_section_lines(&row, ContainerAppDetailSection::Secrets, None, None);
        assert!(secrets.iter().any(|(k, v)| k == "  db-password" && v == "stored in the resource"));
        assert!(secrets.iter().any(|(k, v)| k == "  docker.example" && v.contains("password in secret reg-pass")));
        let identity = container_app_section_lines(&row, ContainerAppDetailSection::Identity, None, None);
        assert!(identity.iter().any(|(k, v)| k == "System-assigned principal" && v == "p-system"));
        let (_, uami) = identity.iter().find(|(k, _)| k == "User-assigned · id-api").unwrap();
        assert_eq!(JumpView::for_arm_id(uami), Some(JumpView::Identities));
    }

    #[test]
    fn no_credential_reaches_a_section_search_or_the_raw_view() {
        let app = ContainerAppRow::from_json(&app_json(), None).unwrap();
        let all = everything(
            &app,
            (0..CONTAINER_APP_SECTIONS.sections.len())
                .map(|i| container_app_section_lines(&app, ContainerAppDetailSection::from_index(i), None, None))
                .collect(),
        );
        assert!(!all.contains("hunter2") && !all.contains("literal-secret"), "an app credential leaked");
        assert!(all.contains("DB_PASSWORD"), "env var names stay");

        let env = EnvironmentRow::from_json(&env_json(), None).unwrap();
        let all = everything(
            &env,
            (0..ENVIRONMENT_SECTIONS.sections.len())
                .map(|i| environment_section_lines(&env, EnvironmentDetailSection::from_index(i)))
                .collect(),
        );
        assert!(!all.contains("secret"), "an environment credential leaked");
        assert!(all.contains("cust-1"), "the workspace customer id stays");

        let job = JobRow::from_json(&job_json(), None).unwrap();
        let all = everything(
            &job,
            (0..JOB_SECTIONS.sections.len())
                .map(|i| job_section_lines(&job, JobDetailSection::from_index(i), None))
                .collect(),
        );
        assert!(!all.contains("job-secret") && !all.contains("job-literal"), "a job credential leaked");
    }

    #[test]
    fn environment_network_is_thorough() {
        let env = EnvironmentRow::from_json(&env_json(), None).unwrap();
        assert_eq!(env.base.location, "australiaeast");
        assert_eq!(env.state(), ResourceState::stateless());
        let lines = environment_section_lines(&env, EnvironmentDetailSection::Network);
        let has = |k: &str, v: &str| lines.iter().any(|(a, b)| a == k && b.starts_with(v));
        assert!(has("Public network access", "Disabled"));
        assert!(has("Internal only", "yes"));
        assert!(has("Static IP", "10.0.16.4"));
        assert!(has("Custom DNS suffix", "apps.contoso.example"));
        assert!(has("Peer mTLS", "yes"));
        assert!(has("Peer traffic encryption", "yes"));
        assert!(lines.iter().any(|(_, v)| v == "· VNet callers need private DNS: *.happy.australiaeast.example → 10.0.16.4"));
        let (_, subnet) = lines.iter().find(|(k, _)| k == "Infrastructure subnet · aca").unwrap();
        assert_eq!(JumpView::for_arm_id(subnet), Some(JumpView::Subnets));
        let profiles = environment_section_lines(&env, EnvironmentDetailSection::WorkloadProfiles);
        assert_eq!(profiles[1], ("d4".to_string(), "D4 · 1–3 nodes".to_string()));
        let related: Vec<String> = env.related().into_iter().map(|(l, _)| l).collect();
        for want in ["Infrastructure subnet aca", "Infrastructure resource group ME_cae-prod", "Private endpoint pe-cae"] {
            assert!(related.iter().any(|l| l == want), "{want} in {related:?}");
        }
        assert!(env.cli_command().unwrap().starts_with("az containerapp env show --ids "));
    }

    #[test]
    fn job_trigger_reads_schedule_and_limits() {
        let job = JobRow::from_json(&job_json(), None).unwrap();
        assert!(job.details().iter().any(|(k, v)| k == "Trigger" && v == "Schedule · 0 2 * * *"));
        let lines = job_section_lines(&job, JobDetailSection::Trigger, None);
        assert!(lines.iter().any(|(k, v)| k == "Cron" && v == "0 2 * * * (UTC)"));
        assert!(lines.iter().any(|(k, v)| k == "Replica timeout" && v == "1800s"));
        assert!(lines.iter().any(|(k, v)| k == "Retry limit" && v == "2"));
        assert!(job.related().iter().any(|(l, _)| l == "Environment cae-prod"));
        assert!(job.cli_command().unwrap().starts_with("az containerapp job show --ids "));
        assert_eq!(ContainerAppsService::rows(JumpView::ContainerAppJobs, &[job_json()], None).len(), 1);
    }

    #[test]
    fn executions_put_the_newest_first_and_mark_a_failure() {
        let job = JobRow::from_json(&job_json(), None).unwrap();
        let items = vec![
            serde_json::json!({"name": "job-old", "properties": {"status": "Succeeded",
                "startTime": "2026-01-01T02:00:00Z", "endTime": "2026-01-01T02:04:00Z"}}),
            serde_json::json!({"name": "job-new", "properties": {"status": "Failed",
                "startTime": "2026-01-02T02:00:00Z", "endTime": "2026-01-02T02:03:00Z",
                "template": {"containers": [{"env": [{"name": "X", "value": "exec-secret"}]}]}}}),
        ];
        let lines = job_section_lines(&job, JobDetailSection::Executions, Some(&Lazy::Loaded(items)));
        assert_eq!(lines[1], ("job-new".to_string(), "⚠ Failed".to_string()));
        assert!(lines.iter().any(|(k, v)| k == "  Started" && v == "2026-01-02 02:00:00"));
        assert!(lines.iter().any(|(k, v)| k == "job-old" && v == "Succeeded"));
        assert!(!lines.iter().any(|(_, v)| v.contains("exec-secret")));
        assert!(lines.last().unwrap().1.starts_with("az containerapp job execution list -n "), "{:?}", lines.last());
        let empty = job_section_lines(&job, JobDetailSection::Executions, Some(&Lazy::Loaded(vec![])));
        assert_eq!(empty[0].1, "No executions");
        assert_eq!(container_app_child_path(&job.base.id, "executions"), format!("{}/executions", job.base.id));
    }

    #[test]
    fn revisions_put_active_first_and_name_the_read_command() {
        let row = ContainerAppRow::from_json(&app_json(), None).unwrap();
        let items = vec![
            serde_json::json!({"name": "api--v1", "properties": {"active": false, "createdTime": "2026-01-01T00:00:00Z", "replicas": 0}}),
            serde_json::json!({"name": "api--v2", "properties": {"active": true, "trafficWeight": 100,
                "createdTime": "2026-02-01T00:00:00Z", "replicas": 2, "healthState": "Healthy", "runningState": "Running",
                "template": {"containers": [{"env": [{"name": "X", "value": "rev-secret"}]}]}}}),
        ];
        let lines = container_app_section_lines(&row, ContainerAppDetailSection::Revisions, Some(&Lazy::Loaded(items)), None);
        assert_eq!(lines[1].0, "api--v2 (latest)");
        assert!(lines.iter().any(|(k, v)| k == "  Traffic" && v == "100%"));
        assert!(!lines.iter().any(|(_, v)| v.contains("rev-secret")));
        assert_eq!(
            lines.last().unwrap().1,
            "az containerapp revision list -n api -g rg-aca --subscription 0000 --all"
        );
        assert_eq!(container_app_child_path(&row.base.id, "revisions"), format!("{}/revisions", row.base.id));
    }

    #[test]
    fn auth_shows_the_entra_client_id_and_only_secret_names() {
        let row = ContainerAppRow::from_json(&app_json(), None).unwrap();
        let items = vec![serde_json::json!({"name": "current", "properties": {
            "platform": {"enabled": true},
            "globalValidation": {"unauthenticatedClientAction": "Return401"},
            "identityProviders": {"azureActiveDirectory": {"enabled": true,
                "registration": {"clientId": "app-client-id", "clientSecretSettingName": "microsoft-provider-authentication-secret",
                    "openIdIssuer": "https://login.example/tenant/v2.0"},
                "validation": {"allowedAudiences": ["api://app-client-id"],
                    "defaultAuthorizationPolicy": {"allowedApplications": ["pp-connector-app"]}}}}
        }})];
        let lines = container_app_section_lines(&row, ContainerAppDetailSection::Auth, None, Some(&Lazy::Loaded(items)));
        let has = |k: &str, v: &str| lines.iter().any(|(a, b)| a == k && b == v);
        assert!(has("Built-in auth", "enabled"));
        assert!(has("Unauthenticated requests", "Return401"));
        assert!(has("Microsoft Entra ID", "enabled"));
        assert!(has("  Client id", "app-client-id"));
        assert!(has("  Allowed audiences", "api://app-client-id"));
        assert!(has("  Allowed client apps", "pp-connector-app"));
        assert!(lines.last().unwrap().1.starts_with("az containerapp auth show --ids "));
        let empty = container_app_section_lines(&row, ContainerAppDetailSection::Auth, None, Some(&Lazy::Loaded(vec![])));
        assert!(empty[0].1.starts_with("No auth config"));
    }
}
