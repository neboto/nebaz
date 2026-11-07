//! Azure Arc (#199, SERVICES.md rule 45): the Arc tab, three
//! subscription-wide lists. Arc-enabled servers
//! (`Microsoft.HybridCompute/machines`, their extensions lazy), Arc
//! Kubernetes clusters (`Microsoft.Kubernetes/connectedClusters`) and Arc
//! private link scopes (`Microsoft.HybridCompute/privateLinkScopes`).
//!
//! An extension's `settings` and `protectedSettings` are stripped before
//! the store keeps a body ([`without_settings`]): ARM never returns the
//! protected ones, but the public ones can carry script text (the VM
//! scale-set rule). A cluster's agentry configurations carry the same
//! pair. Run commands are PUTs, patch assessment and installation are
//! POSTs, and a cluster's user credential is the `listClusterUserCredential`
//! POST; none is ever sent, and the guard names the paths.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource,
    ResourceState,
};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::backup::ago;
use crate::azure::services::directory::{iso_to_unix, now_unix};
use crate::azure::services::{
    arm_row, finish_stream, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

/// The newest stable versions long enough deployed (azure-rest-api-specs,
/// checked 2026-11-07; HybridCompute has 2026-07-15 and 2026-09-01, and
/// Kubernetes 2026-05-01, newer than what is read here).
pub const HYBRID_COMPUTE_API_VERSION: &str = "2025-01-13";
pub const CONNECTED_CLUSTER_API_VERSION: &str = "2024-01-01";
const MACHINES_PATH: &str = "/providers/Microsoft.HybridCompute/machines";
const CLUSTERS_PATH: &str = "/providers/Microsoft.Kubernetes/connectedClusters";
const SCOPES_PATH: &str = "/providers/Microsoft.HybridCompute/privateLinkScopes";

/// A machine disconnected this long is expired: its managed identity
/// certificate has lapsed and the agent must be onboarded again.
pub const EXPIRED_AFTER_SECS: i64 = 45 * 86_400;
/// A cluster's identity certificate this close to expiry is `⚠`.
const CERT_WARN_SECS: i64 = 14 * 86_400;

const NEVER_SETTINGS: &str = "an extension's settings are never shown; ARM never returns its protected settings";

crate::sections! {
    pub enum ArcMachineDetailSection,
    pub static ARC_MACHINE_SECTIONS = [
        Overview "Overview",
        Machine "Machine",
        Agent "Agent",
        Extensions "Extensions" => crate::app::App::trigger_arc_extensions,
        Licensing "Licensing & patching",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ArcClusterDetailSection,
    pub static ARC_CLUSTER_SECTIONS = [
        Overview "Overview",
        Cluster "Cluster",
        Agent "Agent",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum ArcScopeDetailSection,
    pub static ARC_SCOPE_SECTIONS = [
        Overview "Overview",
        Network "Network",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

// ── Settings out ──────────────────────────────────────────────────────

const SECRET_FIELDS: &[&str] = &["settings", "protectedSettings"];

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

/// The body with every `settings` and `protectedSettings` removed: what a
/// row parses and keeps for `e`, and what the Extensions read stores.
pub fn without_settings(v: &Value) -> Value {
    let mut v = v.clone();
    scrub(&mut v);
    v
}

/// `{machine}/extensions`.
pub fn extensions_path(machine_id: &str) -> String {
    format!("{}/extensions", machine_id.trim_end_matches('/'))
}

/// `(major, minor)` of an agent version (`1.45.02897.1735`): the minor is
/// the monthly release.
pub fn agent_release(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.split('.');
    Some((parts.next()?.trim().parse().ok()?, parts.next()?.trim().parse().ok()?))
}

/// `2026-10-25 02:01 (30d ago)`, or `-`.
fn time_ago(s: Option<&str>, now: i64) -> String {
    match s.and_then(iso_to_unix) {
        Some(t) => format!("{} ({})", json::unix_to_ymdhm(t), ago(t, now)),
        None => "-".into(),
    }
}

fn private_endpoints(v: &Value, ptr: &str) -> Vec<(String, Option<String>)> {
    json::arr(v, ptr)
        .iter()
        .filter_map(|c| {
            Some((
                json::arm_id(json::id_at(c, "/properties/privateEndpoint"))?,
                json::str_at(c, "/properties/privateLinkServiceConnectionState/status"),
            ))
        })
        .collect()
}

// ── Arc servers ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArcMachineRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub last_status_change: Option<String>,
    pub error_details: Vec<String>,
    pub display_name: Option<String>,
    pub machine_fqdn: Option<String>,
    pub domain_name: Option<String>,
    pub os_name: Option<String>,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub os_sku: Option<String>,
    pub agent_version: Option<String>,
    pub cloud_provider: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub cores: Option<String>,
    pub memory_gb: Option<String>,
    pub ip_addresses: Vec<String>,
    pub mssql_discovered: Option<String>,
    pub private_link_scope: Option<String>,
    pub parent_cluster: Option<String>,
    pub extensions_enabled: Option<String>,
    pub guest_configuration_enabled: Option<String>,
    pub config_mode: Option<String>,
    pub proxy_url: Option<String>,
    pub incoming_ports: Vec<String>,
    pub auto_upgrade: Option<bool>,
    pub upgrade_status: Option<String>,
    pub extension_service: Option<String>,
    pub guest_configuration_service: Option<String>,
    pub esu_eligibility: Option<String>,
    pub esu_assignment: Option<String>,
    pub esu_key_state: Option<String>,
    pub esu_license: Option<String>,
    pub license_status: Option<String>,
    pub software_assurance: Option<bool>,
    pub assessment_mode: Option<String>,
    pub patch_mode: Option<String>,
    pub identity_type: Option<String>,
}

impl ArcMachineRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ArcMachineRow> {
        let v = &without_settings(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        let detected = |k: &str| json::str_at(v, &p(&format!("detectedProperties/{}", k)));
        let os = json::str_at(v, &p("osType")).unwrap_or_default().to_lowercase();
        let patch = if os == "linux" { "linuxConfiguration" } else { "windowsConfiguration" };
        Some(ArcMachineRow {
            kind: json::str_at(v, "/kind"),
            status: json::str_at(v, &p("status")),
            last_status_change: json::str_at(v, &p("lastStatusChange")),
            error_details: json::arr(v, &p("errorDetails"))
                .iter()
                .filter_map(|e| json::str_at(e, "/message").or_else(|| json::str_at(e, "/code")))
                .collect(),
            display_name: json::str_at(v, &p("displayName")),
            machine_fqdn: json::str_at(v, &p("machineFqdn")),
            domain_name: json::str_at(v, &p("domainName")),
            os_name: json::str_at(v, &p("osName")),
            os_type: json::str_at(v, &p("osType")),
            os_version: json::str_at(v, &p("osVersion")),
            os_sku: json::str_at(v, &p("osSku")),
            agent_version: json::str_at(v, &p("agentVersion")),
            cloud_provider: json::str_at(v, &p("cloudMetadata/provider")).or_else(|| detected("cloudprovider")),
            manufacturer: detected("manufacturer"),
            model: detected("model"),
            cores: detected("logicalCoreCount").or_else(|| detected("coreCount")),
            memory_gb: detected("totalPhysicalMemoryInGigabytes"),
            ip_addresses: json::arr(v, &p("networkProfile/networkInterfaces"))
                .iter()
                .flat_map(|nic| json::arr(nic, "/ipAddresses"))
                .filter_map(|ip| json::str_at(&ip, "/address"))
                .collect(),
            mssql_discovered: json::str_at(v, &p("mssqlDiscovered")),
            private_link_scope: json::arm_id(json::str_at(v, &p("privateLinkScopeResourceId"))),
            parent_cluster: json::arm_id(json::str_at(v, &p("parentClusterResourceId"))),
            extensions_enabled: json::str_at(v, &p("agentConfiguration/extensionsEnabled")),
            guest_configuration_enabled: json::str_at(v, &p("agentConfiguration/guestConfigurationEnabled")),
            config_mode: json::str_at(v, &p("agentConfiguration/configMode")),
            proxy_url: json::str_at(v, &p("agentConfiguration/proxyUrl")).filter(|s| !s.is_empty()),
            incoming_ports: json::strings_at(v, &p("agentConfiguration/incomingConnectionsPorts")),
            auto_upgrade: json::bool_at(v, &p("agentUpgrade/enableAutomaticUpgrade")),
            upgrade_status: json::str_at(v, &p("agentUpgrade/lastAttemptStatus")),
            extension_service: json::str_at(v, &p("serviceStatuses/extensionService/status")),
            guest_configuration_service: json::str_at(v, &p("serviceStatuses/guestConfigurationService/status")),
            esu_eligibility: json::str_at(v, &p("licenseProfile/esuProfile/esuEligibility")),
            esu_assignment: json::str_at(v, &p("licenseProfile/esuProfile/licenseAssignmentState")),
            esu_key_state: json::str_at(v, &p("licenseProfile/esuProfile/esuKeyState")),
            esu_license: json::arm_id(
                json::id_at(v, &p("licenseProfile/esuProfile/assignedLicense"))
                    .or_else(|| json::str_at(v, &p("licenseProfile/esuProfile/assignedLicense"))),
            ),
            license_status: json::str_at(v, &p("licenseProfile/licenseStatus")),
            software_assurance: json::bool_at(v, &p("licenseProfile/softwareAssurance/softwareAssuranceCustomer")),
            assessment_mode: json::str_at(v, &p(&format!("osProfile/{}/patchSettings/assessmentMode", patch))),
            patch_mode: json::str_at(v, &p(&format!("osProfile/{}/patchSettings/patchMode", patch))),
            identity_type: json::str_at(v, "/identity/type"),
            base,
        })
    }

    /// The status as the portal words it: `Expired` for a machine
    /// disconnected longer than [`EXPIRED_AFTER_SECS`] (ARM still says
    /// `Disconnected`).
    pub fn effective_status(&self, now: i64) -> Option<String> {
        let s = self.status.clone()?;
        if s.eq_ignore_ascii_case("disconnected") && self.disconnected_secs(now).is_some_and(|d| d > EXPIRED_AFTER_SECS) {
            return Some("Expired".into());
        }
        Some(s)
    }

    /// How long a disconnected machine has been so; `None` while connected.
    pub fn disconnected_secs(&self, now: i64) -> Option<i64> {
        if !self.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("disconnected")) {
            return None;
        }
        Some(now - iso_to_unix(self.last_status_change.as_deref()?)?)
    }

    fn ladder(&self) -> (ResourceState, String) {
        let status = self.effective_status(now_unix());
        let runtime = status.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "connected" => ResourceState::Available,
                "disconnected" | "expired" | "error" => ResourceState::Unavailable,
                "awaitingconnection" => ResourceState::Pending,
                other => ResourceState::Unknown(other.into()),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    fn os_text(&self) -> String {
        match (&self.os_sku, &self.os_name) {
            (Some(sku), _) => sku.clone(),
            (None, Some(name)) => name.clone(),
            _ => "-".into(),
        }
    }

    /// `Connected`, or `Disconnected since … (12d ago)`.
    fn status_text(&self, now: i64) -> String {
        let status = json::opt(self.effective_status(now));
        match self.disconnected_secs(now) {
            Some(_) => format!("⚠ {} since {}", status, time_ago(self.last_status_change.as_deref(), now)),
            None => status,
        }
    }

    fn machine_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Computer name".into(), json::opt(self.display_name.clone())),
            ("FQDN".into(), json::opt(self.machine_fqdn.clone())),
            ("Domain".into(), json::opt(self.domain_name.clone())),
            ("OS".into(), self.os_text()),
            ("OS version".into(), json::opt(self.os_version.clone())),
            ("OS type".into(), json::opt(self.os_type.clone())),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("Cloud provider".into(), json::opt(self.cloud_provider.clone())),
            ("Manufacturer".into(), json::opt(self.manufacturer.clone())),
            ("Model".into(), json::opt(self.model.clone())),
            ("Logical cores".into(), json::opt(self.cores.clone())),
            ("Memory (GB)".into(), json::opt(self.memory_gb.clone())),
            ("IP addresses".into(), json::join(&self.ip_addresses)),
            ("SQL Server discovered".into(), json::opt(self.mssql_discovered.clone())),
        ];
        if let Some(c) = &self.parent_cluster {
            lines.push((format!("Parent cluster · {}", name_of_id(c)), c.clone()));
        }
        lines
    }

    fn agent_rows(&self, now: i64) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Status".into(), self.status_text(now)),
            ("Last status change".into(), time_ago(self.last_status_change.as_deref(), now)),
            ("Agent version".into(), json::opt(self.agent_version.clone())),
            ("Automatic upgrade".into(), json::yes_no(self.auto_upgrade)),
        ];
        if let Some(s) = &self.upgrade_status {
            lines.push(("Last upgrade attempt".into(), if s.eq_ignore_ascii_case("failed") { format!("⚠ {}", s) } else { s.clone() }));
        }
        lines.extend([
            ("Config mode".into(), json::opt(self.config_mode.clone())),
            ("Extensions allowed".into(), json::opt(self.extensions_enabled.clone())),
            ("Guest configuration".into(), json::opt(self.guest_configuration_enabled.clone())),
            ("Extension service".into(), json::opt(self.extension_service.clone())),
            ("Guest configuration service".into(), json::opt(self.guest_configuration_service.clone())),
            ("Proxy".into(), json::opt(self.proxy_url.clone())),
            ("Incoming ports".into(), json::join(&self.incoming_ports)),
        ]);
        match &self.private_link_scope {
            Some(id) => lines.push((format!("Private link scope · {}", name_of_id(id)), id.clone())),
            None => lines.push(("Private link scope".into(), "none (public endpoints)".into())),
        }
        for e in &self.error_details {
            lines.push(("Error".into(), format!("⚠ {}", e)));
        }
        lines
    }

    /// Extended Security Updates and the patch settings. A machine
    /// eligible for ESU with none assigned is `⚠`: it gets no security
    /// updates past its OS's end of support.
    fn licensing_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![("License status".into(), json::opt(self.license_status.clone()))];
        if self.software_assurance.is_some() {
            lines.push(("Software Assurance".into(), json::yes_no(self.software_assurance)));
        }
        let eligible = self.esu_eligibility.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("eligible"));
        let assigned = self.esu_assignment.as_deref().is_some_and(|a| a.eq_ignore_ascii_case("assigned"));
        lines.push(("ESU eligibility".into(), json::opt(self.esu_eligibility.clone())));
        if eligible || self.esu_assignment.is_some() {
            let text = json::opt(self.esu_assignment.clone());
            lines.push((
                "ESU licence".into(),
                if eligible && !assigned { format!("⚠ {} (no security updates past end of support)", text) } else { text },
            ));
        }
        if let Some(k) = &self.esu_key_state {
            lines.push(("ESU key".into(), k.clone()));
        }
        if let Some(id) = &self.esu_license {
            lines.push((format!("ESU licence · {}", name_of_id(id)), id.clone()));
        }
        lines.push(("Patch assessment".into(), json::opt(self.assessment_mode.clone())));
        lines.push(("Patch mode".into(), json::opt(self.patch_mode.clone())));
        lines
    }

    fn read_command(&self, command: &str) -> (String, String) {
        let args = (|| {
            Some(format!(
                "--machine-name {} -g {} --subscription {}",
                shell_quote(&self.base.name),
                shell_quote(resource_group_of(&self.base.id)?),
                shell_quote(subscription_of(&self.base.id)?)
            ))
        })();
        ("Read command".into(), format!("{} {}", command, args.unwrap_or_default()))
    }
}

impl Resource for ArcMachineRow {
    arm_row!("Arc server");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ARC_MACHINE_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let os = self.os_text();
        Some(match &self.agent_version {
            Some(a) => format!("{} · agent {}", os, a),
            None => os,
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        let now = now_unix();
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Status".into(), self.status_text(now)),
            ("OS".into(), self.os_text()),
            ("Agent version".into(), json::opt(self.agent_version.clone())),
            ("Cloud provider".into(), json::opt(self.cloud_provider.clone())),
            ("FQDN".into(), json::opt(self.machine_fqdn.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(id) = &self.private_link_scope {
            v.push((format!("Private link scope {}", name_of_id(id)), id.clone()));
        }
        if let Some(id) = &self.parent_cluster {
            v.push((format!("Parent cluster {}", name_of_id(id)), id.clone()));
        }
        if let Some(id) = &self.esu_license {
            v.push((format!("ESU licence {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az connectedmachine show --ids {}", shell_quote(&self.base.id)))
    }
}

/// An extension's state: provisioning first, then its instance view's
/// status; a failure or an error-level status is `⚠`.
fn extension_status(e: &Value) -> String {
    let p = |f: &str| format!("/properties/{}", f);
    let prov = json::str_at(e, &p("provisioningState"));
    let level = json::str_at(e, &p("instanceView/status/level"));
    let shown = json::str_at(e, &p("instanceView/status/displayStatus"))
        .or_else(|| json::str_at(e, &p("instanceView/status/code")))
        .or(prov.clone());
    let failed = prov.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("failed"))
        || level.as_deref().is_some_and(|l| l.eq_ignore_ascii_case("error"));
    let text = json::opt(shown);
    if failed {
        format!("⚠ {}", text)
    } else {
        text
    }
}

/// The Extensions body: each extension's type, version, upgrade settings
/// and state, with the first line of its status message.
pub fn extension_rows(items: &[Value], r: &ArcMachineRow) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    if items.is_empty() {
        lines.push((String::new(), "No extensions".into()));
    }
    let mut exts: Vec<&Value> = items.iter().collect();
    exts.sort_by_key(|e| json::text(e, "/name").to_lowercase());
    for e in exts {
        let p = |f: &str| format!("/properties/{}", f);
        lines.push((String::new(), String::new()));
        lines.push((json::text(e, "/name"), String::new()));
        let kind = match (json::str_at(e, &p("publisher")), json::str_at(e, &p("type"))) {
            (Some(publisher), Some(t)) => format!("{}.{}", publisher, t),
            (_, t) => json::opt(t),
        };
        lines.push(("  Type".into(), kind));
        lines.push(("  Version".into(), json::text(e, &p("typeHandlerVersion"))));
        lines.push(("  Automatic upgrade".into(), json::yes_no(json::bool_at(e, &p("enableAutomaticUpgrade")))));
        lines.push(("  State".into(), extension_status(e)));
        if let Some(m) = json::str_at(e, &p("instanceView/status/message")).filter(|m| !m.trim().is_empty()) {
            lines.push(("  Message".into(), m.lines().next().unwrap_or_default().trim().to_string()));
        }
    }
    lines.push((String::new(), String::new()));
    lines.push((String::new(), NEVER_SETTINGS.into()));
    lines.push(r.read_command("az connectedmachine extension list"));
    lines
}

// ── Arc Kubernetes ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArcClusterRow {
    pub base: ArmBase,
    pub kind: Option<String>,
    pub connectivity: Option<String>,
    pub last_connectivity: Option<String>,
    pub cert_expiry: Option<String>,
    pub distribution: Option<String>,
    pub distribution_version: Option<String>,
    pub infrastructure: Option<String>,
    pub offering: Option<String>,
    pub kubernetes_version: Option<String>,
    pub nodes: Option<i64>,
    pub cores: Option<i64>,
    pub agent_version: Option<String>,
    pub agent_auto_upgrade: Option<String>,
    pub desired_agent_version: Option<String>,
    pub agent_state: Option<String>,
    /// `(component, severity, message)`.
    pub agent_errors: Vec<(String, String, String)>,
    pub azure_rbac: Option<bool>,
    pub admin_groups: usize,
    pub private_link_state: Option<String>,
    pub private_link_scope: Option<String>,
    pub azure_hybrid_benefit: Option<String>,
    pub identity_type: Option<String>,
}

impl ArcClusterRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ArcClusterRow> {
        let v = &without_settings(raw);
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        Some(ArcClusterRow {
            kind: json::str_at(v, "/kind"),
            connectivity: json::str_at(v, &p("connectivityStatus")),
            last_connectivity: json::str_at(v, &p("lastConnectivityTime")),
            cert_expiry: json::str_at(v, &p("managedIdentityCertificateExpirationTime")),
            distribution: json::str_at(v, &p("distribution")),
            distribution_version: json::str_at(v, &p("distributionVersion")),
            infrastructure: json::str_at(v, &p("infrastructure")),
            offering: json::str_at(v, &p("offering")),
            kubernetes_version: json::str_at(v, &p("kubernetesVersion")),
            nodes: json::int_at(v, &p("totalNodeCount")),
            cores: json::int_at(v, &p("totalCoreCount")),
            agent_version: json::str_at(v, &p("agentVersion")),
            agent_auto_upgrade: json::str_at(v, &p("arcAgentProfile/agentAutoUpgrade")),
            desired_agent_version: json::str_at(v, &p("arcAgentProfile/desiredAgentVersion")),
            agent_state: json::str_at(v, &p("arcAgentProfile/agentState")),
            agent_errors: json::arr(v, &p("arcAgentProfile/agentErrors"))
                .iter()
                .map(|e| (json::text(e, "/component"), json::text(e, "/severity"), json::text(e, "/message")))
                .collect(),
            azure_rbac: json::bool_at(v, &p("aadProfile/enableAzureRBAC")),
            admin_groups: json::arr(v, &p("aadProfile/adminGroupObjectIDs")).len(),
            private_link_state: json::str_at(v, &p("privateLinkState")),
            private_link_scope: json::arm_id(json::str_at(v, &p("privateLinkScopeResourceId"))),
            azure_hybrid_benefit: json::str_at(v, &p("azureHybridBenefit")),
            identity_type: json::str_at(v, "/identity/type"),
            base,
        })
    }

    /// Provisioning first, then connectivity: `Offline` (no heartbeat)
    /// and `Expired` (offline long enough for its certificate to lapse)
    /// are trouble.
    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.connectivity.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "connected" => ResourceState::Available,
                "offline" | "expired" => ResourceState::Unavailable,
                "connecting" => ResourceState::Pending,
                other => ResourceState::Unknown(other.into()),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }

    pub fn is_offline(&self) -> bool {
        self.connectivity.as_deref().is_some_and(|s| ["offline", "expired"].contains(&s.to_lowercase().as_str()))
    }

    fn connectivity_text(&self) -> String {
        let c = json::opt(self.connectivity.clone());
        if self.is_offline() {
            format!("⚠ {}", c)
        } else {
            c
        }
    }

    fn cluster_rows(&self) -> Vec<(String, String)> {
        let distro = match (&self.distribution, &self.distribution_version) {
            (Some(d), Some(v)) => format!("{} {}", d, v),
            (d, _) => json::opt(d.clone()),
        };
        vec![
            ("Kubernetes version".into(), json::opt(self.kubernetes_version.clone())),
            ("Distribution".into(), distro),
            ("Infrastructure".into(), json::opt(self.infrastructure.clone())),
            ("Offering".into(), json::opt(self.offering.clone())),
            ("Kind".into(), json::opt(self.kind.clone())),
            ("Nodes".into(), json::num(self.nodes)),
            ("Cores".into(), json::num(self.cores)),
            ("Azure RBAC".into(), json::yes_no(self.azure_rbac)),
            ("Entra admin groups".into(), self.admin_groups.to_string()),
            ("Azure Hybrid Benefit".into(), json::opt(self.azure_hybrid_benefit.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
        ]
    }

    fn agent_rows(&self, now: i64) -> Vec<(String, String)> {
        let cert = match self.cert_expiry.as_deref().and_then(iso_to_unix) {
            Some(t) if t < now => format!("⚠ expired {}", json::unix_to_ymdhm(t)),
            Some(t) if t - now < CERT_WARN_SECS => format!("⚠ {} (renews only while connected)", json::unix_to_ymdhm(t)),
            Some(t) => json::unix_to_ymdhm(t),
            None => "-".into(),
        };
        let mut lines = vec![
            ("Connectivity".into(), self.connectivity_text()),
            ("Last connected".into(), time_ago(self.last_connectivity.as_deref(), now)),
            ("Identity certificate expires".into(), cert),
            ("Agent version".into(), json::opt(self.agent_version.clone())),
            ("Agent auto-upgrade".into(), json::opt(self.agent_auto_upgrade.clone())),
        ];
        if let Some(d) = &self.desired_agent_version {
            lines.push(("Desired agent version".into(), d.clone()));
        }
        lines.push(("Agent state".into(), json::opt(self.agent_state.clone())));
        match &self.private_link_scope {
            Some(id) => lines.push((format!("Private link scope · {}", name_of_id(id)), id.clone())),
            None => lines.push(("Private link".into(), json::opt(self.private_link_state.clone()))),
        }
        for (component, severity, message) in &self.agent_errors {
            lines.push((format!("Agent error · {}", component), format!("⚠ {}: {}", severity, message)));
        }
        lines
    }
}

impl Resource for ArcClusterRow {
    arm_row!("Arc Kubernetes cluster");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ARC_CLUSTER_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        let distro = self.distribution.clone().unwrap_or_else(|| "-".into());
        Some(match (&self.kubernetes_version, self.nodes) {
            (Some(k), Some(n)) => format!("{} {} · {} nodes", distro, k, n),
            (Some(k), None) => format!("{} {}", distro, k),
            _ => distro,
        })
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Connectivity".into(), self.connectivity_text()),
            ("Kubernetes version".into(), json::opt(self.kubernetes_version.clone())),
            ("Distribution".into(), json::opt(self.distribution.clone())),
            ("Nodes".into(), json::num(self.nodes)),
            ("Agent version".into(), json::opt(self.agent_version.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(id) = &self.private_link_scope {
            v.push((format!("Private link scope {}", name_of_id(id)), id.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az connectedk8s show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Private link scopes ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArcScopeRow {
    pub base: ArmBase,
    pub public_network_access: Option<String>,
    pub scope_id: Option<String>,
    /// `(endpoint id, status)` of each private endpoint connection.
    pub private_endpoints: Vec<(String, Option<String>)>,
}

impl ArcScopeRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<ArcScopeRow> {
        let v = &without_settings(raw);
        Some(ArcScopeRow {
            public_network_access: json::str_at(v, "/properties/publicNetworkAccess"),
            scope_id: json::str_at(v, "/properties/privateLinkScopeId"),
            private_endpoints: private_endpoints(v, "/properties/privateEndpointConnections"),
            base: ArmBase::from_json(v, tenant)?,
        })
    }

    fn network_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Scope id".into(), json::opt(self.scope_id.clone())),
        ];
        if self.private_endpoints.is_empty() {
            lines.push(("Private endpoints".into(), "none".into()));
        }
        for (pe, status) in &self.private_endpoints {
            let status = json::opt(status.clone());
            let status = if status.eq_ignore_ascii_case("approved") { status } else { format!("⚠ {}", status) };
            lines.push((format!("Private endpoint · {} ({})", name_of_id(pe), status), pe.clone()));
        }
        lines
    }
}

impl Resource for ArcScopeRow {
    arm_row!("Arc private link scope");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ARC_SCOPE_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        self.public_network_access.as_ref().map(|p| format!("public network {}", p.to_lowercase()))
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Private endpoints".into(), self.private_endpoints.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for (pe, _) in &self.private_endpoints {
            v.push((format!("Private endpoint {}", name_of_id(pe)), pe.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az connectedmachine private-link-scope show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Sections ──────────────────────────────────────────────────────────

/// Body lines for one section of an Arc row; `None` for another type.
pub fn arc_section_lines(
    r: &dyn Resource,
    idx: usize,
    extensions: Option<&Lazy<Vec<Value>>>,
    now: i64,
) -> Option<Vec<(String, String)>> {
    if let Some(x) = r.as_any().downcast_ref::<ArcMachineRow>() {
        use ArcMachineDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Machine => x.machine_rows(),
            S::Agent => x.agent_rows(now),
            S::Extensions => lazy_list_rows(extensions, "Extensions", |items| extension_rows(items, x)),
            S::Licensing => x.licensing_rows(),
            S::Access | S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_rows(x),
            S::Tags => tag_rows(x.tags()),
        });
    }
    if let Some(x) = r.as_any().downcast_ref::<ArcClusterRow>() {
        use ArcClusterDetailSection as S;
        return Some(match S::from_index(idx) {
            S::Overview => overview_rows(x),
            S::Cluster => x.cluster_rows(),
            S::Agent => x.agent_rows(now),
            S::Access | S::Activity => crate::azure::services::rendered_by_app(),
            S::Related => related_rows(x),
            S::Tags => tag_rows(x.tags()),
        });
    }
    let x = r.as_any().downcast_ref::<ArcScopeRow>()?;
    use ArcScopeDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Network => x.network_rows(),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => related_rows(x),
        S::Tags => tag_rows(x.tags()),
    })
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct ArcService {
    scope: Scope,
}

impl ArcService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    fn boxed<R: Resource + 'static>(rows: impl Iterator<Item = R>) -> Vec<Box<dyn Resource>> {
        rows.map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }

    fn rows(view: JumpView, page: &[Value], tenant: Option<&str>) -> Vec<Box<dyn Resource>> {
        match view {
            JumpView::ArcClusters => Self::boxed(page.iter().filter_map(|v| ArcClusterRow::from_json(v, tenant))),
            JumpView::ArcPrivateLinkScopes => Self::boxed(page.iter().filter_map(|v| ArcScopeRow::from_json(v, tenant))),
            _ => Self::boxed(page.iter().filter_map(|v| ArcMachineRow::from_json(v, tenant))),
        }
    }

    fn path_of(view: JumpView) -> (&'static str, &'static str, &'static str) {
        match view {
            JumpView::ArcClusters => (CLUSTERS_PATH, CONNECTED_CLUSTER_API_VERSION, "Listing Arc Kubernetes clusters…"),
            JumpView::ArcPrivateLinkScopes => (SCOPES_PATH, HYBRID_COMPUTE_API_VERSION, "Listing Arc private link scopes…"),
            _ => (MACHINES_PATH, HYBRID_COMPUTE_API_VERSION, "Listing Arc servers…"),
        }
    }
}

#[async_trait]
impl AzureService for ArcService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Arc
    }

    fn name(&self) -> &str {
        "Azure Arc"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let (path, version, _) = Self::path_of(view);
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
        let (path, version, message) = Self::path_of(view);
        let r = self
            .scope
            .stream(path, version, &[], service_type, message, &event_tx, |page| {
                Self::rows(view, &page, tenant.as_deref())
            })
            .await;
        finish_stream(service_type, r, &event_tx)
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let view = JumpView::for_arm_id(id).unwrap_or(JumpView::ArcMachines);
        let (_, version, _) = Self::path_of(view);
        let v = self.scope.get(id, version).await?;
        Self::rows(view, std::slice::from_ref(&v), self.scope.tenant())
            .pop()
            .ok_or_else(|| Error::ResourceNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-onprem";
    /// 2026-11-07T00:00:00Z.
    const NOW: i64 = 1_794_009_600;

    fn machine_id(name: &str) -> String {
        format!("{}/providers/Microsoft.HybridCompute/machines/{}", RG, name)
    }

    fn scope_id() -> String {
        format!("{}/providers/Microsoft.HybridCompute/privateLinkScopes/pls-arc", RG)
    }

    fn machine(name: &str, status: &str, changed: &str) -> ArcMachineRow {
        ArcMachineRow::from_json(
            &json!({
                "id": machine_id(name), "name": name, "location": "westeurope", "kind": "SCVMM",
                "identity": {"type": "SystemAssigned"},
                "properties": {
                    "provisioningState": "Succeeded", "status": status, "lastStatusChange": changed,
                    "osName": "windows", "osType": "windows", "osSku": "Windows Server 2012 R2 Datacenter",
                    "osVersion": "6.3.9600", "agentVersion": "1.41.02664.1629", "displayName": name,
                    "machineFqdn": format!("{}.corp.contoso.com", name),
                    "detectedProperties": {"cloudprovider": "N/A", "manufacturer": "VMware, Inc.", "logicalCoreCount": "4"},
                    "networkProfile": {"networkInterfaces": [{"ipAddresses": [{"address": "192.168.10.21"}]}]},
                    "privateLinkScopeResourceId": scope_id(),
                    "agentConfiguration": {"extensionsEnabled": "true", "configMode": "full", "incomingConnectionsPorts": []},
                    "licenseProfile": {"esuProfile": {"esuEligibility": "Eligible", "licenseAssignmentState": "NotAssigned"}},
                    "osProfile": {"windowsConfiguration": {"patchSettings": {"assessmentMode": "AutomaticByPlatform", "patchMode": "Manual"}}},
                    "errorDetails": [{"code": "AgentDisconnected", "message": "The agent has not sent a heartbeat"}]
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

    fn labels(d: &crate::sections::SectionDescriptor) -> Vec<&str> {
        d.sections.iter().map(|s| s.label).collect()
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        assert_eq!(
            labels(&ARC_MACHINE_SECTIONS),
            [
                "Overview", "Machine", "Agent", "Extensions", "Licensing & patching", "Access", "Activity", "Related",
                "Tags"
            ]
        );
        assert_eq!(labels(&ARC_CLUSTER_SECTIONS), ["Overview", "Cluster", "Agent", "Access", "Activity", "Related", "Tags"]);
        assert_eq!(labels(&ARC_SCOPE_SECTIONS), ["Overview", "Network", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn a_machine_disconnected_past_the_window_reads_as_expired() {
        let fresh = machine("srv-web-01", "Disconnected", "2026-11-05T00:00:00Z");
        assert_eq!(fresh.effective_status(NOW).as_deref(), Some("Disconnected"));
        let old = machine("srv-file-03", "Disconnected", "2026-09-01T00:00:00Z");
        assert_eq!(old.effective_status(NOW).as_deref(), Some("Expired"));
        assert_eq!(old.status_text(NOW), "⚠ Expired since 2026-09-01 00:00 (67d ago)");
        assert_eq!(old.state(), ResourceState::Unavailable);
        let ok = machine("srv-dc-01", "Connected", "2026-01-01T00:00:00Z");
        assert_eq!(ok.state(), ResourceState::Available);
        assert_eq!(ok.state_label(), "connected");
        assert_eq!(ok.status_text(NOW), "Connected");
        assert_eq!(ok.disconnected_secs(NOW), None);
    }

    #[test]
    fn a_machine_reads_its_os_agent_licence_and_the_ids_command() {
        let row = machine("srv-dc-01", "Connected", "2026-11-01T00:00:00Z");
        assert_eq!(row.list_summary().as_deref(), Some("Windows Server 2012 R2 Datacenter · agent 1.41.02664.1629"));
        assert_eq!(row.cli_command(), Some(format!("az connectedmachine show --ids {}", machine_id("srv-dc-01"))));
        let m = row.machine_rows();
        assert_eq!(get(&m, "IP addresses"), Some("192.168.10.21"));
        assert_eq!(get(&m, "Manufacturer"), Some("VMware, Inc."));
        assert_eq!(get(&m, "Logical cores"), Some("4"));
        let agent = row.agent_rows(NOW);
        assert!(agent.iter().any(|(k, v)| k == "Private link scope · pls-arc" && v == &scope_id()));
        assert_eq!(get(&agent, "Error"), Some("⚠ The agent has not sent a heartbeat"));
        let lic = row.licensing_rows();
        assert_eq!(get(&lic, "ESU licence"), Some("⚠ NotAssigned (no security updates past end of support)"));
        assert_eq!(get(&lic, "Patch mode"), Some("Manual"));
        assert!(row.related().iter().any(|(l, id)| l == "Private link scope pls-arc" && id == &scope_id()));
        assert_eq!(agent_release("1.41.02664.1629"), Some((1, 41)));
        assert_eq!(agent_release("garbage"), None);
    }

    #[test]
    fn extension_settings_never_reach_the_store() {
        let ext = json!({"name": "CustomScriptExtension", "properties": {
            "publisher": "Microsoft.Compute", "type": "CustomScriptExtension",
            "settings": {"commandToExecute": "planted"}, "protectedSettings": {"storageAccountKey": "planted"}
        }});
        let clean = without_settings(&ext).to_string();
        assert!(!clean.contains("planted"), "a planted value survived the scrub");
        assert!(clean.contains("CustomScriptExtension"));
        let cluster = json!({"id": format!("{}/providers/Microsoft.Kubernetes/connectedClusters/k", RG), "name": "k",
            "location": "westeurope", "properties": {"arcAgentryConfigurations": [{"feature": "proxy",
            "settings": {"a": "planted"}, "protectedSettings": {"b": "planted"}}]}});
        let row = ArcClusterRow::from_json(&cluster, None).unwrap();
        assert!(!row.base.raw.to_string().contains("planted"));
    }

    #[test]
    fn extensions_flag_a_failure_and_say_settings_are_never_shown() {
        let row = machine("srv-dc-01", "Connected", "2026-11-01T00:00:00Z");
        let items = vec![
            json!({"name": "MDE.Windows", "properties": {"publisher": "Microsoft.Azure.AzureDefenderForServers", "type": "MDE.Windows",
                "typeHandlerVersion": "1.0", "provisioningState": "Failed",
                "instanceView": {"status": {"code": "1", "level": "Error", "displayStatus": "Provisioning failed",
                    "message": "Onboarding failed: proxy refused\nstack…"}}}}),
            json!({"name": "AzureMonitorWindowsAgent", "properties": {"publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorWindowsAgent", "typeHandlerVersion": "1.30", "enableAutomaticUpgrade": true,
                "provisioningState": "Succeeded"}}),
        ];
        let lines = extension_rows(&items, &row);
        assert_eq!(all(&lines, "  State"), ["Succeeded", "⚠ Provisioning failed"]);
        assert_eq!(get(&lines, "  Message"), Some("Onboarding failed: proxy refused"));
        assert_eq!(all(&lines, "  Type")[0], "Microsoft.Azure.Monitor.AzureMonitorWindowsAgent");
        assert!(lines.iter().any(|(_, v)| v == NEVER_SETTINGS));
        assert_eq!(
            lines.last().unwrap().1,
            "az connectedmachine extension list --machine-name srv-dc-01 -g rg-onprem --subscription 0000"
        );
        assert_eq!(extensions_path(&machine_id("m")), format!("{}/extensions", machine_id("m")));
    }

    #[test]
    fn a_cluster_reads_connectivity_agent_and_certificate() {
        let row = ArcClusterRow::from_json(
            &json!({"id": format!("{}/providers/Microsoft.Kubernetes/connectedClusters/k3s-branch", RG), "name": "k3s-branch",
                "location": "westeurope", "identity": {"type": "SystemAssigned"},
                "properties": {"provisioningState": "Succeeded", "connectivityStatus": "Offline",
                    "lastConnectivityTime": "2026-10-20T00:00:00Z", "managedIdentityCertificateExpirationTime": "2026-11-12T00:00:00Z",
                    "distribution": "k3s", "kubernetesVersion": "1.29.4", "totalNodeCount": 3, "totalCoreCount": 12,
                    "agentVersion": "1.18.3", "arcAgentProfile": {"agentAutoUpgrade": "Disabled", "agentErrors": [
                        {"component": "clusterconnect-agent", "severity": "Error", "message": "cannot reach the relay"}]},
                    "privateLinkState": "Disabled"}}),
            None,
        )
        .unwrap();
        assert_eq!(row.state(), ResourceState::Unavailable);
        assert_eq!(row.list_summary().as_deref(), Some("k3s 1.29.4 · 3 nodes"));
        assert!(row.cli_command().unwrap().starts_with("az connectedk8s show --ids "));
        let agent = row.agent_rows(NOW);
        assert_eq!(get(&agent, "Connectivity"), Some("⚠ Offline"));
        assert_eq!(get(&agent, "Identity certificate expires"), Some("⚠ 2026-11-12 00:00 (renews only while connected)"));
        assert_eq!(get(&agent, "Agent error · clusterconnect-agent"), Some("⚠ Error: cannot reach the relay"));
        assert_eq!(get(&agent, "Last connected"), Some("2026-10-20 00:00 (18d ago)"));
    }

    #[test]
    fn a_scope_lists_its_endpoints_and_flags_a_pending_one() {
        let pe = format!("{}/providers/Microsoft.Network/privateEndpoints/pe-arc", RG);
        let row = ArcScopeRow::from_json(
            &json!({"id": scope_id(), "name": "pls-arc", "location": "westeurope", "properties": {
                "publicNetworkAccess": "Disabled", "privateLinkScopeId": "1b2c",
                "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": pe},
                    "privateLinkServiceConnectionState": {"status": "Pending"}}}]}}),
            None,
        )
        .unwrap();
        assert_eq!(row.list_summary().as_deref(), Some("public network disabled"));
        assert!(row.network_rows().iter().any(|(k, v)| k == "Private endpoint · pe-arc (⚠ Pending)" && v == &pe));
        assert!(row.related().iter().any(|(_, id)| id == &pe));
        let lines = arc_section_lines(&row, ArcScopeDetailSection::Network as usize, None, NOW).unwrap();
        assert_eq!(get(&lines, "Public network access"), Some("Disabled"));
    }
}
