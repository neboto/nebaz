//! Network Watcher flow logs (#143): not a sub-tab. A flow log is a child
//! of the region's network watcher (`{watcher}/flowLogs/{name}`) and names
//! what it logs by `targetResourceId`: a VNet, a subnet or a NIC (a VNet
//! flow log) or an NSG (an NSG flow log, retiring). No list body carries
//! them (an NSG's `flowLogs` is ids only), so one lazy read per
//! subscription gathers them ([`fetch_flow_logs`]: list the watchers, then
//! each watcher's `flowLogs`, all `GET`s) and the **Flow logs** sections of
//! VNets and NSGs and the `flow-logs-missing` audit check read it
//! (`SERVICES.md` rule 30).
//!
//! Network Watcher's other flow-log calls (configure, query the status)
//! are `POST`s, never sent; the guard refuses their names.

use crate::azure::arm::ArmClient;
use crate::azure::resource::{name_of_id, Resource};
use crate::azure::services::compute::NicRow;
use crate::azure::services::network::{NsgRow, VnetRow};
use crate::azure::services::network::NETWORK_API_VERSION;
use crate::azure::services::{error_rows, json};
use crate::lazy::Lazy;
use serde_json::Value;
use std::sync::Arc;

/// Network Watcher is Microsoft.Network: the Network service's version.
pub const FLOW_LOGS_API_VERSION: &str = NETWORK_API_VERSION;
pub const NETWORK_WATCHERS_PATH: &str = "/providers/Microsoft.Network/networkWatchers";
/// A subscription has one watcher per region it uses; past this many the
/// rest are not read (a warning says so).
pub const FLOW_LOGS_MAX_WATCHERS: usize = 100;

/// What Microsoft says about NSG flow logs (learn.microsoft.com, NSG flow
/// logs overview and "Migrate to virtual network flow logs", checked
/// 2026-10-26).
pub const NSG_FLOW_LOG_RETIREMENT: &str =
    "NSG flow logs retire on 30 September 2027 (no new ones since 30 June 2025): migrate to a VNet flow log";

/// One flow log, from its watcher's `flowLogs` list.
#[derive(Debug, Clone, Default)]
pub struct FlowLog {
    pub id: String,
    pub name: String,
    pub location: String,
    pub watcher_id: String,
    pub target_id: Option<String>,
    pub enabled: Option<bool>,
    pub storage_id: Option<String>,
    pub retention_enabled: Option<bool>,
    pub retention_days: Option<i64>,
    pub format_type: Option<String>,
    pub format_version: Option<i64>,
    pub analytics_enabled: Option<bool>,
    pub workspace_id: Option<String>,
    pub analytics_interval: Option<i64>,
    pub provisioning_state: Option<String>,
}

/// What a flow log targets, from the target id's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowLogTarget {
    Vnet,
    Subnet,
    Nic,
    Nsg,
    Other,
}

impl FlowLog {
    pub fn from_json(v: &Value, watcher_id: &str) -> Option<FlowLog> {
        let id = json::str_at(v, "/id")?;
        let p = |s: &str| format!("/properties/{}", s);
        let ta = "/properties/flowAnalyticsConfiguration/networkWatcherFlowAnalyticsConfiguration";
        Some(FlowLog {
            name: json::str_at(v, "/name").unwrap_or_else(|| name_of_id(&id).to_string()),
            location: json::str_at(v, "/location").unwrap_or_default().to_lowercase(),
            watcher_id: watcher_id.to_string(),
            target_id: json::arm_id(json::str_at(v, &p("targetResourceId"))),
            enabled: json::bool_at(v, &p("enabled")),
            storage_id: json::arm_id(json::str_at(v, &p("storageId"))),
            retention_enabled: json::bool_at(v, &p("retentionPolicy/enabled")),
            retention_days: json::int_at(v, &p("retentionPolicy/days")),
            format_type: json::str_at(v, &p("format/type")),
            format_version: json::int_at(v, &p("format/version")),
            analytics_enabled: json::bool_at(v, &format!("{}/enabled", ta)),
            workspace_id: json::arm_id(json::str_at(v, &format!("{}/workspaceResourceId", ta))),
            analytics_interval: json::int_at(v, &format!("{}/trafficAnalyticsInterval", ta)),
            provisioning_state: json::str_at(v, &p("provisioningState")),
            id,
        })
    }

    pub fn target(&self) -> FlowLogTarget {
        let Some(t) = &self.target_id else { return FlowLogTarget::Other };
        match crate::azure::resource::arm_type_chain(t) {
            Some((ns, chain)) if ns == "microsoft.network" => match chain.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                ["virtualnetworks"] => FlowLogTarget::Vnet,
                ["virtualnetworks", "subnets"] => FlowLogTarget::Subnet,
                ["networkinterfaces"] => FlowLogTarget::Nic,
                ["networksecuritygroups"] => FlowLogTarget::Nsg,
                _ => FlowLogTarget::Other,
            },
            _ => FlowLogTarget::Other,
        }
    }

    pub fn is_nsg_flow_log(&self) -> bool {
        self.target() == FlowLogTarget::Nsg
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled == Some(true)
    }

    fn targets(&self, id: &str) -> bool {
        self.target_id.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(id))
    }

    /// The flow log's lines in a Flow logs section: the header jumps to
    /// nothing nebaz lists (its id is copied), the storage account and
    /// workspace jump.
    pub fn rows(&self) -> Vec<(String, String)> {
        let kind = if self.is_nsg_flow_log() { "NSG flow log" } else { "VNet flow log" };
        let mut lines = vec![(format!("{} · {}", kind, self.name), self.id.clone())];
        if let Some(t) = &self.target_id {
            let what = match self.target() {
                FlowLogTarget::Vnet => "VNet",
                FlowLogTarget::Subnet => "subnet",
                FlowLogTarget::Nic => "NIC",
                FlowLogTarget::Nsg => "NSG",
                FlowLogTarget::Other => "target",
            };
            lines.push((format!("  Target · {} {}", what, target_label(t)), t.clone()));
        }
        lines.push((
            "  Enabled".into(),
            match self.enabled {
                Some(true) => "yes".into(),
                Some(false) => "⚠ no: nothing is logged".into(),
                None => "-".into(),
            },
        ));
        match &self.storage_id {
            Some(s) => lines.push((format!("  Storage · {}", name_of_id(s)), s.clone())),
            None => lines.push(("  Storage".into(), "-".into())),
        }
        lines.push(("  Retention".into(), self.retention_label()));
        lines.push((
            "  Format".into(),
            match (&self.format_type, self.format_version) {
                (Some(t), Some(v)) => format!("{} v{}", t, v),
                (Some(t), None) => t.clone(),
                (None, Some(v)) => format!("v{}", v),
                (None, None) => "-".into(),
            },
        ));
        match self.analytics_enabled {
            Some(true) => {
                let every = self.analytics_interval.map(|m| format!(" · every {} min", m)).unwrap_or_default();
                lines.push(("  Traffic analytics".into(), format!("on{}", every)));
                if let Some(w) = &self.workspace_id {
                    lines.push((format!("  Workspace · {}", name_of_id(w)), w.clone()));
                }
            }
            Some(false) => lines.push(("  Traffic analytics".into(), "off".into())),
            None => lines.push(("  Traffic analytics".into(), "not configured".into())),
        }
        lines.push((format!("  Network Watcher · {}", name_of_id(&self.watcher_id)), self.watcher_id.clone()));
        if self.is_nsg_flow_log() {
            lines.push((String::new(), format!("· {}", NSG_FLOW_LOG_RETIREMENT)));
        }
        lines
    }

    fn retention_label(&self) -> String {
        match (self.retention_enabled, self.retention_days) {
            (Some(true), Some(0)) | (Some(false), _) => "off (kept until deleted)".into(),
            (Some(true), Some(d)) => format!("{} days", d),
            (_, Some(d)) => format!("{} days", d),
            _ => "-".into(),
        }
    }
}

/// `vnet/subnet` for a subnet id, else the name.
fn target_label(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    match parts.iter().rposition(|p| p.eq_ignore_ascii_case("subnets")) {
        Some(i) if i >= 1 && i + 1 < parts.len() => format!("{}/{}", parts[i - 1], parts[i + 1]),
        _ => name_of_id(id).to_string(),
    }
}

/// Every flow log in a subscription: what the Flow logs sections and the
/// audit check read, keyed by `/subscriptions/{sub}` in the lazy store.
#[derive(Debug, Clone, Default)]
pub struct FlowLogs {
    pub logs: Vec<FlowLog>,
    /// A watcher whose `flowLogs` list failed, or watchers past the cap.
    pub warnings: Vec<String>,
    pub watchers: usize,
}

impl FlowLogs {
    /// The flow logs targeting exactly `id`.
    pub fn on<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a FlowLog> + 'a {
        self.logs.iter().filter(move |l| l.targets(id))
    }

    /// The VNet flow logs that log traffic of a VNet: on the VNet itself,
    /// on one of its subnets, or on a NIC the warm NICs list places in one
    /// of its subnets.
    pub fn vnet_logs<'a>(&'a self, vnet: &VnetRow, nics: &[&NicRow]) -> Vec<&'a FlowLog> {
        let prefix = format!("{}/subnets/", vnet.base.id.to_lowercase());
        let nic_ids: Vec<String> = nics
            .iter()
            .filter(|n| {
                n.ip_configs
                    .iter()
                    .any(|c| c.subnet_id.as_deref().is_some_and(|s| s.to_lowercase().starts_with(&prefix)))
            })
            .map(|n| n.base.id.to_lowercase())
            .collect();
        self.logs
            .iter()
            .filter(|l| {
                let Some(t) = l.target_id.as_deref().map(str::to_lowercase) else { return false };
                match l.target() {
                    FlowLogTarget::Vnet => t == vnet.base.id.to_lowercase(),
                    FlowLogTarget::Subnet => t.starts_with(&prefix),
                    FlowLogTarget::Nic => nic_ids.contains(&t),
                    _ => false,
                }
            })
            .collect()
    }

    /// The NSG flow logs on the NSGs of a VNet's subnets.
    pub fn subnet_nsg_logs<'a>(&'a self, vnet: &VnetRow) -> Vec<&'a FlowLog> {
        let nsgs: Vec<String> = vnet.subnets.iter().filter_map(|s| s.nsg_id.as_deref()).map(str::to_lowercase).collect();
        self.logs
            .iter()
            .filter(|l| l.is_nsg_flow_log() && l.target_id.as_deref().is_some_and(|t| nsgs.contains(&t.to_lowercase())))
            .collect()
    }
}

/// One subscription's flow logs: `GET {sub}/providers/Microsoft.Network/
/// networkWatchers`, then `GET {watcher}/flowLogs` for each (at most
/// [`FLOW_LOGS_MAX_WATCHERS`]). Only the watcher list failing fails the
/// whole; a watcher's list failing is a warning.
pub async fn fetch_flow_logs(arm: Arc<ArmClient>, sub: String) -> std::result::Result<FlowLogs, String> {
    let watchers = arm
        .list(&format!("{}{}", sub, NETWORK_WATCHERS_PATH), FLOW_LOGS_API_VERSION)
        .await
        .map_err(|e| e.to_string())?;
    let mut out = FlowLogs { watchers: watchers.len(), ..Default::default() };
    if watchers.len() > FLOW_LOGS_MAX_WATCHERS {
        out.warnings.push(format!(
            "{} network watchers; the flow logs of the first {} were read",
            watchers.len(),
            FLOW_LOGS_MAX_WATCHERS
        ));
    }
    for w in watchers.iter().take(FLOW_LOGS_MAX_WATCHERS) {
        let Some(id) = json::str_at(w, "/id") else { continue };
        match arm.list(&flow_logs_path(&id), FLOW_LOGS_API_VERSION).await {
            Ok(items) => out.logs.extend(items.iter().filter_map(|v| FlowLog::from_json(v, &id))),
            Err(e) => out.warnings.push(format!("flow logs of {}: {}", name_of_id(&id), e)),
        }
    }
    Ok(out)
}

/// `{watcher}/flowLogs`.
pub fn flow_logs_path(watcher_id: &str) -> String {
    format!("{}/flowLogs", watcher_id.trim_end_matches('/'))
}

/// The three arms of a lazy flow-logs read around `render`, plus the
/// read's own warnings at the foot.
fn lazy_rows(logs: Option<&Lazy<FlowLogs>>, render: impl FnOnce(&FlowLogs) -> Vec<(String, String)>) -> Vec<(String, String)> {
    match logs {
        None | Some(Lazy::Loading) => vec![("Flow logs".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => error_rows(e),
        Some(Lazy::Loaded(f)) => {
            let mut lines = render(f);
            for w in &f.warnings {
                lines.push((String::new(), format!("⚠ {}", w)));
            }
            lines
        }
    }
}

fn push_logs(lines: &mut Vec<(String, String)>, logs: &[&FlowLog]) {
    for l in logs {
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines.extend(l.rows());
    }
}

/// A VNet's Flow logs section: its VNet flow logs (on the VNet, a subnet,
/// or a NIC in it when the NICs list is warm), then the NSG flow logs on
/// its subnets' NSGs.
pub fn vnet_flow_log_rows(vnet: &VnetRow, logs: Option<&Lazy<FlowLogs>>, nics: Option<&[Box<dyn Resource>]>) -> Vec<(String, String)> {
    lazy_rows(logs, |f| {
        let warm: Vec<&NicRow> = nics
            .unwrap_or_default()
            .iter()
            .filter_map(|r| r.as_any().downcast_ref::<NicRow>())
            .collect();
        let vnet_logs = f.vnet_logs(vnet, &warm);
        let nsg_logs = f.subnet_nsg_logs(vnet);
        let mut lines = Vec::new();
        push_logs(&mut lines, &vnet_logs);
        if !nsg_logs.is_empty() {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push(("On its subnets' NSGs".into(), String::new()));
            let mut nsg_lines = Vec::new();
            push_logs(&mut nsg_lines, &nsg_logs);
            lines.extend(nsg_lines);
        }
        if lines.is_empty() {
            lines.push((String::new(), "No flow log on this VNet, its subnets or its subnets' NSGs".into()));
        }
        if nics.is_none() {
            lines.push((String::new(), "· a VNet flow log on a NIC is matched once the NICs list is loaded (@nic)".into()));
        }
        lines.push((String::new(), format!("· read from the subscription's {} network watcher(s)", f.watchers)));
        lines
    })
}

/// An NSG's Flow logs section: its own (NSG) flow logs, then the VNet
/// flow logs on the subnets it guards.
pub fn nsg_flow_log_rows(nsg: &NsgRow, logs: Option<&Lazy<FlowLogs>>) -> Vec<(String, String)> {
    lazy_rows(logs, |f| {
        let own: Vec<&FlowLog> = f.on(&nsg.base.id).collect();
        let mut lines = Vec::new();
        push_logs(&mut lines, &own);
        let subnet_logs: Vec<&FlowLog> = nsg
            .subnet_ids
            .iter()
            .flat_map(|s| {
                let vnet = s.to_lowercase().split("/subnets/").next().unwrap_or_default().to_string();
                f.logs.iter().filter(move |l| {
                    l.target_id.as_deref().is_some_and(|t| {
                        let t = t.to_lowercase();
                        t == s.to_lowercase() || t == vnet
                    })
                })
            })
            .fold(Vec::new(), |mut acc, l| {
                if !acc.iter().any(|x: &&FlowLog| x.id == l.id) {
                    acc.push(l);
                }
                acc
            });
        if !subnet_logs.is_empty() {
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push(("On the subnets it guards (VNet flow logs)".into(), String::new()));
            let mut more = Vec::new();
            push_logs(&mut more, &subnet_logs);
            lines.extend(more);
        }
        if lines.is_empty() {
            lines.push((String::new(), "No flow log on this NSG or the subnets it guards".into()));
        }
        lines
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-net/providers/Microsoft.Network";
    const NW: &str = "/subscriptions/0000/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_westeurope";

    fn log(name: &str, target: &str, enabled: bool) -> FlowLog {
        FlowLog::from_json(
            &json!({
                "id": format!("{}/flowLogs/{}", NW, name),
                "name": name,
                "location": "westeurope",
                "properties": {
                    "targetResourceId": target,
                    "enabled": enabled,
                    "storageId": "/subscriptions/0000/resourceGroups/rg-net/providers/Microsoft.Storage/storageAccounts/stflow",
                    "retentionPolicy": {"days": 30, "enabled": true},
                    "format": {"type": "JSON", "version": 2},
                    "flowAnalyticsConfiguration": {"networkWatcherFlowAnalyticsConfiguration": {
                        "enabled": true,
                        "workspaceResourceId": "/subscriptions/0000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law",
                        "trafficAnalyticsInterval": 10
                    }},
                    "provisioningState": "Succeeded"
                }
            }),
            NW,
        )
        .unwrap()
    }

    fn vnet() -> VnetRow {
        VnetRow::from_json(
            &json!({
                "id": format!("{}/virtualNetworks/vnet-hub", RG),
                "name": "vnet-hub",
                "location": "westeurope",
                "properties": {"subnets": [
                    {"id": format!("{}/virtualNetworks/vnet-hub/subnets/a", RG), "name": "a",
                     "properties": {"addressPrefix": "10.0.0.0/24", "networkSecurityGroup": {"id": format!("{}/networkSecurityGroups/nsg-a", RG)}}}
                ]}
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_flow_log_parses_target_storage_and_analytics() {
        let l = log("fl-vnet", &format!("{}/virtualNetworks/vnet-hub", RG), true);
        assert_eq!(l.target(), FlowLogTarget::Vnet);
        assert_eq!(l.retention_days, Some(30));
        assert_eq!(l.analytics_interval, Some(10));
        let rows = l.rows();
        assert!(rows.iter().any(|(k, v)| k.starts_with("  Storage · stflow") && v.ends_with("/stflow")));
        assert!(rows.iter().any(|(k, _)| k.starts_with("  Workspace · law")));
        assert!(rows.iter().any(|(k, v)| k == "  Traffic analytics" && v == "on · every 10 min"));
        assert!(!rows.iter().any(|(_, v)| v.contains("retire")), "a VNet flow log is not retiring");
    }

    #[test]
    fn an_nsg_flow_log_carries_the_retirement_note() {
        let l = log("fl-nsg", &format!("{}/networkSecurityGroups/nsg-a", RG), true);
        assert!(l.is_nsg_flow_log());
        assert!(l.rows().iter().any(|(_, v)| v.contains("30 September 2027")));
    }

    #[test]
    fn a_vnet_sees_its_subnet_logs_and_its_subnets_nsg_logs() {
        let f = FlowLogs {
            logs: vec![
                log("fl-subnet", &format!("{}/virtualNetworks/vnet-hub/subnets/a", RG), true),
                log("fl-nsg", &format!("{}/networkSecurityGroups/nsg-a", RG), true),
                log("fl-other", &format!("{}/virtualNetworks/vnet-other", RG), true),
            ],
            warnings: Vec::new(),
            watchers: 1,
        };
        let v = vnet();
        let own: Vec<&str> = f.vnet_logs(&v, &[]).iter().map(|l| l.name.as_str()).collect();
        assert_eq!(own, vec!["fl-subnet"]);
        let nsg: Vec<&str> = f.subnet_nsg_logs(&v).iter().map(|l| l.name.as_str()).collect();
        assert_eq!(nsg, vec!["fl-nsg"]);
        let rows = vnet_flow_log_rows(&v, Some(&Lazy::Loaded(f)), None);
        assert!(rows.iter().any(|(k, _)| k == "  Target · subnet vnet-hub/a"));
        assert!(rows.iter().any(|(k, _)| k == "On its subnets' NSGs"));
    }

    #[test]
    fn a_disabled_flow_log_is_flagged_and_an_empty_vnet_says_so() {
        let l = log("fl-off", &format!("{}/virtualNetworks/vnet-hub", RG), false);
        assert!(l.rows().iter().any(|(k, v)| k == "  Enabled" && v.starts_with('⚠')));
        let rows = vnet_flow_log_rows(&vnet(), Some(&Lazy::Loaded(FlowLogs::default())), Some(&[]));
        assert!(rows.iter().any(|(_, v)| v.starts_with("No flow log")));
    }
}
