//! The Virtual Machines service (ticket 06): three sub-tabs, each one
//! subscription-wide list.
//!
//! - **VMs** — the model pages stream in, then a second pass of the same
//!   list with `statusOnly=true` fills the power state, merged by id and
//!   delivered as one replacement. The instance view is a lazy section.
//! - **Disks** — `diskState` is the runtime state.
//! - **NICs** — attachment (`virtualMachine.id`) is the runtime state.

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::azure::services::{
    arm_row, error_rows, finish_stream, json, overview_rows, related_rows, tag_rows, ArmBase, Scope,
};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::lazy::Lazy;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub const VM_API_VERSION: &str = "2026-04-01";
pub const DISK_API_VERSION: &str = "2026-03-02";
pub const NIC_API_VERSION: &str = "2025-09-01";

const VM_PATH: &str = "/providers/Microsoft.Compute/virtualMachines";
const DISK_PATH: &str = "/providers/Microsoft.Compute/disks";
const NIC_PATH: &str = "/providers/Microsoft.Network/networkInterfaces";

crate::sections! {
    pub enum VmDetailSection,
    pub static VM_SECTIONS = [
        Overview "Overview",
        InstanceView "Instance view" => crate::app::App::trigger_vm_instance_view,
        Networking "Networking",
        Storage "Storage",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum DiskDetailSection,
    pub static DISK_SECTIONS = [
        Overview "Overview",
        Related "Related",
        Tags "Tags",
    ]
}

crate::sections! {
    pub enum NicDetailSection,
    pub static NIC_SECTIONS = [
        Overview "Overview",
        IpConfigurations "IP configurations",
        Related "Related",
        Tags "Tags",
    ]
}

// ── Virtual machine ───────────────────────────────────────────────────

/// A disk as the VM model references it (OS or data).
#[derive(Debug, Clone)]
pub struct DiskRef {
    pub name: String,
    pub id: Option<String>,
    pub size_gb: Option<i64>,
    pub lun: Option<i64>,
    pub caching: Option<String>,
}

impl DiskRef {
    fn from_json(v: &Value) -> DiskRef {
        let id = json::arm_id(json::id_at(v, "/managedDisk"));
        DiskRef {
            name: json::str_at(v, "/name")
                .or_else(|| id.as_deref().map(|i| name_of_id(i).to_string()))
                .unwrap_or_else(|| "-".into()),
            id,
            size_gb: json::int_at(v, "/diskSizeGB"),
            lun: json::int_at(v, "/lun"),
            caching: json::str_at(v, "/caching"),
        }
    }

    fn label(&self) -> String {
        let mut s = self.name.clone();
        if let Some(gb) = self.size_gb {
            s.push_str(&format!(" · {} GB", gb));
        }
        if let Some(c) = &self.caching {
            s.push_str(&format!(" · {}", c.to_lowercase()));
        }
        s
    }
}

#[derive(Debug, Clone)]
pub struct VmRow {
    pub base: ArmBase,
    /// `running`, `deallocated`, … from `PowerState/<word>`; `None` until
    /// the `statusOnly` pass lands.
    pub power_state: Option<String>,
    pub vm_size: Option<String>,
    pub os_type: Option<String>,
    pub computer_name: Option<String>,
    pub admin_username: Option<String>,
    pub zones: Vec<String>,
    pub priority: Option<String>,
    pub os_disk: Option<DiskRef>,
    pub data_disks: Vec<DiskRef>,
    /// `(id, primary)`.
    pub nics: Vec<(String, bool)>,
    pub availability_set: Option<String>,
    pub time_created: Option<String>,
    pub license_type: Option<String>,
    pub image: Option<String>,
}

impl VmRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<VmRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let image = {
            let r = format!("{}/storageProfile/imageReference", p);
            match json::str_at(v, &format!("{}/publisher", r)) {
                Some(pub_) => Some(format!(
                    "{}:{}:{}:{}",
                    pub_,
                    json::text(v, &format!("{}/offer", r)),
                    json::text(v, &format!("{}/sku", r)),
                    json::text(v, &format!("{}/version", r))
                )),
                None => json::str_at(v, &format!("{}/id", r)).map(|i| name_of_id(&i).to_string()),
            }
        };
        let os_disk = v
            .pointer(&format!("{}/storageProfile/osDisk", p))
            .map(DiskRef::from_json);
        let os_type = json::str_at(v, &format!("{}/storageProfile/osDisk/osType", p));
        Some(VmRow {
            power_state: Self::power_state_of(v),
            vm_size: json::str_at(v, &format!("{}/hardwareProfile/vmSize", p)),
            os_type,
            computer_name: json::str_at(v, &format!("{}/osProfile/computerName", p)),
            admin_username: json::str_at(v, &format!("{}/osProfile/adminUsername", p)),
            zones: json::strings_at(v, "/zones"),
            priority: json::str_at(v, &format!("{}/priority", p)),
            os_disk,
            data_disks: json::arr(v, &format!("{}/storageProfile/dataDisks", p))
                .iter()
                .map(DiskRef::from_json)
                .collect(),
            nics: json::arr(v, &format!("{}/networkProfile/networkInterfaces", p))
                .iter()
                .filter_map(|n| {
                    Some((
                        json::str_at(n, "/id")?,
                        json::bool_at(n, "/properties/primary").unwrap_or(false),
                    ))
                })
                .collect(),
            availability_set: json::arm_id(json::id_at(v, &format!("{}/availabilitySet", p))),
            time_created: json::str_at(v, &format!("{}/timeCreated", p)),
            license_type: json::str_at(v, &format!("{}/licenseType", p)),
            image,
            base,
        })
    }

    /// The `PowerState/<word>` status of a VM body that carries an
    /// instance view (`statusOnly=true` list, `$expand=instanceView` get).
    pub fn power_state_of(v: &Value) -> Option<String> {
        json::arr(v, "/properties/instanceView/statuses")
            .iter()
            .filter_map(|s| json::str_at(s, "/code"))
            .find_map(|c| c.strip_prefix("PowerState/").map(|w| w.to_lowercase()))
    }

    pub fn set_power_state(&mut self, power: Option<String>) {
        self.power_state = power;
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.power_state.as_deref().map(|p| {
            let bucket = match p {
                "running" => ResourceState::Running,
                "deallocated" | "stopped" => ResourceState::Stopped,
                "starting" | "stopping" | "deallocating" => ResourceState::Pending,
                other => ResourceState::Unknown(other.to_string()),
            };
            (bucket, p)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for VmRow {
    arm_row!("Virtual Machine");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&VM_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.vm_size.clone()),
            json::opt(self.computer_name.clone()),
            json::opt(self.power_state.clone()),
            json::opt(self.os_type.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Power state".into(), json::opt(self.power_state.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Size".into(), json::opt(self.vm_size.clone())),
            ("OS".into(), json::opt(self.os_type.clone())),
            ("Image".into(), json::opt(self.image.clone())),
            ("Computer name".into(), json::opt(self.computer_name.clone())),
            ("Admin user".into(), json::opt(self.admin_username.clone())),
            ("Zones".into(), json::join(&self.zones)),
            ("Priority".into(), json::opt(self.priority.clone())),
            ("License".into(), json::opt(self.license_type.clone())),
            ("Created".into(), json::time(self.time_created.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for (id, primary) in &self.nics {
            let label = if *primary { "NIC (primary)" } else { "NIC" };
            v.push((format!("{} {}", label, name_of_id(id)), id.clone()));
        }
        if let Some(d) = self.os_disk.as_ref().and_then(|d| d.id.as_ref()) {
            v.push((format!("OS disk {}", name_of_id(d)), d.clone()));
        }
        for d in self.data_disks.iter().filter_map(|d| d.id.as_ref()) {
            v.push((format!("Data disk {}", name_of_id(d)), d.clone()));
        }
        if let Some(a) = &self.availability_set {
            v.push((format!("Availability set {}", name_of_id(a)), a.clone()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az vm show --ids {}", shell_quote(&self.base.id)))
    }
}

/// Body lines for one section of a VM row.
pub fn vm_section_lines(
    r: &VmRow,
    section: VmDetailSection,
    instance_view: Option<&Lazy<Value>>,
) -> Vec<(String, String)> {
    match section {
        VmDetailSection::Overview => overview_rows(r),
        VmDetailSection::InstanceView => match instance_view {
            None | Some(Lazy::Loading) => vec![("Instance view".into(), "Loading…".into())],
            Some(Lazy::Error(e)) => error_rows(e),
            Some(Lazy::Loaded(v)) => instance_view_rows(v),
        },
        VmDetailSection::Networking => {
            if r.nics.is_empty() {
                return vec![(String::new(), "No network interfaces".into())];
            }
            r.nics
                .iter()
                .map(|(id, primary)| {
                    let label = if *primary { "Primary NIC" } else { "NIC" };
                    (format!("{} {}", label, name_of_id(id)), id.clone())
                })
                .collect()
        }
        VmDetailSection::Storage => {
            let mut lines = Vec::new();
            match &r.os_disk {
                Some(d) => lines.push((
                    format!("OS disk · {}", d.label()),
                    d.id.clone().unwrap_or_else(|| "(unmanaged)".into()),
                )),
                None => lines.push(("OS disk".into(), "-".into())),
            }
            for d in &r.data_disks {
                lines.push((
                    format!("LUN {} · {}", json::num(d.lun), d.label()),
                    d.id.clone().unwrap_or_else(|| "(unmanaged)".into()),
                ));
            }
            lines
        }
        VmDetailSection::Related => related_rows(r),
        VmDetailSection::Tags => tag_rows(r.tags()),
    }
}

/// The instance view object, flattened.
fn instance_view_rows(v: &Value) -> Vec<(String, String)> {
    let mut lines = vec![
        ("Computer name".into(), json::text(v, "/computerName")),
        ("OS".into(), json::text(v, "/osName")),
        ("OS version".into(), json::text(v, "/osVersion")),
        ("Hyper-V generation".into(), json::text(v, "/hyperVGeneration")),
        (
            "VM agent".into(),
            format!(
                "{} · {}",
                json::text(v, "/vmAgent/vmAgentVersion"),
                json::text(v, "/vmAgent/statuses/0/displayStatus")
            ),
        ),
        (
            "Boot diagnostics".into(),
            if v.get("bootDiagnostics").is_some() { "enabled".into() } else { "-".into() },
        ),
    ];
    let statuses = json::arr(v, "/statuses");
    if !statuses.is_empty() {
        lines.push((String::new(), String::new()));
        lines.push(("Statuses".into(), String::new()));
        for s in &statuses {
            let mut val = json::text(s, "/displayStatus");
            if let Some(t) = json::str_at(s, "/time") {
                val.push_str(&format!(" · {}", json::time(Some(t))));
            }
            lines.push((format!("  {}", json::text(s, "/code")), val));
        }
    }
    let disks = json::arr(v, "/disks");
    if !disks.is_empty() {
        lines.push((String::new(), String::new()));
        lines.push(("Disks".into(), String::new()));
        for d in &disks {
            lines.push((
                format!("  {}", json::text(d, "/name")),
                json::text(d, "/statuses/0/displayStatus"),
            ));
        }
    }
    lines
}

// ── Managed disk ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiskRow {
    pub base: ArmBase,
    pub sku: Option<String>,
    pub size_gb: Option<i64>,
    pub disk_state: Option<String>,
    pub os_type: Option<String>,
    pub managed_by: Option<String>,
    pub time_created: Option<String>,
    pub zones: Vec<String>,
    pub encryption: Option<String>,
    pub network_access_policy: Option<String>,
    pub public_network_access: Option<String>,
    pub iops: Option<i64>,
    pub mbps: Option<i64>,
    pub create_option: Option<String>,
    pub source_id: Option<String>,
    pub hyperv_generation: Option<String>,
    pub tier: Option<String>,
}

impl DiskRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<DiskRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(DiskRow {
            sku: json::str_at(v, "/sku/name"),
            size_gb: json::int_at(v, &format!("{}/diskSizeGB", p)),
            disk_state: json::str_at(v, &format!("{}/diskState", p)),
            os_type: json::str_at(v, &format!("{}/osType", p)),
            managed_by: json::arm_id(json::str_at(v, "/managedBy")),
            time_created: json::str_at(v, &format!("{}/timeCreated", p)),
            zones: json::strings_at(v, "/zones"),
            encryption: json::str_at(v, &format!("{}/encryption/type", p)),
            network_access_policy: json::str_at(v, &format!("{}/networkAccessPolicy", p)),
            public_network_access: json::str_at(v, &format!("{}/publicNetworkAccess", p)),
            iops: json::int_at(v, &format!("{}/diskIOPSReadWrite", p)),
            mbps: json::int_at(v, &format!("{}/diskMBpsReadWrite", p)),
            create_option: json::str_at(v, &format!("{}/creationData/createOption", p)),
            source_id: json::str_at(v, &format!("{}/creationData/sourceResourceId", p))
                .or_else(|| json::str_at(v, &format!("{}/creationData/imageReference/id", p))),
            hyperv_generation: json::str_at(v, &format!("{}/hyperVGeneration", p)),
            tier: json::str_at(v, &format!("{}/tier", p)),
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = self.disk_state.as_deref().map(|s| {
            let bucket = match s.to_lowercase().as_str() {
                "attached" => ResourceState::Running,
                "unattached" => ResourceState::Available,
                "reserved" | "activesas" | "activesasfrozen" | "frozen" | "readytoupload"
                | "activeupload" => ResourceState::Pending,
                other => ResourceState::Unknown(other.to_string()),
            };
            (bucket, s)
        });
        state_ladder(self.base.provisioning_state.as_deref(), runtime)
    }
}

impl Resource for DiskRow {
    arm_row!("Disk");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&DISK_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.sku.clone()),
            json::opt(self.disk_state.clone()),
            self.managed_by.as_deref().map(name_of_id).unwrap_or(""),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("State".into(), json::opt(self.disk_state.clone())),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            (
                "Attached to".into(),
                self.managed_by.as_deref().map(name_of_id).unwrap_or("-").to_string(),
            ),
            ("Size".into(), self.size_gb.map(|g| format!("{} GB", g)).unwrap_or_else(|| "-".into())),
            ("SKU".into(), json::opt(self.sku.clone())),
            ("Tier".into(), json::opt(self.tier.clone())),
            ("OS".into(), json::opt(self.os_type.clone())),
            ("IOPS / MBps".into(), format!("{} / {}", json::num(self.iops), json::num(self.mbps))),
            ("Zones".into(), json::join(&self.zones)),
            ("Encryption".into(), json::opt(self.encryption.clone())),
            ("Network access".into(), json::opt(self.network_access_policy.clone())),
            ("Public network access".into(), json::opt(self.public_network_access.clone())),
            ("Created from".into(), json::opt(self.create_option.clone())),
            (
                "Source".into(),
                self.source_id.as_deref().map(name_of_id).unwrap_or("-").to_string(),
            ),
            ("Hyper-V generation".into(), json::opt(self.hyperv_generation.clone())),
            ("Created".into(), json::time(self.time_created.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(m) = &self.managed_by {
            v.push((format!("Attached to {}", name_of_id(m)), m.clone()));
        }
        if let Some(s) = self.source_id.as_deref().filter(|s| s.starts_with("/subscriptions/")) {
            v.push((format!("Source {}", name_of_id(s)), s.to_string()));
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az disk show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn disk_section_lines(r: &DiskRow, section: DiskDetailSection) -> Vec<(String, String)> {
    match section {
        DiskDetailSection::Overview => overview_rows(r),
        DiskDetailSection::Related => related_rows(r),
        DiskDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Network interface ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpConfig {
    pub name: String,
    pub private_ip: Option<String>,
    pub allocation: Option<String>,
    pub primary: Option<bool>,
    pub subnet_id: Option<String>,
    pub public_ip_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NicRow {
    pub base: ArmBase,
    pub mac: Option<String>,
    pub accelerated_networking: Option<bool>,
    pub ip_forwarding: Option<bool>,
    pub nic_type: Option<String>,
    pub primary: Option<bool>,
    pub vm_id: Option<String>,
    pub nsg_id: Option<String>,
    pub ip_configs: Vec<IpConfig>,
    pub dns_servers: Vec<String>,
}

impl NicRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<NicRow> {
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        Some(NicRow {
            mac: json::str_at(v, &format!("{}/macAddress", p)),
            accelerated_networking: json::bool_at(v, &format!("{}/enableAcceleratedNetworking", p)),
            ip_forwarding: json::bool_at(v, &format!("{}/enableIPForwarding", p)),
            nic_type: json::str_at(v, &format!("{}/nicType", p)),
            primary: json::bool_at(v, &format!("{}/primary", p)),
            vm_id: json::arm_id(json::id_at(v, &format!("{}/virtualMachine", p))),
            nsg_id: json::arm_id(json::id_at(v, &format!("{}/networkSecurityGroup", p))),
            ip_configs: json::arr(v, &format!("{}/ipConfigurations", p))
                .iter()
                .map(|c| IpConfig {
                    name: json::text(c, "/name"),
                    private_ip: json::str_at(c, "/properties/privateIPAddress"),
                    allocation: json::str_at(c, "/properties/privateIPAllocationMethod"),
                    primary: json::bool_at(c, "/properties/primary"),
                    subnet_id: json::arm_id(json::id_at(c, "/properties/subnet")),
                    public_ip_id: json::arm_id(json::id_at(c, "/properties/publicIPAddress")),
                })
                .collect(),
            dns_servers: json::strings_at(v, &format!("{}/dnsSettings/dnsServers", p)),
            base,
        })
    }

    fn ladder(&self) -> (ResourceState, String) {
        let runtime = if self.vm_id.is_some() {
            (ResourceState::Running, "attached")
        } else {
            (ResourceState::Available, "unattached")
        };
        state_ladder(self.base.provisioning_state.as_deref(), Some(runtime))
    }

    fn private_ips(&self) -> Vec<String> {
        self.ip_configs.iter().filter_map(|c| c.private_ip.clone()).collect()
    }
}

impl Resource for NicRow {
    arm_row!("Network Interface");
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&NIC_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.mac.clone()),
            self.private_ips().join(" "),
            self.vm_id.as_deref().map(name_of_id).unwrap_or(""),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Attached to".into(), self.vm_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Private IPs".into(), json::join(&self.private_ips())),
            ("MAC".into(), json::opt(self.mac.clone())),
            ("NSG".into(), self.nsg_id.as_deref().map(name_of_id).unwrap_or("-").to_string()),
            ("Accelerated networking".into(), json::yes_no(self.accelerated_networking)),
            ("IP forwarding".into(), json::yes_no(self.ip_forwarding)),
            ("Primary".into(), json::yes_no(self.primary)),
            ("Type".into(), json::opt(self.nic_type.clone())),
            ("DNS servers".into(), json::join(&self.dns_servers)),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        if let Some(vm) = &self.vm_id {
            v.push((format!("VM {}", name_of_id(vm)), vm.clone()));
        }
        if let Some(n) = &self.nsg_id {
            v.push((format!("NSG {}", name_of_id(n)), n.clone()));
        }
        for c in &self.ip_configs {
            if let Some(s) = &c.subnet_id {
                v.push((format!("Subnet {} · {}", name_of_id(s), c.name), s.clone()));
            }
            if let Some(pip) = &c.public_ip_id {
                v.push((format!("Public IP {} · {}", name_of_id(pip), c.name), pip.clone()));
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network nic show --ids {}", shell_quote(&self.base.id)))
    }
}

pub fn nic_section_lines(r: &NicRow, section: NicDetailSection) -> Vec<(String, String)> {
    match section {
        NicDetailSection::Overview => overview_rows(r),
        NicDetailSection::IpConfigurations => {
            if r.ip_configs.is_empty() {
                return vec![(String::new(), "No IP configurations".into())];
            }
            let mut lines = Vec::new();
            for c in &r.ip_configs {
                let primary = if c.primary == Some(true) { " (primary)" } else { "" };
                lines.push((
                    format!("{}{}", c.name, primary),
                    format!(
                        "{} · {}",
                        json::opt(c.private_ip.clone()),
                        json::opt(c.allocation.clone()).to_lowercase()
                    ),
                ));
                lines.push(("  Subnet".into(), c.subnet_id.clone().unwrap_or_else(|| "-".into())));
                lines.push((
                    "  Public IP".into(),
                    c.public_ip_id.clone().unwrap_or_else(|| "-".into()),
                ));
            }
            lines
        }
        NicDetailSection::Related => related_rows(r),
        NicDetailSection::Tags => tag_rows(r.tags()),
    }
}

// ── Provider ──────────────────────────────────────────────────────────

pub struct ComputeService {
    scope: Scope,
}

impl ComputeService {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }

    /// Lowercased VM id → power state, from a `statusOnly=true` list.
    fn power_index(items: &[Value]) -> HashMap<String, String> {
        items
            .iter()
            .filter_map(|v| {
                let id = json::str_at(v, "/id")?.to_lowercase();
                Some((id, VmRow::power_state_of(v)?))
            })
            .collect()
    }

    fn boxed<R: Resource + 'static>(rows: Vec<R>) -> Vec<Box<dyn Resource>> {
        rows.into_iter().map(|r| Box::new(r) as Box<dyn Resource>).collect()
    }
}

#[async_trait]
impl AzureService for ComputeService {
    fn service_type(&self) -> ServiceType {
        ServiceType::VirtualMachines
    }

    fn name(&self) -> &str {
        "Virtual Machines"
    }

    async fn list_resources(&self, view: JumpView) -> Result<Vec<Box<dyn Resource>>> {
        let tenant = self.scope.tenant();
        Ok(match view {
            JumpView::Disks => Self::boxed(
                self.scope
                    .list(DISK_PATH, DISK_API_VERSION)
                    .await?
                    .iter()
                    .filter_map(|v| DiskRow::from_json(v, tenant))
                    .collect(),
            ),
            JumpView::Nics => Self::boxed(
                self.scope
                    .list(NIC_PATH, NIC_API_VERSION)
                    .await?
                    .iter()
                    .filter_map(|v| NicRow::from_json(v, tenant))
                    .collect(),
            ),
            _ => {
                let mut rows: Vec<VmRow> = self
                    .scope
                    .list(VM_PATH, VM_API_VERSION)
                    .await?
                    .iter()
                    .filter_map(|v| VmRow::from_json(v, tenant))
                    .collect();
                let power = Self::power_index(
                    &self
                        .scope
                        .list_query(VM_PATH, VM_API_VERSION, &[("statusOnly", "true")])
                        .await?,
                );
                for r in &mut rows {
                    r.set_power_state(power.get(&r.base.id.to_lowercase()).cloned());
                }
                Self::boxed(rows)
            }
        })
    }

    async fn list_resources_streaming(
        &self,
        view: JumpView,
        event_tx: mpsc::UnboundedSender<Event>,
        service_type: ServiceType,
    ) -> Result<()> {
        let tenant = self.scope.tenant().map(str::to_string);
        match view {
            JumpView::Disks => {
                let r = self
                    .scope
                    .stream(DISK_PATH, DISK_API_VERSION, &[], service_type, "Listing disks…", &event_tx, |page| {
                        Self::boxed(page.iter().filter_map(|v| DiskRow::from_json(v, tenant.as_deref())).collect())
                    })
                    .await;
                finish_stream(service_type, r, &event_tx)
            }
            JumpView::Nics => {
                let r = self
                    .scope
                    .stream(NIC_PATH, NIC_API_VERSION, &[], service_type, "Listing network interfaces…", &event_tx, |page| {
                        Self::boxed(page.iter().filter_map(|v| NicRow::from_json(v, tenant.as_deref())).collect())
                    })
                    .await;
                finish_stream(service_type, r, &event_tx)
            }
            _ => {
                // Pass 1: the model, streamed; rows land with a blank state.
                let mut collected: Vec<VmRow> = Vec::new();
                let streamed = self
                    .scope
                    .stream(VM_PATH, VM_API_VERSION, &[], service_type, "Listing virtual machines…", &event_tx, |page| {
                        let rows: Vec<VmRow> =
                            page.iter().filter_map(|v| VmRow::from_json(v, tenant.as_deref())).collect();
                        collected.extend(rows.iter().cloned());
                        Self::boxed(rows)
                    })
                    .await;
                if streamed.is_err() {
                    return finish_stream(service_type, streamed, &event_tx);
                }
                // Pass 2: the same list with `statusOnly=true` for the
                // power state, merged by id and delivered as one
                // replacement. Its failure keeps the rows, with a warning.
                match self
                    .scope
                    .list_query(VM_PATH, VM_API_VERSION, &[("statusOnly", "true")])
                    .await
                {
                    Ok(items) => {
                        let power = Self::power_index(&items);
                        for r in &mut collected {
                            r.set_power_state(power.get(&r.base.id.to_lowercase()).cloned());
                        }
                        let _ = event_tx.send(Event::ResourcesLoaded {
                            service: service_type,
                            resources: Self::boxed(collected),
                        });
                        Ok(())
                    }
                    Err(e) => {
                        let _ = event_tx.send(Event::ResourceLoadWarning {
                            service: service_type,
                            warning: format!("power state: {}", e),
                        });
                        finish_stream(service_type, streamed, &event_tx)
                    }
                }
            }
        }
    }

    async fn get_resource_details(&self, id: &str) -> Result<Box<dyn Resource>> {
        let tenant = self.scope.tenant();
        let not_found = || Error::ResourceNotFound(id.to_string());
        match JumpView::for_arm_id(id) {
            Some(JumpView::VirtualMachines) => {
                let v = self
                    .scope
                    .arm()?
                    .get_query(id, VM_API_VERSION, &[("$expand", "instanceView")])
                    .await?;
                let mut row = VmRow::from_json(&v, tenant).ok_or_else(not_found)?;
                row.set_power_state(VmRow::power_state_of(&v));
                Ok(Box::new(row))
            }
            Some(JumpView::Disks) => {
                let v = self.scope.get(id, DISK_API_VERSION).await?;
                Ok(Box::new(DiskRow::from_json(&v, tenant).ok_or_else(not_found)?))
            }
            Some(JumpView::Nics) => {
                let v = self.scope.get(id, NIC_API_VERSION).await?;
                Ok(Box::new(NicRow::from_json(&v, tenant).ok_or_else(not_found)?))
            }
            _ => Err(not_found()),
        }
    }
}

/// The instance view path of a VM id, for the lazy section's fetch.
pub fn instance_view_path(vm_id: &str) -> String {
    format!("{}/instanceView", vm_id.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-prod";

    fn vm_json() -> Value {
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Compute/virtualMachines/web-1", RG),
            "name": "web-1",
            "location": "westeurope",
            "zones": ["1"],
            "tags": {"env": "prod"},
            "properties": {
                "provisioningState": "Succeeded",
                "timeCreated": "2024-03-01T10:00:00.1234567+00:00",
                "hardwareProfile": {"vmSize": "Standard_D2s_v5"},
                "storageProfile": {
                    "imageReference": {"publisher": "Canonical", "offer": "ubuntu-24_04-lts", "sku": "server", "version": "latest"},
                    "osDisk": {"name": "web-1_OsDisk", "osType": "Linux", "diskSizeGB": 30, "caching": "ReadWrite",
                               "managedDisk": {"id": format!("{}/providers/Microsoft.Compute/disks/web-1_OsDisk", RG)}},
                    "dataDisks": [{"lun": 0, "name": "data0", "diskSizeGB": 256,
                                   "managedDisk": {"id": format!("{}/providers/Microsoft.Compute/disks/data0", RG)}}]
                },
                "osProfile": {"computerName": "web-1", "adminUsername": "azureuser"},
                "networkProfile": {"networkInterfaces": [
                    {"id": format!("{}/providers/Microsoft.Network/networkInterfaces/web-1-nic", RG), "properties": {"primary": true}}
                ]}
            }
        })
    }

    #[test]
    fn vm_row_parses_the_model_and_takes_power_state_from_the_status_pass() {
        let mut row = VmRow::from_json(&vm_json(), Some("t-1")).unwrap();
        assert_eq!(row.name(), "web-1");
        assert_eq!(row.location(), Some("westeurope"));
        assert_eq!(row.resource_group(), Some("rg-prod"));
        assert_eq!(row.vm_size.as_deref(), Some("Standard_D2s_v5"));
        assert_eq!(row.image.as_deref(), Some("Canonical:ubuntu-24_04-lts:server:latest"));
        assert_eq!(row.os_disk.as_ref().unwrap().size_gb, Some(30));
        assert_eq!(row.data_disks[0].lun, Some(0));
        assert_eq!(row.nics.len(), 1);
        // Blank until the statusOnly pass lands.
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.state_label(), "");

        let status = serde_json::json!({
            "id": format!("{}/providers/Microsoft.Compute/virtualMachines/WEB-1", RG),
            "properties": {"instanceView": {"statuses": [
                {"code": "ProvisioningState/succeeded"},
                {"code": "PowerState/deallocated", "displayStatus": "VM deallocated"}
            ]}}
        });
        let power = ComputeService::power_index(&[status]);
        row.set_power_state(power.get(&row.base.id.to_lowercase()).cloned());
        assert_eq!(row.state(), ResourceState::Stopped);
        assert_eq!(row.state_label(), "deallocated");

        let related = row.related();
        assert_eq!(related[0].0, "Subscription");
        assert_eq!(related[1].1, RG);
        assert!(related.iter().any(|(l, _)| l == "NIC (primary) web-1-nic"));
        assert!(related.iter().any(|(l, _)| l == "OS disk web-1_OsDisk"));
        assert!(related.iter().any(|(l, _)| l == "Data disk data0"));
        assert_eq!(
            row.cli_command().as_deref(),
            Some(format!("az vm show --ids {}/providers/Microsoft.Compute/virtualMachines/web-1", RG).as_str())
        );
        let storage = vm_section_lines(&row, VmDetailSection::Storage, None);
        assert_eq!(storage[0].0, "OS disk · web-1_OsDisk · 30 GB · readwrite");
        assert_eq!(storage[1].0, "LUN 0 · data0 · 256 GB");
        let iv = vm_section_lines(
            &row,
            VmDetailSection::InstanceView,
            Some(&Lazy::Loaded(serde_json::json!({
                "computerName": "web-1", "osName": "ubuntu", "osVersion": "24.04",
                "vmAgent": {"vmAgentVersion": "2.9", "statuses": [{"displayStatus": "Ready"}]},
                "statuses": [{"code": "PowerState/running", "displayStatus": "VM running"}],
                "disks": [{"name": "web-1_OsDisk", "statuses": [{"displayStatus": "Provisioning succeeded"}]}]
            }))),
        );
        assert!(iv.iter().any(|(k, v)| k == "VM agent" && v == "2.9 · Ready"));
        assert!(iv.iter().any(|(k, v)| k == "  PowerState/running" && v == "VM running"));
        assert!(iv.iter().any(|(k, v)| k == "  web-1_OsDisk" && v == "Provisioning succeeded"));
    }

    #[test]
    fn a_transitional_provisioning_state_outranks_power() {
        let mut v = vm_json();
        v["properties"]["provisioningState"] = "Updating".into();
        let mut row = VmRow::from_json(&v, None).unwrap();
        row.set_power_state(Some("running".into()));
        assert_eq!(row.state(), ResourceState::Pending);
        assert_eq!(row.state_label(), "updating");
    }

    #[test]
    fn disk_row_maps_disk_state_and_links_its_vm() {
        let v = serde_json::json!({
            "id": format!("{}/providers/Microsoft.Compute/disks/data0", RG),
            "name": "data0",
            "location": "westeurope",
            "sku": {"name": "Premium_LRS"},
            "managedBy": format!("{}/providers/Microsoft.Compute/virtualMachines/web-1", RG),
            "properties": {"provisioningState": "Succeeded", "diskSizeGB": 256, "diskState": "Attached",
                           "creationData": {"createOption": "Empty"}, "encryption": {"type": "EncryptionAtRestWithPlatformKey"}}
        });
        let row = DiskRow::from_json(&v, None).unwrap();
        assert_eq!(row.state(), ResourceState::Running);
        assert_eq!(row.state_label(), "attached");
        assert!(row.related().iter().any(|(l, _)| l == "Attached to web-1"));
        assert!(row.details().iter().any(|(k, v)| k == "Size" && v == "256 GB"));
        let mut orphan = v.clone();
        orphan["managedBy"] = Value::Null;
        orphan["properties"]["diskState"] = "Unattached".into();
        let row = DiskRow::from_json(&orphan, None).unwrap();
        assert_eq!(row.state(), ResourceState::Available);
        assert_eq!(row.state_label(), "unattached");
        assert_eq!(row.related().len(), 2);
    }

    #[test]
    fn nic_row_derives_attachment_and_links_subnet_and_public_ip() {
        let v = serde_json::json!({
            "id": format!("{}/providers/Microsoft.Network/networkInterfaces/web-1-nic", RG),
            "name": "web-1-nic",
            "location": "westeurope",
            "properties": {
                "provisioningState": "Succeeded",
                "macAddress": "00-0D-3A-00-00-01",
                "virtualMachine": {"id": format!("{}/providers/Microsoft.Compute/virtualMachines/web-1", RG)},
                "networkSecurityGroup": {"id": format!("{}/providers/Microsoft.Network/networkSecurityGroups/web-nsg", RG)},
                "ipConfigurations": [{"name": "ipconfig1", "properties": {
                    "privateIPAddress": "10.0.1.4", "privateIPAllocationMethod": "Dynamic", "primary": true,
                    "subnet": {"id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/web", RG)},
                    "publicIPAddress": {"id": format!("{}/providers/Microsoft.Network/publicIPAddresses/web-1-pip", RG)}
                }}]
            }
        });
        let row = NicRow::from_json(&v, None).unwrap();
        assert_eq!(row.state(), ResourceState::Running);
        assert_eq!(row.state_label(), "attached");
        let labels: Vec<String> = row.related().into_iter().map(|(l, _)| l).collect();
        for expected in ["VM web-1", "NSG web-nsg", "Subnet web · ipconfig1", "Public IP web-1-pip · ipconfig1"] {
            assert!(labels.iter().any(|l| l == expected), "missing {}: {:?}", expected, labels);
        }
        let cfg = nic_section_lines(&row, NicDetailSection::IpConfigurations);
        assert_eq!(cfg[0], ("ipconfig1 (primary)".to_string(), "10.0.1.4 · dynamic".to_string()));
        let mut loose = v.clone();
        loose["properties"]["virtualMachine"] = Value::Null;
        let row = NicRow::from_json(&loose, None).unwrap();
        assert_eq!(row.state_label(), "unattached");
    }
}
