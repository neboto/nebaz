//! VM scale sets (#30): the Virtual Machines tab's Scale sets sub-tab, one
//! subscription-wide list (`virtualMachineScaleSets`), listed by
//! `ComputeService`.
//!
//! - **Uniform** instances are not VMs: they live under the scale set
//!   (`{vmss}/virtualMachines`) and appear only in the lazy Instances
//!   section, with `$expand=instanceView` for the power state.
//! - **Flexible** instances are ordinary VMs (in the VMs sub-tab, whose
//!   Related links back here); Instances lists them with the VM list's
//!   documented `virtualMachineScaleSet/id` filter, each line a jump.
//!
//! Extensions are rendered by **name and type only**: an extension's
//! `settings` can carry plain script text, so it is stripped (with
//! `protectedSettings`, `customData` and `userData`, which a GET should
//! never return anyway) before `ArmBase` keeps the raw JSON for `e`.

use crate::azure::resource::{
    name_of_id, resource_group_of, scope_related, shell_quote, state_ladder, subscription_of, Resource, ResourceState,
};
use crate::azure::services::{arm_row, json, lazy_list_rows, overview_rows, related_rows, tag_rows, ArmBase};
use crate::lazy::Lazy;
use serde_json::Value;

crate::sections! {
    pub enum ScaleSetDetailSection,
    pub static SCALE_SET_SECTIONS = [
        Overview "Overview",
        Model "Model",
        Scaling "Scaling",
        Network "Network",
        Instances "Instances" => crate::app::App::trigger_vmss_instances,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

/// A lazy list request: the ARM path and its query.
pub type InstancesRequest = (String, Vec<(String, String)>);

/// One extension of the scale-set model: what it is, never its settings.
#[derive(Debug, Clone, PartialEq)]
pub struct VmssExtension {
    pub name: String,
    /// `publisher.type`.
    pub kind: String,
    pub version: Option<String>,
    pub auto_upgrade: Option<bool>,
}

/// One IP configuration of a NIC configuration.
#[derive(Debug, Clone, Default)]
pub struct VmssIpConfig {
    pub name: String,
    pub primary: Option<bool>,
    pub subnet_id: Option<String>,
    pub lb_pools: Vec<String>,
    pub lb_nat_pools: Vec<String>,
    pub agw_pools: Vec<String>,
    /// The per-instance public IP configuration's name, when there is one.
    pub public_ip_config: Option<String>,
}

/// One NIC configuration (`networkInterfaceConfigurations[]`).
#[derive(Debug, Clone, Default)]
pub struct VmssNicConfig {
    pub name: String,
    pub primary: Option<bool>,
    pub accelerated_networking: Option<bool>,
    pub ip_forwarding: Option<bool>,
    pub nsg_id: Option<String>,
    pub ip_configs: Vec<VmssIpConfig>,
}

#[derive(Debug, Clone)]
pub struct ScaleSetRow {
    pub base: ArmBase,
    /// `sku.name`: the instances' VM size.
    pub vm_size: Option<String>,
    pub capacity: Option<i64>,
    /// `Uniform` or `Flexible`; ARM omits it on older Uniform sets.
    pub orchestration_mode: Option<String>,
    pub upgrade_mode: Option<String>,
    pub automatic_os_upgrade: Option<bool>,
    pub overprovision: Option<bool>,
    pub zones: Vec<String>,
    pub zone_balance: Option<bool>,
    pub fault_domains: Option<i64>,
    pub single_placement_group: Option<bool>,
    pub priority: Option<String>,
    pub eviction_policy: Option<String>,
    pub max_price: Option<f64>,
    /// `(base regular count, regular % above base)`.
    pub priority_mix: Option<(Option<i64>, Option<i64>)>,
    pub spot_restore: Option<bool>,
    pub automatic_repairs: Option<bool>,
    pub repair_grace_period: Option<String>,
    pub scale_in_rules: Vec<String>,
    pub image: Option<String>,
    pub os_type: Option<String>,
    pub os_disk_type: Option<String>,
    pub os_disk_size_gb: Option<i64>,
    pub os_disk_caching: Option<String>,
    /// `diffDiskSettings.option` (`Local`: an ephemeral OS disk).
    pub ephemeral_os_disk: Option<String>,
    /// `(lun, size GB, storage account type)`.
    pub data_disks: Vec<(Option<i64>, Option<i64>, Option<String>)>,
    pub security_type: Option<String>,
    pub computer_name_prefix: Option<String>,
    pub admin_username: Option<String>,
    pub license_type: Option<String>,
    pub extensions: Vec<VmssExtension>,
    pub nic_configs: Vec<VmssNicConfig>,
    pub health_probe_id: Option<String>,
    pub proximity_placement_group: Option<String>,
    pub host_group: Option<String>,
    pub identity_type: Option<String>,
    pub user_identity_ids: Vec<String>,
    pub time_created: Option<String>,
}

/// The parent resource of a child id: a backend pool → its load balancer.
fn parent_of(id: &str) -> Option<String> {
    let parts: Vec<&str> = id.trim_end_matches('/').split('/').collect();
    // /subscriptions/s/resourceGroups/g/providers/NS/type/name/child/name
    (parts.len() > 9).then(|| parts[..9].join("/"))
}

/// The image reference as `publisher:offer:sku:version`, or a gallery /
/// managed image's name.
pub fn image_label(v: &Value, reference: &str) -> Option<String> {
    match json::str_at(v, &format!("{}/publisher", reference)) {
        Some(publisher) => Some(format!(
            "{}:{}:{}:{}",
            publisher,
            json::text(v, &format!("{}/offer", reference)),
            json::text(v, &format!("{}/sku", reference)),
            json::text(v, &format!("{}/version", reference))
        )),
        None => json::str_at(v, &format!("{}/id", reference))
            .or_else(|| json::str_at(v, &format!("{}/sharedGalleryImageId", reference)))
            .or_else(|| json::str_at(v, &format!("{}/communityGalleryImageId", reference)))
            .map(|i| name_of_id(&i).to_string()),
    }
}

/// The extension and script fields a scale-set body must never keep.
fn strip_secrets(v: &mut Value) {
    let Some(profile) = v.pointer_mut("/properties/virtualMachineProfile") else {
        return;
    };
    if let Some(os) = profile.pointer_mut("/osProfile").and_then(Value::as_object_mut) {
        os.remove("customData");
    }
    if let Some(p) = profile.as_object_mut() {
        p.remove("userData");
    }
    if let Some(exts) = profile.pointer_mut("/extensionProfile/extensions").and_then(Value::as_array_mut) {
        for e in exts {
            if let Some(props) = e.get_mut("properties").and_then(Value::as_object_mut) {
                props.remove("settings");
                props.remove("protectedSettings");
                props.remove("protectedSettingsFromKeyVault");
            }
        }
    }
}

impl ScaleSetRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<ScaleSetRow> {
        let mut v = v.clone();
        strip_secrets(&mut v);
        let v = &v;
        let base = ArmBase::from_json(v, tenant)?;
        let p = "/properties";
        let vm = "/properties/virtualMachineProfile";
        let storage = format!("{}/storageProfile", vm);
        let mix = format!("{}/priorityMixPolicy", p);
        let priority_mix = v.pointer(&mix).filter(|m| m.is_object()).map(|_| {
            (
                json::int_at(v, &format!("{}/baseRegularPriorityCount", mix)),
                json::int_at(v, &format!("{}/regularPriorityPercentageAboveBase", mix)),
            )
        });
        let extensions = json::arr(v, &format!("{}/extensionProfile/extensions", vm))
            .iter()
            .map(|e| VmssExtension {
                name: json::text(e, "/name"),
                kind: format!(
                    "{}.{}",
                    json::text(e, "/properties/publisher"),
                    json::text(e, "/properties/type")
                ),
                version: json::str_at(e, "/properties/typeHandlerVersion"),
                auto_upgrade: json::bool_at(e, "/properties/enableAutomaticUpgrade"),
            })
            .collect();
        let nic_configs = json::arr(v, &format!("{}/networkProfile/networkInterfaceConfigurations", vm))
            .iter()
            .map(|n| VmssNicConfig {
                name: json::text(n, "/name"),
                primary: json::bool_at(n, "/properties/primary"),
                accelerated_networking: json::bool_at(n, "/properties/enableAcceleratedNetworking"),
                ip_forwarding: json::bool_at(n, "/properties/enableIPForwarding"),
                nsg_id: json::arm_id(json::id_at(n, "/properties/networkSecurityGroup")),
                ip_configs: json::arr(n, "/properties/ipConfigurations")
                    .iter()
                    .map(|c| VmssIpConfig {
                        name: json::text(c, "/name"),
                        primary: json::bool_at(c, "/properties/primary"),
                        subnet_id: json::arm_id(json::id_at(c, "/properties/subnet")),
                        lb_pools: json::ids_at(c, "/properties/loadBalancerBackendAddressPools"),
                        lb_nat_pools: json::ids_at(c, "/properties/loadBalancerInboundNatPools"),
                        agw_pools: json::ids_at(c, "/properties/applicationGatewayBackendAddressPools"),
                        public_ip_config: json::str_at(c, "/properties/publicIPAddressConfiguration/name"),
                    })
                    .collect(),
            })
            .collect();
        Some(ScaleSetRow {
            vm_size: json::str_at(v, "/sku/name"),
            capacity: json::int_at(v, "/sku/capacity"),
            orchestration_mode: json::str_at(v, &format!("{}/orchestrationMode", p)),
            upgrade_mode: json::str_at(v, &format!("{}/upgradePolicy/mode", p)),
            automatic_os_upgrade: json::bool_at(
                v,
                &format!("{}/upgradePolicy/automaticOSUpgradePolicy/enableAutomaticOSUpgrade", p),
            ),
            overprovision: json::bool_at(v, &format!("{}/overprovision", p)),
            zones: json::strings_at(v, "/zones"),
            zone_balance: json::bool_at(v, &format!("{}/zoneBalance", p)),
            fault_domains: json::int_at(v, &format!("{}/platformFaultDomainCount", p)),
            single_placement_group: json::bool_at(v, &format!("{}/singlePlacementGroup", p)),
            priority: json::str_at(v, &format!("{}/priority", vm)),
            eviction_policy: json::str_at(v, &format!("{}/evictionPolicy", vm)),
            max_price: v.pointer(&format!("{}/billingProfile/maxPrice", vm)).and_then(Value::as_f64),
            priority_mix,
            spot_restore: json::bool_at(v, &format!("{}/spotRestorePolicy/enabled", p)),
            automatic_repairs: json::bool_at(v, &format!("{}/automaticRepairsPolicy/enabled", p)),
            repair_grace_period: json::str_at(v, &format!("{}/automaticRepairsPolicy/gracePeriod", p)),
            scale_in_rules: json::strings_at(v, &format!("{}/scaleInPolicy/rules", p)),
            image: image_label(v, &format!("{}/imageReference", storage)),
            os_type: json::str_at(v, &format!("{}/osDisk/osType", storage)),
            os_disk_type: json::str_at(v, &format!("{}/osDisk/managedDisk/storageAccountType", storage)),
            os_disk_size_gb: json::int_at(v, &format!("{}/osDisk/diskSizeGB", storage)),
            os_disk_caching: json::str_at(v, &format!("{}/osDisk/caching", storage)),
            ephemeral_os_disk: json::str_at(v, &format!("{}/osDisk/diffDiskSettings/option", storage)),
            data_disks: json::arr(v, &format!("{}/dataDisks", storage))
                .iter()
                .map(|d| {
                    (
                        json::int_at(d, "/lun"),
                        json::int_at(d, "/diskSizeGB"),
                        json::str_at(d, "/managedDisk/storageAccountType"),
                    )
                })
                .collect(),
            security_type: json::str_at(v, &format!("{}/securityProfile/securityType", vm)),
            computer_name_prefix: json::str_at(v, &format!("{}/osProfile/computerNamePrefix", vm)),
            admin_username: json::str_at(v, &format!("{}/osProfile/adminUsername", vm)),
            license_type: json::str_at(v, &format!("{}/licenseType", vm)),
            extensions,
            nic_configs,
            health_probe_id: json::arm_id(json::id_at(v, &format!("{}/networkProfile/healthProbe", vm))),
            proximity_placement_group: json::arm_id(json::id_at(v, &format!("{}/proximityPlacementGroup", p))),
            host_group: json::arm_id(json::id_at(v, &format!("{}/hostGroup", p))),
            identity_type: json::str_at(v, "/identity/type"),
            user_identity_ids: json::user_identity_ids(v),
            time_created: json::str_at(v, &format!("{}/timeCreated", p)),
            base,
        })
    }

    /// Flexible orchestration: its instances are ordinary VMs.
    pub fn is_flexible(&self) -> bool {
        self.orchestration_mode.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("Flexible"))
    }

    /// The mode as shown: ARM leaves it out on an older Uniform set.
    pub fn mode_label(&self) -> &str {
        match self.orchestration_mode.as_deref() {
            Some(m) if !m.is_empty() => m,
            _ => "Uniform",
        }
    }

    /// The Instances section's request, `(path, query)`: a Uniform set's
    /// own `virtualMachines` list, or for a Flexible one the subscription's
    /// VM list filtered to this set (the filter `$expand` needs). Both with
    /// the instance view, for the power state.
    pub fn instances_request(&self) -> Option<InstancesRequest> {
        let expand = ("$expand".to_string(), "instanceView".to_string());
        if self.is_flexible() {
            let sub = subscription_of(&self.base.id)?;
            Some((
                format!("/subscriptions/{}/providers/Microsoft.Compute/virtualMachines", sub),
                vec![
                    ("$filter".into(), format!("'virtualMachineScaleSet/id' eq '{}'", self.base.id)),
                    expand,
                ],
            ))
        } else {
            Some((format!("{}/virtualMachines", self.base.id.trim_end_matches('/')), vec![expand]))
        }
    }

    /// Every load balancer the model points at (backend pools, NAT pools,
    /// the health probe), deduplicated, in order.
    pub fn load_balancer_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let pools = self
            .nic_configs
            .iter()
            .flat_map(|n| n.ip_configs.iter())
            .flat_map(|c| c.lb_pools.iter().chain(c.lb_nat_pools.iter()));
        for id in pools.chain(self.health_probe_id.iter()) {
            if let Some(lb) = parent_of(id) {
                if !out.iter().any(|o| o.eq_ignore_ascii_case(&lb)) {
                    out.push(lb);
                }
            }
        }
        out
    }

    pub fn subnet_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in self.nic_configs.iter().flat_map(|n| n.ip_configs.iter()).filter_map(|c| c.subnet_id.clone()) {
            if !out.iter().any(|o| o.eq_ignore_ascii_case(&s)) {
                out.push(s);
            }
        }
        out
    }

    fn app_gateway_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for id in self.nic_configs.iter().flat_map(|n| n.ip_configs.iter()).flat_map(|c| c.agw_pools.iter()) {
            if let Some(g) = parent_of(id) {
                if !out.iter().any(|o| o.eq_ignore_ascii_case(&g)) {
                    out.push(g);
                }
            }
        }
        out
    }

    fn os_disk_label(&self) -> String {
        let mut parts = vec![json::opt(self.os_disk_type.clone())];
        if let Some(gb) = self.os_disk_size_gb {
            parts.push(format!("{} GB", gb));
        }
        if let Some(c) = &self.os_disk_caching {
            parts.push(c.to_lowercase());
        }
        if let Some(e) = &self.ephemeral_os_disk {
            parts.push(format!("ephemeral ({})", e));
        }
        parts.join(" · ")
    }
}

impl Resource for ScaleSetRow {
    arm_row!("VM Scale Set");
    /// The mode, the size and how many: what the set is at a glance.
    fn list_summary(&self) -> Option<String> {
        let mut s = self.mode_label().to_string();
        if let Some(size) = &self.vm_size {
            s.push_str(&format!(" · {}", size));
        }
        if let Some(n) = self.capacity {
            s.push_str(&format!(" × {}", n));
        }
        Some(s)
    }
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&SCALE_SET_SECTIONS)
    }
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.base.id,
            self.base.name,
            self.resource_group().unwrap_or(""),
            json::opt(self.vm_size.clone()),
            self.mode_label(),
            json::opt(self.os_type.clone()),
        )
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Orchestration".into(), self.mode_label().to_string()),
            ("Size".into(), json::opt(self.vm_size.clone())),
            ("Capacity".into(), json::num(self.capacity)),
            ("OS".into(), json::opt(self.os_type.clone())),
            ("Image".into(), json::opt(self.image.clone())),
            ("Upgrade policy".into(), json::opt(self.upgrade_mode.clone())),
            ("Zones".into(), json::join(&self.zones)),
            ("Priority".into(), json::opt(self.priority.clone())),
            ("Identity".into(), json::opt(self.identity_type.clone())),
            ("Created".into(), json::time(self.time_created.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = scope_related(&self.base.id);
        for s in self.subnet_ids() {
            v.push((format!("Subnet {}", name_of_id(&s)), s));
        }
        for lb in self.load_balancer_ids() {
            v.push((format!("Load balancer {}", name_of_id(&lb)), lb));
        }
        for g in self.app_gateway_ids() {
            v.push((format!("Application gateway {}", name_of_id(&g)), g));
        }
        for n in self.nic_configs.iter().filter_map(|n| n.nsg_id.clone()) {
            if !v.iter().any(|(_, id)| id.eq_ignore_ascii_case(&n)) {
                v.push((format!("NSG {}", name_of_id(&n)), n));
            }
        }
        for id in &self.user_identity_ids {
            v.push((format!("Identity {}", name_of_id(id)), id.clone()));
        }
        if let Some(p) = &self.proximity_placement_group {
            v.push((format!("Proximity placement group {}", name_of_id(p)), p.clone()));
        }
        if let Some(h) = &self.host_group {
            v.push((format!("Host group {}", name_of_id(h)), h.clone()));
        }
        v
    }
    /// `az vmss show` declares its name without an `id_part` (because of
    /// `--instance-id`), so `--ids` is not accepted: the name form.
    fn cli_command(&self) -> Option<String> {
        Some(format!(
            "az vmss show -n {} -g {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(resource_group_of(&self.base.id)?),
            shell_quote(subscription_of(&self.base.id)?)
        ))
    }
}

/// Body lines for one section of a scale-set row.
pub fn scale_set_section_lines(
    r: &ScaleSetRow,
    section: ScaleSetDetailSection,
    instances: Option<&Lazy<Vec<Value>>>,
) -> Vec<(String, String)> {
    match section {
        ScaleSetDetailSection::Overview => overview_rows(r),
        ScaleSetDetailSection::Model => model_rows(r),
        ScaleSetDetailSection::Scaling => scaling_rows(r),
        ScaleSetDetailSection::Network => network_rows(r),
        ScaleSetDetailSection::Instances => lazy_list_rows(instances, "Instances", |items| instance_rows(r, items)),
        ScaleSetDetailSection::Access => crate::azure::services::rendered_by_app(),
        ScaleSetDetailSection::Activity => crate::azure::services::rendered_by_app(),
        ScaleSetDetailSection::Related => related_rows(r),
        ScaleSetDetailSection::Tags => tag_rows(r.tags()),
    }
}

fn model_rows(r: &ScaleSetRow) -> Vec<(String, String)> {
    let mut lines = vec![
        ("Image".into(), json::opt(r.image.clone())),
        ("VM size".into(), json::opt(r.vm_size.clone())),
        ("OS".into(), json::opt(r.os_type.clone())),
        ("OS disk".into(), r.os_disk_label()),
    ];
    for (lun, gb, kind) in &r.data_disks {
        lines.push((
            format!("Data disk LUN {}", json::num(*lun)),
            format!("{} · {}", gb.map(|g| format!("{} GB", g)).unwrap_or_else(|| "-".into()), json::opt(kind.clone())),
        ));
    }
    lines.extend([
        ("Security type".into(), json::opt(r.security_type.clone())),
        ("Computer name prefix".into(), json::opt(r.computer_name_prefix.clone())),
        ("Admin user".into(), json::opt(r.admin_username.clone())),
        ("License".into(), json::opt(r.license_type.clone())),
        (String::new(), String::new()),
    ]);
    if r.extensions.is_empty() {
        lines.push(("Extensions".into(), "none".into()));
        return lines;
    }
    lines.push(("Extensions".into(), format!("{} (names and types; settings are never shown)", r.extensions.len())));
    for e in &r.extensions {
        let mut value = e.kind.clone();
        if let Some(ver) = &e.version {
            value.push_str(&format!(" {}", ver));
        }
        if e.auto_upgrade == Some(true) {
            value.push_str(" · auto-upgrade");
        }
        lines.push((format!("  {}", e.name), value));
    }
    lines
}

fn scaling_rows(r: &ScaleSetRow) -> Vec<(String, String)> {
    let mut upgrade = json::opt(r.upgrade_mode.clone());
    if r.automatic_os_upgrade == Some(true) {
        upgrade.push_str(" · automatic OS upgrades");
    }
    let mut lines = vec![
        ("Capacity".into(), json::num(r.capacity)),
        ("Orchestration".into(), r.mode_label().to_string()),
        ("Upgrade policy".into(), upgrade),
    ];
    if !r.is_flexible() {
        lines.push(("Overprovision".into(), json::yes_no(r.overprovision)));
    }
    lines.extend([
        ("Zones".into(), json::join(&r.zones)),
        ("Zone balance".into(), json::yes_no(r.zone_balance)),
        ("Fault domains".into(), json::num(r.fault_domains)),
        ("Single placement group".into(), json::yes_no(r.single_placement_group)),
        ("Priority".into(), json::opt(r.priority.clone())),
    ]);
    if r.priority.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("Spot")) || r.priority_mix.is_some() {
        lines.push(("Eviction policy".into(), json::opt(r.eviction_policy.clone())));
        lines.push((
            "Max price".into(),
            match r.max_price {
                Some(p) if p < 0.0 => "pay up to on-demand".into(),
                Some(p) => format!("{}", p),
                None => "-".into(),
            },
        ));
        lines.push(("Spot restore".into(), json::yes_no(r.spot_restore)));
    }
    if let Some((base, above)) = r.priority_mix {
        lines.push((
            "Priority mix".into(),
            format!(
                "{} regular first, then {}% regular above that",
                json::num(base),
                json::num(above)
            ),
        ));
    }
    let mut repairs = json::yes_no(r.automatic_repairs);
    if let (Some(true), Some(g)) = (r.automatic_repairs, &r.repair_grace_period) {
        repairs.push_str(&format!(" · grace {}", g));
    }
    lines.push(("Automatic repairs".into(), repairs));
    lines.push(("Scale-in policy".into(), json::join(&r.scale_in_rules)));
    lines
}

fn network_rows(r: &ScaleSetRow) -> Vec<(String, String)> {
    if r.nic_configs.is_empty() {
        return vec![(String::new(), "No network interface configurations".into())];
    }
    let mut lines = Vec::new();
    for n in &r.nic_configs {
        let primary = if n.primary == Some(true) { " (primary)" } else { "" };
        lines.push((
            format!("{}{}", n.name, primary),
            format!(
                "accelerated networking {} · IP forwarding {}",
                json::yes_no(n.accelerated_networking),
                json::yes_no(n.ip_forwarding)
            ),
        ));
        if let Some(nsg) = &n.nsg_id {
            lines.push(("  NSG".into(), nsg.clone()));
        }
        for c in &n.ip_configs {
            let primary = if c.primary == Some(true) && n.ip_configs.len() > 1 { " (primary)" } else { "" };
            lines.push((
                format!("  {}{} subnet", c.name, primary),
                c.subnet_id.clone().unwrap_or_else(|| "-".into()),
            ));
            for pool in &c.lb_pools {
                let lb = parent_of(pool).unwrap_or_else(|| pool.clone());
                lines.push((format!("    LB backend pool {}", name_of_id(pool)), lb));
            }
            for pool in &c.lb_nat_pools {
                let lb = parent_of(pool).unwrap_or_else(|| pool.clone());
                lines.push((format!("    LB inbound NAT pool {}", name_of_id(pool)), lb));
            }
            for pool in &c.agw_pools {
                let g = parent_of(pool).unwrap_or_else(|| pool.clone());
                lines.push((format!("    App gateway pool {}", name_of_id(pool)), g));
            }
            if let Some(pip) = &c.public_ip_config {
                lines.push(("    Public IP per instance".into(), pip.clone()));
            }
        }
    }
    if let Some(probe) = &r.health_probe_id {
        lines.push((
            format!("Health probe {}", name_of_id(probe)),
            parent_of(probe).unwrap_or_else(|| probe.clone()),
        ));
    }
    lines
}

/// One instance, as the Instances section and the audit check read it.
#[derive(Debug, Clone, PartialEq)]
pub struct VmssInstance {
    pub name: String,
    pub id: String,
    /// `None` for a Flexible set's VMs (the field is Uniform's).
    pub latest_model: Option<bool>,
    pub power_state: Option<String>,
    pub zone: Option<String>,
    pub provisioning_state: Option<String>,
}

impl VmssInstance {
    pub fn from_json(v: &Value) -> VmssInstance {
        VmssInstance {
            name: json::str_at(v, "/name").unwrap_or_else(|| json::text(v, "/instanceId")),
            id: json::text(v, "/id"),
            latest_model: json::bool_at(v, "/properties/latestModelApplied"),
            power_state: crate::azure::services::compute::VmRow::power_state_of(v),
            zone: json::strings_at(v, "/zones").into_iter().next(),
            provisioning_state: json::str_at(v, "/properties/provisioningState"),
        }
    }
}

fn instance_rows(r: &ScaleSetRow, items: &[Value]) -> Vec<(String, String)> {
    if items.is_empty() {
        return vec![(String::new(), "No instances".into())];
    }
    let instances: Vec<VmssInstance> = items.iter().map(VmssInstance::from_json).collect();
    let stale = instances.iter().filter(|i| i.latest_model == Some(false)).count();
    let mut summary = format!("{}", instances.len());
    if !r.is_flexible() {
        summary.push_str(&format!(" · {} not on the latest model", stale));
    } else {
        summary.push_str(" VMs (Flexible: each is in the VMs sub-tab)");
    }
    let mut lines = vec![("Instances".into(), summary), (String::new(), String::new())];
    for i in &instances {
        let mut facts = vec![json::opt(i.power_state.clone())];
        if let Some(z) = &i.zone {
            facts.push(format!("zone {}", z));
        }
        if let Some(latest) = i.latest_model {
            facts.push(if latest { "latest model".into() } else { "⚠ not on the latest model".into() });
        }
        if let Some(p) = i.provisioning_state.as_deref().filter(|p| !p.eq_ignore_ascii_case("Succeeded")) {
            facts.push(p.to_lowercase());
        }
        // The id is the value: a Flexible VM's jumps, a Uniform instance's
        // copies (instances are in no list).
        lines.push((format!("{} · {}", i.name, facts.join(" · ")), i.id.clone()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-prod";

    fn vmss_json(mode: &str) -> Value {
        let network = serde_json::json!({
                        "healthProbe": {"id": format!("{}/providers/Microsoft.Network/loadBalancers/lb-web/probes/http", RG)},
                        "networkInterfaceConfigurations": [{"name": "nic-web", "properties": {
                            "primary": true, "enableAcceleratedNetworking": true,
                            "networkSecurityGroup": {"id": format!("{}/providers/Microsoft.Network/networkSecurityGroups/nsg-web", RG)},
                            "ipConfigurations": [{"name": "ipconfig1", "properties": {
                                "subnet": {"id": format!("{}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet-web", RG)},
                                "loadBalancerBackendAddressPools": [{"id": format!("{}/providers/Microsoft.Network/loadBalancers/lb-web/backendAddressPools/web", RG)}],
                                "applicationGatewayBackendAddressPools": [{"id": format!("{}/providers/Microsoft.Network/applicationGateways/agw/backendAddressPools/web", RG)}]
                            }}]
                        }}]
        });
        serde_json::json!({
            "id": format!("{}/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web", RG),
            "name": "vmss-web",
            "location": "westeurope",
            "sku": {"name": "Standard_D2s_v5", "tier": "Standard", "capacity": 3},
            "zones": ["1", "2", "3"],
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                format!("{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-web", RG): {}
            }},
            "properties": {
                "provisioningState": "Succeeded",
                "orchestrationMode": mode,
                "upgradePolicy": {"mode": "Rolling", "automaticOSUpgradePolicy": {"enableAutomaticOSUpgrade": true}},
                "overprovision": true,
                "zoneBalance": true,
                "platformFaultDomainCount": 1,
                "priorityMixPolicy": {"baseRegularPriorityCount": 2, "regularPriorityPercentageAboveBase": 50},
                "proximityPlacementGroup": {"id": format!("{}/providers/Microsoft.Compute/proximityPlacementGroups/ppg-web", RG)},
                "virtualMachineProfile": {
                    "priority": "Spot",
                    "evictionPolicy": "Deallocate",
                    "billingProfile": {"maxPrice": -1},
                    "osProfile": {"computerNamePrefix": "web", "adminUsername": "azureuser", "customData": "c2VjcmV0"},
                    "userData": "c2VjcmV0",
                    "storageProfile": {
                        "imageReference": {"publisher": "Canonical", "offer": "ubuntu-24_04-lts", "sku": "server", "version": "latest"},
                        "osDisk": {"osType": "Linux", "caching": "ReadWrite", "diskSizeGB": 64,
                                   "managedDisk": {"storageAccountType": "Premium_LRS"}},
                        "dataDisks": [{"lun": 0, "diskSizeGB": 128, "managedDisk": {"storageAccountType": "StandardSSD_LRS"}}]
                    },
                    "extensionProfile": {"extensions": [
                        {"name": "CustomScript", "properties": {"publisher": "Microsoft.Azure.Extensions", "type": "CustomScript",
                            "typeHandlerVersion": "2.1", "settings": {"commandToExecute": "echo hunter2 | login"},
                            "protectedSettings": {"storageAccountKey": "k"}}},
                        {"name": "HealthExtension", "properties": {"publisher": "Microsoft.ManagedServices", "type": "ApplicationHealthLinux",
                            "typeHandlerVersion": "1.0", "enableAutomaticUpgrade": true, "settings": {"port": 80}}}
                    ]},
                    "networkProfile": network
                }
            }
        })
    }

    #[test]
    fn a_scale_set_parses_its_model_scaling_and_network() {
        let row = ScaleSetRow::from_json(&vmss_json("Uniform"), Some("t")).unwrap();
        assert_eq!(row.list_summary().as_deref(), Some("Uniform · Standard_D2s_v5 × 3"));
        assert_eq!(row.state(), ResourceState::stateless());
        assert_eq!(row.image.as_deref(), Some("Canonical:ubuntu-24_04-lts:server:latest"));
        assert_eq!(row.os_disk_label(), "Premium_LRS · 64 GB · readwrite");
        assert_eq!(row.priority_mix, Some((Some(2), Some(50))));
        assert!(!row.is_flexible());

        let model = scale_set_section_lines(&row, ScaleSetDetailSection::Model, None);
        assert!(model.iter().any(|(k, v)| k == "  CustomScript" && v == "Microsoft.Azure.Extensions.CustomScript 2.1"));
        assert!(model.iter().any(|(k, v)| k == "  HealthExtension" && v.ends_with("auto-upgrade")));
        assert!(model.iter().any(|(k, v)| k == "Data disk LUN 0" && v == "128 GB · StandardSSD_LRS"));

        let scaling = scale_set_section_lines(&row, ScaleSetDetailSection::Scaling, None);
        assert!(scaling.iter().any(|(k, v)| k == "Upgrade policy" && v == "Rolling · automatic OS upgrades"));
        assert!(scaling.iter().any(|(k, v)| k == "Max price" && v == "pay up to on-demand"));
        assert!(scaling.iter().any(|(k, v)| k == "Priority mix" && v.starts_with("2 regular first, then 50%")));
        assert!(scaling.iter().any(|(k, _)| k == "Overprovision"));

        let net = scale_set_section_lines(&row, ScaleSetDetailSection::Network, None);
        let lb = format!("{}/providers/Microsoft.Network/loadBalancers/lb-web", RG);
        assert!(net.iter().any(|(k, v)| k == "    LB backend pool web" && *v == lb));
        assert!(net.iter().any(|(k, v)| k == "Health probe http" && *v == lb));

        let related = row.related();
        let labels: Vec<&str> = related.iter().map(|(l, _)| l.as_str()).collect();
        for expected in [
            "Subnet snet-web",
            "Load balancer lb-web",
            "Application gateway agw",
            "NSG nsg-web",
            "Identity id-web",
            "Proximity placement group ppg-web",
        ] {
            assert!(labels.contains(&expected), "missing {expected}: {labels:?}");
        }
        assert_eq!(labels.iter().filter(|l| l.starts_with("Load balancer")).count(), 1, "pool and probe: one LB");
        assert_eq!(
            row.cli_command().as_deref(),
            Some("az vmss show -n vmss-web -g rg-prod --subscription 0000")
        );
    }

    #[test]
    fn extension_settings_and_custom_data_never_reach_the_raw_json() {
        let row = ScaleSetRow::from_json(&vmss_json("Uniform"), None).unwrap();
        let raw = row.raw_content().unwrap();
        for (i, needle) in ["hunter2", "storageAccountKey", "customData", "userData", "c2VjcmV0", "\"port\""].iter().enumerate() {
            assert!(!raw.contains(needle), "fixture value {i} kept in the raw JSON");
        }
        assert!(raw.contains("CustomScript"), "the extension's name stays");
    }

    #[test]
    fn the_instances_request_follows_the_orchestration_mode() {
        let uniform = ScaleSetRow::from_json(&vmss_json("Uniform"), None).unwrap();
        let (path, query) = uniform.instances_request().unwrap();
        assert_eq!(path, format!("{}/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web/virtualMachines", RG));
        assert_eq!(query, vec![("$expand".to_string(), "instanceView".to_string())]);

        let flex = ScaleSetRow::from_json(&vmss_json("Flexible"), None).unwrap();
        assert!(flex.is_flexible());
        let (path, query) = flex.instances_request().unwrap();
        assert_eq!(path, "/subscriptions/0000/providers/Microsoft.Compute/virtualMachines");
        assert_eq!(
            query[0].1,
            format!("'virtualMachineScaleSet/id' eq '{}/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web'", RG)
        );
        let scaling = scale_set_section_lines(&flex, ScaleSetDetailSection::Scaling, None);
        assert!(!scaling.iter().any(|(k, _)| k == "Overprovision"), "Uniform only");
    }

    #[test]
    fn instances_show_power_zone_and_the_latest_model() {
        let row = ScaleSetRow::from_json(&vmss_json("Uniform"), None).unwrap();
        let inst = |n: u32, latest: bool, power: &str| {
            serde_json::json!({
                "id": format!("{}/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web/virtualMachines/{}", RG, n),
                "name": format!("vmss-web_{}", n), "instanceId": n.to_string(), "zones": [ (n % 3 + 1).to_string() ],
                "properties": {"latestModelApplied": latest, "provisioningState": "Succeeded",
                    "instanceView": {"statuses": [{"code": "ProvisioningState/succeeded"}, {"code": format!("PowerState/{}", power)}]}}
            })
        };
        let loaded = Lazy::Loaded(vec![inst(0, true, "running"), inst(1, false, "deallocated")]);
        let lines = scale_set_section_lines(&row, ScaleSetDetailSection::Instances, Some(&loaded));
        assert_eq!(lines[0], ("Instances".to_string(), "2 · 1 not on the latest model".to_string()));
        assert!(lines.iter().any(|(k, _)| k == "vmss-web_0 · running · zone 1 · latest model"));
        assert!(lines.iter().any(|(k, v)| k == "vmss-web_1 · deallocated · zone 2 · ⚠ not on the latest model"
            && v.ends_with("/virtualMachines/1")));
        let loading = scale_set_section_lines(&row, ScaleSetDetailSection::Instances, None);
        assert_eq!(loading[0].1, "Loading…");
    }

    #[test]
    fn section_labels_follow_the_house_order() {
        let labels: Vec<&str> = SCALE_SET_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            ["Overview", "Model", "Scaling", "Network", "Instances", "Access", "Activity", "Related", "Tags"]
        );
    }
}
