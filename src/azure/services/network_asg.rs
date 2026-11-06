//! Application security groups (#203, SERVICES.md rule 40): the Network
//! tab's ASGs sub-tab, one subscription-wide list of
//! `Microsoft.Network/applicationSecurityGroups`. An ASG body is only a
//! name; its value is in the joins, both read from lists, never a call per
//! group: **Members**, the NICs whose IP configurations name it (the NICs
//! list), and **Rules**, the NSG rules that use it as a source or a
//! destination (the NSGs list). Either list loads for the section when its
//! own sub-tab is cold (`App::trigger_section_list`).

use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::services::compute::NicRow;
use crate::azure::services::governance::Warm;
use crate::azure::services::network::NsgRow;
use crate::azure::services::{arm_row, json, overview_rows, related_rows_with, tag_rows, ArmBase};
use serde_json::Value;

pub const ASGS_PATH: &str = "/providers/Microsoft.Network/applicationSecurityGroups";

crate::sections! {
    pub enum AsgDetailSection,
    pub static ASG_SECTIONS = [
        Overview "Overview",
        Members "Members" => crate::app::App::trigger_asg_members,
        Rules "Rules" => crate::app::App::trigger_asg_rules,
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related" => crate::app::App::trigger_asg_joins,
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct AsgRow {
    pub base: ArmBase,
    pub guid: Option<String>,
}

impl AsgRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<AsgRow> {
        let base = ArmBase::from_json(v, tenant)?;
        Some(AsgRow { guid: json::str_at(v, "/properties/resourceGuid"), base })
    }

    fn is(&self, id: &str) -> bool {
        id.eq_ignore_ascii_case(&self.base.id)
    }

    /// `(nic, ip configuration)` for every IP configuration that names
    /// this group.
    fn members<'a>(&self, nics: &'a [Box<dyn Resource>]) -> Vec<(&'a NicRow, String)> {
        nics.iter()
            .filter_map(|r| r.as_any().downcast_ref::<NicRow>())
            .flat_map(|n| {
                n.ip_configs
                    .iter()
                    .filter(|c| c.asg_ids.iter().any(|a| self.is(a)))
                    .map(move |c| (n, c.name.clone()))
            })
            .collect()
    }

    /// `(nsg, rules)` for every NSG with a rule that names this group.
    fn rules<'a>(&self, nsgs: &'a [Box<dyn Resource>]) -> Vec<(&'a NsgRow, Vec<(String, String)>)> {
        nsgs.iter()
            .filter_map(|r| r.as_any().downcast_ref::<NsgRow>())
            .filter_map(|nsg| {
                let lines: Vec<(String, String)> = nsg
                    .rules
                    .iter()
                    .filter_map(|rule| {
                        let src = rule.source_asgs.iter().any(|a| self.is(a));
                        let dst = rule.destination_asgs.iter().any(|a| self.is(a));
                        let role = match (src, dst) {
                            (true, true) => "source and destination",
                            (true, false) => "source",
                            (false, true) => "destination",
                            (false, false) => return None,
                        };
                        let (key, text) = rule.line();
                        Some((format!("  {} · {} · as {}", key, rule.direction.to_lowercase(), role), text))
                    })
                    .collect();
                (!lines.is_empty()).then_some((nsg, lines))
            })
            .collect()
    }
}

impl Resource for AsgRow {
    arm_row!("Application Security Group");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&ASG_SECTIONS)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("GUID".into(), json::opt(self.guid.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az network asg show --ids {}", shell_quote(&self.base.id)))
    }
}

fn member_rows(r: &AsgRow, nics: Warm) -> Vec<(String, String)> {
    let Some(nics) = nics.rows() else {
        return nics.waiting("NICs");
    };
    let members = r.members(nics);
    if members.is_empty() {
        return vec![(String::new(), "No NIC in this subscription is a member".into())];
    }
    let mut lines = Vec::new();
    for (nic, config) in members {
        let vm = nic.vm_id.as_deref().map(|v| format!(" · VM {}", name_of_id(v))).unwrap_or_default();
        lines.push((format!("NIC · {} ({}){}", nic.base.name, config, vm), nic.base.id.clone()));
    }
    lines
}

fn rule_rows(r: &AsgRow, nsgs: Warm) -> Vec<(String, String)> {
    let Some(nsgs) = nsgs.rows() else {
        return nsgs.waiting("NSGs");
    };
    let found = r.rules(nsgs);
    if found.is_empty() {
        return vec![(String::new(), "No NSG rule in this subscription names this group".into())];
    }
    let mut lines = Vec::new();
    for (nsg, rules) in found {
        if !lines.is_empty() {
            lines.push((String::new(), String::new()));
        }
        lines.push((format!("NSG · {}", nsg.base.name), nsg.base.id.clone()));
        lines.extend(rules);
    }
    lines
}

/// Body lines for one section of an ASG; `None` for another type. The
/// NICs and NSGs are the current subscription's lists, warm or loading.
pub fn asg_section_lines(r: &dyn Resource, idx: usize, nics: Warm, nsgs: Warm) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<AsgRow>()?;
    use AsgDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Members => member_rows(x, nics),
        S::Rules => rule_rows(x, nsgs),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => {
            let mut extra: Vec<(String, String)> = Vec::new();
            if let Some(nics) = nics.rows() {
                for (nic, _) in x.members(nics) {
                    extra.push((format!("Member NIC {}", nic.base.name), nic.base.id.clone()));
                }
            }
            if let Some(nsgs) = nsgs.rows() {
                for (nsg, _) in x.rules(nsgs) {
                    extra.push((format!("NSG {} (rules name it)", nsg.base.name), nsg.base.id.clone()));
                }
            }
            related_rows_with(x, extra)
        }
        S::Tags => tag_rows(x.tags()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-app";

    fn asg_id(name: &str) -> String {
        format!("{}/providers/Microsoft.Network/applicationSecurityGroups/{}", RG, name)
    }

    fn asg() -> AsgRow {
        AsgRow::from_json(&json!({"id": asg_id("asg-web"), "name": "asg-web", "location": "westeurope",
            "properties": {"provisioningState": "Succeeded", "resourceGuid": "g-1"}}), None)
        .unwrap()
    }

    fn nic(name: &str, asg: Option<&str>) -> Box<dyn Resource> {
        let asgs: Vec<Value> = asg.map(|a| json!({"id": asg_id(a)})).into_iter().collect();
        Box::new(
            NicRow::from_json(
                &json!({"id": format!("{}/providers/Microsoft.Network/networkInterfaces/{}", RG, name), "name": name,
                    "location": "westeurope", "properties": {
                        "virtualMachine": {"id": format!("{}/providers/Microsoft.Compute/virtualMachines/vm-{}", RG, name)},
                        "ipConfigurations": [{"name": "ipconfig1", "properties": {"applicationSecurityGroups": asgs}}]
                    }}),
                None,
            )
            .unwrap(),
        )
    }

    fn nsg() -> Box<dyn Resource> {
        Box::new(
            NsgRow::from_json(
                &json!({"id": format!("{}/providers/Microsoft.Network/networkSecurityGroups/nsg-app", RG), "name": "nsg-app",
                    "location": "westeurope", "properties": {"securityRules": [
                        {"name": "web-in", "properties": {"priority": 100, "direction": "Inbound", "access": "Allow",
                            "protocol": "Tcp", "sourceAddressPrefix": "*", "sourcePortRange": "*",
                            "destinationApplicationSecurityGroups": [{"id": asg_id("asg-web")}], "destinationPortRange": "443"}},
                        {"name": "other", "properties": {"priority": 200, "direction": "Inbound", "access": "Deny",
                            "protocol": "*", "sourceAddressPrefix": "*", "sourcePortRange": "*",
                            "destinationAddressPrefix": "*", "destinationPortRange": "*"}}
                    ]}}),
                None,
            )
            .unwrap(),
        )
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = ASG_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Members", "Rules", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn members_and_rules_come_from_the_lists() {
        let r = asg();
        assert_eq!(r.cli_command(), Some(format!("az network asg show --ids {}", asg_id("asg-web"))));
        let nics = vec![nic("nic-web-1", Some("asg-web")), nic("nic-db-1", Some("asg-db")), nic("nic-x", None)];
        let nsgs = vec![nsg()];
        let at = |s: AsgDetailSection| asg_section_lines(&r, s as usize, Warm::Rows(&nics), Warm::Rows(&nsgs)).unwrap();

        let members = at(AsgDetailSection::Members);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, "NIC · nic-web-1 (ipconfig1) · VM vm-nic-web-1");

        let rules = at(AsgDetailSection::Rules);
        assert_eq!(rules[0].0, "NSG · nsg-app");
        assert_eq!(rules[1].0, "  100 web-in · inbound · as destination");
        assert_eq!(rules.len(), 2, "the rule that names no ASG is not listed");

        let related = at(AsgDetailSection::Related);
        for want in ["Member NIC nic-web-1", "NSG nsg-app (rules name it)"] {
            assert!(related.iter().any(|(l, _)| l == want), "{want} in {related:?}");
        }
    }

    #[test]
    fn a_cold_or_loading_list_says_so() {
        let r = asg();
        let cold = asg_section_lines(&r, AsgDetailSection::Members as usize, Warm::Cold, Warm::Loading).unwrap();
        assert_eq!(cold[0].1, "Open the NICs sub-tab to load them");
        let loading = asg_section_lines(&r, AsgDetailSection::Rules as usize, Warm::Cold, Warm::Loading).unwrap();
        assert_eq!(loading[0].1, "Loading…");
    }
}
