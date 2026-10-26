//! The Firewall tab's glue (#136): the warm lists its sections read, the
//! lazy triggers (a policy's rule collection groups and its base's, a
//! rulestack's rules and objects, a Cloud NGFW's status) and the section
//! dispatch. The rows and renderers are `src/azure/services/firewall.rs`.

use super::App;
use crate::azure::resource::{subscription_of, Resource};
use crate::azure::service::JumpView;
use crate::azure::services::firewall::{
    azure_firewall_section_lines, cloud_ngfw_section_lines, firewall_policy_section_lines, ip_group_section_lines,
    ngfw_status_path, rule_collection_groups_path, rules_key, rulestack_child_path, rulestack_section_lines,
    AzureFirewallDetailSection, AzureFirewallRow, CloudNgfwDetailSection, CloudNgfwRow, FirewallLazy, FirewallLists,
    FirewallPolicyDetailSection, FirewallPolicyRow, IpGroupDetailSection, IpGroupRow, NgfwManagement, RulestackDetailSection,
    RulestackRow, AZFW_API_VERSION, NGFW_API_VERSION,
};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The warm Firewall-tab lists of an ARM id's subscription (never a
    /// call).
    pub(crate) fn firewall_lists(&self, id: &str) -> FirewallLists<'_> {
        let Some(sub) = subscription_of(id) else {
            return FirewallLists::default();
        };
        let get = |view: JumpView| self.cache.get_ref(&view.service(), sub, Some(view.as_str()));
        FirewallLists {
            firewalls: get(JumpView::AzureFirewalls),
            policies: get(JumpView::FirewallPolicies),
            ip_groups: get(JumpView::IpGroups),
            ngfws: get(JumpView::CloudNgfws),
            rulestacks: get(JumpView::NgfwRulestacks),
            route_tables: get(JumpView::RouteTables),
        }
    }

    fn firewall_lazy(&self) -> FirewallLazy<'_> {
        FirewallLazy {
            rule_collection_groups: &self.lazy.firewall_rule_collection_groups,
            ngfw_rules: &self.lazy.ngfw_local_rules,
            prefix_lists: &self.lazy.ngfw_prefix_lists,
            fqdn_lists: &self.lazy.ngfw_fqdn_lists,
            ngfw_status: &self.lazy.ngfw_status,
        }
    }

    /// The Firewall-tab arm of `section_lines_for`; `None` for any other
    /// type.
    pub(crate) fn firewall_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let any = resource.as_any();
        let lists = self.firewall_lists(resource.id());
        let lazy = self.firewall_lazy();
        if let Some(r) = any.downcast_ref::<AzureFirewallRow>() {
            return Some(azure_firewall_section_lines(r, AzureFirewallDetailSection::from_index(idx), &lists, &lazy));
        }
        if let Some(r) = any.downcast_ref::<FirewallPolicyRow>() {
            return Some(firewall_policy_section_lines(r, FirewallPolicyDetailSection::from_index(idx), &lists, &lazy));
        }
        if let Some(r) = any.downcast_ref::<IpGroupRow>() {
            return Some(ip_group_section_lines(r, IpGroupDetailSection::from_index(idx)));
        }
        if let Some(r) = any.downcast_ref::<CloudNgfwRow>() {
            return Some(cloud_ngfw_section_lines(r, CloudNgfwDetailSection::from_index(idx), &lists, &lazy));
        }
        if let Some(r) = any.downcast_ref::<RulestackRow>() {
            return Some(rulestack_section_lines(r, RulestackDetailSection::from_index(idx), &lists, &lazy));
        }
        None
    }

    /// `GET {policy}/ruleCollectionGroups` once per policy.
    fn trigger_rule_collection_groups(&mut self, policy: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = self.azure_clients.list_fetch(&rule_collection_groups_path(policy), AZFW_API_VERSION);
        self.trigger_lazy(|s| &mut s.firewall_rule_collection_groups, rules_key(policy), event_tx, move || fut);
    }

    /// `GET {rulestack}/localRules` once per rulestack.
    fn trigger_local_rules(&mut self, rulestack: &str, event_tx: &mpsc::UnboundedSender<Event>) {
        let fut = self.azure_clients.list_fetch(&rulestack_child_path(rulestack, "localRules"), NGFW_API_VERSION);
        self.trigger_lazy(|s| &mut s.ngfw_local_rules, rules_key(rulestack), event_tx, move || fut);
    }

    /// On-enter hook for every Firewall-tab rules section: a policy's (or
    /// an Azure Firewall's policy's) rule collection groups and its base
    /// policy's; a rulestack's (or a Cloud NGFW's local rulestack's) rules.
    /// A Panorama-, Strata- or global-rulestack-managed NGFW reads nothing.
    pub fn trigger_firewall_rules(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(r) = app.get_selected_resource().map(|r| r.clone_box()) else {
            return;
        };
        let any = r.as_any();
        let mut policies = Vec::new();
        let mut rulestack = None;
        if let Some(p) = any.downcast_ref::<FirewallPolicyRow>() {
            policies.push(p.base.id.clone());
            policies.extend(p.base_policy_id.clone());
        } else if let Some(f) = any.downcast_ref::<AzureFirewallRow>() {
            policies = f.rule_sources(&app.firewall_lists(&f.base.id));
        } else if let Some(n) = any.downcast_ref::<CloudNgfwRow>() {
            if n.management() == NgfwManagement::LocalRulestack {
                rulestack = n.rulestack_id();
            }
        } else if let Some(s) = any.downcast_ref::<RulestackRow>() {
            rulestack = Some(s.base.id.clone());
        }
        for p in policies {
            app.trigger_rule_collection_groups(&p, event_tx);
        }
        if let Some(s) = rulestack {
            app.trigger_local_rules(&s, event_tx);
        }
    }

    /// On-enter hook for a rulestack's Objects: its prefix lists and FQDN
    /// lists, one read each.
    pub fn trigger_rulestack_objects(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(id) = app
            .get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<RulestackRow>())
            .map(|r| r.base.id.clone())
        else {
            return;
        };
        let prefixes = app.azure_clients.list_fetch(&rulestack_child_path(&id, "prefixlists"), NGFW_API_VERSION);
        app.trigger_lazy(|s| &mut s.ngfw_prefix_lists, rules_key(&id), event_tx, move || prefixes);
        let fqdns = app.azure_clients.list_fetch(&rulestack_child_path(&id, "fqdnlists"), NGFW_API_VERSION);
        app.trigger_lazy(|s| &mut s.ngfw_fqdn_lists, rules_key(&id), event_tx, move || fqdns);
    }

    /// On-enter hook for a Cloud NGFW's Status: `GET {fw}/statuses/default`.
    pub fn trigger_ngfw_status(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.ngfw_status,
            event_tx,
            |c, id| c.get_fetch(&ngfw_status_path(id), NGFW_API_VERSION),
        );
    }
}
