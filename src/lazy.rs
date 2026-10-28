// ported from neboto-tui src/lazy.rs @ d483900
//! The deep module behind the "lazy section" pattern (vocabulary in
//! CONTEXT.md, the event design in docs/adr/0001-apply-closure-lazy-event.md).
//!
//! A lazy section's data lives in a [`LazyMap`] inside the app's single
//! [`LazyStore`]. Fetches are spawned through `App::trigger_lazy` and resolve
//! to a [`Lazy`] outcome delivered by the one `Event::Lazy` apply-closure
//! event. The store's epoch stamp lets a stale in-flight fetch — one spawned
//! before a subscription switch — be dropped instead of poisoning the
//! fresh store, and replacing the store wholesale on a switch makes the old
//! "clear it in `reset_subscription_scoped_state`" convention unnecessary: a new
//! map field resets by construction.

use std::collections::HashMap;

/// The three-state outcome of a lazy fetch. "Nothing found" is a normal
/// `Loaded` payload (e.g. `Loaded(None)`), never an `Error`.
#[derive(Debug, Clone)]
pub enum Lazy<T> {
    Loading,
    Loaded(T),
    Error(String),
}

/// A keyed collection of [`Lazy`] outcomes for one detail concern (e.g. flow
/// logs by VPC id). Triggering a key that is already present is a no-op, so a
/// section can be triggered from digit keys, `Tab`-cycling, and drill-in
/// alike without duplicate fetches.
#[derive(Debug, Clone)]
pub struct LazyMap<T> {
    map: HashMap<String, Lazy<T>>,
}

impl<T> Default for LazyMap<T> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<T> LazyMap<T> {
    pub fn get(&self, key: &str) -> Option<&Lazy<T>> {
        self.map.get(key)
    }

    /// The trigger idempotence guard: an entry in any state (including
    /// `Error` — failures don't auto-retry) blocks a re-fetch.
    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Mark a fetch as in flight. `App::trigger_lazy` calls this before
    /// spawning; renderers show `Loading` until the apply lands.
    pub fn insert_loading(&mut self, key: String) {
        self.map.insert(key, Lazy::Loading);
    }

    /// Deliver a fetch result (the apply-closure's body).
    pub fn apply(&mut self, key: String, result: Result<T, String>) {
        let state = match result {
            Ok(v) => Lazy::Loaded(v),
            Err(e) => Lazy::Error(e),
        };
        self.map.insert(key, state);
    }

    /// Forget one key so the next trigger refetches it (manual refresh).
    #[allow(dead_code)]
    pub fn invalidate(&mut self, key: &str) {
        self.map.remove(key);
    }

    /// Every entry, in no particular order — for consumers that aggregate
    /// across keys (the Route 53 Records tab flattens every loaded zone).
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Lazy<T>)> {
        self.map.iter()
    }

    /// How many keys are still in flight.
    pub fn loading_count(&self) -> usize {
        self.map.values().filter(|v| matches!(v, Lazy::Loading)).count()
    }
}

/// The single owner of every [`LazyMap`]. Any subscription
/// switch replaces the whole store with `LazyStore::new(epoch + 1)` — every
/// map clears and every in-flight fetch is invalidated in one move.
///
/// Adding a lazy section = add a field here + a `trigger_*` fn calling
/// `App::trigger_lazy`. No `Event` variant, no `*State` enum, no reset
/// wiring.
#[derive(Default)]
pub struct LazyStore {
    epoch: u64,

    // ── Scoping ──────────────────────────────────────────────────────────
    /// `GET /subscriptions/{id}/locations`, keyed by subscription id: what
    /// the `R` picker merges with the current list's own locations. One
    /// fetch per subscription; resets with the store on a switch.
    pub locations: LazyMap<Vec<crate::azure::location::LocationInfo>>,

    // ── Subscriptions ────────────────────────────────────────────────────
    /// `GET /subscriptions/{id}` — the ARM subscription object behind a
    /// subscription row's Details section, keyed by ARM id.
    pub subscription_details: LazyMap<serde_json::Value>,

    // ── Virtual Machines ─────────────────────────────────────────────────
    /// `GET {vm}/instanceView` — the Instance view section, keyed by VM id.
    pub vm_instance_views: LazyMap<serde_json::Value>,
    /// A scale set's Instances: `{vmss}/virtualMachines` (Uniform) or the
    /// VM list filtered to the set (Flexible), both with the instance
    /// view; keyed by scale-set id.
    pub vmss_instances: LazyMap<Vec<serde_json::Value>>,

    // ── Storage ──────────────────────────────────────────────────────────
    /// `GET {account}/blobServices/default/containers` — the Containers
    /// section, keyed by storage-account id. Counts against the Storage
    /// resource provider's 100 list calls per 5 minutes.
    pub containers: LazyMap<Vec<serde_json::Value>>,

    // ── Key Vault ────────────────────────────────────────────────────────
    /// `GET {vault}/secrets` — secret **names** and attributes, keyed by
    /// vault id. ARM never returns a value.
    pub vault_secrets: LazyMap<Vec<serde_json::Value>>,
    /// `GET {vault}/keys` — key names and attributes, keyed by vault id.
    pub vault_keys: LazyMap<Vec<serde_json::Value>>,

    // ── Network ──────────────────────────────────────────────────────────
    /// `GET {zone}/ALL` — a private DNS zone's record sets, keyed by zone id.
    pub dns_records: LazyMap<Vec<serde_json::Value>>,
    /// `GET {zone}/virtualNetworkLinks`, keyed by zone id.
    pub dns_vnet_links: LazyMap<Vec<serde_json::Value>>,
    /// `GET {zone}/all` — a public DNS zone's record sets, keyed by zone
    /// id; capped at `DNS_RECORDS_MAX`.
    pub public_dns_records: LazyMap<Vec<serde_json::Value>>,
    /// `GET {ruleset}/forwardingRules`, keyed by ruleset id.
    pub dns_forwarding_rules: LazyMap<Vec<serde_json::Value>>,
    /// `GET {policy}/dnsSecurityRules`, keyed by policy id.
    pub dns_security_rules: LazyMap<Vec<serde_json::Value>>,
    /// Every resolver endpoint and ruleset / policy / private zone VNet
    /// link in a subscription, keyed by `/subscriptions/{sub}`: what the
    /// resolver, ruleset and policy sections and the VNet and subnet
    /// Related sections read.
    pub dns_topology: LazyMap<crate::azure::services::network_dns::DnsTopology>,
    /// Every Network Watcher flow log in a subscription, keyed by
    /// `/subscriptions/{sub}`: what the VNet and NSG Flow logs sections and
    /// the `flow-logs-missing` audit check read (`flow_logs.rs`).
    pub flow_logs: LazyMap<crate::azure::services::flow_logs::FlowLogs>,

    // ── Governance ───────────────────────────────────────────────────────
    /// A built-in policy definition or initiative an assignment applies,
    /// keyed by its id (`/providers/Microsoft.Authorization/…`): the one
    /// definition a GET reads, since a custom one comes from the warm list
    /// (ADR 0009, decision 2).
    pub policy_definitions: LazyMap<serde_json::Value>,
    /// A governance list a section reads while its own sub-tab is cold
    /// (an assignment's Definition and Exemptions, a definition's
    /// Assignments), keyed `{subscription}|{sub-tab}`: loaded by the same
    /// provider stream the tab uses, never instead of the list cache.
    pub governance_lists: LazyMap<Vec<Box<dyn crate::azure::resource::Resource>>>,

    // ── Edge ─────────────────────────────────────────────────────────────
    /// A Front Door profile's endpoints with their routes, origin groups
    /// with their origins, custom domains and security policies, keyed by
    /// profile id: one read per profile (`fetch_afd_topology`). Never the
    /// profile's `secrets`.
    pub afd_topology: LazyMap<crate::azure::services::edge::AfdTopology>,

    // ── Firewall ─────────────────────────────────────────────────────────
    /// `GET {policy}/ruleCollectionGroups`, keyed by the lowercased policy
    /// id (`firewall::rules_key`): a policy's rules, and its base's.
    pub firewall_rule_collection_groups: LazyMap<Vec<serde_json::Value>>,
    /// `GET {rulestack}/localRules`, keyed by the lowercased rulestack id:
    /// read for the rulestack and for each Cloud NGFW that uses it.
    pub ngfw_local_rules: LazyMap<Vec<serde_json::Value>>,
    /// `GET {rulestack}/prefixlists`, keyed like the rules.
    pub ngfw_prefix_lists: LazyMap<Vec<serde_json::Value>>,
    /// `GET {rulestack}/fqdnlists`, keyed like the rules.
    pub ngfw_fqdn_lists: LazyMap<Vec<serde_json::Value>>,
    /// `GET {firewall}/statuses/default`, keyed by Cloud NGFW id: health
    /// and the Panorama connection.
    pub ngfw_status: LazyMap<serde_json::Value>,

    // ── Backup ───────────────────────────────────────────────────────────
    /// `GET {vault}/backupProtectedItems`, keyed by Recovery Services vault
    /// id: the Protected items section, the VM-side reverse look-up
    /// (`backup::protection_of`) and `@audit`.
    pub backup_protected_items: LazyMap<Vec<serde_json::Value>>,
    /// `GET {vault}/backupInstances`, keyed by Backup vault id, with the
    /// data source credentials stripped (`backup::without_secrets`).
    pub backup_instances: LazyMap<Vec<serde_json::Value>>,
    /// `GET {vault}/backupPolicies`, keyed by vault id (either kind).
    pub backup_policies: LazyMap<Vec<serde_json::Value>>,
    /// `GET {vault}/backupJobs`, keyed by vault id: a Recovery Services
    /// vault's failed jobs of the last week, a Backup vault's recent jobs.
    pub backup_jobs: LazyMap<Vec<serde_json::Value>>,

    // ── App Service ──────────────────────────────────────────────────────
    /// `GET {site}/config/web` — the Configuration section, keyed by site
    /// id. Never app settings or connection strings.
    pub site_configs: LazyMap<serde_json::Value>,

    // ── SQL ──────────────────────────────────────────────────────────────
    /// `GET {server}/databases`, keyed by server id.
    pub sql_databases: LazyMap<Vec<serde_json::Value>>,
    /// `GET {server}/firewallRules`, keyed by server id.
    pub sql_firewall_rules: LazyMap<Vec<serde_json::Value>>,

    // ── PostgreSQL & MySQL ───────────────────────────────────────────────
    /// `GET {server}/databases`, keyed by flexible server id (either engine).
    pub flex_databases: LazyMap<Vec<serde_json::Value>>,
    /// `GET {server}/firewallRules`, keyed by flexible server id.
    pub flex_firewall_rules: LazyMap<Vec<serde_json::Value>>,
    /// `GET {server}/administrators` — the Entra admins, keyed by server id.
    pub flex_admins: LazyMap<Vec<serde_json::Value>>,
    /// `GET {server}/configurations` — every server parameter, keyed by
    /// server id; only the TLS and auth ones are rendered.
    pub flex_parameters: LazyMap<Vec<serde_json::Value>>,

    // ── Access (every type) ──────────────────────────────────────────────
    /// `GET {id}/…/roleAssignments?$filter=atScope()`, keyed by ARM id.
    pub role_assignments: LazyMap<Vec<serde_json::Value>>,
    /// `GET /subscriptions/{sub}/…/roleDefinitions`, keyed by
    /// `/subscriptions/{sub}`: role GUID → name for every Access section.
    pub role_definitions: LazyMap<Vec<serde_json::Value>>,
    /// An identity's own assignments (`principalId eq`), keyed by identity id.
    pub identity_role_assignments: LazyMap<Vec<serde_json::Value>>,
    /// Microsoft Graph `GET directoryObjects/{id}` (ADR 0004): a role
    /// assignment's principal, keyed by lowercase object id. Resets with
    /// the store, so a tenant switch never shows another directory's names.
    pub principals: LazyMap<serde_json::Value>,

    // ── Directory (Graph: service principals, app registrations) ─────────
    /// A directory row's child lists (`owners`, `federatedIdentityCredentials`,
    /// `appRoleAssignments`, `oauth2PermissionGrants`), keyed by
    /// `{row id}/{child}` (`directory::child_key`).
    pub directory_children: LazyMap<Vec<serde_json::Value>>,
    /// `GET servicePrincipals(appId='…')`: an API an app registration asks
    /// permissions of, keyed by lowercase app id.
    pub sp_by_app_id: LazyMap<serde_json::Value>,

    // ── Activity (every type) ────────────────────────────────────────────
    /// The last week of the activity log filtered to the row, keyed by ARM
    /// id; capped at `ACTIVITY_MAX_EVENTS`.
    pub activity: LazyMap<Vec<serde_json::Value>>,

    // ── Cosmos DB ────────────────────────────────────────────────────────
    /// `GET {account}/{sqlDatabases|mongodbDatabases|…}` — the path the
    /// account's API picks, keyed by account id.
    pub cosmos_databases: LazyMap<Vec<serde_json::Value>>,

    // ── Container Registry ───────────────────────────────────────────────
    /// `GET {registry}/replications`, keyed by registry id; Premium only.
    pub acr_replications: LazyMap<Vec<serde_json::Value>>,
    /// `GET {registry}/webhooks`, keyed by registry id. Never the URI.
    pub acr_webhooks: LazyMap<Vec<serde_json::Value>>,

    // ── Identity ─────────────────────────────────────────────────────────
    /// `GET {identity}/federatedIdentityCredentials`, keyed by identity id.
    pub federated_credentials: LazyMap<Vec<serde_json::Value>>,

    // ── Foundry ──────────────────────────────────────────────────────────
    /// `GET {account}/deployments` — model deployments, keyed by account id.
    pub foundry_deployments: LazyMap<Vec<serde_json::Value>>,
    /// `GET {account}/projects` — Foundry projects, keyed by account id;
    /// only ever fetched for accounts with project management on.
    pub foundry_projects: LazyMap<Vec<serde_json::Value>>,

    // ── Container Apps ───────────────────────────────────────────────────
    /// `GET {app}/revisions`, keyed by app id. The template (env) is
    /// never rendered.
    pub aca_revisions: LazyMap<Vec<serde_json::Value>>,
    /// `GET {app}/authConfigs`, keyed by app id. Secret setting names only.
    pub aca_auth_configs: LazyMap<Vec<serde_json::Value>>,
    /// `GET {job}/executions`, keyed by job id. The template (env) is
    /// never rendered.
    pub aca_job_executions: LazyMap<Vec<serde_json::Value>>,

    // ── Redis ────────────────────────────────────────────────────────────
    /// `GET {cache}/firewallRules`, keyed by cache id.
    pub redis_firewall_rules: LazyMap<Vec<serde_json::Value>>,
    /// `GET {cache}/linkedServers` (geo-replication), keyed by cache id;
    /// only fetched when the cache names a linked server.
    pub redis_linked_servers: LazyMap<Vec<serde_json::Value>>,
    /// `GET {cluster}/databases` (Managed Redis), keyed by cluster id.
    pub redis_databases: LazyMap<Vec<serde_json::Value>>,

    // ── Messaging (Service Bus, Event Hubs) ──────────────────────────────
    /// `GET {ns}/networkRuleSets/default`, keyed by namespace id: default
    /// action, trusted services, IP and VNet rules.
    pub messaging_network_rules: LazyMap<serde_json::Value>,
    /// `GET {ns}/authorizationRules`, keyed by namespace id. Names and
    /// rights; keys come only from `listKeys` (a POST, never sent).
    pub messaging_auth_rules: LazyMap<Vec<serde_json::Value>>,
    /// `GET {ns}/queues`, keyed by Service Bus namespace id.
    pub sb_queues: LazyMap<Vec<serde_json::Value>>,
    /// `GET {ns}/topics`, keyed by Service Bus namespace id.
    pub sb_topics: LazyMap<Vec<serde_json::Value>>,
    /// `GET {ns}/eventhubs`, keyed by Event Hubs namespace id.
    pub eh_hubs: LazyMap<Vec<serde_json::Value>>,

    // ── Ownership ribbon (every type) ────────────────────────────────────
    /// `GET {group}/providers/Microsoft.Resources/deployments` (and the
    /// operations of its newest unfinished ones), keyed by the lowercased
    /// group id: the deployment that last touched a row.
    pub rg_deployments: LazyMap<crate::azure::ownership::RgDeployments>,
}

impl LazyStore {
    /// A fresh store at the given epoch (see the type docs for when).
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            ..Default::default()
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// The payload of the one `Event::Lazy` variant: an epoch-stamped closure
/// that writes a fetch result into its [`LazyMap`]. The single handler arm in
/// `App::handle_event` runs it — or drops it when the epoch is stale.
pub struct LazyApply {
    pub epoch: u64,
    pub apply: Box<dyn FnOnce(&mut crate::app::App) + Send>,
}

impl std::fmt::Debug for LazyApply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyApply")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_maps_ok_to_loaded_and_err_to_error() {
        let mut m: LazyMap<u32> = LazyMap::default();
        m.insert_loading("a".into());
        assert!(matches!(m.get("a"), Some(Lazy::Loading)));
        m.apply("a".into(), Ok(7));
        assert!(matches!(m.get("a"), Some(Lazy::Loaded(7))));
        m.apply("b".into(), Err("denied".into()));
        assert!(matches!(m.get("b"), Some(Lazy::Error(e)) if e == "denied"));
    }

    #[test]
    fn contains_blocks_retrigger_until_invalidated() {
        let mut m: LazyMap<u32> = LazyMap::default();
        m.apply("a".into(), Err("boom".into()));
        assert!(m.contains("a"), "an Error entry must block re-trigger");
        m.invalidate("a");
        assert!(!m.contains("a"), "invalidate must allow a refetch");
    }

    #[test]
    fn new_store_is_empty_at_the_given_epoch() {
        let mut store = LazyStore::new(3);
        store.containers.insert_loading("/subscriptions/x".into());
        store = LazyStore::new(store.epoch() + 1);
        assert_eq!(store.epoch(), 4);
        assert!(store.containers.get("/subscriptions/x").is_none());
    }
}
