// ported from neboto-tui src/app.rs @ 693449a (run_audit, rerun_audit,
// load_audit_sources, handle_audit_source_loaded; the generation counter
// becomes the lazy epoch and the event the apply closure)
//! `@audit` on `App` (#60, ADR 0007): the rows computed from the warm
//! caches, `r` loading what the checks miss in the background, Enter
//! opening the resource a finding is about. The checks are `crate::audit`.

use super::App;
use crate::audit::{self, AuditFinding, AuditInput, AUDIT_LAZY_MAX};
use crate::azure::auth::AuthError;
use crate::azure::resource::Resource;
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::access::{at_scope_filter, role_assignments_path, ACCESS_API_VERSION};
use crate::azure::services::app_service::{site_config_path, WEB_API_VERSION};
use crate::azure::services::directory::now_unix;
use crate::azure::services::messaging::{api_version_for as messaging_api_version, messaging_child_path};
use crate::azure::services::postgres_mysql::{api_version_for as flex_api_version, flexible_server_child_path};
use crate::azure::services::redis::{redis_child_path, REDIS_API_VERSION};
use crate::azure::services::compute::VMSS_API_VERSION;
use crate::azure::services::scale_sets::{InstancesRequest, ScaleSetRow};
use crate::azure::services::sql::{server_child_path, SQL_API_VERSION};
use crate::event::Event;
use crate::lazy::{Lazy, LazyApply};
use tokio::sync::mpsc;

/// What `r` in `@audit` has in flight. Reset with the lazy store on a
/// subscription switch; a load from before the switch carries the old
/// epoch and is dropped on arrival.
#[derive(Default)]
pub struct AuditState {
    /// Source lists loading right now: their checks read "loading…".
    pub loading: Vec<JumpView>,
    /// Sources that failed (or loaded partially) during the current `r`,
    /// reported once all have landed.
    failures: Vec<String>,
    /// `r` was pressed in this subscription: as lazy data lands, fetch
    /// what it unlocks (an SQL server's firewall once the server list is
    /// in, a privileged user's directory object once the Access list is).
    armed: bool,
}

impl App {
    /// The `@audit` rows: every check over the current subscription's
    /// warm lists (every sub-tab) and the lazy store.
    pub(crate) fn run_audit(&self) -> Vec<Box<dyn Resource>> {
        let sub = self.subscription_key();
        let mut input = AuditInput::new(&sub, now_unix());
        input.set_loading(&self.audit.loading);
        input.set_lazy(&self.lazy);
        for service in ServiceType::all().into_iter().filter(|s| !s.is_virtual()) {
            for view in service.views() {
                if let Some(list) = self.cache.get_ref(&service, &sub, Some(view.as_str())) {
                    input.add(*view, list);
                }
            }
        }
        audit::run(&input)
            .into_iter()
            .map(|f| Box::new(f) as Box<dyn Resource>)
            .collect()
    }

    /// Recompute the `@audit` rows in place (the selection follows its id),
    /// when `@audit` is what the list shows.
    pub(super) fn rerun_audit(&mut self) {
        // `@*` owns `resources` while it is open, whatever tab is under it.
        if self.current_service != Some(ServiceType::Audit) || self.all_search_mode {
            return;
        }
        self.resources = self.run_audit();
        self.update_search();
    }

    /// The resource the selected finding is about, when it has one (a
    /// coverage note has none).
    pub(super) fn selected_audit_target(&self) -> Option<String> {
        self.get_selected_resource()
            .and_then(|r| r.as_any().downcast_ref::<AuditFinding>())
            .map(|f| f.resource_id.clone())
            .filter(|id| !id.is_empty())
    }

    /// `r` in `@audit`: load every source list that isn't cached — in the
    /// background, straight into its cache slot — re-auditing as each
    /// lands, and fetch the per-resource lazy data the checks read (capped
    /// at `AUDIT_LAZY_MAX` each). A cached source is left alone (`r` in its
    /// tab reloads it), so a second `r` costs nothing once all is warm.
    pub(super) fn load_audit_sources(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if !self.audit.loading.is_empty() {
            self.audit_progress_message();
            return;
        }
        let sub = self.subscription_key();
        if sub.is_empty() {
            self.error_message = Some("No subscription selected (P picks one)".into());
            return;
        }
        let missing: Vec<JumpView> = audit::sources()
            .into_iter()
            .filter(|v| self.cache.get_ref(&v.service(), &sub, Some(v.as_str())).is_none())
            .collect();
        self.audit.armed = true;
        self.audit.failures.clear();
        self.error_message = None;
        self.trigger_audit_lazies(event_tx);
        if missing.is_empty() {
            self.rerun_audit();
            self.toast("Re-audited: every source is cached (r in a tab reloads it)");
            return;
        }
        self.audit.loading = missing.clone();
        let epoch = self.lazy.epoch();
        for view in missing {
            let provider = self.azure_clients.service(view.service());
            let tx = event_tx.clone();
            let sub = sub.clone();
            tokio::spawn(async move {
                let result = audit::load_source(provider, view).await;
                let apply: Box<dyn FnOnce(&mut App) + Send> =
                    Box::new(move |app: &mut App| app.audit_source_landed(view, &sub, result));
                let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
            });
        }
        self.rerun_audit(); // the pending checks now read "loading…"
        self.audit_progress_message();
    }

    fn audit_progress_message(&mut self) {
        let names: Vec<String> = self.audit.loading.iter().map(|v| audit::source_name(*v)).collect();
        self.toast(format!("Audit: loading {}…", names.join(", ")));
    }

    /// One source list from `r` landed (through `Event::Lazy`, so a stale
    /// epoch never gets here): cache it under its own sub-tab's key, as
    /// visiting the tab would have.
    pub(super) fn audit_source_landed(
        &mut self,
        view: JumpView,
        sub: &str,
        result: audit::SourceLoad,
    ) {
        if !self.audit.loading.contains(&view) {
            return;
        }
        self.audit.loading.retain(|v| *v != view);
        match result {
            Ok((rows, warnings)) => {
                self.cache.insert(view.service(), sub, Some(view.as_str().to_string()), rows);
                for w in warnings {
                    self.audit.failures.push(format!("{} partial: {}", audit::source_name(view), w));
                }
            }
            Err(e) => {
                if let Some(a) = AuthError::classify(&e) {
                    self.auth_error = Some(a);
                }
                self.audit.failures.push(format!("{}: {}", audit::source_name(view), e));
            }
        }
        if !self.audit.loading.is_empty() {
            self.audit_progress_message();
        } else if self.audit.failures.is_empty() {
            let n = self
                .run_audit()
                .iter()
                .filter_map(|r| r.as_any().downcast_ref::<AuditFinding>())
                .filter(|f| f.is_finding())
                .count();
            self.toast(format!("Audit: sources loaded, {} finding{}", n, if n == 1 { "" } else { "s" }));
        } else {
            self.success_message = None;
            self.error_message = Some(format!("Audit: some checks couldn't run: {}", self.audit.failures.join("; ")));
        }
    }

    /// After any lazy result: re-audit when `@audit` is on screen, and once
    /// `r` has armed it, fetch what the new data unlocks.
    pub(super) fn audit_after_lazy(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.audit.armed {
            self.trigger_audit_lazies(event_tx);
        }
        self.rerun_audit();
    }

    /// The per-resource reads behind the lazy-fed checks, each through the
    /// same `LazyMap` its detail section uses (present keys never
    /// refetch): the subscription's role assignments and its privileged
    /// users' directory objects, each cached SQL server's and Redis cache's firewall rules, each
    /// PostgreSQL and MySQL server's firewall rules, parameters and Entra admins, each
    /// messaging namespace's network rule set,
    /// each cached site's config, the subscription's flow logs, each backup vault's protected items. Capped at `AUDIT_LAZY_MAX` per kind.
    fn trigger_audit_lazies(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let sub = self.subscription_key();
        if sub.is_empty() {
            return;
        }
        let scope = format!("/subscriptions/{}", sub);
        if !self.lazy.role_assignments.contains(&scope) {
            let fut = self
                .azure_clients
                .list_fetch_query(&role_assignments_path(&scope), ACCESS_API_VERSION, at_scope_filter());
            self.trigger_lazy(|s| &mut s.role_assignments, scope.clone(), event_tx, move || fut);
        }
        if let Some(Lazy::Loaded(items)) = self.lazy.role_assignments.get(&scope) {
            let users = audit::privileged_user_ids(items);
            for oid in users.into_iter().take(AUDIT_LAZY_MAX) {
                if self.lazy.principals.contains(&oid) {
                    continue;
                }
                let fut = self.azure_clients.directory_object_fetch(&scope, &oid);
                // A Graph read: never the app-wide auth line (ADR 0004).
                self.trigger_lazy_with(|s| &mut s.principals, oid, event_tx, move || fut, false);
            }
        }
        for id in self.cached_ids(JumpView::SqlServers, &sub) {
            let fut = self.azure_clients.list_fetch(&server_child_path(&id, "firewallRules"), SQL_API_VERSION);
            self.trigger_lazy(|s| &mut s.sql_firewall_rules, id, event_tx, move || fut);
        }
        for id in self.cached_ids(JumpView::RedisCaches, &sub) {
            let fut = self.azure_clients.list_fetch(&redis_child_path(&id, "firewallRules"), REDIS_API_VERSION);
            self.trigger_lazy(|s| &mut s.redis_firewall_rules, id, event_tx, move || fut);
        }
        // A flexible server's firewall rules, parameters (one list each, the
        // TLS checks read two of them) and Entra admins.
        for view in [JumpView::PostgresServers, JumpView::MysqlServers] {
            for id in self.cached_ids(view, &sub) {
                let fut = self.azure_clients.list_fetch(&flexible_server_child_path(&id, "firewallRules"), flex_api_version(&id));
                self.trigger_lazy(|s| &mut s.flex_firewall_rules, id.clone(), event_tx, move || fut);
                let fut = self.azure_clients.list_fetch(&flexible_server_child_path(&id, "configurations"), flex_api_version(&id));
                self.trigger_lazy(|s| &mut s.flex_parameters, id.clone(), event_tx, move || fut);
                let fut = self.azure_clients.list_fetch(&flexible_server_child_path(&id, "administrators"), flex_api_version(&id));
                self.trigger_lazy(|s| &mut s.flex_admins, id, event_tx, move || fut);
            }
        }
        for view in [JumpView::ServiceBusNamespaces, JumpView::EventHubNamespaces] {
            for id in self.cached_ids(view, &sub) {
                let fut = self
                    .azure_clients
                    .get_fetch(&messaging_child_path(&id, "networkRuleSets/default"), messaging_api_version(&id));
                self.trigger_lazy(|s| &mut s.messaging_network_rules, id, event_tx, move || fut);
            }
        }
        // The subscription's flow logs (one read: the watchers, then each
        // one's flowLogs), for flow-logs-missing.
        self.trigger_flow_logs_for(scope.clone(), event_tx);
        // A vault's protected items (and the policies that set how old a
        // last backup may be) or its backup instances and jobs.
        for view in [JumpView::RecoveryVaults, JumpView::BackupVaults] {
            for id in self.cached_ids(view, &sub) {
                self.trigger_backup_audit_reads(&id, event_tx);
            }
        }
        for id in self.cached_ids(JumpView::WebApps, &sub) {
            let fut = self.azure_clients.get_fetch(&site_config_path(&id), WEB_API_VERSION);
            self.trigger_lazy(|s| &mut s.site_configs, id, event_tx, move || fut);
        }
        // A Uniform scale set's instances (a Flexible set's VMs carry no
        // model flag, so no call for them).
        let requests: Vec<(String, InstancesRequest)> = self
            .cache
            .get_ref(&ServiceType::VirtualMachines, &sub, Some(JumpView::ScaleSets.as_str()))
            .map(|l| {
                l.iter()
                    .filter_map(|r| r.as_any().downcast_ref::<ScaleSetRow>())
                    .filter(|s| !s.is_flexible())
                    .take(AUDIT_LAZY_MAX)
                    .filter_map(|s| Some((s.base.id.clone(), s.instances_request()?)))
                    .collect()
            })
            .unwrap_or_default();
        for (id, (path, query)) in requests {
            let fut = self.azure_clients.list_fetch_query(&path, VMSS_API_VERSION, query);
            self.trigger_lazy(|s| &mut s.vmss_instances, id, event_tx, move || fut);
        }
    }

    /// Whether anything `r` started is still in flight: a source list, or
    /// one of the lazy reads the checks use (the headless audit waits on
    /// this before it prints).
    pub(crate) fn audit_in_flight(&self) -> bool {
        let l = &self.lazy;
        !self.audit.loading.is_empty()
            || l.role_assignments.loading_count()
                + l.principals.loading_count()
                + l.sql_firewall_rules.loading_count()
                + l.redis_firewall_rules.loading_count()
                + l.flex_firewall_rules.loading_count()
                + l.flex_parameters.loading_count()
                + l.flex_admins.loading_count()
                + l.messaging_network_rules.loading_count()
                + l.site_configs.loading_count()
                + l.flow_logs.loading_count()
                + l.vmss_instances.loading_count()
                + l.backup_protected_items.loading_count()
                + l.backup_policies.loading_count()
                + l.backup_instances.loading_count()
                + l.backup_jobs.loading_count()
                > 0
    }

    /// The first `AUDIT_LAZY_MAX` ids of a cached list.
    fn cached_ids(&self, view: JumpView, sub: &str) -> Vec<String> {
        self.cache
            .get_ref(&view.service(), sub, Some(view.as_str()))
            .map(|l| l.iter().take(AUDIT_LAZY_MAX).map(|r| r.id().to_string()).collect())
            .unwrap_or_default()
    }
}
