// ported from neboto-tui src/aws/cli_actions.rs @ 343ef65 (adapted: Azure catalogue, one file, no batching or role gate)
//! The `C` command catalogue (#47): ready-to-paste `az` commands for the
//! selected row, grouped Inspect / Connect / Change.
//!
//! nebaz is read-only and stays that way: **nothing here is ever run**.
//! `C` copies one command to the clipboard and the user runs it in their
//! own terminal, under their own `az login` (ADR 0005). The row's read
//! command (`Resource::cli_command`) is always the first entry, so a
//! straight `C` `⏎` copies what `C` always copied.
//!
//! This is the **one file** allowed to hold an `az` literal whose verb is
//! not a read: `tests/readonly_guard.rs` admits the Connect and Change
//! verbs listed there in this file only, and still refuses here what it
//! refuses everywhere (a destructive verb, a secret-revealing command or
//! flag). This file never spawns a process (the guard checks that too).
//!
//! Rules for what goes in (from neboto, issue #47):
//! - **Nothing destructive.** No delete / purge / remove / reset /
//!   regenerate: reversible operational commands only.
//! - **Never a command that reveals a secret**: no `keyvault secret show`,
//!   no key listings, no connection strings, no `aks get-credentials` with
//!   the admin switch, no `acr login` that prints its token.
//! - A command that takes a value (a node count) is **prefilled with the
//!   current value**, so a blind paste is a no-op.
//! - `--ids` or the name form exactly as `cli_command()` does
//!   (`SERVICES.md` rule 9): `--ids` carries the subscription; the name
//!   form carries `--subscription`. A data-plane command addressed by a
//!   vault or registry name needs neither.

use crate::azure::resource::{name_of_id, resource_group_of, shell_quote, subscription_of, Resource};
use crate::azure::services::aks::{ClusterRow, NodePoolRow};
use crate::azure::services::app_service::SiteRow;
use crate::azure::services::compute::{NicRow, VmRow};
use crate::azure::services::container_apps::{ContainerAppRow, EnvironmentRow, JobRow};
use crate::azure::services::container_registry::RegistryRow;
use crate::azure::services::directory::{AppRegistrationRow, ServicePrincipalRow};
use crate::azure::services::edge::{AppGatewayRow, FrontDoorProfileRow, WafKind, WafPolicyRow};
use crate::azure::services::keyvault::VaultRow;
use crate::azure::services::messaging::{EventHubsRow, ServiceBusRow};
use crate::azure::services::network::{NsgRow, SubnetRow};
use crate::azure::services::postgres_mysql::{Engine, FlexibleServerRow};
use crate::azure::services::power_platform::EnterprisePolicyRow;
use crate::azure::services::redis::{ManagedRedisRow, RedisCacheRow};
use crate::azure::services::sql::SqlServerRow;
use crate::azure::services::storage::StorageAccountRow;

/// How much a command can do: drives grouping, colour and the toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CliTier {
    /// Reads state (`show`, `list`, `get-instance-view`, a log tail).
    Inspect,
    /// Opens a session or configures a local tool (`ssh vm`,
    /// `aks get-credentials`, `containerapp exec`, `acr login`). Changes
    /// nothing in Azure.
    Connect,
    /// Changes Azure (start / stop / restart / scale). Flagged ⚠ in the
    /// picker and in the toast.
    Change,
}

impl CliTier {
    pub fn heading(self) -> &'static str {
        match self {
            CliTier::Inspect => "Inspect",
            CliTier::Connect => "Connect",
            CliTier::Change => "Change",
        }
    }
}

/// One copyable command for one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliAction {
    pub tier: CliTier,
    /// Short row label: the command chain (`vm get-instance-view`).
    pub label: String,
    /// The exact text `⏎` copies.
    pub command: String,
    /// Caveat shown under the preview.
    pub note: Option<String>,
}

impl CliAction {
    fn new(tier: CliTier, command: String) -> Self {
        CliAction {
            tier,
            label: chain_label(&command),
            command,
            note: None,
        }
    }

    fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }
}

fn inspect(command: String) -> CliAction {
    CliAction::new(CliTier::Inspect, command)
}

fn connect(command: String) -> CliAction {
    CliAction::new(CliTier::Connect, command)
}

fn change(command: String) -> CliAction {
    CliAction::new(CliTier::Change, command)
}

/// The words between `az` and the first flag: `az vm show --ids …` →
/// `vm show`.
pub fn chain_label(command: &str) -> String {
    command
        .split_whitespace()
        .skip_while(|w| *w == "az")
        .take_while(|w| !w.starts_with('-'))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `--ids {id}`.
fn ids(id: &str) -> String {
    format!("--ids {}", shell_quote(id))
}

/// `-g {rg} --subscription {sub}` from an ARM id.
fn rg_sub(id: &str) -> Option<String> {
    Some(format!(
        "-g {} --subscription {}",
        shell_quote(resource_group_of(id)?),
        shell_quote(subscription_of(id)?)
    ))
}

/// `-n {name} -g {rg} --subscription {sub}`: the name form.
fn name_args(name: &str, id: &str) -> Option<String> {
    Some(format!("-n {} {}", shell_quote(name), rg_sub(id)?))
}

/// Every command for one row: the read command first, then the type's
/// catalogue in tier order (stable within a tier), then the reads every
/// ARM row shares. An entry identical to the read command is dropped.
pub fn actions_for(r: &dyn Resource) -> Vec<CliAction> {
    let read = r.cli_command();
    let mut extra = type_actions(r);
    extra.extend(generic_actions(r));
    extra.retain(|a| Some(&a.command) != read.as_ref());
    extra.sort_by_key(|a| a.tier);
    let mut out: Vec<CliAction> = read.map(inspect).into_iter().collect();
    out.extend(extra);
    out
}

/// The reads every ARM row offers: who has access (the Access section's
/// question) and, for a resource, its recent activity log.
fn generic_actions(r: &dyn Resource) -> Vec<CliAction> {
    let id = r.id();
    if !id.starts_with("/subscriptions/") {
        return Vec::new();
    }
    let q = shell_quote(id);
    let mut out = vec![inspect(format!("az role assignment list --scope {} --include-inherited", q))
        .note("role assignments at this scope and inherited from above (the Access section)")];
    if id.contains("/providers/") {
        out.push(
            inspect(format!("az monitor activity-log list --resource-id {} --offset 7d", q))
                .note("the last 7 days of control-plane operations (the Activity section)"),
        );
    }
    out
}

/// The type's own commands, by downcast (like `App::section_lines_for`).
fn type_actions(r: &dyn Resource) -> Vec<CliAction> {
    let any = r.as_any();
    let id = r.id();
    let built = if let Some(vm) = any.downcast_ref::<VmRow>() {
        vm_actions(vm)
    } else if any.downcast_ref::<NicRow>().is_some() {
        nic_actions(id)
    } else if let Some(c) = any.downcast_ref::<ClusterRow>() {
        cluster_actions(c)
    } else if let Some(p) = any.downcast_ref::<NodePoolRow>() {
        node_pool_actions(p)
    } else if let Some(a) = any.downcast_ref::<ContainerAppRow>() {
        container_app_actions(a)
    } else if let Some(e) = any.downcast_ref::<EnvironmentRow>() {
        environment_actions(e)
    } else if let Some(j) = any.downcast_ref::<JobRow>() {
        job_actions(j)
    } else if let Some(s) = any.downcast_ref::<SiteRow>() {
        site_actions(s)
    } else if let Some(v) = any.downcast_ref::<VaultRow>() {
        vault_actions(v)
    } else if let Some(reg) = any.downcast_ref::<RegistryRow>() {
        registry_actions(reg)
    } else if let Some(sa) = any.downcast_ref::<StorageAccountRow>() {
        storage_actions(sa)
    } else if let Some(s) = any.downcast_ref::<SqlServerRow>() {
        sql_actions(s)
    } else if let Some(c) = any.downcast_ref::<RedisCacheRow>() {
        redis_cache_actions(c)
    } else if let Some(c) = any.downcast_ref::<ManagedRedisRow>() {
        Some(managed_redis_actions(c))
    } else if let Some(f) = any.downcast_ref::<FlexibleServerRow>() {
        flexible_server_actions(f)
    } else if let Some(n) = any.downcast_ref::<NsgRow>() {
        nsg_actions(n)
    } else if let Some(s) = any.downcast_ref::<SubnetRow>() {
        subnet_actions(s)
    } else if let Some(sp) = any.downcast_ref::<ServicePrincipalRow>() {
        service_principal_actions(&sp.base.app_id)
    } else if let Some(app) = any.downcast_ref::<AppRegistrationRow>() {
        app_registration_actions(&app.base.app_id)
    } else if let Some(p) = any.downcast_ref::<EnterprisePolicyRow>() {
        power_platform_actions(p)
    } else if let Some(sb) = any.downcast_ref::<ServiceBusRow>() {
        servicebus_actions(sb)
    } else if let Some(eh) = any.downcast_ref::<EventHubsRow>() {
        eventhubs_actions(eh)
    } else if let Some(g) = any.downcast_ref::<AppGatewayRow>() {
        app_gateway_actions(g)
    } else if let Some(w) = any.downcast_ref::<WafPolicyRow>() {
        waf_policy_actions(w)
    } else if let Some(p) = any.downcast_ref::<FrontDoorProfileRow>() {
        front_door_actions(p)
    } else {
        None
    };
    built.unwrap_or_default()
}

// ── Compute ──────────────────────────────────────────────────────────

/// `az vm` takes `--ids` (`vm_name` has `id_part='name'`); the `ssh` and
/// `serial-console` extensions declare no `id_part`, so they use the
/// name form.
fn vm_actions(vm: &VmRow) -> Option<Vec<CliAction>> {
    let id = &vm.base.id;
    let i = ids(id);
    let named = name_args(&vm.base.name, id)?;
    let sub = shell_quote(subscription_of(id)?);
    let windows = vm.os_type.as_deref().is_some_and(|o| o.eq_ignore_ascii_case("windows"));
    let mut out = vec![
        inspect(format!("az vm get-instance-view {}", i)).note("power state, agent status and extension health"),
        inspect(format!("az vm boot-diagnostics get-boot-log {}", i)).note("the serial log; needs boot diagnostics on"),
        connect(format!("az ssh vm {}", named))
            .note("needs the ssh CLI extension; Entra sign-in needs the AADSSHLoginForLinux extension and a VM login role"),
        connect(format!(
            "az network bastion ssh --name <bastion> --resource-group <bastion-rg> --target-resource-id {} --auth-type AAD --subscription {}",
            shell_quote(id),
            sub
        ))
        .note("fill in your Bastion host (Standard SKU or above, native client support on) and its subscription"),
    ];
    if windows {
        out.push(
            connect(format!(
                "az network bastion rdp --name <bastion> --resource-group <bastion-rg> --target-resource-id {} --subscription {}",
                shell_quote(id),
                sub
            ))
            .note("Windows client only; fill in your Bastion host"),
        );
    }
    out.extend([
        connect(format!("az serial-console connect {}", named))
            .note("needs the serial-console CLI extension and boot diagnostics"),
        change(format!("az vm start {}", i)),
        change(format!("az vm restart {}", i)),
        change(format!("az vm stop {}", i)).note("powers off but keeps the compute allocated, and billed; deallocate releases it"),
        change(format!("az vm deallocate {}", i))
            .note("releases the compute; a dynamic public IP is released with it"),
    ]);
    Some(out)
}

/// Both are Azure-computed views that ARM serves only as a POST action
/// Reader does not grant: nebaz never calls them, but you may.
fn nic_actions(id: &str) -> Option<Vec<CliAction>> {
    let note = "computed by Azure through a POST action Reader does not grant; the VM must be running";
    Some(vec![
        inspect(format!("az network nic list-effective-nsg {}", ids(id))).note(note),
        inspect(format!("az network nic show-effective-route-table {}", ids(id))).note(note),
    ])
}

// ── AKS ──────────────────────────────────────────────────────────────

/// No `id_part` anywhere in `az aks`: the name form throughout.
fn cluster_actions(c: &ClusterRow) -> Option<Vec<CliAction>> {
    let id = &c.base.id;
    let named = name_args(&c.base.name, id)?;
    Some(vec![
        inspect(format!("az aks get-upgrades {}", named)),
        inspect(format!("az aks nodepool list --cluster-name {} {}", shell_quote(&c.base.name), rg_sub(id)?)),
        connect(format!("az aks get-credentials {}", named)).note(
            "merges the cluster into your kubeconfig with your own user credentials; never the admin switch (the cluster-admin certificate)",
        ),
        change(format!("az aks start {}", named)),
        change(format!("az aks stop {}", named)).note("stops the control plane and every node pool"),
    ])
}

fn node_pool_actions(p: &NodePoolRow) -> Option<Vec<CliAction>> {
    let args = format!(
        "--cluster-name {} -n {} {}",
        shell_quote(&p.cluster_name),
        shell_quote(&p.name),
        rg_sub(&p.id)?
    );
    let mut out = vec![inspect(format!("az aks nodepool get-upgrades {}", args))];
    if let Some(count) = p.count {
        let note = if p.autoscale == Some(true) {
            format!(
                "the autoscaler owns this pool ({}–{} nodes): scale is refused while it is on",
                p.min_count.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                p.max_count.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
            )
        } else {
            format!("prefilled with the current count ({}): pasted as is, nothing changes", count)
        };
        out.push(change(format!("az aks nodepool scale {} --node-count {}", args, count)).note(note));
    }
    out.push(change(format!("az aks nodepool start {}", args)));
    out.push(change(format!("az aks nodepool stop {}", args)).note("a cluster needs one running system pool"));
    Some(out)
}

// ── Container Apps ───────────────────────────────────────────────────

/// `containerapp` and `containerapp job` take `--ids`; `exec`, `logs
/// show`, `replica`, `revision list` and `job execution` reset `id_part`,
/// so they use the name form.
fn container_app_actions(a: &ContainerAppRow) -> Option<Vec<CliAction>> {
    let id = &a.base.id;
    let named = name_args(&a.base.name, id)?;
    let mut out = vec![
        inspect(format!("az containerapp revision list {}", named)),
        inspect(format!("az containerapp replica list {}", named)),
        inspect(format!("az containerapp logs show {} --tail 50", named)).note("the last 50 console log lines"),
        connect(format!("az containerapp exec {}", named)).note("a shell (sh) in a running replica"),
        connect(format!("az containerapp logs show {} --follow", named))
            .label("containerapp logs show --follow")
            .note("streams the console log until Ctrl-C"),
    ];
    if let Some(rev) = &a.latest_revision {
        out.push(
            change(format!("az containerapp revision restart {} --revision {}", named, shell_quote(rev)))
                .note("restarts the latest revision's replicas"),
        );
    }
    Some(out)
}

fn environment_actions(e: &EnvironmentRow) -> Option<Vec<CliAction>> {
    let id = &e.base.id;
    let named = name_args(&e.base.name, id)?;
    Some(vec![
        inspect(format!("az containerapp list --environment {} {}", shell_quote(id), rg_sub(id)?))
            .note("the apps in this environment's resource group that run in it"),
        inspect(format!("az containerapp env certificate list {}", named)),
        connect(format!("az containerapp env logs show {} --follow", named))
            .label("containerapp env logs show --follow")
            .note("streams the environment's system log until Ctrl-C"),
    ])
}

fn job_actions(j: &JobRow) -> Option<Vec<CliAction>> {
    let id = &j.base.id;
    Some(vec![
        inspect(format!("az containerapp job execution list {}", name_args(&j.base.name, id)?)),
        change(format!("az containerapp job start {}", ids(id))).note("starts one execution now, with the job's own template"),
    ])
}

// ── App Service ──────────────────────────────────────────────────────

/// Web apps take `--ids` (`webapp_name_arg_type` has `id_part='name'`,
/// except `list-instances`); function and logic apps declare their name
/// without one, so they use the name form, like their `show`.
fn site_actions(s: &SiteRow) -> Option<Vec<CliAction>> {
    let id = &s.base.id;
    let n = name_args(&s.base.name, id)?;
    let i = ids(id);
    // Each group spelled out, so every verb is a literal the guard reads.
    Some(if s.kind.contains("workflowapp") {
        vec![
            change(format!("az logicapp restart {}", n)),
            change(format!("az logicapp stop {}", n)),
            change(format!("az logicapp start {}", n)),
        ]
    } else if s.is_function_app() {
        vec![
            inspect(format!("az functionapp function list {}", n)),
            change(format!("az functionapp restart {}", n)),
            change(format!("az functionapp stop {}", n)),
            change(format!("az functionapp start {}", n)),
        ]
    } else {
        vec![
            inspect(format!("az webapp config show {}", i)).note("site config; app settings are never shown"),
            inspect(format!("az webapp list-instances {}", n)),
            connect(format!("az webapp ssh {}", i)).note("Linux apps with SSH enabled in the container"),
            connect(format!("az webapp log tail {}", i)).note("streams the app's log until Ctrl-C"),
            change(format!("az webapp restart {}", i)),
            change(format!("az webapp stop {}", i)),
            change(format!("az webapp start {}", i)),
        ]
    })
}

// ── Key Vault, ACR, Storage, SQL ─────────────────────────────────────

/// Data-plane listings by vault name: names and attributes only. A value
/// (`secret show`, `key show`, any certificate command) is never offered;
/// the guard forbids them by name.
fn vault_actions(v: &VaultRow) -> Option<Vec<CliAction>> {
    let n = shell_quote(&v.base.name);
    let note = "names and attributes only, never a value; the vault's data plane, under your own access";
    Some(vec![
        inspect(format!("az keyvault secret list --vault-name {}", n)).note(note),
        inspect(format!("az keyvault key list --vault-name {}", n)).note(note),
        inspect(format!("az keyvault network-rule list {}", name_args(&v.base.name, &v.base.id)?)),
    ])
}

fn registry_actions(reg: &RegistryRow) -> Option<Vec<CliAction>> {
    let id = &reg.base.id;
    let n = shell_quote(&reg.base.name);
    Some(vec![
        inspect(format!("az acr repository list -n {}", n)).note("the registry's data plane; needs a repository read role (AcrPull)"),
        inspect(format!("az acr replication list -r {} {}", n, rg_sub(id)?)),
        connect(format!("az acr login -n {} --subscription {}", n, shell_quote(subscription_of(id)?)))
            .note("docker login with your Entra token, kept by docker; never the expose-token switch, which prints it"),
    ])
}

/// Never `keys list`, `show-connection-string` or `generate-sas`: each
/// returns a credential. The container listing passes `--auth-mode login`
/// so the CLI uses your Entra identity instead of fetching the account key.
fn storage_actions(sa: &StorageAccountRow) -> Option<Vec<CliAction>> {
    let id = &sa.base.id;
    let n = shell_quote(&sa.base.name);
    Some(vec![
        inspect(format!("az storage account network-rule list --account-name {} {}", n, rg_sub(id)?)),
        inspect(format!("az storage container list --account-name {} --auth-mode login", n))
            .note("the blob data plane as you (Storage Blob Data Reader); login mode never fetches the account key"),
    ])
}

/// `az redis` children take the name form (`id_part=None` on the cache
/// name for `firewall-rules list`, `server-link`, `patch-schedule`,
/// `access-policy-assignment list`). Nothing here prints a key: `redis
/// list-keys` is refused by the guard, and there is no Connect command
/// because every client needs a key or an Entra token.
fn redis_cache_actions(c: &RedisCacheRow) -> Option<Vec<CliAction>> {
    let args = name_args(&c.base.name, &c.base.id)?;
    Some(vec![
        inspect(format!("az redis firewall-rules list {}", args)).note("the IP rules (the Network section)"),
        inspect(format!("az redis server-link list {}", args)).note("geo-replication links"),
        inspect(format!("az redis patch-schedule show {}", args)).note("the maintenance window; errors when none is set"),
        inspect(format!("az redis access-policy-assignment list {}", args))
            .note("Entra data-access assignments (who may connect with a token)"),
    ])
}

/// `az redisenterprise` is a CLI extension; `database list` takes the
/// cluster by name (`--cluster-name`, no `id_part`).
fn managed_redis_actions(c: &ManagedRedisRow) -> Vec<CliAction> {
    vec![inspect(format!("az redisenterprise database list {}", c.cluster_args()))
        .note("needs the redisenterprise CLI extension; ports, protocol, persistence, modules")]
}

fn sql_actions(s: &SqlServerRow) -> Option<Vec<CliAction>> {
    let args = format!("-s {} {}", shell_quote(&s.base.name), rg_sub(&s.base.id)?);
    Some(vec![
        inspect(format!("az sql db list {}", args)),
        inspect(format!("az sql server firewall-rule list {}", args)),
        inspect(format!("az sql server ad-admin list {}", args)),
    ])
}

// ── PostgreSQL & MySQL ───────────────────────────────────────────────

/// `flexible-server show / start / stop / restart` take `--ids` (the
/// server name has `id_part='name'`); the child lists reset it, so they use
/// the name form, and `connect` (the rdbms-connect extension) takes the
/// server name alone. `connect --interactive` prompts for the password:
/// the command never carries one.
fn flexible_server_actions(f: &FlexibleServerRow) -> Option<Vec<CliAction>> {
    let id = &f.base.id;
    let i = ids(id);
    let s = format!("--server-name {} {}", shell_quote(&f.base.name), rg_sub(id)?);
    let n = shell_quote(&f.base.name);
    let user = f.admin_login.as_deref().map(shell_quote).unwrap_or_else(|| "<user>".into());
    let reach = "needs the rdbms-connect extension and a network path to the server (VNet, private endpoint or a firewall rule for your IP); prompts for the password";
    let running = f.state.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("ready"));
    let stopped = f.state.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("stopped"));
    let mut out = match f.engine {
        Engine::Postgres => vec![
            inspect(format!("az postgres flexible-server db list {}", s)),
            inspect(format!("az postgres flexible-server firewall-rule list {}", s)),
            inspect(format!("az postgres flexible-server microsoft-entra-admin list {}", s)),
            inspect(format!("az postgres flexible-server parameter show {} -n require_secure_transport", s)),
            inspect(format!("az postgres flexible-server private-endpoint-connection list {}", s)),
            connect(format!("az postgres flexible-server connect -n {} -u {} --interactive", n, user)).note(reach),
        ],
        Engine::Mysql => vec![
            inspect(format!("az mysql flexible-server db list {}", s)),
            inspect(format!("az mysql flexible-server firewall-rule list --name {} {}", n, rg_sub(id)?)),
            inspect(format!("az mysql flexible-server ad-admin list {}", s)),
            inspect(format!("az mysql flexible-server parameter show {} -n require_secure_transport", s)),
            connect(format!("az mysql flexible-server connect -n {} -u {} --interactive", n, user)).note(reach),
        ],
    };
    let (start, stop, restart) = match f.engine {
        Engine::Postgres => (
            format!("az postgres flexible-server start {}", i),
            format!("az postgres flexible-server stop {}", i),
            format!("az postgres flexible-server restart {}", i),
        ),
        Engine::Mysql => (
            format!("az mysql flexible-server start {}", i),
            format!("az mysql flexible-server stop {}", i),
            format!("az mysql flexible-server restart {}", i),
        ),
    };
    if stopped {
        out.push(change(start));
    }
    if running {
        out.push(change(restart).note("a short outage; with HA, a failover is an option on the CLI"));
        out.push(change(stop).note("stopped for at most 7 days, then Azure starts it again; storage is still billed"));
    }
    Some(out)
}

// ── Network ──────────────────────────────────────────────────────────

fn nsg_actions(n: &NsgRow) -> Option<Vec<CliAction>> {
    Some(vec![inspect(format!(
        "az network nsg rule list --nsg-name {} {} --include-default",
        shell_quote(&n.base.name),
        rg_sub(&n.base.id)?
    ))
    .note("custom and default rules")])
}

fn subnet_actions(s: &SubnetRow) -> Option<Vec<CliAction>> {
    let mut out = Vec::new();
    if let Some(nsg) = &s.nsg_id {
        out.push(inspect(format!("az network nsg show {}", ids(nsg))).label("network nsg show (the subnet's NSG)"));
    }
    if let Some(rt) = &s.route_table_id {
        out.push(
            inspect(format!("az network route-table show {}", ids(rt))).label("network route-table show (the subnet's)"),
        );
    }
    Some(out)
}

// ── Directory (Microsoft Graph) ──────────────────────────────────────

/// Credential metadata only (key id, name, expiry). `credential reset`
/// mints a new secret and prints it: never offered, and the guard refuses
/// `reset` everywhere.
fn service_principal_actions(app_id: &str) -> Option<Vec<CliAction>> {
    if app_id.is_empty() {
        return None;
    }
    let a = shell_quote(app_id);
    Some(vec![
        inspect(format!("az ad sp credential list --id {}", a)).note("key ids, names and expiry dates; never a secret value"),
        inspect(format!("az ad sp owner list --id {}", a)),
    ])
}

fn app_registration_actions(app_id: &str) -> Option<Vec<CliAction>> {
    if app_id.is_empty() {
        return None;
    }
    let a = shell_quote(app_id);
    Some(vec![
        inspect(format!("az ad app credential list --id {}", a)).note("key ids, names and expiry dates; never a secret value"),
        inspect(format!("az ad app federated-credential list --id {}", a)),
        inspect(format!("az ad app owner list --id {}", a)),
    ])
}

// ── Power Platform ───────────────────────────────────────────────────

/// The delegated subnets the policy injects into: Power Platform itself
/// has no `az` command group.
fn power_platform_actions(p: &EnterprisePolicyRow) -> Option<Vec<CliAction>> {
    let subnets = p
        .networks
        .iter()
        .filter_map(|n| n.subnet_id())
        .map(|subnet| {
            inspect(format!("az network vnet subnet show {}", ids(&subnet)))
                .label(format!("network vnet subnet show ({})", name_of_id(&subnet)))
                .note("a subnet the policy injects into; it must stay delegated to Power Platform")
        })
        .collect();
    Some(subnets)
}

// ── Messaging ────────────────────────────────────────────────────────

/// Reads only: a namespace has nothing to start or stop. The entity,
/// rule-set and policy listings declare `--namespace-name` without an
/// `id_part`, so they take the name form. Never `authorization-rule keys`
/// (the guard forbids it): policy names and rights only.
fn servicebus_actions(sb: &ServiceBusRow) -> Option<Vec<CliAction>> {
    let a = format!("--namespace-name {} {}", shell_quote(&sb.base.name), rg_sub(&sb.base.id)?);
    Some(vec![
        inspect(format!("az servicebus queue list {}", a)).note("message counts per queue, from ARM (no data plane)"),
        inspect(format!("az servicebus topic list {}", a)),
        inspect(format!("az servicebus namespace network-rule-set list {}", a))
            .note("default action, trusted services, IP and VNet rules (the Network section)"),
        inspect(format!("az servicebus namespace private-endpoint-connection list {}", a)),
        inspect(format!("az servicebus namespace authorization-rule list {}", a)).note("names and rights; never the keys"),
    ])
}

fn eventhubs_actions(eh: &EventHubsRow) -> Option<Vec<CliAction>> {
    let a = format!("--namespace-name {} {}", shell_quote(&eh.base.name), rg_sub(&eh.base.id)?);
    Some(vec![
        inspect(format!("az eventhubs eventhub list {}", a)).note("partitions, retention and capture per hub"),
        inspect(format!("az eventhubs namespace network-rule-set list {}", a))
            .note("default action, trusted services, IP and VNet rules (the Network section)"),
        inspect(format!("az eventhubs namespace private-endpoint-connection list {}", a)),
        inspect(format!("az eventhubs namespace authorization-rule list {}", a)).note("names and rights; never the keys"),
    ])
}

// ── Edge ─────────────────────────────────────────────────────────────

/// `application-gateway` takes `--ids` (`id_part='name'`); its
/// sub-resource `list` commands declare `--gateway-name` without one, so
/// they take the name form. Backend health is the one way to see whether
/// the backends answer: a POST (`…/backendhealth`), not in `Reader`, which
/// nebaz never sends; copied for the user to run. Never `ssl-cert`.
fn app_gateway_actions(g: &AppGatewayRow) -> Option<Vec<CliAction>> {
    let id = &g.base.id;
    let i = ids(id);
    let gw = format!("--gateway-name {} {}", shell_quote(&g.base.name), rg_sub(id)?);
    Some(vec![
        inspect(format!("az network application-gateway show-backend-health {}", i))
            .note("a POST action (backend health): not in the Reader role, can take a minute; nebaz never sends it"),
        inspect(format!("az network application-gateway http-listener list {}", gw)),
        inspect(format!("az network application-gateway rule list {}", gw)),
        inspect(format!("az network application-gateway address-pool list {}", gw)),
        inspect(format!("az network application-gateway http-settings list {}", gw)),
        inspect(format!("az network application-gateway probe list {}", gw)),
        change(format!("az network application-gateway stop {}", i)).note("stops the gateway: every listener goes dark until start"),
        change(format!("az network application-gateway start {}", i)),
    ])
}

/// The policy rule listings declare `--policy-name` without an `id_part`:
/// the name form. Front Door's are the `front-door` CLI extension's.
fn waf_policy_actions(w: &WafPolicyRow) -> Option<Vec<CliAction>> {
    let a = format!("--policy-name {} {}", shell_quote(&w.base.name), rg_sub(&w.base.id)?);
    Some(match w.kind {
        // The managed rule sets and settings have no listing of their own:
        // `show` (the read command) carries them.
        WafKind::AppGateway => vec![inspect(format!("az network application-gateway waf-policy custom-rule list {}", a))],
        WafKind::FrontDoor => vec![
            inspect(format!("az network front-door waf-policy rule list {}", a)).note("the front-door CLI extension"),
            inspect(format!("az network front-door waf-policy managed-rules list {}", a)).note("the front-door CLI extension"),
        ],
    })
}

/// The `afd` child listings declare `--profile-name` without an
/// `id_part`: the name form (the `cdn` CLI extension). Never `afd secret`
/// or a purge.
fn front_door_actions(p: &FrontDoorProfileRow) -> Option<Vec<CliAction>> {
    let a = format!("--profile-name {} {}", shell_quote(&p.base.name), rg_sub(&p.base.id)?);
    Some(vec![
        inspect(format!("az afd endpoint list {}", a)),
        inspect(format!("az afd origin-group list {}", a)),
        inspect(format!("az afd custom-domain list {}", a)).note("validation state per domain"),
        inspect(format!("az afd security-policy list {}", a)).note("which WAF policy covers which domain"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::harness_tests::mocks;

    /// Whole words that must never appear in a command chain. Kept as bare
    /// words (no prefix) so the guard does not read them as commands.
    const DESTRUCTIVE: &[&str] = &["delete", "purge", "remove", "reset", "regenerate", "rotate", "invoke", "reimage"];
    const SECRET_FLAGS: &[&str] = &["--admin", "--expose-token", "--show-values", "--show-secrets"];
    const CONNECT_VERBS: &[&str] = &["ssh", "rdp", "connect", "get-credentials", "exec", "login", "tail", "show"];
    const CHANGE_VERBS: &[&str] = &["start", "stop", "restart", "deallocate", "scale"];

    /// Whether any word of the command chain is on `verbs` (`az ssh vm`:
    /// the group is the verb), as the guard judges it.
    fn has_verb(command: &str, verbs: &[&str]) -> bool {
        chain_label(command).split_whitespace().any(|w| verbs.contains(&w))
    }

    /// Every mock row's catalogue obeys the rules: an `az` command, the
    /// read command first, tiers in order, Connect / Change verbs from the
    /// short lists, nothing destructive or secret-revealing, and `--ids`
    /// never mixed with `--subscription`.
    #[test]
    fn every_mock_catalogue_follows_the_rules() {
        for m in mocks::all_mocks().into_iter() {
            let r = m.resource.as_ref();
            let actions = actions_for(r);
            if let Some(read) = r.cli_command() {
                assert_eq!(actions[0].command, read, "{}: the read command comes first", m.label);
            }
            let tiers: Vec<_> = actions.iter().map(|a| a.tier).collect();
            let mut sorted = tiers.clone();
            sorted.sort();
            assert_eq!(tiers, sorted, "{}: grouped by tier", m.label);
            for a in &actions {
                let c = &a.command;
                assert_eq!(c.split_whitespace().next(), Some("az"), "{}: {c}", m.label);
                let words: Vec<&str> = c.split_whitespace().collect();
                for w in DESTRUCTIVE {
                    assert!(!chain_label(c).split_whitespace().any(|x| x == *w), "{}: destructive {c}", m.label);
                }
                for f in SECRET_FLAGS {
                    assert!(!words.contains(f), "{}: secret flag in {c}", m.label);
                }
                assert!(
                    !(words.contains(&"--ids") && words.contains(&"--subscription")),
                    "{}: --ids carries the subscription: {c}",
                    m.label
                );
                match a.tier {
                    CliTier::Connect => assert!(has_verb(c, CONNECT_VERBS), "{}: {c}", m.label),
                    CliTier::Change => assert!(has_verb(c, CHANGE_VERBS), "{}: {c}", m.label),
                    CliTier::Inspect => {}
                }
            }
        }
    }

    fn find<'a>(actions: &'a [CliAction], label: &str) -> &'a CliAction {
        actions
            .iter()
            .find(|a| a.label == label)
            .unwrap_or_else(|| panic!("no {label} in {:?}", actions.iter().map(|a| &a.label).collect::<Vec<_>>()))
    }

    fn mock(label: &str) -> Box<dyn Resource> {
        mocks::all_mocks()
            .into_iter()
            .find(|m| m.label == label)
            .unwrap_or_else(|| panic!("no mock {label}"))
            .resource
    }

    #[test]
    fn vm_has_all_three_tiers_with_ids_and_name_forms() {
        let vm = mocks::vm("vm-1", "westeurope");
        let a = actions_for(vm.as_ref());
        let id = vm.id().to_string();
        assert_eq!(a[0].label, "vm show");
        assert_eq!(find(&a, "vm get-instance-view").command, format!("az vm get-instance-view --ids {id}"));
        assert_eq!(find(&a, "vm deallocate").command, format!("az vm deallocate --ids {id}"));
        assert_eq!(find(&a, "vm deallocate").tier, CliTier::Change);
        let ssh = find(&a, "ssh vm");
        assert_eq!(ssh.tier, CliTier::Connect);
        assert_eq!(
            ssh.command,
            format!("az ssh vm -n vm-1 -g {} --subscription {}", mocks::RG, crate::app::harness_tests::SUB_DEV)
        );
        assert!(find(&a, "network bastion ssh").command.contains(&format!("--target-resource-id {id}")));
        assert!(a.iter().all(|x| x.label != "network bastion rdp"), "Linux VM: no RDP");
        assert!(find(&a, "monitor activity-log list").command.contains("--offset 7d"));
        assert!(find(&a, "role assignment list").command.ends_with("--include-inherited"));
    }

    #[test]
    fn aks_uses_the_name_form_and_prefills_the_node_count() {
        let c = mock("ClusterRow");
        let a = actions_for(c.as_ref());
        let creds = find(&a, "aks get-credentials");
        assert_eq!(creds.tier, CliTier::Connect);
        assert!(creds.command.contains("--subscription") && !creds.command.contains("--ids"));

        let p = mock("NodePoolRow");
        let pool = p.as_any().downcast_ref::<NodePoolRow>().unwrap();
        let a = actions_for(p.as_ref());
        if let Some(count) = pool.count {
            let scale = find(&a, "aks nodepool scale");
            assert!(scale.command.ends_with(&format!("--node-count {count}")), "{}", scale.command);
            assert_eq!(scale.tier, CliTier::Change);
        }
        assert!(find(&a, "aks nodepool stop").command.contains(&format!("--cluster-name {}", pool.cluster_name)));
    }

    #[test]
    fn container_apps_cover_app_environment_and_job() {
        let a = actions_for(mock("ContainerAppRow").as_ref());
        assert!(a.iter().all(|x| x.tier != CliTier::Change), "no latest revision, nothing to restart");
        let id = mocks::arm_id("Microsoft.App/containerApps/ca-1");
        let body = serde_json::json!({"id": id, "name": "ca-1", "location": "westeurope",
            "properties": {"latestRevisionName": "ca-1--v2"}});
        let row = ContainerAppRow::from_json(&body, None).expect("parses");
        let restart = actions_for(&row);
        assert!(find(&restart, "containerapp revision restart").command.ends_with("--revision ca-1--v2"));
        assert_eq!(find(&a, "containerapp exec").tier, CliTier::Connect);
        assert!(!find(&a, "containerapp exec").command.contains("--ids"), "exec resets id_part");
        let e = actions_for(mock("EnvironmentRow").as_ref());
        assert!(find(&e, "containerapp list").command.contains("--environment /subscriptions/"));
        let j = actions_for(mock("JobRow").as_ref());
        assert!(find(&j, "containerapp job start").command.contains("--ids"));
    }

    #[test]
    fn web_apps_take_ids_and_function_apps_the_name_form() {
        let web = mock("SiteRow");
        let a = actions_for(web.as_ref());
        let restart = a.iter().find(|x| x.label.ends_with(" restart")).unwrap();
        assert_eq!(restart.tier, CliTier::Change);
        let site = web.as_any().downcast_ref::<SiteRow>().unwrap();
        if site.is_function_app() {
            assert!(restart.command.starts_with("az functionapp restart -n "));
        } else {
            assert_eq!(restart.command, format!("az webapp restart --ids {}", web.id()));
            assert!(find(&a, "webapp ssh").command.contains("--ids"));
        }
    }

    #[test]
    fn vault_registry_storage_and_sql_offer_reads_only_or_login() {
        let v = actions_for(mock("VaultRow").as_ref());
        assert!(v.iter().all(|a| a.tier == CliTier::Inspect));
        assert!(find(&v, "keyvault secret list").command.starts_with("az keyvault secret list --vault-name "));
        let r = actions_for(mock("RegistryRow").as_ref());
        assert_eq!(find(&r, "acr login").tier, CliTier::Connect);
        let s = actions_for(mock("StorageAccountRow").as_ref());
        assert!(find(&s, "storage container list").command.ends_with("--auth-mode login"));
        assert!(s.iter().all(|a| a.tier == CliTier::Inspect));
        let q = actions_for(mock("SqlServerRow").as_ref());
        assert!(find(&q, "sql server firewall-rule list").command.contains("-s "));
    }

    #[test]
    fn redis_offers_reads_only_and_never_a_key() {
        let c = actions_for(mock("RedisCacheRow").as_ref());
        assert!(c[0].command.starts_with("az redis show --ids "));
        assert!(find(&c, "redis firewall-rules list").command.contains("--subscription"));
        let m = actions_for(mock("ManagedRedisRow").as_ref());
        assert!(find(&m, "redisenterprise database list").command.contains("--cluster-name amr-1"));
        for a in c.iter().chain(&m) {
            assert_eq!(a.tier, CliTier::Inspect, "{}", a.command);
            assert!(!a.command.contains("keys"), "{}", a.command);
        }
    }

    #[test]
    fn network_rows_offer_their_rule_and_attachment_reads() {
        let n = actions_for(mock("NsgRow").as_ref());
        assert!(find(&n, "network nsg rule list").command.contains("--include-default"));
        let nic = actions_for(mock("NicRow").as_ref());
        assert!(find(&nic, "network nic list-effective-nsg").note.as_deref().unwrap().contains("POST"));
        let subnet = actions_for(mock("SubnetRow").as_ref());
        assert!(subnet.iter().all(|a| a.tier == CliTier::Inspect));
    }

    #[test]
    fn directory_rows_list_credentials_never_reset_them() {
        let sp = actions_for(mocks::sp_application().as_ref());
        assert_eq!(sp[0].command, format!("az ad sp show --id {}", mocks::APP_ID));
        assert!(find(&sp, "ad sp credential list").command.ends_with(mocks::APP_ID));
        let app = actions_for(mocks::app_registration().as_ref());
        assert!(find(&app, "ad app federated-credential list").tier == CliTier::Inspect);
        assert!(app.iter().chain(&sp).all(|a| a.tier == CliTier::Inspect));
        assert!(
            app.iter().chain(&sp).all(|a| !a.label.contains("monitor")),
            "Graph objects have no ARM id: no activity log"
        );
    }

    #[test]
    fn power_platform_policy_lists_its_subnets() {
        let p = mock("EnterprisePolicyRow");
        let policy = p.as_any().downcast_ref::<EnterprisePolicyRow>().unwrap();
        let a = actions_for(p.as_ref());
        assert_eq!(a[0].command, format!("az resource show --ids {}", p.id()));
        let subnets = a.iter().filter(|x| x.label.starts_with("network vnet subnet show")).count();
        assert_eq!(subnets, policy.networks.iter().filter(|n| n.subnet.is_some()).count());
    }

    #[test]
    fn messaging_namespaces_offer_reads_in_the_name_form_and_never_keys() {
        for label in ["ServiceBusRow", "EventHubsRow"] {
            let r = mock(label);
            let a = actions_for(r.as_ref());
            assert!(a[0].command.contains("namespace show --ids "), "{label}: {}", a[0].command);
            assert!(a.iter().all(|x| x.tier == CliTier::Inspect), "{label}: reads only");
            assert!(a.iter().all(|x| !x.command.contains(" keys")), "{label}: never a key listing");
        }
        let sb = actions_for(mock("ServiceBusRow").as_ref());
        assert!(find(&sb, "servicebus queue list").command.contains("--namespace-name sb-1 -g "));
        let eh = actions_for(mock("EventHubsRow").as_ref());
        assert!(find(&eh, "eventhubs namespace network-rule-set list").command.contains("--subscription"));
    }

    #[test]
    fn flexible_servers_connect_without_a_password_and_change_by_state() {
        let pg = mock("FlexibleServerRow (PostgreSQL)");
        let a = actions_for(pg.as_ref());
        assert_eq!(a[0].command, format!("az postgres flexible-server show --ids {}", pg.id()));
        let conn = find(&a, "postgres flexible-server connect");
        assert_eq!(conn.tier, CliTier::Connect);
        assert!(conn.command.ends_with("--interactive"), "{}", conn.command);
        assert!(
            !conn.command.split_whitespace().any(|w| w == "-p" || w == "--admin-password"),
            "connect never carries a password: {}",
            conn.command
        );
        assert!(find(&a, "postgres flexible-server microsoft-entra-admin list").command.contains("--server-name pg-1"));
        assert_eq!(find(&a, "postgres flexible-server restart").tier, CliTier::Change);
        assert!(a.iter().all(|x| x.label != "postgres flexible-server start"), "already running");

        let my = mock("FlexibleServerRow (MySQL)");
        let a = actions_for(my.as_ref());
        assert!(find(&a, "mysql flexible-server firewall-rule list").command.contains("--name mysql-1 -g"));
        assert!(find(&a, "mysql flexible-server ad-admin list").command.contains("--server-name mysql-1"));
        assert_eq!(find(&a, "mysql flexible-server stop").command, format!("az mysql flexible-server stop --ids {}", my.id()));
    }

    #[test]
    fn edge_rows_offer_reads_and_only_start_stop_on_a_gateway() {
        let g = actions_for(mock("AppGatewayRow").as_ref());
        assert!(g[0].command.starts_with("az network application-gateway show --ids "));
        assert!(find(&g, "network application-gateway show-backend-health").command.contains("--ids "));
        assert!(find(&g, "network application-gateway http-listener list").command.contains("--gateway-name agw-1 -g "));
        assert_eq!(g.iter().filter(|x| x.tier == CliTier::Change).count(), 2);
        assert!(g.iter().all(|x| !x.command.contains("ssl-cert")), "never a certificate listing");
        for label in ["WafPolicyRow", "FrontDoorProfileRow"] {
            let a = actions_for(mock(label).as_ref());
            assert!(a.iter().all(|x| x.tier == CliTier::Inspect), "{label}: reads only");
            assert!(a.iter().all(|x| !x.command.contains("secret") && !x.command.contains("purge")), "{label}");
        }
        let p = actions_for(mock("FrontDoorProfileRow").as_ref());
        assert!(find(&p, "afd origin-group list").command.contains("--profile-name afd-1 -g "));
    }

    #[test]
    fn chain_label_stops_at_the_first_flag() {
        assert_eq!(chain_label("az vm show --ids /x"), "vm show");
        assert_eq!(chain_label("az aks nodepool scale --cluster-name c"), "aks nodepool scale");
    }
}
