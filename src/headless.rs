// ported from neboto-tui src/headless.rs @ 08fcd0c (services / ls / get;
// table and CSV output are not carried over; `ls --regions` came over
// from 1ebd69f as `ls --subscriptions`, #62; audit from neboto-tui @
// 693449a, driven through the TUI's own `r`)
//! Headless subcommands (`nebaz services`, `ls`, `get`, `changes`,
//! `audit`): run once, print,
//! exit, no terminal UI (#44). `ls` and `get` drive a terminal-less `App`
//! (`src/app/headless.rs`) over the same `AzureClients` and `arm.rs` the
//! TUI uses, so the read-only guard covers them like everything else under
//! `src/`, and a list or a pane cannot drift from what the TUI shows.
//!
//! stdout carries only the result, in the chosen format; warnings (a
//! partial load, a config problem) go to stderr, so `-o json | jq` stays
//! parseable. Exit codes: see [`Failure`] and `src/headless/contract.json`.

use crate::app::{App, ListShaping};
use crate::azure::client::AzureClients;
use crate::azure::location::{Location, GLOBAL};
use crate::azure::resource::{subscription_of, Resource};
use crate::azure::service::{JumpView, ServiceType};
use crate::audit::{AuditFinding, RowKind, Severity};
use crate::cli::{AuditArgs, ChangesArgs, Cli, Command, GetArgs, LsArgs, OutputFormat};
use crate::config::Config;
use crate::error::Error;
use crate::event::Event;
use serde_json::{json, Map, Value};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Version tag carried in every JSON document, so a consumer can tell when
/// the shape changes.
pub const SCHEMA: &str = "nebaz/v1";

/// Most resources one `get` may ask for: each one fans out into every
/// section's fetches.
const MAX_GET: usize = 50;

/// A list load that hasn't finished by now is stuck, not slow.
const LIST_LOAD_LIMIT: Duration = Duration::from_secs(600);

/// A failure and the exit code it maps to. 0 is success (an empty list
/// included); 3 is `audit`'s: it ran and found something at or above
/// `--fail-on` ([`FINDINGS_EXIT`]).
#[derive(Debug)]
pub enum Failure {
    /// The request itself is wrong: an unknown prefix, sub-tab, section,
    /// subscription or location, or a resource that isn't there or is
    /// ambiguous. Exit 2 (clap's own usage errors exit 2 as well).
    Usage(String),
    /// Azure or the runtime failed. Exit 1.
    Error(String),
    /// No token: `az` is missing, not logged in, or the login expired —
    /// the TUI's one auth line. Exit 4.
    Auth(String),
}

impl Failure {
    pub(crate) fn code(&self) -> i32 {
        match self {
            Failure::Error(_) => 1,
            Failure::Usage(_) => 2,
            Failure::Auth(_) => 4,
        }
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            Failure::Usage(m) | Failure::Error(m) | Failure::Auth(m) => m,
        }
    }
}

/// `nebaz audit`'s exit code when it ran and found something at or above
/// `--fail-on`: distinct from every failure, so a script can tell "found
/// something" from "couldn't look".
pub const FINDINGS_EXIT: i32 = 3;

/// Run the subcommand in `cli.command` and return the process exit code.
pub async fn run(cli: Cli) -> i32 {
    let format = cli.output.unwrap_or(OutputFormat::Json);
    let ok = |r: Result<String, Failure>| r.map(|out| (out, 0));
    let result = match &cli.command {
        Some(Command::Services) => Ok((services(format), 0)),
        Some(Command::Ls(args)) => ok(ls(&cli, args, format).await),
        Some(Command::Get(args)) => ok(get(&cli, args, format).await),
        Some(Command::Changes(args)) => ok(changes(&cli, args, format).await),
        Some(Command::Audit(args)) => audit(&cli, args, format).await,
        None => Ok((String::new(), 0)),
    };
    match result {
        Ok((out, code)) => {
            emit(&out);
            code
        }
        Err(f) => {
            eprintln!("nebaz: {}", f.message());
            f.code()
        }
    }
}

/// Write to stdout, tolerating a closed pipe (`nebaz ls … | head`).
fn emit(out: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(out.as_bytes());
    if !out.ends_with('\n') {
        let _ = stdout.write_all(b"\n");
    }
    let _ = stdout.flush();
}

/// The auth line without the TUI's key advice (there is no `R` here).
fn auth_line(line: &str) -> String {
    line.replace(", then press R to retry", "")
        .replace(" — press R to retry", "")
}

/// Config + clients for a one-shot run. Unlike the TUI, which opens with
/// the auth line, this fails: a script must never be answered from a
/// subscription it did not ask for, or from no subscription at all.
async fn setup(cli: &Cli, subscription: Option<&str>) -> Result<(Config, AzureClients), Failure> {
    let mut config = Config::load();
    cli.apply_to(&mut config);
    if let Some(w) = config.load_warning.take() {
        eprintln!("nebaz: warning: config: {w}");
    }
    if let Some(s) = subscription {
        config.default_subscription = Some(s.to_string());
    }
    // The location is a flag of `ls`, never the config's TUI default.
    config.default_location = None;
    // One run revisits a sub-tab it loaded (several `get` ids): keep it.
    config.cache_ttl = Some(24 * 3600);
    config.cache_ttls = None;
    let clients = AzureClients::new(&config).await.map_err(|e| match e {
        Error::Auth(a) => Failure::Auth(auth_line(&a.status_line())),
        Error::InvalidConfig(m) => Failure::Usage(m),
        other => Failure::Error(other.to_string()),
    })?;
    if let Some(a) = clients.auth_error() {
        return Err(Failure::Auth(auth_line(&a.status_line())));
    }
    if clients.current_subscription().is_none() {
        return Err(Failure::Error(
            "no enabled subscription: `az account list` shows none".into(),
        ));
    }
    Ok((config, clients))
}

/// `--location`: any short name the subscription's locations list knows,
/// or `global`. The list is the same `GET …/locations` the `R` picker
/// reads; when it cannot be read the name is used unchecked.
async fn validate_location(clients: &AzureClients, location: &Location) -> Result<(), Failure> {
    let Location::Named(name) = location else {
        return Ok(());
    };
    if name.eq_ignore_ascii_case(GLOBAL) {
        return Ok(());
    }
    let Some(sub) = clients.current_subscription() else {
        return Ok(());
    };
    match clients.locations_fetch(sub).await {
        Ok(infos) if infos.is_empty() || infos.iter().any(|i| i.name.eq_ignore_ascii_case(name)) => Ok(()),
        Ok(infos) => {
            let mut names: Vec<&str> = infos.iter().map(|i| i.name.as_str()).collect();
            names.sort();
            Err(Failure::Usage(format!(
                "unknown location {name} for this subscription — known: {}",
                names.join(", ")
            )))
        }
        Err(e) => {
            if let Some(a) = crate::azure::auth::AuthError::classify(&e) {
                return Err(Failure::Auth(auth_line(&a.status_line())));
            }
            eprintln!("nebaz: warning: location {name} not checked: {e}");
            Ok(())
        }
    }
}

// ── targets ─────────────────────────────────────────────────────────────────

/// `vm`, `@nsg`, `rg` (any prefix or alias the TUI's `@` search takes), or
/// `service/sub-tab` where the sub-tab is its routing prefix, its label or
/// its stable name (`vnet/subnets`, `aca/jobs`, `app/function-apps`).
pub fn resolve_list(target: &str) -> Result<JumpView, Failure> {
    let target = target.trim();
    let (svc_part, sub) = match target.split_once('/') {
        Some((a, b)) => (a, Some(b.trim())),
        None => (target, None),
    };
    let unknown = || Failure::Usage(format!("unknown service {target:?} — `nebaz services` lists them"));
    let (service, view) = ServiceType::from_prefix(svc_part).ok_or_else(unknown)?;
    let Some(sub) = sub.filter(|s| !s.is_empty()) else {
        return Ok(view.unwrap_or(service.default_view()));
    };
    let want = sub.trim_start_matches('@').to_lowercase();
    service
        .views()
        .iter()
        .copied()
        .find(|v| {
            v.as_str() == want
                || v.label().eq_ignore_ascii_case(&want)
                || ServiceType::from_prefix(&want).is_some_and(|(s, rv)| s == service && rv.unwrap_or(s.default_view()) == *v)
        })
        .ok_or_else(|| {
            let known: Vec<&str> = service.views().iter().map(|v| v.as_str()).collect();
            Failure::Usage(format!(
                "{} has no sub-tab {sub:?} — sub-tabs: {}",
                service.name(),
                known.join(", ")
            ))
        })
}

/// The routing prefix that names `view` (without the `@`): the canonical
/// service prefix for a default sub-tab, else its own.
pub fn view_prefix(view: JumpView) -> String {
    ServiceType::completion_prefixes()
        .into_iter()
        .find(|p| ServiceType::from_prefix(p).is_some_and(|(s, v)| v.unwrap_or(s.default_view()) == view))
        .unwrap_or_default()
        .trim_start_matches('@')
        .to_string()
}

fn service_key(service: ServiceType) -> String {
    service.prefix().trim_start_matches('@').to_string()
}

/// Whether a `get` argument is an id (routes itself) rather than a name.
fn is_id(arg: &str) -> bool {
    arg.starts_with("/subscriptions/") || crate::azure::graph::is_row_id(arg)
}

// ── services ────────────────────────────────────────────────────────────────

pub(crate) fn services(format: OutputFormat) -> String {
    let all = ServiceType::all();
    match format {
        OutputFormat::Json => {
            let items: Vec<Value> = all
                .iter()
                .map(|s| {
                    let subtabs: Vec<Value> = s
                        .views()
                        .iter()
                        .map(|v| json!({"subtab": v.as_str(), "label": v.label(), "prefix": view_prefix(*v)}))
                        .collect();
                    json!({
                        "prefix": service_key(*s),
                        "name": s.name(),
                        "category": s.category(),
                        "subtabs": subtabs,
                    })
                })
                .collect();
            pretty(&json!({"schema": SCHEMA, "count": items.len(), "services": items}))
        }
        OutputFormat::Md => {
            let mut out = String::from("| Prefix | Service | Sub-tabs |\n| --- | --- | --- |\n");
            for s in &all {
                let subtabs: Vec<String> = s
                    .views()
                    .iter()
                    .map(|v| format!("{} (`{}`)", v.label(), view_prefix(*v)))
                    .collect();
                out.push_str(&format!("| `{}` | {} | {} |\n", service_key(*s), s.name(), subtabs.join(", ")));
            }
            out
        }
    }
}

// ── the event pump ──────────────────────────────────────────────────────────

/// Handle the next event (waiting at most 200ms, never past `deadline`),
/// then everything else already queued: one capture pass per burst rather
/// than per event.
async fn pump(
    app: &mut App,
    tx: &mpsc::UnboundedSender<Event>,
    rx: &mut mpsc::UnboundedReceiver<Event>,
    deadline: Instant,
) -> Result<(), Failure> {
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(200));
    let Ok(Some(first)) = tokio::time::timeout(wait, rx.recv()).await else {
        return Ok(());
    };
    let mut next = Some(first);
    while let Some(ev) = next {
        app.handle_event(ev, tx)
            .await
            .map_err(|e| Failure::Error(e.to_string()))?;
        next = rx.try_recv().ok();
    }
    Ok(())
}

/// Open `view` and pump until its list has landed, as the main loop would.
async fn load_view(
    app: &mut App,
    tx: &mpsc::UnboundedSender<Event>,
    rx: &mut mpsc::UnboundedReceiver<Event>,
    view: JumpView,
) -> Result<(), Failure> {
    app.headless_open(view);
    let deadline = Instant::now() + LIST_LOAD_LIMIT;
    loop {
        if app.should_load_resources() {
            app.load_resources_async(tx);
        }
        if !app.loading {
            break;
        }
        if Instant::now() >= deadline {
            return Err(Failure::Error(format!("{} list load timed out", view.label())));
        }
        pump(app, tx, rx, deadline).await?;
    }
    for w in app.headless_load_warnings() {
        eprintln!("nebaz: warning: {}: {w}", view.label());
    }
    match app.headless_load_failure() {
        Some((true, m)) => Err(Failure::Auth(auth_line(&m))),
        Some((false, m)) => Err(Failure::Error(m)),
        None => Ok(()),
    }
}

// ── ls ──────────────────────────────────────────────────────────────────────

async fn ls(cli: &Cli, args: &LsArgs, format: OutputFormat) -> Result<String, Failure> {
    let view = resolve_list(&args.target)?;
    if view.service().is_virtual() {
        return Err(Failure::Usage(format!(
            "{} is computed, not listed — run `nebaz audit`",
            view.service().prefix()
        )));
    }
    if args.subscriptions.is_some() || args.all_configured {
        return ls_subscriptions(cli, view, args, format).await;
    }
    list_view(cli, view, args, format, None).await
}

/// How one subscription's list went, for the `subscriptions` array.
pub(crate) struct SubscriptionOutcome {
    pub id: String,
    pub name: String,
    /// `ok`, `denied` (a 403), `disabled` (not `Enabled`) or `error`.
    pub status: &'static str,
    pub message: Option<String>,
}

/// The subscriptions `ls --subscriptions` lists, ids in order, each once.
/// An explicit list must name only subscriptions `az account list` knows
/// (the `--subscription` rule: a script is never answered from somewhere
/// it didn't ask for). `--all-configured` is config `subscriptions`, whose
/// unknown entries warn and are skipped (the config rule); unset, it is a
/// usage error that says how to set it.
pub(crate) fn fan_out_subscriptions(
    config: &Config,
    clients: &AzureClients,
    args: &LsArgs,
) -> Result<Vec<String>, Failure> {
    let known = || {
        let names: Vec<&str> = clients.subscriptions().iter().map(|s| s.name.as_str()).collect();
        names.join(", ")
    };
    if let Some(given) = &args.subscriptions {
        let mut ids: Vec<String> = Vec::new();
        for g in given.iter().map(|g| g.trim()).filter(|g| !g.is_empty()) {
            let entry = clients
                .resolve_subscription(g)
                .ok_or_else(|| Failure::Usage(format!("unknown subscription {g:?} — known: {}", known())))?;
            if !ids.contains(&entry.id) {
                ids.push(entry.id);
            }
        }
        if ids.is_empty() {
            return Err(Failure::Usage("--subscriptions: name at least one subscription".into()));
        }
        return Ok(ids);
    }
    let wanted = config.subscriptions.clone().ok_or_else(|| {
        Failure::Usage(
            "--all-configured: no `subscriptions` in config — set e.g. subscriptions = [\"Prod\", \"Dev\"], \
             or name them: --subscriptions Prod,Dev"
                .into(),
        )
    })?;
    let (ids, unknown) = clients.resolve_configured(&wanted);
    if !unknown.is_empty() {
        eprintln!("nebaz: warning: config: subscriptions: unknown subscription {}", unknown.join(", "));
    }
    if ids.is_empty() {
        return Err(Failure::Usage(format!(
            "--all-configured: config `subscriptions` names none `az account list` knows — known: {}",
            known()
        )));
    }
    Ok(ids)
}

/// `ls --subscriptions`: the same list in each subscription, through the
/// TUI's `P` fan-out (`App::fanout_subscriptions`: a few at a time, each
/// on its tenant's pipeline, into its cache slot), then per subscription
/// the TUI's filters, joined in the order given with the subscription on
/// every row. A subscription that fails is reported and skipped; the
/// command fails only when every one did, or on the app-wide auth line.
async fn ls_subscriptions(cli: &Cli, view: JumpView, args: &LsArgs, format: OutputFormat) -> Result<String, Failure> {
    if !view.fans_out() {
        return Err(Failure::Usage(format!(
            "{} · {} isn't listed per subscription (it is the tenant's, or @changes' one list per window) \
             — drop --subscriptions",
            view.service().name(),
            view.label()
        )));
    }
    let location = cli.location.as_deref().map(Location::parse).unwrap_or_default();
    let (config, clients) = setup(cli, None).await?;
    validate_location(&clients, &location).await?;
    let targets = fan_out_subscriptions(&config, &clients, args)?;

    let mut app = App::new_headless(config, clients);
    let (tx, mut rx) = mpsc::unbounded_channel();
    // Start on the first target: the current subscription is the normal
    // load's, so the fan-out lists the rest alongside it.
    app.headless_switch_subscription(&targets[0]).map_err(Failure::Error)?;
    app.fanout_subscriptions(view, &targets, &tx);
    let shaping = ListShaping {
        query: args.filter.clone().unwrap_or_default(),
        location: location.clone(),
        state: args.state.clone(),
        hide_noise: args.hide_noise,
    };
    let (outcomes, rows) = collect_subscriptions(&mut app, &tx, &mut rx, view, &targets, &shaping).await?;
    if outcomes.iter().all(|o| o.status != "ok") {
        return Err(Failure::Error(format!(
            "no subscription could be listed ({})",
            outcomes.iter().map(|o| format!("{} {}", o.name, o.status)).collect::<Vec<_>>().join(", ")
        )));
    }
    let mut rows = rows;
    if let Some(n) = args.limit {
        rows.truncate(n);
    }
    Ok(render_list_subscriptions(view, &location, &outcomes, &rows, format))
}

/// Each target in turn: wait for its fan-out slot, then open the sub-tab
/// there (a cache hit, or the current subscription's own load) and shape
/// it. `--limit` is the caller's, across every subscription.
pub(crate) async fn collect_subscriptions(
    app: &mut App,
    tx: &mpsc::UnboundedSender<Event>,
    rx: &mut mpsc::UnboundedReceiver<Event>,
    view: JumpView,
    targets: &[String],
    shaping: &ListShaping,
) -> Result<(Vec<SubscriptionOutcome>, Vec<(String, Box<dyn Resource>)>), Failure> {
    use crate::ui::widgets::subscription_selector::SubscriptionCount;
    let deadline = Instant::now() + LIST_LOAD_LIMIT;
    let mut outcomes = Vec::new();
    let mut rows: Vec<(String, Box<dyn Resource>)> = Vec::new();
    for sub in targets {
        let entry = app.azure_clients.resolve_subscription(sub);
        let name = entry.as_ref().map(|e| e.name.clone()).unwrap_or_else(|| sub.clone());
        if let Some(e) = entry.filter(|e| !e.is_enabled()) {
            let message = format!("subscription is {}", e.state.to_lowercase());
            eprintln!("nebaz: warning: {name}: {message}");
            outcomes.push(SubscriptionOutcome { id: sub.clone(), name, status: "disabled", message: Some(message) });
            continue;
        }
        while matches!(app.fanout_status(view, sub), Some((SubscriptionCount::Loading, _))) {
            if Instant::now() >= deadline {
                return Err(Failure::Error(format!("{} list load timed out in {name}", view.label())));
            }
            pump(app, tx, rx, deadline).await?;
        }
        if let Some((count, message)) = app.fanout_status(view, sub).cloned() {
            eprintln!("nebaz: warning: {name}: {}", message.as_deref().unwrap_or(count.status()));
            outcomes.push(SubscriptionOutcome { id: sub.clone(), name, status: count.status(), message });
            continue;
        }
        app.headless_switch_subscription(sub).map_err(Failure::Error)?;
        match load_view(app, tx, rx, view).await {
            Ok(()) => {
                rows.extend(app.headless_rows(shaping).into_iter().map(|r| (sub.clone(), r.clone_box())));
                outcomes.push(SubscriptionOutcome { id: sub.clone(), name, status: "ok", message: None });
            }
            Err(f @ Failure::Auth(_)) => return Err(f),
            Err(f) => {
                let status = SubscriptionCount::from_error(f.message()).status();
                eprintln!("nebaz: warning: {name}: {}", f.message());
                outcomes.push(SubscriptionOutcome { id: sub.clone(), name, status, message: Some(f.message().to_string()) });
            }
        }
    }
    Ok((outcomes, rows))
}

pub(crate) fn render_list_subscriptions(
    view: JumpView,
    location: &Location,
    outcomes: &[SubscriptionOutcome],
    rows: &[(String, Box<dyn Resource>)],
    format: OutputFormat,
) -> String {
    let name_of = |id: &str| outcomes.iter().find(|o| o.id == id).map(|o| o.name.clone()).unwrap_or_default();
    match format {
        OutputFormat::Json => {
            let items: Vec<Value> = rows
                .iter()
                .map(|(sub, r)| {
                    let mut o = list_item(r.as_ref());
                    if let Some(m) = o.as_object_mut() {
                        m.insert("subscription".into(), json!(sub));
                        m.insert("subscription_name".into(), json!(name_of(sub)));
                    }
                    o
                })
                .collect();
            let subs: Vec<Value> = outcomes
                .iter()
                .map(|o| {
                    json!({
                        "subscription": o.id,
                        "name": o.name,
                        "status": o.status,
                        "count": rows.iter().filter(|(s, _)| *s == o.id).count(),
                        "message": o.message,
                    })
                })
                .collect();
            pretty(&json!({
                "schema": SCHEMA,
                "service": service_key(view.service()),
                "subtab": view.as_str(),
                "subscriptions": subs,
                "location": location.as_str(),
                "count": items.len(),
                "resources": items,
            }))
        }
        OutputFormat::Md => {
            let refs: Vec<&dyn Resource> = rows.iter().map(|(_, r)| r.as_ref()).collect();
            let names: Vec<String> = rows.iter().map(|(s, _)| name_of(s)).collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            crate::export::list_markdown_in_subscriptions(
                &refs,
                Some(&names),
                &format!("{} · {}", view.service().name(), view.label()),
            )
        }
    }
}

/// `nebaz changes --since 6h`: `ls changes` over a window (#61).
async fn changes(cli: &Cli, args: &ChangesArgs, format: OutputFormat) -> Result<String, Failure> {
    use crate::azure::services::changes::ChangesWindow;
    let window = ChangesWindow::parse(&args.since).ok_or_else(|| {
        let known: Vec<&str> = ChangesWindow::ALL.iter().map(|w| w.label()).collect();
        Failure::Usage(format!("--since {:?}: one of {}", args.since, known.join(", ")))
    })?;
    let view = match args.source.as_deref().map(|s| s.trim().to_lowercase()) {
        None => JumpView::ChangesAll,
        Some(s) => match s.as_str() {
            "all" => JumpView::ChangesAll,
            "activity" => JumpView::ChangesActivity,
            "deployments" | "deploys" => JumpView::ChangesDeployments,
            "health" => JumpView::ChangesHealth,
            _ => return Err(Failure::Usage(format!("--source {s:?}: one of activity, deployments, health"))),
        },
    };
    let ls = LsArgs {
        target: String::new(),
        filter: args.filter.clone(),
        state: None,
        hide_noise: args.hide_noise,
        limit: args.limit,
        subscriptions: None,
        all_configured: false,
    };
    list_view(cli, view, &ls, format, Some(window)).await

}

/// One sub-tab, listed and shaped (`ls`, `changes`).
async fn list_view(
    cli: &Cli,
    view: JumpView,
    args: &LsArgs,
    format: OutputFormat,
    window: Option<crate::azure::services::changes::ChangesWindow>,
) -> Result<String, Failure> {
    let location = cli.location.as_deref().map(Location::parse).unwrap_or_default();
    let (config, clients) = setup(cli, None).await?;
    validate_location(&clients, &location).await?;
    let subscription = clients.current_subscription().unwrap_or_default().to_string();

    let mut app = App::new_headless(config, clients);
    if let Some(w) = window {
        app.set_changes_window(w);
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    load_view(&mut app, &tx, &mut rx, view).await?;

    let shaping = ListShaping {
        query: args.filter.clone().unwrap_or_default(),
        location: location.clone(),
        state: args.state.clone(),
        hide_noise: args.hide_noise,
    };
    let mut rows = app.headless_rows(&shaping);
    if let Some(n) = args.limit {
        rows.truncate(n);
    }
    Ok(render_list(view, &subscription, &location, &rows, format))
}

/// One `ls` row: the export's object (core keys, list-level fields, tags)
/// plus the row's location and resource group.
pub(crate) fn list_item(r: &dyn Resource) -> Value {
    let mut o = crate::export::resource_object(r);
    if let Some(m) = o.as_object_mut() {
        let tags = m.remove("tags").unwrap_or(Value::Object(Map::new()));
        m.insert("location".into(), json!(r.location()));
        m.insert("resource_group".into(), json!(r.resource_group()));
        m.insert("tags".into(), tags);
    }
    o
}

pub(crate) fn render_list(
    view: JumpView,
    subscription: &str,
    location: &Location,
    rows: &[&dyn Resource],
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Json => {
            let items: Vec<Value> = rows.iter().map(|r| list_item(*r)).collect();
            pretty(&json!({
                "schema": SCHEMA,
                "service": service_key(view.service()),
                "subtab": view.as_str(),
                "subscription": subscription,
                "location": location.as_str(),
                "count": items.len(),
                "resources": items,
            }))
        }
        OutputFormat::Md => crate::export::list_markdown(rows, &format!("{} · {}", view.service().name(), view.label())),
    }
}

// ── audit ───────────────────────────────────────────────────────────────────

/// `--fail-on`: the lowest severity that exits 3, or `None` for never.
pub(crate) fn parse_fail_on(s: &str) -> Result<Option<Severity>, Failure> {
    match s.trim().to_ascii_lowercase().as_str() {
        "never" | "none" => Ok(None),
        other => Severity::parse(other).map(Some).ok_or_else(|| {
            Failure::Usage(format!("--fail-on {s:?}: one of critical, high, medium, low, info, never"))
        }),
    }
}

/// 3 when a finding is at or above `fail_on`, else 0. Coverage notes never
/// count: a check that could not run is not a finding.
pub(crate) fn audit_exit_code(rows: &[AuditFinding], fail_on: Option<Severity>) -> i32 {
    match fail_on {
        Some(min) if rows.iter().any(|f| f.is_finding() && f.severity <= min) => FINDINGS_EXIT,
        _ => 0,
    }
}

/// `nebaz audit`: the TUI's `@audit` with `r` pressed. A terminal-less
/// `App` loads every source list the checks read and the capped lazy reads
/// that follow (`App::load_audit_sources`, the same code), pumps until
/// nothing is in flight, then prints the findings worst first and the
/// checks that could not run. A source that fails is a warning on stderr
/// and its checks come back as `not_checked`: a permission gap never reads
/// as a clean bill.
async fn audit(cli: &Cli, args: &AuditArgs, format: OutputFormat) -> Result<(String, i32), Failure> {
    let fail_on = parse_fail_on(&args.fail_on)?;
    let location = cli.location.as_deref().map(Location::parse).unwrap_or_default();
    let (config, clients) = setup(cli, None).await?;
    validate_location(&clients, &location).await?;
    let subscription = clients.current_subscription().unwrap_or_default().to_string();

    let mut app = App::new_headless(config, clients);
    let (tx, mut rx) = mpsc::unbounded_channel();
    app.headless_audit_start(&tx);
    let deadline = Instant::now() + LIST_LOAD_LIMIT;
    while app.audit_in_flight() {
        if Instant::now() >= deadline {
            eprintln!(
                "nebaz: warning: audit sources still loading after {}s; printed as not checked",
                LIST_LOAD_LIMIT.as_secs()
            );
            break;
        }
        pump(&mut app, &tx, &mut rx, deadline).await?;
    }
    if let Some(a) = &app.auth_error {
        return Err(Failure::Auth(auth_line(&a.status_line())));
    }
    if let Some(w) = app.headless_audit_warning() {
        eprintln!("nebaz: warning: {w}");
    }
    let rows: Vec<AuditFinding> = app
        .headless_audit_rows()
        .into_iter()
        .filter(|f| location.admits(f.location.as_deref()))
        .collect();
    let code = audit_exit_code(&rows, fail_on);
    Ok((render_audit(&subscription, &location, &rows, format), code))
}

pub(crate) fn render_audit(subscription: &str, location: &Location, rows: &[AuditFinding], format: OutputFormat) -> String {
    let findings: Vec<&AuditFinding> = rows.iter().filter(|f| f.is_finding()).collect();
    let skipped: Vec<&AuditFinding> = rows.iter().filter(|f| f.kind == RowKind::NotChecked).collect();
    match format {
        OutputFormat::Json => {
            let items: Vec<Value> = findings
                .iter()
                .map(|f| {
                    json!({
                        "severity": f.severity.label(),
                        "check": f.check_id,
                        "title": f.check_title,
                        "resource_id": f.resource_id,
                        "resource_name": f.resource_name,
                        "location": f.location,
                        "reason": f.reason,
                        "evidence": f.evidence,
                        "remediation": f.fix,
                    })
                })
                .collect();
            let not_checked: Vec<Value> = skipped
                .iter()
                .map(|f| json!({"check": f.check_id, "title": f.check_title, "status": f.list_note(), "reason": f.reason}))
                .collect();
            pretty(&json!({
                "schema": SCHEMA,
                "subscription": subscription,
                "location": location.as_str(),
                "count": items.len(),
                "findings": items,
                "not_checked": not_checked,
            }))
        }
        OutputFormat::Md => {
            let cell = |s: &str| s.replace('|', "\\|").replace('\n', " ");
            let mut out = format!("# nebaz audit · {subscription}\n\n");
            if findings.is_empty() {
                out.push_str("No findings.\n");
            } else {
                out.push_str("| Severity | Check | Resource | Finding |\n| --- | --- | --- | --- |\n");
                for f in &findings {
                    out.push_str(&format!(
                        "| {} | {} | `{}` | {} |\n",
                        f.severity.label(),
                        cell(f.check_title),
                        cell(&f.resource_id),
                        cell(&f.reason)
                    ));
                }
            }
            if !skipped.is_empty() {
                out.push_str("\n## Not checked\n\n");
                for f in &skipped {
                    out.push_str(&format!("- {} (`{}`): {}\n", f.check_title, f.check_id, f.list_note()));
                }
            }
            out
        }
    }
}

// ── get ─────────────────────────────────────────────────────────────────────

/// One resource's pane, captured.
pub(crate) struct Captured {
    pub view: JumpView,
    pub resource: Box<dyn Resource>,
    pub sections: Vec<(String, Vec<(String, String)>)>,
}

/// `nebaz get`: the detail pane, headless. A terminal-less `App` loads the
/// sub-tab each id routes to (`JumpView::landing_for_arm_id`, the jump
/// router), selects the row the way a jump does and fires every section's
/// on-enter hook, pumping events until nothing reads as loading.
async fn get(cli: &Cli, args: &GetArgs, format: OutputFormat) -> Result<String, Failure> {
    let mut wanted: Vec<&str> = Vec::new();
    for id in &args.ids {
        let id = id.trim();
        if !id.is_empty() && !wanted.contains(&id) {
            wanted.push(id);
        }
    }
    if wanted.len() > MAX_GET {
        return Err(Failure::Usage(format!(
            "at most {MAX_GET} resources per get ({} given)",
            wanted.len()
        )));
    }
    let within = args.within.as_deref().map(resolve_list).transpose()?;

    // Route every argument before any call, so a typo fails fast.
    let mut routed: Vec<(JumpView, &str)> = Vec::new();
    for arg in &wanted {
        let view = if is_id(arg) {
            JumpView::landing_for_arm_id(arg).ok_or_else(|| {
                Failure::Usage(format!("{arg}: not a type nebaz lists (nor a top-level resource in a group)"))
            })?
        } else {
            within.ok_or_else(|| {
                Failure::Usage(format!(
                    "{arg:?} is not an ARM id (/subscriptions/…) or a directory id (graph:/…); \
                     pass --in PREFIX to look it up by name"
                ))
            })?
        };
        routed.push((view, arg));
    }

    // The ids name their subscription; one get reads one.
    let mut subs: Vec<String> = Vec::new();
    for (_, arg) in &routed {
        if let Some(s) = subscription_of(arg) {
            if !subs.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                subs.push(s.to_string());
            }
        }
    }
    if subs.len() > 1 {
        return Err(Failure::Usage(format!(
            "the ids span {} subscriptions ({}); run one get per subscription",
            subs.len(),
            subs.join(", ")
        )));
    }
    let id_sub = subs.first().cloned();
    let override_sub = if cli.subscription.is_none() { id_sub.as_deref() } else { None };
    let (config, clients) = setup(cli, override_sub).await?;
    let subscription = clients.current_subscription().unwrap_or_default().to_string();
    if let Some(s) = &id_sub {
        if !s.eq_ignore_ascii_case(&subscription) {
            return Err(Failure::Usage(format!(
                "the ids are in subscription {s}, but --subscription selects {subscription}"
            )));
        }
    }

    let mut app = App::new_headless(config, clients);
    let (tx, mut rx) = mpsc::unbounded_channel();

    // Each sub-tab's list once, then every argument to one row id.
    let mut loaded: Vec<JumpView> = Vec::new();
    let mut plans: Vec<(JumpView, String, Option<Vec<usize>>)> = Vec::new();
    for (view, arg) in &routed {
        if !loaded.contains(view) {
            load_view(&mut app, &tx, &mut rx, *view).await?;
            loaded.push(*view);
        } else {
            app.headless_open(*view);
        }
        let hits = app.headless_find(arg);
        let id = match hits.as_slice() {
            [one] => one.clone(),
            [] => {
                return Err(Failure::Usage(format!(
                    "no row {arg:?} in {} · {} of subscription {subscription} — `nebaz ls {}` lists them",
                    view.service().name(),
                    view.label(),
                    view_prefix(*view)
                )))
            }
            many => {
                return Err(Failure::Usage(format!(
                    "{arg:?} names {} resources — pass an id: {}",
                    many.len(),
                    many.join(", ")
                )))
            }
        };
        if plans.iter().any(|(_, p, _)| p.eq_ignore_ascii_case(&id)) {
            continue;
        }
        if !app.headless_select(*view, &id) {
            return Err(Failure::Error(format!("{id} is listed but can't be selected")));
        }
        let only = if args.sections.is_empty() {
            None
        } else {
            Some(resolve_sections(&app.headless_section_labels(), &args.sections, &id)?)
        };
        plans.push((*view, id, only));
    }

    let settle = Instant::now() + Duration::from_secs(args.wait);
    let snapshots = loop {
        let mut snaps = Vec::with_capacity(plans.len());
        for (view, id, only) in &plans {
            app.headless_select(*view, id);
            snaps.push(app.headless_capture(only.as_deref(), &tx));
        }
        let waiting = snaps.iter().any(|s| !crate::export::unloaded_sections(s).is_empty());
        if !waiting || Instant::now() >= settle {
            break snaps;
        }
        pump(&mut app, &tx, &mut rx, settle).await?;
    };

    let mut items = Vec::with_capacity(plans.len());
    for ((view, id, _), sections) in plans.iter().zip(snapshots) {
        app.headless_select(*view, id);
        let Some(resource) = app.get_selected_resource().map(|r| r.clone_box()) else {
            continue;
        };
        let pending = crate::export::unloaded_sections(&sections);
        if !pending.is_empty() {
            eprintln!(
                "nebaz: {} still loading after {}s, printed as not loaded: {}",
                resource.id(),
                args.wait,
                pending.join(", ")
            );
        }
        items.push(Captured {
            view: *view,
            resource,
            sections: strip_key_hints(sections),
        });
    }
    Ok(render_detail(&subscription, &items, format))
}

/// `--section` names → section indices, any case. An unknown name lists the
/// resource's real sections.
pub(crate) fn resolve_sections(labels: &[String], wanted: &[String], id: &str) -> Result<Vec<usize>, Failure> {
    let mut out = Vec::new();
    for w in wanted {
        let i = labels
            .iter()
            .position(|l| l.trim().eq_ignore_ascii_case(w.trim()))
            .ok_or_else(|| Failure::Usage(format!("{id} has no section {w:?} — sections: {}", labels.join(", "))))?;
        if !out.contains(&i) {
            out.push(i);
        }
    }
    Ok(out)
}

/// Drop the Related section's `⏎ on a line jumps to it …` row: there are
/// no keys here (the export strips `press …` hints itself).
pub(crate) fn strip_key_hints(sections: Vec<(String, Vec<(String, String)>)>) -> Vec<(String, Vec<(String, String)>)> {
    sections
        .into_iter()
        .map(|(name, lines)| {
            let lines = lines
                .into_iter()
                .filter(|(k, v)| !(k.trim().is_empty() && v.trim_start().starts_with('⏎')))
                .collect();
            (name, lines)
        })
        .collect()
}

/// One `get` item: the export's `{resource, sections, tags}` (a section
/// that never loaded is `null`) with the row's location and group on
/// `resource`.
pub(crate) fn detail_item(c: &Captured) -> Value {
    let r = c.resource.as_ref();
    let mut v = crate::export::detail_value(r, &c.sections);
    if let Some(ident) = v.get_mut("resource").and_then(Value::as_object_mut) {
        ident.insert("location".into(), json!(r.location()));
        ident.insert("resource_group".into(), json!(r.resource_group()));
    }
    let mut out = Map::new();
    out.insert("service".into(), json!(service_key(c.view.service())));
    out.insert("subtab".into(), json!(c.view.as_str()));
    if let Value::Object(m) = v {
        out.extend(m);
    }
    Value::Object(out)
}

pub(crate) fn render_detail(subscription: &str, items: &[Captured], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            let values: Vec<Value> = items.iter().map(detail_item).collect();
            let doc = match values.as_slice() {
                // One id → the object itself, so `.sections.Overview` works.
                [one] => {
                    let mut doc = Map::new();
                    doc.insert("schema".into(), json!(SCHEMA));
                    doc.insert("subscription".into(), json!(subscription));
                    if let Some(o) = one.as_object() {
                        doc.extend(o.clone());
                    }
                    Value::Object(doc)
                }
                _ => json!({
                    "schema": SCHEMA,
                    "subscription": subscription,
                    "count": values.len(),
                    "resources": values,
                }),
            };
            pretty(&doc)
        }
        OutputFormat::Md => match items {
            [one] => crate::export::detail_markdown_at(one.resource.as_ref(), &one.sections, 1),
            _ => {
                let mut md = format!("# nebaz get ({})\n\n", items.len());
                for c in items {
                    md.push_str(&crate::export::detail_markdown_at(c.resource.as_ref(), &c.sections, 2));
                }
                md
            }
        },
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod contract_tests;
