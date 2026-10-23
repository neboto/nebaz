// ported from neboto-tui src/headless.rs @ 08fcd0c (services / ls / get;
// table and CSV output, --regions and audit are not carried over)
//! Headless subcommands (`nebaz services`, `ls`, `get`): run once, print,
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
use crate::cli::{Cli, Command, GetArgs, LsArgs, OutputFormat};
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
/// included); 3 is reserved for `audit --fail-on` (#60).
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

/// Run the subcommand in `cli.command` and return the process exit code.
pub async fn run(cli: Cli) -> i32 {
    let format = cli.output.unwrap_or(OutputFormat::Json);
    let result = match &cli.command {
        Some(Command::Services) => Ok(services(format)),
        Some(Command::Ls(args)) => ls(&cli, args, format).await,
        Some(Command::Get(args)) => get(&cli, args, format).await,
        None => Ok(String::new()),
    };
    match result {
        Ok(out) => {
            emit(&out);
            0
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
    let location = cli.location.as_deref().map(Location::parse).unwrap_or_default();
    let (config, clients) = setup(cli, None).await?;
    validate_location(&clients, &location).await?;
    let subscription = clients.current_subscription().unwrap_or_default().to_string();

    let mut app = App::new_headless(config, clients);
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
