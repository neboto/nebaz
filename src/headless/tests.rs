// ported from neboto-tui src/headless/tests.rs @ 08fcd0c (the demo account
// is replaced by the offline harness and its mocks)
//! Headless argument parsing and output shapes, offline: rows come from
//! the harness mocks through their real `from_json`, panes from the real
//! `App` (`Harness`), and nothing reaches the network.

use super::*;
use crate::app::harness_tests::mocks::{self, Mock};
use crate::app::harness_tests::{Harness, SUB_DEV, TENANT};
use clap::Parser;

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("nebaz").chain(args.iter().copied())).expect("parses")
}

/// One mock's pane as `get` captures it: installed as its sub-tab's only
/// row, selected the way a jump lands, every section entered once.
pub(super) async fn capture(mock: Mock) -> Captured {
    let mut h = Harness::new().await;
    let view = mock.view;
    h.install(mock).await;
    let id = h.app.get_selected_resource_id().expect("selected");
    assert!(h.app.headless_select(view, &id), "selectable");
    let sections = h.app.headless_capture(None, &h.tx);
    let resource = h.app.get_selected_resource().expect("selected").clone_box();
    Captured { view, resource, sections: strip_key_hints(sections) }
}

pub(super) fn mock(view: JumpView) -> Mock {
    mocks::all_mocks().into_iter().find(|m| m.view == view).expect("a mock for the view")
}

// ── parsing ─────────────────────────────────────────────────────────────────

#[test]
fn no_subcommand_is_the_tui() {
    assert!(parse(&[]).command.is_none());
    assert!(parse(&["-s", "vm"]).command.is_none());
}

#[test]
fn ls_parses_its_flags_and_the_global_ones_after_it() {
    let cli = parse(&[
        "ls", "vnet/subnets", "-f", "web rg:prod", "--state", "Succeeded", "--hide-noise", "--limit", "3", "-o", "md",
        "-p", "Dev", "-r", "westeurope",
    ]);
    let Some(Command::Ls(a)) = &cli.command else { panic!("ls") };
    assert_eq!(a.target, "vnet/subnets");
    assert_eq!(a.filter.as_deref(), Some("web rg:prod"));
    assert_eq!(a.state.as_deref(), Some("Succeeded"));
    assert!(a.hide_noise);
    assert_eq!(a.limit, Some(3));
    assert_eq!(cli.output, Some(OutputFormat::Md));
    assert_eq!(cli.subscription.as_deref(), Some("Dev"));
    assert_eq!(cli.location.as_deref(), Some("westeurope"));
    // `list` is the same command.
    assert!(matches!(parse(&["list", "vm"]).command, Some(Command::Ls(_))));
}

#[test]
fn get_takes_several_ids_and_repeated_sections() {
    let cli = parse(&["get", "/subscriptions/s/a", "graph:/applications/x", "--section", "access", "--section", "Related", "--wait", "5"]);
    let Some(Command::Get(a)) = &cli.command else { panic!("get") };
    assert_eq!(a.ids.len(), 2);
    assert_eq!(a.sections, vec!["access", "Related"]);
    assert_eq!(a.wait, 5);
    assert!(a.within.is_none());
    let Some(Command::Get(a)) = parse(&["get", "web-1", "--in", "vm"]).command else { panic!("get") };
    assert_eq!(a.within.as_deref(), Some("vm"));
    assert_eq!(a.wait, 60, "the default wait");
    // An id is required; an unknown format is clap's usage error (exit 2).
    assert!(Cli::try_parse_from(["nebaz", "get"]).is_err());
    let err = Cli::try_parse_from(["nebaz", "services", "-o", "csv"]).unwrap_err();
    assert_eq!(err.exit_code(), 2);
}

#[tokio::test]
async fn changes_takes_a_window_and_a_source_and_refuses_others_before_any_call() {
    let cli = parse(&["changes", "--since", "6h", "--source", "health", "--hide-noise", "--limit", "5"]);
    let Some(Command::Changes(args)) = &cli.command else { panic!("a changes command") };
    assert_eq!(args.since, "6h");
    assert_eq!(args.source.as_deref(), Some("health"));
    assert!(args.hide_noise);
    let Some(Command::Changes(args)) = parse(&["changes"]).command else { panic!("changes") };
    assert_eq!(args.since, "1h", "the default window");

    for (bad, says) in [
        (&["changes", "--since", "2h"][..], "15m, 1h, 6h, 24h, 7d"),
        (&["changes", "--source", "alerts"][..], "activity, deployments, health"),
    ] {
        let cli = parse(bad);
        let Some(Command::Changes(args)) = &cli.command else { panic!("changes") };
        let err = changes(&cli, args, OutputFormat::Json).await.unwrap_err();
        assert_eq!(err.code(), 2, "a usage error");
        assert!(err.message().contains(says), "{}", err.message());
    }
}

#[test]
fn targets_resolve_like_the_search_prefixes() {
    let ok = |t: &str| resolve_list(t).unwrap_or_else(|f| panic!("{t}: {}", f.message()));
    assert_eq!(ok("vm"), JumpView::VirtualMachines);
    assert_eq!(ok("@nsg"), JumpView::NetworkSecurityGroups);
    assert_eq!(ok("rg"), JumpView::ResourceGroups);
    assert_eq!(ok("vnet/subnets"), JumpView::Subnets);
    assert_eq!(ok("vnet/@nsg"), JumpView::NetworkSecurityGroups);
    assert_eq!(ok("aca/jobs"), JumpView::ContainerAppJobs);
    assert_eq!(ok("app/function-apps"), JumpView::FunctionApps);
    assert_eq!(ok("id/Service principals"), JumpView::ServicePrincipals);
    assert_eq!(resolve_list("nope").unwrap_err().code(), 2);
    let err = resolve_list("vm/nope").unwrap_err();
    assert_eq!(err.code(), 2);
    assert!(err.message().contains("disks"), "lists the real sub-tabs: {}", err.message());
}

#[test]
fn every_subtab_has_a_prefix_that_routes_back_to_it() {
    for s in ServiceType::all() {
        for v in s.views() {
            let p = view_prefix(*v);
            assert!(!p.is_empty(), "{v:?} has no routing prefix");
            assert_eq!(resolve_list(&p).ok(), Some(*v), "{p} routes elsewhere");
            assert_eq!(resolve_list(&format!("{}/{}", service_key(s), v.as_str())).ok(), Some(*v));
        }
    }
}

#[test]
fn ids_route_themselves_and_names_need_in() {
    assert!(is_id(&mocks::arm_id("Microsoft.Compute/virtualMachines/vm-1")));
    assert!(is_id("graph:/applications/00af5dfb-85da-4b41-a677-0c6b86dd34f8"));
    assert!(!is_id("vm-1"));
    assert_eq!(
        JumpView::landing_for_arm_id(&mocks::arm_id("Microsoft.Compute/virtualMachines/vm-1")),
        Some(JumpView::VirtualMachines)
    );
}

#[test]
fn failures_map_to_their_exit_codes() {
    assert_eq!(Failure::Error(String::new()).code(), 1);
    assert_eq!(Failure::Usage(String::new()).code(), 2);
    assert_eq!(Failure::Auth(String::new()).code(), 4);
}

#[test]
fn the_auth_line_drops_the_tui_key_advice() {
    use crate::azure::auth::AuthError;
    let line = auth_line(&AuthError::NotLoggedIn.status_line());
    assert_eq!(line, "Azure CLI not logged in. Run `az login`");
    assert!(!auth_line(&AuthError::Other("boom".into()).status_line()).contains("press R"));
}

#[test]
fn sections_resolve_in_any_case_and_name_the_real_ones() {
    let labels = vec!["Overview".to_string(), "Access".to_string(), "Related".to_string()];
    assert_eq!(resolve_sections(&labels, &["related".into(), "OVERVIEW".into()], "x").unwrap(), vec![2, 0]);
    let err = resolve_sections(&labels, &["nope".into()], "x").unwrap_err();
    assert_eq!(err.code(), 2);
    assert!(err.message().contains("Overview, Access, Related"));
}

#[test]
fn loading_placeholders_and_key_hints() {
    let l = |k: &str, v: &str| (k.to_string(), v.to_string());
    let pending = |lines: Vec<(String, String)>| !crate::export::unloaded_sections(&[("S".into(), lines)]).is_empty();
    assert!(pending(vec![l("Instance view", "Loading…")]));
    assert!(pending(vec![l("Owner", "x"), l("", "· principal names are loading (Microsoft Graph)")]));
    assert!(pending(vec![l("Zone", "x"), l("", "· linked VNets: loading…")]));
    assert!(!pending(vec![l("Name", "loading-svc"), l("State", "running")]));
    let stripped = strip_key_hints(vec![(
        "Related".into(),
        vec![l("VNet", "/subscriptions/x"), l("", ""), l("", "⏎ on a line jumps to it (y copies the id)")],
    )]);
    assert_eq!(stripped[0].1.len(), 2);
}

// ── output shapes ───────────────────────────────────────────────────────────

#[test]
fn services_lists_every_service_and_subtab() {
    let v: Value = serde_json::from_str(&services(OutputFormat::Json)).unwrap();
    assert_eq!(v["schema"], SCHEMA);
    let items = v["services"].as_array().unwrap();
    assert_eq!(items.len(), ServiceType::all().len());
    assert_eq!(v["count"], items.len());
    let vm = items.iter().find(|s| s["prefix"] == "vm").unwrap();
    let subtabs: Vec<&str> = vm["subtabs"].as_array().unwrap().iter().map(|t| t["prefix"].as_str().unwrap()).collect();
    assert_eq!(subtabs, vec!["vm", "disk", "nic"]);
    let md = services(OutputFormat::Md);
    assert!(md.starts_with("| Prefix | Service | Sub-tabs |"));
    assert!(md.contains("| `vm` | Virtual Machines | VMs (`vm`), Disks (`disk`), NICs (`nic`) |"), "{md}");
}

#[tokio::test]
async fn ls_applies_the_tui_filters() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("web-1", "westeurope"), mocks::vm("web-2", "eastus"), mocks::vm("db-1", "westeurope")])
        .await;
    let names = |h: &mut Harness, shaping: ListShaping| -> Vec<String> {
        h.app.headless_rows(&shaping).iter().map(|r| r.name().to_string()).collect()
    };
    assert_eq!(names(&mut h, ListShaping::default()).len(), 3);
    let west = ListShaping { location: Location::parse("westeurope"), ..Default::default() };
    assert_eq!(names(&mut h, west), vec!["web-1", "db-1"]);
    let web = ListShaping { query: "web".into(), ..Default::default() };
    assert_eq!(names(&mut h, web).len(), 2);
    let rg = ListShaping { query: format!("rg:{}", mocks::RG), ..Default::default() };
    assert_eq!(names(&mut h, rg).len(), 3);
    let none = ListShaping { query: "rg:elsewhere".into(), ..Default::default() };
    assert!(names(&mut h, none).is_empty());

    let rows = h.app.headless_rows(&ListShaping::default());
    let v: Value = serde_json::from_str(&render_list(
        JumpView::VirtualMachines,
        SUB_DEV,
        &Location::All,
        &rows,
        OutputFormat::Json,
    ))
    .unwrap();
    assert_eq!(v["service"], "vm");
    assert_eq!(v["subtab"], "vms");
    assert_eq!(v["location"], "all");
    assert_eq!(v["count"], 3);
    let row = &v["resources"][0];
    assert_eq!(row["name"], "web-1");
    assert_eq!(row["location"], "westeurope");
    assert_eq!(row["resource_group"], mocks::RG);
    assert_eq!(row["tags"]["env"], "test");
    let md = render_list(JumpView::VirtualMachines, SUB_DEV, &Location::All, &rows, OutputFormat::Md);
    assert!(md.starts_with("# Virtual Machines · VMs (3)"), "{md}");
}

#[tokio::test]
async fn get_finds_by_id_in_any_case_then_by_exact_name() {
    let mut h = Harness::new().await;
    h.open(JumpView::VirtualMachines).await;
    h.land(vec![mocks::vm("web-1", "westeurope"), mocks::vm("web-2", "westeurope")]).await;
    let id = mocks::arm_id("Microsoft.Compute/virtualMachines/web-2");
    assert_eq!(h.app.headless_find(&id.to_uppercase()), vec![id.clone()]);
    assert_eq!(h.app.headless_find("web-2"), vec![id.clone()]);
    assert!(h.app.headless_find("web").is_empty(), "no partial matches");
    assert!(h.app.headless_select(JumpView::VirtualMachines, &id));
    assert_eq!(h.app.get_selected_resource_id(), Some(id));
}

#[tokio::test]
async fn get_renders_every_section_of_the_pane() {
    let c = capture(mock(JumpView::VirtualMachines)).await;
    let labels: Vec<&str> = c.sections.iter().map(|(n, _)| n.as_str()).collect();
    let desc: Vec<&str> = c.resource.detail_sections().unwrap().sections.iter().map(|s| s.label).collect();
    assert_eq!(labels, desc, "every section, in pane order");

    let v: Value = serde_json::from_str(&render_detail(SUB_DEV, std::slice::from_ref(&c), OutputFormat::Json)).unwrap();
    assert_eq!(v["schema"], SCHEMA);
    assert_eq!(v["subscription"], SUB_DEV);
    assert_eq!(v["service"], "vm");
    assert_eq!(v["resource"]["id"], c.resource.id());
    assert_eq!(v["resource"]["location"], "westeurope");
    assert!(v["sections"]["Overview"].is_object());
    // Offline, the instance view never lands: not loaded is null.
    assert!(v["sections"]["Instance view"].is_null(), "{}", v["sections"]);
    // The Related key hint is the pane's, not the output's.
    assert!(!v.to_string().contains('⏎'));

    let md = render_detail(SUB_DEV, std::slice::from_ref(&c), OutputFormat::Md);
    assert!(md.starts_with("# "), "{md}");
    assert!(md.contains("## Overview"));
}

#[tokio::test]
async fn get_several_wraps_them_in_resources() {
    let items = vec![capture(mock(JumpView::VirtualMachines)).await, capture(mock(JumpView::KeyVaults)).await];
    let v: Value = serde_json::from_str(&render_detail(SUB_DEV, &items, OutputFormat::Json)).unwrap();
    assert_eq!(v["count"], 2);
    assert_eq!(v["resources"][1]["service"], "kv");
    assert!(v["resources"][1]["sections"].is_object());
    let md = render_detail(SUB_DEV, &items, OutputFormat::Md);
    assert!(md.starts_with("# nebaz get (2)"));
}

/// The credential rule (CLAUDE.md): a secret the ARM body carries is
/// stripped before the row keeps it, so `get` cannot print it in any
/// format, from any section.
#[tokio::test]
async fn get_never_emits_a_secret_value() {
    let app = container_apps::ContainerAppRow::from_json(
        &serde_json::json!({
            "id": mocks::arm_id("Microsoft.App/containerApps/aca-secret"),
            "name": "aca-secret",
            "location": "East US",
            "properties": {
                "provisioningState": "Succeeded",
                "runningStatus": "Running",
                "configuration": {
                    "secrets": [{"name": "db-password", "value": "SECRET-VALUE-1"}],
                    "registries": [{"server": "example.invalid", "username": "u", "passwordSecretRef": "db-password"}],
                    "dapr": {"enabled": true, "appId": "aca"}
                },
                "template": {"containers": [{"name": "api", "image": "example/api:1",
                    "env": [{"name": "API_KEY", "value": "SECRET-VALUE-2"},
                            {"name": "DB_PASSWORD", "secretRef": "db-password"}]}]}
            }
        }),
        Some(TENANT),
    )
    .expect("parses");
    let component = monitor::ComponentRow::from_json(
        &serde_json::json!({
            "id": mocks::arm_id("Microsoft.Insights/components/appi-secret"),
            "name": "appi-secret",
            "location": "westeurope",
            "kind": "web",
            "properties": {"InstrumentationKey": "SECRET-VALUE-3",
                "ConnectionString": "InstrumentationKey=SECRET-VALUE-3;IngestionEndpoint=x"}
        }),
        Some(TENANT),
    )
    .expect("parses");
    let items = vec![
        capture(Mock { view: JumpView::ContainerApps, label: "ContainerAppRow", resource: Box::new(app) }).await,
        capture(Mock { view: JumpView::AppInsights, label: "ComponentRow", resource: Box::new(component) }).await,
    ];
    for one in &items {
        for format in [OutputFormat::Json, OutputFormat::Md] {
            let out = render_detail(SUB_DEV, std::slice::from_ref(one), format);
            assert!(!out.contains("SECRET-VALUE"), "a secret value leaked:\n{out}");
        }
    }
    let both = render_detail(SUB_DEV, &items, OutputFormat::Json);
    assert!(!both.contains("SECRET-VALUE"));
    // The names still show: what exists, never what it holds.
    assert!(both.contains("db-password") && both.contains("API_KEY"), "{both}");
}

use crate::azure::services::{container_apps, monitor};

// ── ls --subscriptions (#62) ────────────────────────────────────────────────

use crate::app::harness_tests::SUB_PROD;

#[test]
fn subscriptions_flags_parse_and_exclude_each_other() {
    let ls = |argv: &[&str]| match parse(argv).command {
        Some(Command::Ls(a)) => (a.subscriptions, a.all_configured),
        _ => unreachable!(),
    };
    assert_eq!(ls(&["ls", "vm"]), (None, false));
    assert_eq!(ls(&["ls", "vm", "--subscriptions", "Prod,Dev"]), (Some(vec!["Prod".into(), "Dev".into()]), false));
    assert_eq!(ls(&["ls", "--subscriptions", "Prod", "vm"]), (Some(vec!["Prod".into()]), false));
    assert_eq!(ls(&["ls", "vm", "--all-configured"]), (None, true));
    let err = Cli::try_parse_from(["nebaz", "ls", "vm", "--all-configured", "--subscriptions", "Prod"]).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    // Not the global `-p/--subscription`, which picks the one to browse.
    let cli = parse(&["ls", "vm", "-p", "Dev", "--subscriptions", "Prod"]);
    assert_eq!(cli.subscription.as_deref(), Some("Dev"));
}

#[tokio::test]
async fn fan_out_subscriptions_explicit_configured_and_refused() {
    let h = Harness::new().await;
    let clients = &h.app.azure_clients;
    let none = Config::default();
    let args = |subs: Option<&[&str]>, all: bool| LsArgs {
        target: "vm".into(),
        filter: None,
        state: None,
        hide_noise: false,
        limit: None,
        subscriptions: subs.map(|s| s.iter().map(|x| x.to_string()).collect()),
        all_configured: all,
    };
    // Explicit: ids or names, in order, each once; an unknown one is usage.
    let ids = fan_out_subscriptions(&none, clients, &args(Some(&["prod", SUB_DEV, "Prod"]), false)).unwrap();
    assert_eq!(ids, [SUB_PROD, SUB_DEV]);
    let err = fan_out_subscriptions(&none, clients, &args(Some(&["Nope"]), false)).unwrap_err();
    assert_eq!(err.code(), 2);
    assert!(err.message().contains("known: Dev, Prod"), "{}", err.message());
    assert_eq!(fan_out_subscriptions(&none, clients, &args(Some(&[""]), false)).unwrap_err().code(), 2);
    // --all-configured: config `subscriptions`, unknown entries skipped.
    let config: Config = toml::from_str(r#"subscriptions = ["Prod", "gone", "Dev"]"#).unwrap();
    assert_eq!(fan_out_subscriptions(&config, clients, &args(None, true)).unwrap(), [SUB_PROD, SUB_DEV]);
    let err = fan_out_subscriptions(&none, clients, &args(None, true)).unwrap_err();
    assert_eq!(err.code(), 2);
    assert!(err.message().contains("subscriptions = ["), "says how to set it: {}", err.message());
}

#[tokio::test]
async fn ls_subscriptions_refuses_tenant_wide_lists_before_any_call() {
    for target in ["sub", "id/service-principals", "changes"] {
        let cli = parse(&["ls", target, "--subscriptions", "Prod"]);
        let Some(Command::Ls(args)) = &cli.command else { panic!("ls") };
        let err = ls(&cli, args, OutputFormat::Json).await.unwrap_err();
        assert_eq!(err.code(), 2, "{target}: {}", err.message());
        assert!(err.message().contains("drop --subscriptions"), "{}", err.message());
    }
}

/// A VM in subscription `sub`, through the real `from_json`.
fn vm_in(sub: &str, name: &str) -> Box<dyn Resource> {
    let id = format!("/subscriptions/{sub}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/{name}");
    let v = serde_json::json!({
        "id": id, "name": name, "location": "westeurope",
        "properties": {"provisioningState": "Succeeded"},
    });
    Box::new(crate::azure::services::compute::VmRow::from_json(&v, Some(TENANT)).expect("a VM"))
}

/// Both subscriptions' lists already in their cache slots (as the
/// fan-out leaves them), Prod's replaced by a 403 when `prod_denied`:
/// each is opened, shaped and tagged.
async fn collected(shaping: ListShaping, prod_denied: bool) -> (Vec<SubscriptionOutcome>, Vec<(String, Box<dyn Resource>)>) {
    use crate::ui::widgets::subscription_selector::SubscriptionCount;
    let mut h = Harness::new().await;
    let vms = |sub, names: &[&str]| names.iter().map(|n| vm_in(sub, n)).collect::<Vec<_>>();
    h.app.cache.insert(ServiceType::VirtualMachines, SUB_DEV, Some("vms".into()), vms(SUB_DEV, &["web-1", "db-1"]));
    if prod_denied {
        h.app.subscription_fanout.insert(
            (JumpView::VirtualMachines, SUB_PROD.to_string()),
            (SubscriptionCount::Denied, Some("Azure error: 403 AuthorizationFailed: no read".into())),
        );
    } else {
        h.app.cache.insert(ServiceType::VirtualMachines, SUB_PROD, Some("vms".into()), vms(SUB_PROD, &["web-9"]));
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let targets = [SUB_PROD.to_string(), SUB_DEV.to_string()];
    collect_subscriptions(&mut h.app, &tx, &mut rx, JumpView::VirtualMachines, &targets, &shaping)
        .await
        .unwrap_or_else(|f| panic!("{}", f.message()))
}

#[tokio::test]
async fn ls_subscriptions_tags_every_row_in_every_format() {
    let (outcomes, rows) = collected(ListShaping::default(), false).await;
    let names: Vec<(&str, &str)> = rows.iter().map(|(s, r)| (s.as_str(), r.name())).collect();
    assert_eq!(names, [(SUB_PROD, "web-9"), (SUB_DEV, "web-1"), (SUB_DEV, "db-1")], "in the order given");

    let doc: Value = serde_json::from_str(&render_list_subscriptions(
        JumpView::VirtualMachines,
        &Location::All,
        &outcomes,
        &rows,
        OutputFormat::Json,
    ))
    .unwrap();
    assert!(doc.get("subscription").is_none(), "the single-subscription key would be a lie here");
    assert_eq!(doc["count"], 3);
    let per = doc["subscriptions"].as_array().unwrap();
    assert_eq!(per[0], json!({"subscription": SUB_PROD, "name": "Prod", "status": "ok", "count": 1, "message": null}));
    assert_eq!(per[1]["count"], 2);
    assert_eq!(doc["resources"][0]["subscription"], SUB_PROD);
    assert_eq!(doc["resources"][0]["subscription_name"], "Prod");
    assert_eq!(doc["resources"][2]["subscription_name"], "Dev");

    let md = render_list_subscriptions(JumpView::VirtualMachines, &Location::All, &outcomes, &rows, OutputFormat::Md);
    assert!(md.contains("| Subscription | Type |"), "{md}");
    assert!(md.contains("| Prod | Virtual Machine |"), "{md}");

    // The TUI's filters apply per subscription.
    let (_, rows) = collected(ListShaping { query: "web".into(), ..Default::default() }, false).await;
    let names: Vec<&str> = rows.iter().map(|(_, r)| r.name()).collect();
    assert_eq!(names, ["web-9", "web-1"]);
}

#[tokio::test]
async fn a_denied_subscription_is_reported_not_fatal() {
    let (outcomes, rows) = collected(ListShaping::default(), true).await;
    assert_eq!(outcomes[0].status, "denied");
    assert!(outcomes[0].message.as_deref().unwrap_or_default().contains("403"));
    assert_eq!(outcomes[1].status, "ok");
    assert_eq!(rows.len(), 2);
}
