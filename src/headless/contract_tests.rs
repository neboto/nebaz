// ported from neboto-tui src/headless/contract_tests.rs @ 08fcd0c (demo
// data → the offline harness mocks; `ls --regions`, audit and CSV dropped;
// exit codes added)
//! The stable half of the headless output, pinned to `contract.json`.
//!
//! What scripts may rely on (`skills/nebaz/SKILL.md`, README "Headless"):
//! the flags, the exit codes, the JSON envelopes, the core resource keys,
//! the service and sub-tab prefixes, and each resource type's section
//! names. Everything inside a section is the pane, serialized, and is
//! deliberately left out: it may change in any release.
//!
//! Anything in `contract.json` that the build no longer produces is a
//! **breaking change**: it needs a new `SCHEMA` version and a release note,
//! not an edit to the file. Anything new is an addition: record it with
//! `NEBAZ_BLESS=1 cargo test contract`.

use super::tests::{capture, mock};
use super::*;
use clap::{CommandFactory, Parser};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/headless/contract.json");

/// The keys every `ls` row and every `get` resource carry; a type's own
/// list-level fields come on top and are not part of the contract.
const LS_CORE: &[&str] = &["type", "id", "name", "state", "location", "resource_group", "tags"];

fn keys(v: &Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

/// Every flag, by subcommand ("" = the global/TUI ones).
fn flags() -> Value {
    let cli = Cli::command();
    let longs = |c: &clap::Command| -> Vec<String> {
        let mut v: Vec<String> = c
            .get_arguments()
            .filter(|a| !a.is_global_set())
            .filter_map(|a| a.get_long())
            .map(|l| format!("--{l}"))
            .collect();
        v.sort();
        v
    };
    let mut out = Map::new();
    let mut top: Vec<String> = cli.get_arguments().filter_map(|a| a.get_long()).map(|l| format!("--{l}")).collect();
    top.sort();
    out.insert(String::new(), json!(top));
    for sub in cli.get_subcommands() {
        out.insert(sub.get_name().to_string(), json!(longs(sub)));
    }
    Value::Object(out)
}

/// Section names per resource type, from every pane's descriptor (the
/// mocks cover every split pane; a type without one is the flat "Details").
fn sections_by_type() -> Value {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in crate::app::harness_tests::mocks::all_mocks() {
        let names = match m.resource.detail_sections() {
            Some(d) => d.sections.iter().map(|s| s.label.to_string()).collect(),
            None => vec!["Details".to_string()],
        };
        out.entry(m.resource.resource_type().to_string()).or_insert(names);
    }
    json!(out)
}

fn exit_codes() -> Value {
    json!({
        "ok": 0,
        "error": Failure::Error(String::new()).code(),
        "usage": Failure::Usage(String::new()).code(),
        // `audit --fail-on` (#60): it ran and found something.
        "findings": 3,
        "auth": Failure::Auth(String::new()).code(),
    })
}

async fn current() -> Value {
    let svcs: Value = serde_json::from_str(&services(OutputFormat::Json)).unwrap();

    let vm = capture(mock(JumpView::VirtualMachines)).await;
    let rows: Vec<&dyn Resource> = vec![vm.resource.as_ref()];
    let ls: Value = serde_json::from_str(&render_list(
        JumpView::VirtualMachines,
        "sub",
        &Location::All,
        &rows,
        OutputFormat::Json,
    ))
    .unwrap();
    for k in LS_CORE {
        assert!(ls["resources"][0].get(*k).is_some(), "ls rows carry {k}");
    }

    // `ls --subscriptions` (#62): `subscriptions` replaces `subscription`,
    // and every row carries its own.
    let outcomes = [SubscriptionOutcome { id: "sub".into(), name: "Dev".into(), status: "ok", message: None }];
    let multi_rows = vec![("sub".to_string(), vm.resource.clone_box())];
    let multi: Value = serde_json::from_str(&render_list_subscriptions(
        JumpView::VirtualMachines,
        &Location::All,
        &outcomes,
        &multi_rows,
        OutputFormat::Json,
    ))
    .unwrap();
    let multi_core: Vec<&str> = [LS_CORE, &["subscription", "subscription_name"]].concat();
    for k in &multi_core {
        assert!(multi["resources"][0].get(*k).is_some(), "ls --subscriptions rows carry {k}");
    }

    let one: Value = serde_json::from_str(&render_detail("sub", std::slice::from_ref(&vm), OutputFormat::Json)).unwrap();
    let kv = capture(mock(JumpView::KeyVaults)).await;
    let several: Value = serde_json::from_str(&render_detail("sub", &[vm, kv], OutputFormat::Json)).unwrap();

    // `audit` over one warm finding (and every other check a note).
    let nsg = crate::azure::services::network::NsgRow::from_json(
        &json!({"id": crate::app::harness_tests::mocks::arm_id("Microsoft.Network/networkSecurityGroups/nsg"),
            "name": "nsg", "location": "westeurope", "properties": {"securityRules": [
            {"name": "ssh", "properties": {"priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                "sourceAddressPrefix": "*", "sourcePortRange": "*", "destinationAddressPrefix": "*",
                "destinationPortRange": "22"}}]}}),
        None,
    )
    .expect("parses");
    let mut input = crate::audit::AuditInput::new("sub", 0);
    let nsgs: Vec<Box<dyn Resource>> = vec![Box::new(nsg)];
    input.add(JumpView::NetworkSecurityGroups, &nsgs);
    let audit_rows = crate::audit::run(&input);
    let audit: Value = serde_json::from_str(&render_audit("sub", &Location::All, &audit_rows, OutputFormat::Json)).unwrap();

    let doctor_checks = [super::doctor::Check { name: "proxy", status: super::doctor::Status::Info, detail: "none".into(), hint: None }];
    let doctor: Value = serde_json::from_str(&super::doctor::render(&doctor_checks, OutputFormat::Json)).unwrap();

    let mut prefixes = BTreeMap::new();
    for s in ServiceType::all() {
        let subtabs: Vec<String> = s.views().iter().map(|v| format!("{} ({})", v.as_str(), view_prefix(*v))).collect();
        prefixes.insert(service_key(s), subtabs);
    }

    json!({
        "schema": SCHEMA,
        "flags": flags(),
        "exit_codes": exit_codes(),
        "services": {
            "envelope": keys(&svcs),
            "service": keys(&svcs["services"][0]),
            "subtab": keys(&svcs["services"][0]["subtabs"][0]),
        },
        "ls": {"envelope": keys(&ls), "resource": LS_CORE},
        "ls_subscriptions": {
            "envelope": keys(&multi),
            "subscription": keys(&multi["subscriptions"][0]),
            "resource": multi_core,
        },
        "get": {
            "one": keys(&one),
            "several": keys(&several),
            "item": keys(&several["resources"][0]),
            "resource": keys(&one["resource"]),
        },
        "audit": {
            "envelope": keys(&audit),
            "finding": keys(&audit["findings"][0]),
            "not_checked": keys(&audit["not_checked"][0]),
            "severities": ["critical", "high", "medium", "low", "info"],
        },
        "doctor": {
            "envelope": keys(&doctor),
            "check": keys(&doctor["checks"][0]),
            "statuses": ["ok", "info", "warn", "fail", "skip"],
        },
        "prefixes": prefixes,
        "sections": sections_by_type(),
    })
}

/// Every leaf as a path: `ls › envelope › count`,
/// `sections › Virtual Machine › Overview`.
fn paths(v: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    let join = |k: &str| if prefix.is_empty() { k.to_string() } else { format!("{prefix} › {k}") };
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                paths(v, &join(k), out);
            }
        }
        Value::Array(a) => {
            for v in a {
                paths(v, prefix, out);
            }
        }
        Value::String(s) => {
            out.insert(join(s));
        }
        other => {
            out.insert(join(&other.to_string()));
        }
    }
}

#[tokio::test]
async fn output_contract_holds() {
    let now = current().await;
    if std::env::var_os("NEBAZ_BLESS").is_some() {
        std::fs::write(GOLDEN, serde_json::to_string_pretty(&now).unwrap() + "\n").unwrap();
        return;
    }
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(GOLDEN).unwrap()).unwrap();
    assert_eq!(
        golden["schema"], SCHEMA,
        "SCHEMA changed: re-record the contract for the new version with NEBAZ_BLESS=1"
    );

    let (mut was, mut is) = (BTreeSet::new(), BTreeSet::new());
    paths(&golden, "", &mut was);
    paths(&now, "", &mut is);
    let removed: Vec<_> = was.difference(&is).collect();
    let added: Vec<_> = is.difference(&was).collect();
    assert!(
        removed.is_empty(),
        "BREAKING: scripts rely on these and they're gone or renamed:\n  {}\n\
         Put them back, or bump SCHEMA (a new nebaz/vN), note it in the release, \
         and re-record with NEBAZ_BLESS=1 cargo test contract",
        removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  ")
    );
    assert!(
        added.is_empty(),
        "New stable output (not breaking):\n  {}\nRecord it with NEBAZ_BLESS=1 cargo test contract",
        added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  ")
    );
}

/// The skill's examples are real invocations: each parses.
#[test]
fn the_skill_examples_parse() {
    let skill = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/skills/nebaz/SKILL.md")).unwrap();
    let mut seen = 0;
    for line in skill.lines().map(str::trim).filter(|l| l.starts_with("nebaz ")) {
        // `nebaz ls vm | jq …`: only the nebaz half is ours.
        let words = shell_words(line.split(" | ").next().unwrap_or(line));
        Cli::try_parse_from(&words).unwrap_or_else(|e| panic!("SKILL.md example does not parse: {line}\n{e}"));
        seen += 1;
    }
    assert!(seen >= 5, "only {seen} examples found in SKILL.md");
}

/// Split on whitespace, honouring single and double quotes (enough for
/// the examples; no escapes).
fn shell_words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}
