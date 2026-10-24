//! Demo coverage (#45): the made-up tenant through the real headless `ls`
//! and `get`, offline (`--demo` answers from `src/demo`'s fixtures). Two
//! ratchets: [`EMPTY_YET`] names the sub-tabs with no demo rows, and
//! [`WARNS_YET`] the ones whose rows still open with a `⚠` line (a
//! section asking for something no fixture answers). Both only shrink: a
//! tab that gets its fixtures must leave the list, or the test says so.

use super::*;
use clap::Parser;
use serde_json::Value;

fn demo_cli(args: &[&str]) -> Cli {
    Cli::try_parse_from(["nebaz", "--demo"].into_iter().chain(args.iter().copied())).expect("parses")
}

/// Sub-tabs (by `ls` prefix) the demo has no rows for yet.
const EMPTY_YET: &[&str] = &[
    "vm", "disk", "nic", "storage", "vnet", "subnet", "nsg", "pip", "lb", "rt", "nat", "pe",
    "dns", "dnsz", "dnsr", "dnsfr", "dnsp", "agw", "afd", "waf", "kv", "id", "sp", "appreg", "aks", "pool", "acr",
    "app", "func", "plan", "sql", "cosmos", "pg", "mysql", "foundry", "monitor", "appi", "pp", "aca", "acaenv",
    "acajob", "redis", "amr", "sb", "eh",
];

/// Sub-tabs whose demo rows still open with a `⚠` line somewhere.
const WARNS_YET: &[&str] = &[
    "vm", "disk", "nic", "storage", "vnet", "subnet", "nsg", "pip", "lb", "rt", "nat", "pe",
    "dns", "dnsz", "dnsr", "dnsfr", "dnsp", "agw", "afd", "waf", "kv", "id", "sp", "appreg", "aks", "pool", "acr",
    "app", "func", "plan", "sql", "cosmos", "pg", "mysql", "foundry", "monitor", "appi", "pp", "aca", "acaenv",
    "acajob", "redis", "amr", "sb", "eh",
];

/// `⚠` lines that are planted findings (`docs/DEMO.md`), not missing
/// fixtures: `(ARM id substring, line substring)`, both case-insensitive.
/// The warning test skips these lines; any other `⚠` still counts.
const PLANTED: &[(&str, &str)] = &[
    ("/registries/acrcontosoprod", "a shared username and password"),
    ("/containerApps/ca-orders-worker", "ca-orders-worker--v119"),
    ("/flexibleServers/mysql-reporting-legacy", "require_secure_transport"),
    ("/Redis/redis-orders-cache", "6379"),
    ("/namespaces/sb-orders-prod", "dead"),
    // core: failed operations in the Activity sections of contoso-prod (the
    // v119 rollout, the batch pool's quota, the guest's denied VM start).
    (crate::demo::PROD, "⚠ Failed | Create Deployment"),
    (crate::demo::PROD, "⚠ Failed | Create or Update Container App"),
    (crate::demo::PROD, "⚠ Failed | Create or Update Agent Pool"),
    (crate::demo::PROD, "⚠ Failed | Start Virtual Machine"),
];

fn planted(id: &str, line: &str) -> bool {
    let (id, line) = (id.to_lowercase(), line.to_lowercase());
    PLANTED.iter().any(|(i, l)| id.contains(&i.to_lowercase()) && line.contains(&l.to_lowercase()))
}

/// Audit checks the demo's data must trip (`nebaz --demo audit`), each a
/// planted finding. Each area appends its own.
const AUDIT_EXPECTED: &[&str] = &[
    // core: github-actions-deploy holds User Access Administrator on the subscription.
    "sub-privileged-guest-or-sp",
];

/// Every listed sub-tab's `ls` prefix (the audit is computed, not listed).
fn prefixes() -> Vec<String> {
    ServiceType::all()
        .into_iter()
        .filter(|s| !s.is_virtual())
        .flat_map(|s| s.views().iter().copied())
        .map(view_prefix)
        .collect()
}

async fn demo_ls(prefix: &str) -> Vec<Value> {
    let cli = demo_cli(&["ls", prefix]);
    let Some(Command::Ls(args)) = &cli.command else { unreachable!() };
    let out = ls(&cli, args, OutputFormat::Json)
        .await
        .unwrap_or_else(|f| panic!("ls {prefix}: {}", f.message()));
    let v: Value = serde_json::from_str(&out).expect("ls prints JSON");
    v["resources"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn every_sub_tab_has_demo_rows() {
    let all = prefixes();
    for p in EMPTY_YET {
        assert!(all.iter().any(|a| a == p), "EMPTY_YET names {p:?}, which is no sub-tab");
    }
    let (mut empty, mut filled_but_listed) = (Vec::new(), Vec::new());
    for p in &all {
        let rows = demo_ls(p).await;
        let listed = EMPTY_YET.contains(&p.as_str());
        if rows.is_empty() && !listed {
            empty.push(p.clone());
        }
        if !rows.is_empty() && listed {
            filled_but_listed.push(p.clone());
        }
    }
    assert!(empty.is_empty(), "demo sub-tabs with no rows: {empty:?} (add fixtures, docs/DEMO.md)");
    assert!(
        filled_but_listed.is_empty(),
        "these have demo rows now; take them out of EMPTY_YET: {filled_but_listed:?}"
    );
}

#[tokio::test]
async fn every_demo_row_opens_without_a_warning() {
    let (mut warned, mut clean_but_listed) = (Vec::new(), Vec::new());
    for p in prefixes() {
        let rows = demo_ls(&p).await;
        let mut lines = Vec::new();
        for id in rows.iter().filter_map(|r| r["id"].as_str()) {
            let cli = demo_cli(&["get", id, "--in", &p, "-o", "md"]);
            let Some(Command::Get(args)) = &cli.command else { unreachable!() };
            match get(&cli, args, OutputFormat::Md).await {
                Ok(out) => lines.extend(
                    out.lines().filter(|l| l.contains('⚠') && !planted(id, l)).map(|l| format!("{id}: {l}")),
                ),
                Err(f) => lines.push(format!("{id}: get failed: {}", f.message())),
            }
        }
        let listed = WARNS_YET.contains(&p.as_str());
        if !lines.is_empty() && !listed {
            warned.push(format!("{p}:\n    {}", lines.join("\n    ")));
        }
        if lines.is_empty() && !rows.is_empty() && listed {
            clean_but_listed.push(p);
        }
    }
    assert!(warned.is_empty(), "demo rows that open with a warning:\n  {}", warned.join("\n  "));
    assert!(
        clean_but_listed.is_empty(),
        "these open clean now; take them out of WARNS_YET: {clean_but_listed:?}"
    );
}

#[tokio::test]
async fn the_demo_audit_finds_every_planted_check() {
    let cli = demo_cli(&["audit", "--fail-on", "never"]);
    let Some(Command::Audit(args)) = &cli.command else { unreachable!() };
    let (out, _) = audit(&cli, args, OutputFormat::Json).await.unwrap_or_else(|f| panic!("audit: {}", f.message()));
    let v: Value = serde_json::from_str(&out).expect("audit prints JSON");
    let found: Vec<&str> = v["findings"].as_array().into_iter().flatten().filter_map(|f| f["check"].as_str()).collect();
    let missing: Vec<&&str> = AUDIT_EXPECTED.iter().filter(|c| !found.contains(c)).collect();
    assert!(missing.is_empty(), "the demo audit no longer finds {missing:?} (found {found:?})");
}
