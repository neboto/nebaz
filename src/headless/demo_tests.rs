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
];

/// Sub-tabs whose demo rows still open with a `⚠` line somewhere.
const WARNS_YET: &[&str] = &[
];

/// `⚠` lines that are planted findings (`docs/DEMO.md`), not missing
/// fixtures: `(ARM id substring, line substring)`, both case-insensitive.
/// The warning test skips these lines; any other `⚠` still counts.
const PLANTED: &[(&str, &str)] = &[
    ("/registries/acrcontosoprod", "a shared username and password"),
    ("/containerApps/ca-orders-worker", "ca-orders-worker--v119"),
    ("/containerApps/ca-orders-worker", "MANIFEST_UNKNOWN"),
    ("/flexibleServers/mysql-reporting-legacy", "require_secure_transport"),
    ("/flexibleServers/mysql-reporting-legacy", "allows every Azure service"),
    // All resources lists SQL databases, as ARM does; nebaz browses them
    // only as a section of their server, so `get` refuses the bare id.
    ("/providers/Microsoft.Sql/servers/sql-orders-prod/databases/", "not a type nebaz lists"),
    ("/Redis/redis-orders-cache", "6379"),
    ("/namespaces/sb-orders-prod", "dead"),
    // network: the branch office's backup VPN tunnel is down.
    ("/connections/cn-vpn-branch-office", "NotConnected"),
    // network: contoso-dev's endpoint to the partner Private Link service
    // waits for approval; Traffic Manager's on-premises DR endpoint is
    // degraded.
    ("/privateLinkServices/pls-orders-partner", "Pending"),
    ("/trafficManagerProfiles/tm-contoso-api", "Degraded"),
    // compute: caj-nightly-export's last execution failed (its Executions section).
    ("/jobs/caj-nightly-export", "caj-nightly-export-q7k2m9x"),
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
    // core: github-actions-deploy holds User Access Administrator and
    // Contributor on the subscription.
    "sub-privileged-guest-or-sp",
    "sub-contributor-guest-or-sp",
    // compute
    "aks-public-api",
    "aks-local-accounts",
    "acr-admin-user",
    "app-https-only",
    "app-min-tls",
    "app-ftps",
    "disk-unattached",
    // data
    "storage-blob-public-access",
    "storage-min-tls",
    "storage-public-network",
    "storage-shared-key",
    "kv-public-network",
    "kv-purge-protection",
    "sql-firewall-open",
    "sql-public-network",
    "cosmos-local-auth",
    "cosmos-public-network",
    "redis-non-ssl-port",
    "mysql-insecure-transport",
    "mysql-public-network",
    "mysql-firewall-open",
    "mysql-password-no-entra",
    "sb-local-auth",
    "sb-public-network",
    // identity
    "appreg-credential-expiry",
    "foundry-public-network",
    "foundry-local-auth",
    // network
    "nsg-open-internet",
    "subnet-pp-no-nsg",
    "subnet-no-nsg",
    "waf-not-blocking",
    "pip-unattached",
    "nic-orphaned",
    "vpn-connection-down",
    "flow-logs-missing",
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
                Err(f) if planted(id, f.message()) => {}
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

/// The `N` lens on the story's two NSG findings, from the demo fixtures
/// alone (nothing warm, so every subnet, NIC and NSG is a GET): Power
/// Platform's subnet meets `DenyAllOutbound` 4000, which shadows the
/// default VNet allow, and the jump box's NIC is open to SSH from the
/// internet through its subnet's NSG.
#[tokio::test]
async fn the_network_lens_finds_the_story_in_the_demo() {
    use crate::azure::nsg_eval::{build_lines, resolve, Dir, Known, RuleView, Seed};
    let fetch = |path: String| async move {
        let r = crate::demo::respond(&path, "api-version=2025-09-01", 0);
        match r.status {
            200 => serde_json::from_str::<Value>(&r.body).map_err(|e| e.to_string()),
            s => Err(format!("{s} {}", r.body)),
        }
    };
    let rg = |name: &str| format!("/subscriptions/{}/resourceGroups/{name}/providers/Microsoft.Network", crate::demo::PROD);
    let rule = |views: &[RuleView], name: &str| views.iter().find(|r| r.name == name).cloned();

    let subnet = format!("{}/virtualNetworks/vnet-hub-prod/subnets/snet-pp-injection", rg("rg-network-prod"));
    let r = resolve(Seed { subnets: vec![subnet], ..Default::default() }, Known::default(), fetch).await;
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let views: Vec<RuleView> = build_lines(&r, &[Dir::Outbound]).into_iter().filter_map(|l| l.rule).collect();
    let deny = rule(&views, "DenyAllOutbound").expect("the lockdown rule");
    assert!(!deny.allow && deny.priority == "4000" && deny.nsg_name == "nsg-pp-injection", "{deny:?}");
    let vnet = rule(&views, "AllowVnetOutBound").expect("the default rule");
    assert_eq!(vnet.shadowed_by.as_deref(), Some("4000 DenyAllOutbound"));

    let nic = format!("{}/networkInterfaces/nic-vm-jump-01", rg("rg-legacy-prod"));
    let r = resolve(Seed { nics: vec![nic], ..Default::default() }, Known::default(), fetch).await;
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let views: Vec<RuleView> = build_lines(&r, &[Dir::Inbound]).into_iter().filter_map(|l| l.rule).collect();
    let ssh = rule(&views, "AllowSSHInbound").expect("the vendor's SSH rule");
    assert!(ssh.allow && ssh.open_to_internet && ssh.nsg_name == "nsg-jump-prod", "{ssh:?}");
}

/// The demo's `appi-orders` carries an instrumentation key and connection
/// string, as a real ARM `GET` does; the row (and so the `e` view) must not.
#[test]
fn demo_app_insights_credentials_are_stripped() {
    use crate::azure::resource::Resource;
    use crate::azure::services::monitor::ComponentRow;
    let path = format!(
        "/subscriptions/{}/resourceGroups/rg-orders-prod/providers/Microsoft.Insights/components/appi-orders",
        crate::demo::PROD
    );
    let reply = crate::demo::respond(&path, "api-version=2020-02-02", 1_790_000_000);
    assert!(reply.body.contains("InstrumentationKey") && reply.body.contains("ConnectionString"), "the fixture keeps them");
    let v: Value = serde_json::from_str(&reply.body).expect("JSON");
    let raw = ComponentRow::from_json(&v, None).expect("parses").raw_content().unwrap_or_default();
    assert!(!raw.contains("InstrumentationKey") && !raw.contains("ConnectionString"), "{raw}");
}
