//! Every check over fixtures: a row that should fire, one that shouldn't,
//! parsed through the row type's real `from_json` so the checks read what
//! the lists carry.

use super::*;
use crate::audit::{run, RowKind};
use crate::azure::services::{
    aks, app_service, compute, container_apps, container_registry, cosmos, directory, edge, foundry, keyvault, messaging,
    network, postgres_mysql, power_platform, redis, sql, storage,
};
use crate::lazy::LazyStore;
use serde_json::json;

const SUB: &str = "00000000-0000-0000-0000-0000000000d1";
const NOW: i64 = 1_800_000_000; // 2027-01-15

fn id(provider_path: &str) -> String {
    format!("/subscriptions/{}/resourceGroups/rg/providers/{}", SUB, provider_path)
}

fn body(provider_path: &str, properties: Value) -> Value {
    json!({"id": id(provider_path), "name": name_of_id(&id(provider_path)), "location": "westeurope", "properties": properties})
}

fn boxed<T: Resource + 'static>(r: Option<T>) -> Box<dyn Resource> {
    Box::new(r.expect("fixture parses"))
}

/// Run every check over `lists` (and `lazy`), returning the findings and
/// notes of one check.
fn audit(check: &str, lists: &[(JumpView, Vec<Box<dyn Resource>>)], lazy: Option<&LazyStore>) -> Vec<AuditFinding> {
    let mut input = AuditInput::new(SUB, NOW);
    for (view, rows) in lists {
        input.add(*view, rows);
    }
    if let Some(l) = lazy {
        input.set_lazy(l);
    }
    run(&input).into_iter().filter(|f| f.check_id == check).collect()
}

fn findings(rows: &[AuditFinding]) -> Vec<(String, Severity)> {
    rows.iter().filter(|f| f.kind == RowKind::Finding).map(|f| (f.resource_name.clone(), f.severity)).collect()
}

fn notes(rows: &[AuditFinding]) -> Vec<String> {
    rows.iter().filter(|f| f.kind == RowKind::NotChecked).map(|f| f.list_note()).collect()
}

// ── Network ──

fn rule(name: &str, priority: i64, source: &str, port: &str, protocol: &str) -> Value {
    json!({"name": name, "properties": {"priority": priority, "direction": "Inbound", "access": "Allow",
        "protocol": protocol, "sourceAddressPrefix": source, "sourcePortRange": "*",
        "destinationAddressPrefix": "*", "destinationPortRange": port}})
}

fn nsg(name: &str, rules: Vec<Value>) -> Box<dyn Resource> {
    let v = body(&format!("Microsoft.Network/networkSecurityGroups/{name}"), json!({"securityRules": rules,
        "defaultSecurityRules": [rule("AllowVnetInBound", 65000, "VirtualNetwork", "*", "*")]}));
    boxed(network::NsgRow::from_json(&v, None))
}

#[test]
fn nsg_rules_from_the_internet_are_graded_by_port() {
    let lists = vec![(
        V::NetworkSecurityGroups,
        vec![
            nsg("nsg-ssh", vec![rule("ssh", 100, "*", "22", "Tcp")]),
            nsg("nsg-sql", vec![rule("sql", 100, "Internet", "1433", "Tcp")]),
            nsg("nsg-app", vec![rule("app", 100, "0.0.0.0/0", "8080", "Tcp")]),
            nsg("nsg-web", vec![rule("https", 100, "Internet", "443", "Tcp")]),
            nsg("nsg-all", vec![rule("any", 100, "Internet", "*", "*")]),
            nsg("nsg-office", vec![rule("ssh", 100, "203.0.113.0/24", "22", "Tcp")]),
        ],
    )];
    let rows = audit("nsg-open-internet", &lists, None);
    let mut got = findings(&rows);
    got.sort();
    assert_eq!(
        got,
        vec![
            ("nsg-all".into(), Severity::Critical),
            ("nsg-app".into(), Severity::Medium),
            ("nsg-sql".into(), Severity::High),
            ("nsg-ssh".into(), Severity::Critical),
            ("nsg-web".into(), Severity::Low),
        ],
        "a rule from a known range never fires; default rules are not the user's"
    );
    let ssh = rows.iter().find(|f| f.resource_name == "nsg-ssh").unwrap();
    assert!(ssh.evidence[0].contains("100 ssh") && ssh.evidence[0].contains("22"), "{:?}", ssh.evidence);
    assert_eq!(ssh.resource_id, id("Microsoft.Network/networkSecurityGroups/nsg-ssh"), "Enter routes on the ARM id");
}

#[test]
fn port_ranges_and_icmp_grade_as_expected() {
    let r = |port: &str, proto: &str| network::SecurityRule::from_json(&rule("r", 1, "*", port, proto), false);
    assert_eq!(rule_severity(&r("3000-4000", "Tcp")), Severity::Critical, "spans 3389");
    assert_eq!(rule_severity(&r("5000-5500", "Tcp")), Severity::High, "spans 5432");
    assert_eq!(rule_severity(&r("80", "Tcp")), Severity::Low);
    assert_eq!(rule_severity(&r("*", "Icmp")), Severity::Low);
}

fn vnet_with_subnets(subnets: Value) -> Box<dyn Resource> {
    let v = body("Microsoft.Network/virtualNetworks/vnet-pp", json!({"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": subnets}));
    boxed(network::VnetRow::from_json(&v, None))
}

fn subnet(name: &str, delegation: Option<&str>, nsg: Option<&str>) -> Value {
    let mut p = json!({"addressPrefix": "10.0.1.0/24"});
    if let Some(d) = delegation {
        p["delegations"] = json!([{"name": "d", "properties": {"serviceName": d}}]);
    }
    if let Some(n) = nsg {
        p["networkSecurityGroup"] = json!({"id": id(&format!("Microsoft.Network/networkSecurityGroups/{n}"))});
    }
    json!({"id": id(&format!("Microsoft.Network/virtualNetworks/vnet-pp/subnets/{name}")), "name": name, "properties": p})
}

#[test]
fn a_power_platform_subnet_without_an_nsg_is_medium() {
    let lists = vec![(
        V::VirtualNetworks,
        vec![vnet_with_subnets(json!([
            subnet("snet-pp", Some("Microsoft.PowerPlatform/enterprisePolicies"), None),
            subnet("snet-pp-guarded", Some("Microsoft.PowerPlatform/enterprisePolicies"), Some("nsg-pp")),
            subnet("snet-web", Some("Microsoft.Web/serverFarms"), None),
        ]))],
    )];
    assert_eq!(findings(&audit("subnet-pp-no-nsg", &lists, None)), vec![("vnet-pp/snet-pp".into(), Severity::Medium)]);
}

// ── Storage ──

fn account(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(storage::StorageAccountRow::from_json(&body(&format!("Microsoft.Storage/storageAccounts/{name}"), props), None))
}

#[test]
fn storage_checks_read_the_account_properties() {
    let lists = vec![(
        V::StorageAccounts,
        vec![
            account(
                "stloose",
                json!({"allowBlobPublicAccess": true, "allowSharedKeyAccess": true, "minimumTlsVersion": "TLS1_0",
                    "supportsHttpsTrafficOnly": false, "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"}}),
            ),
            account(
                "sttight",
                json!({"allowBlobPublicAccess": false, "allowSharedKeyAccess": false, "minimumTlsVersion": "TLS1_2",
                    "supportsHttpsTrafficOnly": true, "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Deny"}}),
            ),
        ],
    )];
    for (check, sev) in [
        ("storage-blob-public-access", Severity::High),
        ("storage-shared-key", Severity::Medium),
        ("storage-min-tls", Severity::High),
        ("storage-https-only", Severity::High),
        ("storage-public-network", Severity::Medium),
    ] {
        assert_eq!(findings(&audit(check, &lists, None)), vec![("stloose".into(), sev)], "{check}");
    }
}

#[test]
fn unset_shared_key_access_counts_as_allowed() {
    let lists = vec![(V::StorageAccounts, vec![account("stdefault", json!({}))])];
    let rows = audit("storage-shared-key", &lists, None);
    assert_eq!(rows[0].reason, "allowSharedKeyAccess unset (allowed)");
    assert!(findings(&audit("storage-blob-public-access", &lists, None)).is_empty(), "unset is not evidence");
}

#[test]
fn tls_spellings_of_every_provider() {
    for low in ["TLS1_0", "TLS1_1", "1.0", "1.1", "Tls", "Tls11", "None"] {
        assert!(tls_below_1_2(low), "{low}");
    }
    for ok in ["TLS1_2", "1.2", "1.3", "Tls12", "TLS1_3"] {
        assert!(!tls_below_1_2(ok), "{ok}");
    }
}

// ── Key Vault ──

fn vault(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(keyvault::VaultRow::from_json(&body(&format!("Microsoft.KeyVault/vaults/{name}"), props), None))
}

#[test]
fn key_vault_checks() {
    let lists = vec![(
        V::KeyVaults,
        vec![
            vault("kv-open", json!({"enableSoftDelete": false, "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"}})),
            vault("kv-closed", json!({"enableSoftDelete": true, "enablePurgeProtection": true, "publicNetworkAccess": "Disabled"})),
        ],
    )];
    assert_eq!(findings(&audit("kv-purge-protection", &lists, None)), vec![("kv-open".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("kv-soft-delete", &lists, None)), vec![("kv-open".into(), Severity::High)]);
    assert_eq!(findings(&audit("kv-public-network", &lists, None)), vec![("kv-open".into(), Severity::Medium)]);
}

// ── SQL ──

fn sql_server(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(sql::SqlServerRow::from_json(&body(&format!("Microsoft.Sql/servers/{name}"), props), None))
}

fn fw(name: &str, start: &str, end: &str) -> Value {
    json!({"name": name, "properties": {"startIpAddress": start, "endIpAddress": end}})
}

#[test]
fn sql_firewall_reads_the_warm_lazy_rules_and_notes_the_rest() {
    let lists = vec![(
        V::SqlServers,
        vec![
            sql_server("sql-open", json!({"publicNetworkAccess": "Enabled", "minimalTlsVersion": "1.0"})),
            sql_server("sql-azure", json!({"publicNetworkAccess": "Disabled", "minimalTlsVersion": "1.2"})),
            sql_server("sql-unvisited", json!({"publicNetworkAccess": "Disabled"})),
        ],
    )];
    let mut lazy = LazyStore::new(0);
    lazy.sql_firewall_rules
        .apply(id("Microsoft.Sql/servers/sql-open"), Ok(vec![fw("everyone", "0.0.0.0", "255.255.255.255"), fw("office", "203.0.113.1", "203.0.113.9")]));
    lazy.sql_firewall_rules.apply(id("Microsoft.Sql/servers/sql-azure"), Ok(vec![fw("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0")]));
    let rows = audit("sql-firewall-open", &lists, Some(&lazy));
    assert_eq!(
        findings(&rows),
        vec![("sql-open".into(), Severity::Critical), ("sql-azure".into(), Severity::Low)]
    );
    assert_eq!(notes(&rows), vec!["1 of 3 not checked — r fetches firewall rules".to_string()]);
    assert_eq!(findings(&audit("sql-public-network", &lists, None)), vec![("sql-open".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("sql-min-tls", &lists, None)), vec![("sql-open".into(), Severity::Medium)]);
}

#[test]
fn with_no_lazy_data_the_firewall_check_is_all_note() {
    let lists = vec![(V::SqlServers, vec![sql_server("sql-1", json!({}))])];
    let rows = audit("sql-firewall-open", &lists, None);
    assert!(findings(&rows).is_empty());
    assert_eq!(notes(&rows).len(), 1);
}

// ── Cosmos ──

fn cosmos_account(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(cosmos::CosmosAccountRow::from_json(&body(&format!("Microsoft.DocumentDB/databaseAccounts/{name}"), props), None))
}

#[test]
fn cosmos_checks() {
    let lists = vec![(
        V::CosmosAccounts,
        vec![
            cosmos_account("cosmos-open", json!({"publicNetworkAccess": "Enabled", "ipRules": []})),
            cosmos_account("cosmos-ranged", json!({"publicNetworkAccess": "Enabled", "ipRules": [{"ipAddressOrRange": "203.0.113.0/24"}], "disableLocalAuth": true})),
            cosmos_account("cosmos-private", json!({"publicNetworkAccess": "Disabled", "disableLocalAuth": true})),
        ],
    )];
    assert_eq!(
        findings(&audit("cosmos-public-network", &lists, None)),
        vec![("cosmos-open".into(), Severity::Medium), ("cosmos-ranged".into(), Severity::Low)]
    );
    assert_eq!(findings(&audit("cosmos-local-auth", &lists, None)), vec![("cosmos-open".into(), Severity::Medium)]);
}

// ── AKS ──

fn cluster(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(aks::ClusterRow::from_json(&body(&format!("Microsoft.ContainerService/managedClusters/{name}"), props), None))
}

#[test]
fn aks_checks() {
    let lists = vec![(
        V::Clusters,
        vec![
            cluster("aks-open", json!({"enableRBAC": false})),
            cluster(
                "aks-locked",
                json!({"enableRBAC": true, "disableLocalAccounts": true,
                    "apiServerAccessProfile": {"authorizedIPRanges": ["203.0.113.0/24"]}}),
            ),
            cluster("aks-private", json!({"enableRBAC": true, "disableLocalAccounts": true, "apiServerAccessProfile": {"enablePrivateCluster": true}})),
        ],
    )];
    assert_eq!(findings(&audit("aks-public-api", &lists, None)), vec![("aks-open".into(), Severity::High)]);
    assert_eq!(findings(&audit("aks-local-accounts", &lists, None)), vec![("aks-open".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("aks-rbac-disabled", &lists, None)), vec![("aks-open".into(), Severity::High)]);
}

// ── ACR ──

#[test]
fn acr_checks() {
    let reg = |name: &str, props: Value| {
        boxed(container_registry::RegistryRow::from_json(&body(&format!("Microsoft.ContainerRegistry/registries/{name}"), props), None))
    };
    let lists = vec![(
        V::Registries,
        vec![reg("acropen", json!({"adminUserEnabled": true, "anonymousPullEnabled": true})), reg("acrok", json!({"adminUserEnabled": false}))],
    )];
    assert_eq!(findings(&audit("acr-admin-user", &lists, None)), vec![("acropen".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("acr-anonymous-pull", &lists, None)), vec![("acropen".into(), Severity::High)]);
}

// ── App Service ──

#[test]
fn app_service_checks_read_the_site_and_its_warm_config() {
    let site = |name: &str, https: bool| {
        let mut v = body(&format!("Microsoft.Web/sites/{name}"), json!({"httpsOnly": https}));
        v["kind"] = json!("app");
        boxed(app_service::SiteRow::from_json(&v, None))
    };
    let lists = vec![(V::WebApps, vec![site("app-plain", false), site("app-ok", true)])];
    assert_eq!(findings(&audit("app-https-only", &lists, None)), vec![("app-plain".into(), Severity::High)]);
    let mut lazy = LazyStore::new(0);
    lazy.site_configs.apply(
        id("Microsoft.Web/sites/app-plain"),
        Ok(json!({"properties": {"minTlsVersion": "1.0", "ftpsState": "AllAllowed"}})),
    );
    lazy.site_configs.insert_loading(id("Microsoft.Web/sites/app-ok"));
    let tls = audit("app-min-tls", &lists, Some(&lazy));
    assert_eq!(findings(&tls), vec![("app-plain".into(), Severity::Medium)]);
    assert_eq!(notes(&tls), vec!["1 loading…".to_string()]);
    assert_eq!(findings(&audit("app-ftps", &lists, Some(&lazy))), vec![("app-plain".into(), Severity::Medium)]);
}

// ── Redis ──

fn redis_cache(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(redis::RedisCacheRow::from_json(&body(&format!("Microsoft.Cache/Redis/{name}"), props), None))
}

fn managed_redis(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(redis::ManagedRedisRow::from_json(&body(&format!("Microsoft.Cache/redisEnterprise/{name}"), props), None))
}

#[test]
fn redis_port_and_tls_checks_read_the_cache_properties() {
    let lists = vec![(
        V::RedisCaches,
        vec![
            redis_cache("redis-plain", json!({"enableNonSslPort": true, "port": 6379, "minimumTlsVersion": "1.0"})),
            redis_cache("redis-tls", json!({"enableNonSslPort": false, "minimumTlsVersion": "1.2"})),
        ],
    )];
    assert_eq!(findings(&audit("redis-non-ssl-port", &lists, None)), vec![("redis-plain".into(), Severity::High)]);
    assert_eq!(findings(&audit("redis-min-tls", &lists, None)), vec![("redis-plain".into(), Severity::Medium)]);
    let amr = vec![(
        V::ManagedRedis,
        vec![
            managed_redis("amr-old", json!({"minimumTlsVersion": "1.1"})),
            managed_redis("amr-ok", json!({"minimumTlsVersion": "1.2"})),
        ],
    )];
    assert_eq!(findings(&audit("amr-min-tls", &amr, None)), vec![("amr-old".into(), Severity::Medium)]);
    assert_eq!(notes(&audit("amr-min-tls", &lists, None)), vec!["not checked — load @redis Managed Redis".to_string()]);
}

#[test]
fn a_public_redis_cache_with_no_firewall_rules_reads_the_warm_network_section() {
    let subnet = id("Microsoft.Network/virtualNetworks/vnet/subnets/snet-redis");
    let lists = vec![(
        V::RedisCaches,
        vec![
            redis_cache("redis-open", json!({"publicNetworkAccess": "Enabled"})),
            redis_cache("redis-fenced", json!({"publicNetworkAccess": "Enabled"})),
            redis_cache("redis-private", json!({"publicNetworkAccess": "Disabled"})),
            redis_cache("redis-injected", json!({"subnetId": subnet})),
            redis_cache("redis-unvisited", json!({})),
        ],
    )];
    let mut lazy = LazyStore::new(0);
    lazy.redis_firewall_rules.apply(id("Microsoft.Cache/Redis/redis-open"), Ok(vec![]));
    lazy.redis_firewall_rules.apply(
        id("Microsoft.Cache/Redis/redis-fenced"),
        Ok(vec![json!({"name": "office", "properties": {"startIP": "203.0.113.1", "endIP": "203.0.113.9"}})]),
    );
    let rows = audit("redis-public-no-firewall", &lists, Some(&lazy));
    assert_eq!(findings(&rows), vec![("redis-open".into(), Severity::Medium)]);
    // Private and VNet-injected caches need no rules; the unvisited one is
    // counted, never passed.
    assert_eq!(notes(&rows), vec!["1 of 3 not checked — r fetches firewall rules".to_string()]);
}

// ── PostgreSQL & MySQL ──

fn pg(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(postgres_mysql::FlexibleServerRow::from_json(
        &body(&format!("Microsoft.DBforPostgreSQL/flexibleServers/{name}"), props),
        None,
    ))
}

fn mysql(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(postgres_mysql::FlexibleServerRow::from_json(
        &body(&format!("Microsoft.DBforMySQL/flexibleServers/{name}"), props),
        None,
    ))
}

fn param(name: &str, value: &str) -> Value {
    json!({"name": name, "properties": {"value": value}})
}

#[test]
fn flexible_server_public_access_skips_vnet_integrated_and_private_servers() {
    let subnet = id("Microsoft.Network/virtualNetworks/vnet/subnets/snet-pg");
    let lists = vec![(
        V::PostgresServers,
        vec![
            pg("pg-public", json!({"network": {"publicNetworkAccess": "Enabled"}})),
            pg("pg-private", json!({"network": {"publicNetworkAccess": "Disabled"}})),
            pg("pg-vnet", json!({"network": {"publicNetworkAccess": "Disabled", "delegatedSubnetResourceId": subnet}})),
        ],
    )];
    assert_eq!(findings(&audit("pg-public-network", &lists, None)), vec![("pg-public".into(), Severity::Medium)]);
    assert_eq!(
        notes(&audit("mysql-public-network", &lists, None)),
        vec!["not checked — load @pg MySQL".to_string()],
        "MySQL has its own list"
    );
}

#[test]
fn flexible_server_firewall_grades_the_internet_and_allow_azure_rules() {
    let lists = vec![(
        V::MysqlServers,
        vec![
            mysql("my-world", json!({"network": {"publicNetworkAccess": "Enabled"}})),
            mysql("my-azure", json!({"network": {"publicNetworkAccess": "Enabled"}})),
            mysql("my-office", json!({"network": {"publicNetworkAccess": "Enabled"}})),
            mysql("my-closed", json!({"network": {"publicNetworkAccess": "Disabled"}})),
            mysql("my-unvisited", json!({"network": {"publicNetworkAccess": "Enabled"}})),
        ],
    )];
    let mut lazy = LazyStore::new(0);
    let fid = |n: &str| id(&format!("Microsoft.DBforMySQL/flexibleServers/{n}"));
    lazy.flex_firewall_rules.apply(fid("my-world"), Ok(vec![fw("AllowAll", "0.0.0.0", "255.255.255.255")]));
    lazy.flex_firewall_rules.apply(
        fid("my-azure"),
        Ok(vec![fw("AllowAllAzureServicesAndResourcesWithinAzureIps_2026", "0.0.0.0", "0.0.0.0")]),
    );
    lazy.flex_firewall_rules.apply(fid("my-office"), Ok(vec![fw("office", "203.0.113.1", "203.0.113.9")]));
    let rows = audit("mysql-firewall-open", &lists, Some(&lazy));
    let mut got = findings(&rows);
    got.sort();
    assert_eq!(got, vec![("my-azure".into(), Severity::Low), ("my-world".into(), Severity::Critical)]);
    // Public access off: rules admit nothing, so it is neither a finding
    // nor a gap; the unvisited server is counted, never passed.
    assert_eq!(notes(&rows), vec!["1 of 4 not checked — r fetches firewall rules".to_string()]);
}

#[test]
fn flexible_server_transport_and_tls_read_the_warm_parameters() {
    let lists = vec![
        (V::PostgresServers, vec![pg("pg-plain", json!({})), pg("pg-strict", json!({})), pg("pg-unvisited", json!({}))]),
        (V::MysqlServers, vec![mysql("my-old", json!({})), mysql("my-new", json!({}))]),
    ];
    let mut lazy = LazyStore::new(0);
    let pid = |n: &str| id(&format!("Microsoft.DBforPostgreSQL/flexibleServers/{n}"));
    let mid = |n: &str| id(&format!("Microsoft.DBforMySQL/flexibleServers/{n}"));
    lazy.flex_parameters.apply(
        pid("pg-plain"),
        Ok(vec![param("require_secure_transport", "off"), param("ssl_min_protocol_version", "TLSv1.1")]),
    );
    lazy.flex_parameters.apply(
        pid("pg-strict"),
        Ok(vec![param("require_secure_transport", "on"), param("ssl_min_protocol_version", "TLSv1.2")]),
    );
    lazy.flex_parameters.apply(
        mid("my-old"),
        Ok(vec![param("require_secure_transport", "OFF"), param("tls_version", "TLSv1,TLSv1.1,TLSv1.2")]),
    );
    lazy.flex_parameters.apply(
        mid("my-new"),
        Ok(vec![param("require_secure_transport", "ON"), param("tls_version", "TLSv1.2,TLSv1.3")]),
    );
    let rows = audit("pg-insecure-transport", &lists, Some(&lazy));
    assert_eq!(findings(&rows), vec![("pg-plain".into(), Severity::High)]);
    assert_eq!(notes(&rows), vec!["1 of 3 not checked — r fetches server parameters".to_string()]);
    assert_eq!(findings(&audit("pg-min-tls", &lists, Some(&lazy))), vec![("pg-plain".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("mysql-insecure-transport", &lists, Some(&lazy))), vec![("my-old".into(), Severity::High)]);
    assert_eq!(findings(&audit("mysql-min-tls", &lists, Some(&lazy))), vec![("my-old".into(), Severity::Medium)]);
    // Nothing warm: every server is "not checked", never passed.
    assert_eq!(
        notes(&audit("mysql-insecure-transport", &lists, None)),
        vec!["2 of 2 not checked — r fetches server parameters".to_string()]
    );
}

#[test]
fn flexible_server_password_auth_without_an_entra_admin_is_low() {
    let lists = vec![
        (
            V::PostgresServers,
            vec![
                pg("pg-password", json!({"authConfig": {"passwordAuth": "Enabled", "activeDirectoryAuth": "Disabled"}})),
                pg("pg-both", json!({"authConfig": {"passwordAuth": "Enabled", "activeDirectoryAuth": "Enabled"}})),
                pg("pg-entra", json!({"authConfig": {"passwordAuth": "Disabled", "activeDirectoryAuth": "Enabled"}})),
            ],
        ),
        (V::MysqlServers, vec![mysql("my-noadmin", json!({})), mysql("my-admin", json!({}))]),
    ];
    let mut lazy = LazyStore::new(0);
    lazy.flex_admins.apply(id("Microsoft.DBforPostgreSQL/flexibleServers/pg-both"), Ok(vec![]));
    lazy.flex_admins.apply(id("Microsoft.DBforMySQL/flexibleServers/my-noadmin"), Ok(vec![]));
    lazy.flex_admins.apply(
        id("Microsoft.DBforMySQL/flexibleServers/my-admin"),
        Ok(vec![json!({"properties": {"administratorType": "ActiveDirectory", "login": "dba", "sid": "s"}})]),
    );
    let mut got = findings(&audit("pg-password-no-entra", &lists, Some(&lazy)));
    got.sort();
    assert_eq!(got, vec![("pg-both".into(), Severity::Low), ("pg-password".into(), Severity::Low)]);
    assert_eq!(findings(&audit("mysql-password-no-entra", &lists, Some(&lazy))), vec![("my-noadmin".into(), Severity::Low)]);
}

// ── Messaging ──

fn service_bus(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(messaging::ServiceBusRow::from_json(&body(&format!("Microsoft.ServiceBus/namespaces/{name}"), props), None))
}

fn event_hubs(name: &str, props: Value) -> Box<dyn Resource> {
    boxed(messaging::EventHubsRow::from_json(&body(&format!("Microsoft.EventHub/namespaces/{name}"), props), None))
}

#[test]
fn messaging_local_auth_and_tls_read_the_namespace() {
    let sb = vec![(
        V::ServiceBusNamespaces,
        vec![
            service_bus("sb-keys", json!({"minimumTlsVersion": "1.0"})),
            service_bus("sb-entra", json!({"disableLocalAuth": true, "minimumTlsVersion": "1.2"})),
        ],
    )];
    assert_eq!(findings(&audit("sb-local-auth", &sb, None)), vec![("sb-keys".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("sb-min-tls", &sb, None)), vec![("sb-keys".into(), Severity::Medium)]);
    let eh = vec![(
        V::EventHubNamespaces,
        vec![
            event_hubs("eh-keys", json!({"disableLocalAuth": false, "minimumTlsVersion": "1.1"})),
            event_hubs("eh-entra", json!({"disableLocalAuth": true, "minimumTlsVersion": "1.2"})),
        ],
    )];
    assert_eq!(findings(&audit("eh-local-auth", &eh, None)), vec![("eh-keys".into(), Severity::Medium)]);
    assert_eq!(findings(&audit("eh-min-tls", &eh, None)), vec![("eh-keys".into(), Severity::Medium)]);
    // Event Hubs not cached: its checks say so.
    assert_eq!(notes(&audit("eh-local-auth", &sb, None)), vec!["not checked — load @sb Event Hubs".to_string()]);
}

#[test]
fn a_messaging_namespace_open_to_every_network_reads_the_warm_rule_set() {
    let lists = vec![(
        V::ServiceBusNamespaces,
        vec![
            service_bus("sb-allow", json!({"publicNetworkAccess": "Enabled"})),
            service_bus("sb-deny-empty", json!({})),
            service_bus("sb-fenced", json!({})),
            service_bus("sb-private", json!({"publicNetworkAccess": "Disabled"})),
            service_bus("sb-unvisited", json!({})),
        ],
    )];
    let rules = |action: &str, ips: Value| json!({"properties": {"defaultAction": action, "ipRules": ips, "virtualNetworkRules": []}});
    let mut lazy = LazyStore::new(0);
    let ns = |n: &str| id(&format!("Microsoft.ServiceBus/namespaces/{n}"));
    lazy.messaging_network_rules.apply(ns("sb-allow"), Ok(rules("Allow", json!([]))));
    lazy.messaging_network_rules.apply(ns("sb-deny-empty"), Ok(rules("Deny", json!([]))));
    lazy.messaging_network_rules.apply(ns("sb-fenced"), Ok(rules("Deny", json!([{"ipMask": "203.0.113.0/24"}]))));
    let rows = audit("sb-public-network", &lists, Some(&lazy));
    assert_eq!(
        findings(&rows),
        vec![("sb-allow".into(), Severity::Medium), ("sb-deny-empty".into(), Severity::Medium)]
    );
    assert_eq!(notes(&rows), vec!["1 of 4 not checked — r fetches network rule sets".to_string()]);
}

// ── Container Apps and Power Platform ──

fn aca(name: &str, env: &str, configuration: Value) -> Box<dyn Resource> {
    let v = body(
        &format!("Microsoft.App/containerApps/{name}"),
        json!({"environmentId": id(&format!("Microsoft.App/managedEnvironments/{env}")), "configuration": configuration,
            "template": {"containers": [{"name": "c", "image": "example/c:1"}]}}),
    );
    boxed(container_apps::ContainerAppRow::from_json(&v, None))
}

fn environment(name: &str, internal: bool, vnet: &str) -> Box<dyn Resource> {
    let v = body(
        &format!("Microsoft.App/managedEnvironments/{name}"),
        json!({"vnetConfiguration": {"internal": internal,
            "infrastructureSubnetId": id(&format!("Microsoft.Network/virtualNetworks/{vnet}/subnets/snet-aca"))}}),
    );
    boxed(container_apps::EnvironmentRow::from_json(&v, None))
}

fn policy(name: &str, vnet: &str, health: &str) -> Box<dyn Resource> {
    let mut v = body(
        &format!("Microsoft.PowerPlatform/enterprisePolicies/{name}"),
        json!({"healthStatus": health, "networkInjection": {"virtualNetworks": [
            {"id": id(&format!("Microsoft.Network/virtualNetworks/{vnet}")), "subnet": {"name": "snet-pp"}}
        ]}}),
    );
    v["kind"] = json!("NetworkInjection");
    boxed(power_platform::EnterprisePolicyRow::from_json(&v, None))
}

#[test]
fn aca_ingress_is_graded_by_the_environment_when_it_is_cached() {
    let open = json!({"ingress": {"external": true, "targetPort": 80}});
    let apps = vec![
        aca("api-public", "cae-ext", open.clone()),
        aca("api-vnet", "cae-int", open.clone()),
        aca("api-ranged", "cae-ext", json!({"ingress": {"external": true, "ipSecurityRestrictions": [{"name": "office", "action": "Allow", "ipAddressRange": "203.0.113.0/24"}]}})),
        aca("api-internal", "cae-ext", json!({"ingress": {"external": false}})),
        aca("worker", "cae-ext", json!({})),
    ];
    let envs = vec![environment("cae-ext", false, "vnet-a"), environment("cae-int", true, "vnet-b")];
    let lists = vec![(V::ContainerApps, apps), (V::ContainerAppEnvironments, envs)];
    let mut got = findings(&audit("aca-ingress-open", &lists, None));
    got.sort();
    assert_eq!(got, vec![("api-public".into(), Severity::Medium), ("api-vnet".into(), Severity::Low)]);
}

#[test]
fn aca_allow_insecure_and_plain_secrets() {
    let lists = vec![(
        V::ContainerApps,
        vec![
            aca(
                "api",
                "cae",
                json!({"ingress": {"external": true, "allowInsecure": true},
                    "secrets": [{"name": "db-password"}, {"name": "api-key", "keyVaultUrl": "https://kv/secrets/api-key", "identity": "system"}]}),
            ),
            aca("clean", "cae", json!({"secrets": [{"name": "x", "keyVaultUrl": "https://kv/secrets/x", "identity": "system"}]})),
        ],
    )];
    assert_eq!(findings(&audit("aca-allow-insecure", &lists, None)), vec![("api".into(), Severity::Medium)]);
    let secrets = audit("aca-secrets-not-kv", &lists, None);
    assert_eq!(findings(&secrets), vec![("api".into(), Severity::Low)]);
    assert!(secrets[0].evidence[0].contains("db-password") && !secrets[0].evidence.iter().any(|e| e.contains("api-key:")));
}

#[test]
fn an_external_environment_in_a_power_platform_vnet_is_info_and_needs_both_lists() {
    let envs = || vec![environment("cae-ext", false, "vnet-pp"), environment("cae-int", true, "vnet-pp"), environment("cae-elsewhere", false, "vnet-x")];
    let only_envs = vec![(V::ContainerAppEnvironments, envs())];
    assert_eq!(notes(&audit("aca-env-external-pp-vnet", &only_envs, None)), vec!["not checked — load @pp".to_string()]);
    let lists = vec![(V::ContainerAppEnvironments, envs()), (V::EnterprisePolicies, vec![policy("ep-vnet", "vnet-pp", "Healthy")])];
    let rows = audit("aca-env-external-pp-vnet", &lists, None);
    assert_eq!(findings(&rows), vec![("cae-ext".into(), Severity::Info)]);
    assert_eq!(rows[0].state_label(), "info");
}

#[test]
fn an_unhealthy_power_platform_policy_is_medium() {
    let lists = vec![(V::EnterprisePolicies, vec![policy("ep-ok", "v", "Healthy"), policy("ep-bad", "v", "Undetermined")])];
    assert_eq!(findings(&audit("pp-policy-unhealthy", &lists, None)), vec![("ep-bad".into(), Severity::Medium)]);
}

// ── Edge ──

fn waf(path: &str, settings: Value, links: Value) -> Box<dyn Resource> {
    let mut props = json!({"policySettings": settings});
    props.as_object_mut().unwrap().extend(links.as_object().unwrap().clone());
    boxed(edge::WafPolicyRow::from_json(&body(path, props), None))
}

#[test]
fn a_waf_policy_that_does_not_block_is_medium_when_attached() {
    let agw = |name: &str| json!({"applicationGateways": [{"id": id(&format!("Microsoft.Network/applicationGateways/{name}"))}]});
    let lists = vec![(
        V::WafPolicies,
        vec![
            waf("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-detect",
                json!({"state": "Enabled", "mode": "Detection"}), agw("agw-1")),
            waf("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-prevent",
                json!({"state": "Enabled", "mode": "Prevention"}), agw("agw-2")),
            waf("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-spare",
                json!({"state": "Enabled", "mode": "Detection"}), json!({})),
            waf("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/wafafdoff",
                json!({"enabledState": "Disabled", "mode": "Prevention"}),
                json!({"securityPolicyLinks": [{"id": id("Microsoft.Cdn/profiles/afd/securityPolicies/sp")}]})),
        ],
    )];
    let rows = audit("waf-not-blocking", &lists, None);
    assert_eq!(
        findings(&rows),
        vec![("waf-detect".into(), Severity::Medium), ("wafafdoff".into(), Severity::Medium)],
        "Prevention passes; an unattached policy protects nothing either way"
    );
    let off = rows.iter().find(|f| f.resource_name == "wafafdoff").unwrap();
    assert_eq!(off.reason, "policy disabled");
    assert!(off.evidence.iter().any(|e| e == "kind: Front Door"), "{:?}", off.evidence);
}

// ── Foundry ──

fn ai_account(name: &str, props: Value) -> Box<dyn Resource> {
    let mut v = body(&format!("Microsoft.CognitiveServices/accounts/{name}"), props);
    v["kind"] = json!("AIServices");
    boxed(foundry::FoundryRow::from_json(&v, None))
}

#[test]
fn foundry_network_and_key_auth() {
    let lists = vec![(
        V::AiAccounts,
        vec![
            ai_account("ai-open", json!({"publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"}})),
            ai_account("ai-ranged", json!({"publicNetworkAccess": "Enabled", "disableLocalAuth": true,
                "networkAcls": {"defaultAction": "Deny", "ipRules": [{"value": "203.0.113.24"}]}})),
            ai_account("ai-private", json!({"publicNetworkAccess": "Disabled", "disableLocalAuth": false})),
        ],
    )];
    assert_eq!(findings(&audit("foundry-public-network", &lists, None)), vec![("ai-open".into(), Severity::Medium)]);
    assert_eq!(
        findings(&audit("foundry-local-auth", &lists, None)),
        vec![("ai-open".into(), Severity::Medium), ("ai-private".into(), Severity::Medium)],
        "unset is the service default: keys work"
    );
}

// ── Compute ──

fn disk(name: &str, state: &str) -> Box<dyn Resource> {
    let mut v = body(&format!("Microsoft.Compute/disks/{name}"), json!({"diskState": state, "diskSizeGB": 1024}));
    v["sku"] = json!({"name": "Premium_LRS"});
    boxed(compute::DiskRow::from_json(&v, None))
}

#[test]
fn an_unattached_disk_is_info() {
    let lists = vec![(V::Disks, vec![disk("d-loose", "Unattached"), disk("d-used", "Attached"), disk("d-reserved", "Reserved")])];
    let rows = audit("disk-unattached", &lists, None);
    assert_eq!(findings(&rows), vec![("d-loose".into(), Severity::Info)], "Reserved is a deallocated VM's disk");
    assert_eq!(rows[0].reason, "unattached, 1024 GiB");
}

// ── Directory ──

fn iso(unix: i64) -> String {
    // Days-from-civil inverse is overkill here: fixed dates around NOW.
    match unix {
        u if u < NOW => "2026-01-01T00:00:00Z".into(),
        u if u < NOW + 30 * 86_400 => "2027-01-20T00:00:00Z".into(),
        _ => "2030-01-01T00:00:00Z".into(),
    }
}

#[test]
fn app_registration_and_sp_credentials_are_graded_by_expiry() {
    let app = |oid: &str, name: &str, end: i64| {
        let v = json!({"id": oid, "appId": oid, "displayName": name,
            "passwordCredentials": [{"displayName": "ci", "keyId": "k", "endDateTime": iso(end)}]});
        boxed(directory::AppRegistrationRow::from_json(&v, Some("t"), NOW))
    };
    let lists = vec![(
        V::AppRegistrations,
        vec![
            app("00000000-0000-0000-0000-000000000001", "app-expired", NOW - 1),
            app("00000000-0000-0000-0000-000000000002", "app-soon", NOW + 86_400),
            app("00000000-0000-0000-0000-000000000003", "app-fine", NOW + 400 * 86_400),
        ],
    )];
    let rows = audit("appreg-credential-expiry", &lists, None);
    assert_eq!(
        findings(&rows),
        vec![("app-expired".into(), Severity::Medium), ("app-soon".into(), Severity::Low)]
    );
    assert!(rows[0].resource_id.starts_with("graph:/applications/"), "Enter lands on the directory row");

    let sp = |oid: &str, name: &str, kind: &str| {
        let v = json!({"id": oid, "appId": oid, "displayName": name, "servicePrincipalType": kind,
            "keyCredentials": [{"displayName": "saml", "keyId": "k", "endDateTime": iso(NOW - 1)}]});
        boxed(directory::ServicePrincipalRow::from_json(&v, Some("t"), NOW))
    };
    let lists = vec![(
        V::ServicePrincipals,
        vec![
            sp("00000000-0000-0000-0000-000000000011", "sp-saml", "Application"),
            sp("00000000-0000-0000-0000-000000000012", "id-managed", "ManagedIdentity"),
        ],
    )];
    assert_eq!(findings(&audit("sp-credential-expiry", &lists, None)), vec![("sp-saml".into(), Severity::Medium)]);
}

// ── Access ──

fn assignment(principal: &str, kind: &str, role: &str) -> Value {
    json!({"id": format!("/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/{principal}"),
        "properties": {"principalId": principal, "principalType": kind, "scope": format!("/subscriptions/{SUB}"),
            "roleDefinitionId": format!("/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role}")}})
}

#[test]
fn privileged_guests_and_service_principals_on_the_subscription() {
    const READER: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
    let guest = "00000000-0000-0000-0000-0000000000a1";
    let member = "00000000-0000-0000-0000-0000000000a2";
    let sp = "00000000-0000-0000-0000-0000000000a3";
    let unknown = "00000000-0000-0000-0000-0000000000a4";
    let reader_sp = "00000000-0000-0000-0000-0000000000a5";
    let items = vec![
        assignment(guest, "User", OWNER_ROLE),
        assignment(member, "User", OWNER_ROLE),
        assignment(sp, "ServicePrincipal", USER_ACCESS_ADMIN_ROLE),
        assignment(unknown, "User", OWNER_ROLE),
        assignment(reader_sp, "ServicePrincipal", READER),
    ];
    assert_eq!(privileged_user_ids(&items), vec![guest.to_string(), member.to_string(), unknown.to_string()]);
    let mut lazy = LazyStore::new(0);
    lazy.role_assignments.apply(format!("/subscriptions/{SUB}"), Ok(items));
    lazy.principals.apply(guest.into(), Ok(json!({"@odata.type": "#microsoft.graph.user", "displayName": "Pat", "userPrincipalName": "pat_example.com#EXT#@contoso.onmicrosoft.com"})));
    lazy.principals.apply(member.into(), Ok(json!({"@odata.type": "#microsoft.graph.user", "displayName": "Sam", "userPrincipalName": "sam@contoso.com"})));
    let rows = audit("sub-privileged-guest-or-sp", &[], Some(&lazy));
    let got = findings(&rows);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0].1, Severity::Critical);
    assert!(got[0].0.starts_with("Pat"));
    assert_eq!(got[1], (sp.to_string(), Severity::High), "an unresolved SP shows its object id");
    assert_eq!(rows[0].resource_id, format!("/subscriptions/{SUB}"), "Enter opens the subscription");
    assert_eq!(notes(&rows), vec!["1 privileged user(s) not resolved — r looks them up".to_string()]);
}

#[test]
fn contributor_on_the_subscription_for_a_guest_or_sp_is_its_own_lower_check() {
    let guest = "00000000-0000-0000-0000-0000000000b1";
    let sp = "00000000-0000-0000-0000-0000000000b2";
    let rg_sp = "00000000-0000-0000-0000-0000000000b3";
    let other_sub_sp = "00000000-0000-0000-0000-0000000000b4";
    let mg_sp = "00000000-0000-0000-0000-0000000000b5";
    let narrow = |pid: &str, scope: String| {
        let mut a = assignment(pid, "ServicePrincipal", CONTRIBUTOR_ROLE);
        a["properties"]["scope"] = json!(scope);
        a
    };
    let items = vec![
        assignment(guest, "User", CONTRIBUTOR_ROLE),
        assignment(sp, "ServicePrincipal", CONTRIBUTOR_ROLE),
        assignment(sp, "ServicePrincipal", USER_ACCESS_ADMIN_ROLE),
        narrow(rg_sp, format!("/subscriptions/{SUB}/resourceGroups/rg")),
        narrow(other_sub_sp, "/subscriptions/00000000-0000-0000-0000-0000000000ff".into()),
        narrow(mg_sp, "/providers/Microsoft.Management/managementGroups/root".into()),
    ];
    assert_eq!(privileged_user_ids(&items), vec![guest.to_string()], "a Contributor user is resolved too");
    let mut lazy = LazyStore::new(0);
    lazy.role_assignments.apply(format!("/subscriptions/{SUB}"), Ok(items));
    lazy.principals.apply(guest.into(), Ok(json!({"@odata.type": "#microsoft.graph.user", "displayName": "Pat", "userType": "Guest"})));
    let rows = audit("sub-contributor-guest-or-sp", &[], Some(&lazy));
    let mut got = findings(&rows);
    got.sort();
    assert_eq!(
        got,
        vec![(sp.to_string(), Severity::Medium), (mg_sp.to_string(), Severity::Medium), ("Pat".to_string(), Severity::High)],
        "a resource-group or other-subscription assignment is not subscription-wide; a management group's is"
    );
    let privileged = findings(&audit("sub-privileged-guest-or-sp", &[], Some(&lazy)));
    assert_eq!(privileged, vec![(sp.to_string(), Severity::High)], "UAA stays in the privileged check");
}

/// An SP Graph hasn't resolved is named from the loaded Service
/// principals list when it is there; otherwise it keeps its object id.
#[test]
fn an_sp_assignment_takes_its_name_from_the_loaded_sp_list() {
    let named = "00000000-0000-0000-0000-0000000000c1";
    let resolved = "00000000-0000-0000-0000-0000000000c2";
    let unknown = "00000000-0000-0000-0000-0000000000c3";
    let items = vec![
        assignment(named, "ServicePrincipal", USER_ACCESS_ADMIN_ROLE),
        assignment(resolved, "ServicePrincipal", USER_ACCESS_ADMIN_ROLE),
        assignment(unknown, "ServicePrincipal", USER_ACCESS_ADMIN_ROLE),
    ];
    let mut lazy = LazyStore::new(0);
    lazy.role_assignments.apply(format!("/subscriptions/{SUB}"), Ok(items));
    lazy.principals.apply(resolved.into(), Ok(json!({"@odata.type": "#microsoft.graph.servicePrincipal", "displayName": "From Graph"})));
    let sp = |oid: &str, name: &str| {
        let v = json!({"id": oid, "appId": oid, "displayName": name, "servicePrincipalType": "Application"});
        boxed(directory::ServicePrincipalRow::from_json(&v, Some("t"), NOW))
    };
    let lists = vec![(V::ServicePrincipals, vec![sp(named, "deploy-bot"), sp(resolved, "list name")])];
    let mut got = findings(&audit("sub-privileged-guest-or-sp", &lists, Some(&lazy)));
    got.sort();
    assert_eq!(
        got,
        vec![
            (unknown.to_string(), Severity::High),
            ("From Graph".to_string(), Severity::High),
            ("deploy-bot".to_string(), Severity::High),
        ]
    );
}

#[test]
fn without_the_access_list_the_access_check_says_how_to_get_it() {
    let rows = audit("sub-privileged-guest-or-sp", &[], None);
    assert_eq!(notes(&rows), vec!["not checked — r fetches the subscription's role assignments".to_string()]);
}

#[test]
fn findings_sort_worst_first_and_notes_come_last() {
    let lists = vec![
        (V::NetworkSecurityGroups, vec![nsg("nsg-ssh", vec![rule("ssh", 100, "*", "22", "Tcp")])]),
        (V::Registries, vec![boxed(container_registry::RegistryRow::from_json(
            &body("Microsoft.ContainerRegistry/registries/acr", json!({"adminUserEnabled": true})), None))]),
    ];
    let mut input = AuditInput::new(SUB, NOW);
    for (v, rows) in &lists {
        input.add(*v, rows);
    }
    let rows = run(&input);
    let kinds: Vec<&RowKind> = rows.iter().map(|r| &r.kind).collect();
    let first_note = kinds.iter().position(|k| **k != RowKind::Finding).unwrap();
    assert!(kinds[first_note..].iter().all(|k| **k == RowKind::NotChecked), "notes after findings");
    assert_eq!(rows[0].severity, Severity::Critical);
    assert_eq!(rows[0].state(), crate::azure::resource::ResourceState::Unavailable);
    assert_eq!(rows[1].state_label(), "medium");
}

#[test]
fn a_clean_run_says_so() {
    let lists = [(V::NetworkSecurityGroups, vec![nsg("nsg-tight", vec![rule("ssh", 100, "10.0.0.0/8", "22", "Tcp")])])];
    let mut input = AuditInput::new(SUB, NOW);
    input.add(lists[0].0, &lists[0].1);
    let rows = run(&input);
    assert_eq!(rows[0].kind, RowKind::AllClear);
    assert_eq!(rows[0].resource_name, "✓ no findings — 1 check ran clean");
}
