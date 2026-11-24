//! Demo fixtures: the `data` area (see `docs/DEMO.md` for who owns what):
//! Storage, Key Vault, SQL, Cosmos DB, PostgreSQL & MySQL, Redis,
//! Messaging and Backup, in both subscriptions. Lists first, then each
//! resource's lazy children (containers, secret and key names, databases,
//! firewall rules, parameters, admins, queues, topics, hubs, network rule
//! sets, protected items, policies, jobs).

use super::{fx, Fixture};

pub static FIXTURES: &[Fixture] = &[
    // ── Storage ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.Storage/storageAccounts", "storage-accounts-prod.json"),
    fx!("data", "/subscriptions/{{dev}}/providers/Microsoft.Storage/storageAccounts", "storage-accounts-dev.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.Storage/storageAccounts/stcontosoordersprod/blobServices/default/containers",
        "storage-containers-prod.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{dev}}/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/stcontosoordersdev/blobServices/default/containers",
        "storage-containers-dev.json"
    ),
    // ── Key Vault (names only, through ARM; never a value) ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.KeyVault/vaults", "kv-vaults-prod.json"),
    fx!("data", "/subscriptions/{{dev}}/providers/Microsoft.KeyVault/vaults", "kv-vaults-dev.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.KeyVault/vaults/kv-orders-prod/secrets",
        "kv-orders-prod-secrets.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.KeyVault/vaults/kv-orders-prod/keys",
        "kv-orders-prod-keys.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.KeyVault/vaults/kv-legacy-prod/secrets",
        "kv-legacy-prod-secrets.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.KeyVault/vaults/kv-legacy-prod/keys",
        "kv-legacy-prod-keys.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{dev}}/resourceGroups/rg-dev/providers/Microsoft.KeyVault/vaults/kv-orders-dev/secrets",
        "kv-orders-dev-secrets.json"
    ),
    // ── SQL ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.Sql/servers", "sql-servers-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.Sql/servers/sql-orders-prod/databases",
        "sql-orders-databases.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.Sql/servers/sql-orders-prod/firewallRules",
        "sql-orders-firewall.json"
    ),
    // SQL Managed Instance (#195): the failover groups of rg-legacy-prod in
    // westeurope are none (the default empty collection).
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.Sql/managedInstances", "sql-managed-instances-prod.json"),
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.Sql/instancePools", "sql-instance-pools-prod.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Sql/managedInstances/sqlmi-legacy-prod/databases", "sqlmi-legacy-prod-databases.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Sql/managedInstances/sqlmi-legacy-prod", "sqlmi-legacy-prod.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Sql/instancePools/sqlpool-legacy-prod", "sqlpool-legacy-prod.json"),
    // ── Cosmos DB ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.DocumentDB/databaseAccounts", "cosmos-accounts-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-legacy/sqlDatabases",
        "cosmos-legacy-databases.json"
    ),
    // ── PostgreSQL & MySQL ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.DBforPostgreSQL/flexibleServers", "pg-servers-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-orders-prod/administrators",
        "pg-orders-admins.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-orders-prod/configurations",
        "pg-orders-configurations.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-orders-prod/databases",
        "pg-orders-databases.json"
    ),
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.DBforMySQL/flexibleServers", "mysql-servers-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.DBforMySQL/flexibleServers/mysql-reporting-legacy/firewallRules",
        "mysql-reporting-firewall.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.DBforMySQL/flexibleServers/mysql-reporting-legacy/configurations",
        "mysql-reporting-configurations.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.DBforMySQL/flexibleServers/mysql-reporting-legacy/databases",
        "mysql-reporting-databases.json"
    ),
    // ── Redis ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.Cache/redis", "redis-caches-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.Cache/Redis/redis-orders-cache/firewallRules",
        "redis-orders-firewall.json"
    ),
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.Cache/redisEnterprise", "amr-clusters-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.Cache/redisEnterprise/amr-orders-sessions/databases",
        "amr-sessions-databases.json"
    ),
    // ── Messaging ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.ServiceBus/namespaces", "sb-namespaces-prod.json"),
    // ── API Management (#159): the orders gateway (a certificate near
    //    expiry, an open product, a Key Vault reference it cannot read)
    //    and a legacy dev instance on the retired stv1 platform ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.ApiManagement/service", "apim-services.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ApiManagement/service/apim-contoso-prod/apis", "apim-contoso-prod.apis.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ApiManagement/service/apim-contoso-prod/products", "apim-contoso-prod.products.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ApiManagement/service/apim-contoso-prod/backends", "apim-contoso-prod.backends.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ApiManagement/service/apim-contoso-prod/namedValues", "apim-contoso-prod.named-values.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ApiManagement/service/apim-contoso-prod", "apim-contoso-prod.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.ApiManagement/service/apim-legacy-dev/apis", "apim-legacy-dev.apis.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.ApiManagement/service/apim-legacy-dev", "apim-legacy-dev.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ServiceBus/namespaces/sb-orders-prod/networkRuleSets/default",
        "sb-orders-network.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ServiceBus/namespaces/sb-orders-prod/queues",
        "sb-orders-queues.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ServiceBus/namespaces/sb-orders-prod/topics",
        "sb-orders-topics.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ServiceBus/namespaces/sb-orders-prod/topics/order-events/subscriptions",
        "sb-orders-subscriptions.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.ServiceBus/namespaces/sb-orders-prod/authorizationRules",
        "sb-orders-auth-rules.json"
    ),
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.EventHub/namespaces", "eh-namespaces-prod.json"),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.EventHub/namespaces/evh-orders-prod/networkRuleSets/default",
        "eh-orders-network.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.EventHub/namespaces/evh-orders-prod/eventhubs",
        "eh-orders-hubs.json"
    ),
    fx!(
        "data",
        "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.EventHub/namespaces/evh-orders-prod/authorizationRules",
        "eh-orders-auth-rules.json"
    ),
    // ── Backup: both vaults, then each one's lazy reads ──
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.RecoveryServices/vaults", "recovery-vaults-prod.json"),
    fx!("data", "/subscriptions/{{prod}}/providers/Microsoft.DataProtection/backupVaults", "backup-vaults-prod.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.RecoveryServices/vaults/rsv-contoso-prod/backupProtectedItems", "rsv-protected-items.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.RecoveryServices/vaults/rsv-contoso-prod/backupPolicies", "rsv-policies.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.RecoveryServices/vaults/rsv-contoso-prod/backupJobs", when ["status eq 'Failed'"], "rsv-failed-jobs.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.DataProtection/backupVaults/bvault-contoso-prod/backupInstances", "bvault-instances.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.DataProtection/backupVaults/bvault-contoso-prod/backupPolicies", "bvault-policies.json"),
    fx!("data", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.DataProtection/backupVaults/bvault-contoso-prod/backupJobs", "bvault-jobs.json"),
];
