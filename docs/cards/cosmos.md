# Azure Cosmos DB

Cosmos DB is a globally distributed database for NoSQL data: documents, key-value, wide-column and graph. An account chooses its API once (NoSQL, MongoDB, Cassandra, Gremlin or Table) and can replicate to any number of regions, with reads and optionally writes in each one.

## Key ideas

- **Resource model**: account, then databases, then containers (collections, tables or graphs), then items. Each container has a partition key that spreads its data and load.
- **Request units (RU/s)**: the currency of throughput. Provisioned (fixed or autoscale), on a database or a container, or serverless (pay per request).
- **Consistency levels**: strong, bounded staleness, session (the default), consistent prefix and eventual: a trade between freshness and latency.
- **Global distribution**: regions in failover priority order, service-managed failover, and multi-region writes.
- **Security**: Entra ID data-plane roles, or the account keys (key auth can be turned off); public access, IP and VNet rules or private endpoints.
- **Backup**: periodic (by interval and retention) or continuous (point-in-time restore for 7 or 30 days).

## In nebaz

- Replication shows the consistency level, multi-region writes and every region by failover priority. Security shows network access, key auth, minimum TLS and encryption. Backup shows the mode.
- Databases is one lazy read of the names, on the API's own path; containers are not listed.
- Never read: the keys or connection strings (POST calls), or any data.
- @audit: cosmos-public-network, cosmos-local-auth.

## Learn more

- Overview: https://learn.microsoft.com/azure/cosmos-db/overview
- Request units: https://learn.microsoft.com/azure/cosmos-db/request-units
- Consistency levels: https://learn.microsoft.com/azure/cosmos-db/consistency-levels
- Partitioning: https://learn.microsoft.com/azure/cosmos-db/partitioning
- Disable key auth: https://learn.microsoft.com/azure/cosmos-db/how-to-connect-role-based-access-control
