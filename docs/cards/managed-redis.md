# Azure Managed Redis

Azure Managed Redis runs Redis Enterprise as an Azure service: an in-memory store for caching, sessions, vector search and JSON, with high availability and active geo-replication. It replaces Azure Cache for Redis, which is being retired.

## Key ideas

- **Cluster and database**: the resource is a cluster; it holds one database, where the port, protocol, clustering policy, eviction, persistence and modules are set.
- **Tiers**: Memory Optimized, Balanced and Compute Optimized trade memory against vCPUs; Flash Optimized keeps cold keys on NVMe.
- **Modules**: RediSearch (including vector search), RedisJSON, RedisBloom and RedisTimeSeries.
- **Clustering policy**: OSS (clients talk to each shard) or Enterprise (one endpoint proxies them).
- **Network access**: public or private endpoints. There are no firewall rules and no VNet injection.
- **Active geo-replication**: several clusters in a group, all writable, kept in sync.

## In nebaz

- Security shows the minimum TLS, encryption and public access. Network shows private endpoints with their status.
- Databases is a lazy read: the port, the protocol (Plaintext flagged), access-key auth, clustering and eviction, persistence, modules and the geo-replication group, each linked cluster a jump.
- Never read: the access keys (a POST), or any key in the cache.
- @audit: amr-min-tls.

## Learn more

- Overview: https://learn.microsoft.com/azure/redis/overview
- Architecture: https://learn.microsoft.com/azure/redis/architecture
- Active geo-replication: https://learn.microsoft.com/azure/redis/how-to-active-geo-replication
- Moving from Azure Cache for Redis: https://learn.microsoft.com/azure/redis/migrate/migrate-basic-standard-premium-overview
