# Azure Cache for Redis

Azure Cache for Redis is a managed Redis cache: an in-memory key-value store used for caching, sessions and queues in front of slower storage. Microsoft is retiring it in favour of Azure Managed Redis (its own sub-tab), so new work should start there.

## Key ideas

- **Tiers**: Basic (one node, no SLA), Standard (a primary and a replica) and Premium (clustering into shards, persistence, VNet injection, geo-replication, zones).
- **Ports and TLS**: the TLS port 6380, and the plaintext port 6379, which is off by default. TLS 1.0 and 1.1 are no longer supported.
- **Authentication**: access keys, or Microsoft Entra ID; access-key auth can be turned off.
- **Network access**: public with firewall rules, private endpoints, or (classic Premium) VNet injection. Injection and private endpoints don't mix.
- **Geo-replication**: Premium caches linked across regions, a primary and a read-only secondary.

## In nebaz

- Security flags the non-SSL port, a minimum TLS below 1.2 and a cache that needs no auth. Network is a lazy read of the private endpoints and the firewall rules; an empty firewall list is flagged when public access is on and nothing else fences the cache.
- Geo-replication is a lazy read of the linked caches.
- Never read: the access keys (a POST), or any key in the cache.
- @audit: redis-non-ssl-port, redis-min-tls, redis-public-no-firewall.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-cache-for-redis/cache-overview
- Retirement: https://learn.microsoft.com/azure/azure-cache-for-redis/retirement-faq
- Network isolation: https://learn.microsoft.com/azure/azure-cache-for-redis/cache-network-isolation
- Entra authentication: https://learn.microsoft.com/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication
