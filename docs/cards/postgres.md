# Azure Database for PostgreSQL

Azure Database for PostgreSQL flexible server is community PostgreSQL run by Azure: you choose the version, the compute and the storage, and Azure handles patching, backups and high availability. Single Server, the older offering, is retired.

## Key ideas

- **Compute tiers**: Burstable (small, uneven loads), General Purpose and Memory Optimized. Storage can grow automatically.
- **Networking**: chosen when the server is created. Either VNet integration (the server in a delegated subnet, with a private DNS zone) or public access with firewall rules, to which private endpoints can be added.
- **Authentication**: PostgreSQL passwords, Microsoft Entra ID, or both.
- **High availability**: a standby in the same zone or another zone, with automatic failover.
- **Server parameters**: PostgreSQL's settings, such as require_secure_transport, the TLS versions and the built-in PgBouncer.
- **Backup and replicas**: automatic backups with point-in-time restore (geo-redundant if chosen at creation); read replicas in the same or other regions.

## In nebaz

- Networking says how the server is reached, and what a caller in another VNet needs. A private DNS zone that doesn't match the FQDN's domain is flagged.
- Firewall flags 0.0.0.0 ("allow Azure services"), the whole internet and very large ranges, and says when the rules don't apply.
- Security shows the auth mode, the admin login (never its password) and the Entra admins. Parameters shows the security-relevant settings only, each with its default.
- Never read: data, or anything that needs a connection to the server.
- @audit: pg-public-network, pg-firewall-open, pg-insecure-transport, pg-min-tls, pg-password-no-entra.

## Learn more

- Overview: https://learn.microsoft.com/azure/postgresql/overview
- Networking: https://learn.microsoft.com/azure/postgresql/network/concepts-networking-private
- Entra authentication: https://learn.microsoft.com/azure/postgresql/security/security-entra-concepts
- High availability: https://learn.microsoft.com/azure/postgresql/high-availability/concepts-high-availability
- Server parameters: https://learn.microsoft.com/azure/postgresql/parameters/concepts-parameters
- Backup and restore: https://learn.microsoft.com/azure/postgresql/backup-restore/concepts-backup-restore
