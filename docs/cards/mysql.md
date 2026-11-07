# Azure Database for MySQL

Azure Database for MySQL flexible server is community MySQL run by Azure: you choose the version, the compute and the storage, and Azure handles patching, backups and high availability. Single Server, the older offering, is retired.

## Key ideas

- **Compute tiers**: Burstable, General Purpose and Business Critical. Storage can grow automatically, with IOPS provisioned or autoscaled.
- **Networking**: chosen when the server is created. Either VNet integration (the server in a delegated subnet, with a private DNS zone) or public access with firewall rules, to which private endpoints can be added.
- **Authentication**: MySQL passwords, Microsoft Entra ID, or both. Entra needs a user-assigned identity that can read the directory.
- **High availability**: a standby in the same zone or another zone, with automatic failover.
- **Server parameters**: MySQL's settings, such as require_secure_transport and tls_version.
- **Backup and replicas**: automatic backups with point-in-time restore (geo-redundant if chosen at creation); read replicas.

## In nebaz

- Networking says how the server is reached, and what a caller in another VNet needs. A private DNS zone that doesn't match the FQDN's domain is flagged.
- Firewall flags 0.0.0.0 ("allow Azure services"), the whole internet and very large ranges, and says when the rules don't apply.
- Security shows the admin login (never its password), the Entra admins and the identity used for the directory lookup. Parameters shows the security-relevant settings only, each with its default.
- Never read: data, or anything that needs a connection to the server.
- @audit: mysql-public-network, mysql-firewall-open, mysql-insecure-transport, mysql-min-tls, mysql-password-no-entra.

## Learn more

- Overview: https://learn.microsoft.com/azure/mysql/flexible-server/overview
- Networking: https://learn.microsoft.com/azure/mysql/flexible-server/concepts-networking
- Entra authentication: https://learn.microsoft.com/azure/mysql/security/security-entra-authentication
- High availability: https://learn.microsoft.com/azure/mysql/flexible-server/concepts-high-availability
- Server parameters: https://learn.microsoft.com/azure/mysql/flexible-server/concepts-server-parameters
- Encrypted connections: https://learn.microsoft.com/azure/mysql/security/security-tls-how-to-connect
