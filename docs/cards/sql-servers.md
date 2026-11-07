# Azure SQL Database

Azure SQL Database is SQL Server's engine as a managed service: Azure runs the patching, backups and high availability, and you work with databases. Databases live on a logical server, which holds the admin login, the firewall rules and the network settings they share; the server itself has no compute of its own.

## Key ideas

- **Logical server**: a name (myserver.database.windows.net), an admin, firewall rules and network settings. Databases and elastic pools belong to it.
- **Purchasing models**: vCore (General Purpose, Business Critical, Hyperscale) or DTU (Basic, Standard, Premium). Serverless compute scales by load and can pause when idle.
- **Elastic pools**: databases sharing one pool of compute, for many databases with uneven load.
- **Authentication**: Microsoft Entra ID, SQL logins, or Entra-only, which turns SQL logins off.
- **Network access**: public access through server firewall rules, VNet rules or private endpoints. The "Allow Azure services" rule (0.0.0.0) admits every Azure address, other customers' included.
- **Backups and geo**: automatic backups with point-in-time restore; active geo-replication and failover groups for a copy in another region.

## In nebaz

- Servers: Security (Entra admin, Entra-only, minimum TLS, TDE key), Networking (public access, private endpoints), and Databases and Firewall as lazy reads. A database shows its SKU, status, size, redundancy, auto-pause and elastic pool.
- The state is the server's own (Ready is available): servers carry no provisioning state.
- Never read: data, or anything that needs a connection to the database.
- @audit: sql-public-network, sql-firewall-open, sql-min-tls.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-sql/database/sql-database-paas-overview
- Logical servers: https://learn.microsoft.com/azure/azure-sql/database/logical-servers
- vCore and DTU: https://learn.microsoft.com/azure/azure-sql/database/purchasing-models
- Firewall rules: https://learn.microsoft.com/azure/azure-sql/database/firewall-configure
- Entra authentication: https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-overview
- Failover groups: https://learn.microsoft.com/azure/azure-sql/database/failover-group-sql-db
