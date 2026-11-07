# Azure SQL Managed Instance

SQL Managed Instance is a whole SQL Server instance run by Azure inside your virtual network, close to complete compatibility with SQL Server: SQL Agent, cross-database queries, Service Broker and CLR, which Azure SQL Database does not have. It suits moving existing SQL Server workloads with few changes.

## Key ideas

- **Subnet**: an instance lives in a subnet of its own, delegated to Managed Instance, with the NSG rules and routes it needs.
- **Service tiers**: General Purpose (remote storage; the Next-gen version sets IOPS separately) and Business Critical (local SSDs, a readable secondary).
- **Endpoints**: the private VNet endpoint, an optional public endpoint on port 3342, and private endpoints.
- **Failover groups**: replicate every database to an instance in another region, with listener names that follow the primary.
- **Instance pools**: pre-provisioned compute in which smaller instances (from 2 vCores) are created quickly and share the cost.
- **Licence**: Azure Hybrid Benefit uses your SQL Server licences; a hybrid failover replica can be licence-free.

## In nebaz

- Managed instances: Instance (SKU, vCores, storage, licence, maintenance), Security and Networking, with ⚠ on the public endpoint. Databases (⚠ unless online) and Failover group are lazy reads.
- Instance pools: the pool's SKU and vCores, and its instances from the Managed instances list with the vCores they use of the pool's.
- Never read: data, or anything that needs a connection to the instance.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-sql/managed-instance/sql-managed-instance-paas-overview
- Connectivity: https://learn.microsoft.com/azure/azure-sql/managed-instance/connectivity-architecture-overview
- Public endpoint: https://learn.microsoft.com/azure/azure-sql/managed-instance/public-endpoint-overview
- Failover groups: https://learn.microsoft.com/azure/azure-sql/managed-instance/failover-group-sql-mi
- Instance pools: https://learn.microsoft.com/azure/azure-sql/managed-instance/instance-pools-overview
