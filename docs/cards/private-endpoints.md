# Private endpoints

A private endpoint gives a service, such as a storage account, a key vault or a SQL server, a private IP address in your subnet. Traffic to the service then stays on your network and Microsoft's backbone, and the service can turn its public access off.

## Key ideas

- **Target and sub-resource**: the resource behind the endpoint, and which part of it (blob or file on a storage account, sqlServer on a SQL server).
- **Approval**: the target's owner approves the connection, automatically when you have rights on it, otherwise by hand. Until it is Approved, no traffic flows.
- **DNS**: the service's name must resolve to the private IP. Usually a private DNS zone such as privatelink.blob.core.windows.net, linked to the VNets that call it.
- **Network policies**: subnets can apply NSGs and route tables to private endpoints too, if switched on.
- **Private Link service**: your own service behind a load balancer, offered to others through their private endpoints.

## In nebaz

- Connection shows the target, the sub-resource, the status and whether approval was automatic or manual. DNS lists each FQDN and its IPs.
- The state follows the connection: Approved is available, Pending is pending, Rejected or Disconnected is unavailable.
- Related jumps to the target (the vault, account or server it fronts), the subnet and the NIC.
- @audit: pe-not-approved.

## Learn more

- Overview: https://learn.microsoft.com/azure/private-link/private-endpoint-overview
- DNS: https://learn.microsoft.com/azure/private-link/private-endpoint-dns
- DNS zone names: https://learn.microsoft.com/azure/private-link/private-endpoint-dns-integration
- Network policies: https://learn.microsoft.com/azure/private-link/disable-private-endpoint-network-policy
