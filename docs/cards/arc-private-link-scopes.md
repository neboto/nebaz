# Azure Arc private link scopes

A private link scope lets Arc-enabled servers reach Azure through a private endpoint in your network instead of over the public internet. Machines are assigned to the scope; its private endpoint gives the Arc services private IPs, and private DNS zones resolve their names there.

## Key ideas

- **Scope**: a resource that machines and clusters are linked to. Once linked, their agents use the scope's private endpoint.
- **Private endpoint**: the scope's IP in your virtual network. Its connection must be approved before traffic flows.
- **Public network access**: whether machines in the scope may still use the public endpoints.
- **DNS**: the Arc service names have to resolve to the private endpoint, through private DNS zones or your own DNS.

## In nebaz

- Network shows public network access, the scope id, and each private endpoint (a jump), ⚠ unless its connection is approved.
- Arc servers and Kubernetes clusters that use the scope link to it from their Agent section.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-arc/servers/private-link-security
