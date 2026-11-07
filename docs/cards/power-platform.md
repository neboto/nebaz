# Power Platform enterprise policies

An enterprise policy is the Azure resource that connects Power Platform environments (Power Apps, Power Automate, Copilot Studio, Dataverse) to your Azure resources. The network injection kind lets an environment reach your private resources through delegated subnets in your VNets; the encryption kind encrypts its data with your own Key Vault key.

## Key ideas

- **Network injection (subnet delegation)**: an environment runs its outbound calls from subnets in your VNets, delegated to Microsoft.PowerPlatform/enterprisePolicies, so they can reach private endpoints and on-premises networks.
- **Region pairs**: a policy names a VNet in each of the environment's paired Azure regions, so failover keeps its network.
- **Customer-managed keys**: an encryption policy names a Key Vault key that Dataverse uses, read through the policy's identity.
- **Linking**: an environment is linked to a policy in the Power Platform admin centre or its API, not in Azure.
- **Health**: Healthy, Warning or Unhealthy, for instance when a subnet or key can no longer be used.

## In nebaz

- Network injection lists each VNet and delegated subnet, in the policy's order. Encryption shows the key vault, key and its state. Identity shows the principal.
- The state is the health status; a subnet's Related names the policy that injects into it.
- Never called: the Power Platform admin API, so which environments are linked isn't shown.
- @audit: pp-policy-unhealthy, subnet-pp-no-nsg, aca-env-external-pp-vnet.

## Learn more

- Virtual network support: https://learn.microsoft.com/power-platform/admin/vnet-support-overview
- Set up VNet support: https://learn.microsoft.com/power-platform/admin/vnet-support-setup-configure
- Customer-managed keys: https://learn.microsoft.com/power-platform/admin/customer-managed-key
