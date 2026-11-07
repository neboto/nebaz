# Subscriptions and resource groups

Everything in Azure lives in a subscription, and every resource in it sits in exactly one resource group. A subscription is a billing and access boundary tied to one Microsoft Entra tenant; a resource group is a folder for resources that share a lifecycle: deployed, secured and deleted together.

## Key ideas

- **Tenant, subscription, group, resource**: the tenant is the directory; subscriptions belong to it (and to management groups above them); groups belong to a subscription; resources to a group.
- **Subscription state**: Enabled, Warned, PastDue, Disabled or Deleted. Only Enabled runs and creates resources normally.
- **Limits and quotas**: many limits (cores per region, VNets, public IPs) are per subscription and region; several subscriptions are how large estates scale.
- **Resource group location**: where the group's metadata is stored, not where its resources must be. Deleting a group deletes everything in it.
- **Inheritance**: role assignments, policies and locks on a subscription or group apply to everything below.
- **Managed resource groups**: groups that a service creates and owns (AKS's MC_ group, a managed application's), shown as managed by that resource.

## In nebaz

- P picks the subscription every tab lists; choosing one chooses its tenant. Only Enabled subscriptions show by default (a shows the rest).
- Subscriptions: Details and Locations are lazy reads. Resource groups: the state and the resource that manages the group, if any.
- Access on a subscription is the role assignments at and above it, and the users and service principals who hold them.
- @audit: sub-privileged-guest-or-sp, sub-contributor-guest-or-sp.

## Learn more

- Resource Manager: https://learn.microsoft.com/azure/azure-resource-manager/management/overview
- Resource groups: https://learn.microsoft.com/azure/azure-resource-manager/management/manage-resource-groups-portal
- Organise resources: https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-setup-guide/organize-resources
- Subscription states: https://learn.microsoft.com/azure/cost-management-billing/manage/subscription-states
- Limits: https://learn.microsoft.com/azure/azure-resource-manager/management/azure-subscription-service-limits
