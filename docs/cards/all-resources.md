# All resources

Every resource in Azure has a type from a resource provider (Microsoft.Compute/virtualMachines, Microsoft.Storage/storageAccounts) and an ARM id that names its subscription, group, provider, type and name. This sub-tab is the subscription's generic resource list: every top-level resource, whatever its type.

## Key ideas

- **Resource providers**: the services behind the types. A provider must be registered on a subscription before its types can be created there.
- **ARM id**: /subscriptions/{sub}/resourceGroups/{group}/providers/{namespace}/{type}/{name}, with child types appended. It is the one name every API, role assignment and portal link uses.
- **Child resources**: subnets, databases, containers; they live under a parent and are not in this list.
- **Provisioning state**: Succeeded, Failed, or a transitional word while ARM is creating, updating or deleting it.
- **Managed by**: a resource another one owns, such as a disk managed by a VM.

## In nebaz

- Every top-level resource: its type, kind, SKU, identity, managed by, created and changed, and whether nebaz has a tab for the type.
- Enter on a type nebaz browses opens the row in its own tab; others stay here. A Related jump to a type nebaz doesn't browse lands here.
- / searches the list: a type name narrows it, and rg: limits it to one resource group.

## Learn more

- Resource providers and types: https://learn.microsoft.com/azure/azure-resource-manager/management/resource-providers-and-types
- Resource Manager: https://learn.microsoft.com/azure/azure-resource-manager/management/overview
- Naming rules: https://learn.microsoft.com/azure/azure-resource-manager/management/resource-name-rules
