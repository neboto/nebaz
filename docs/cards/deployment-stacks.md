# Deployment stacks

A deployment stack is a deployment that remembers what it created. Azure keeps the list of resources the stack manages, can put a deny assignment on them so nobody changes them outside the stack, and decides what happens to a resource when the template stops declaring it. This is the closest thing Azure has to a CloudFormation stack.

## Key ideas

- **Scope**: a stack lives at a resource group, a subscription or a management group, and can manage resources below that scope.
- **Managed resources**: what the stack's last run deployed. A resource can also be detached (still in Azure, no longer managed) or failed.
- **Action on unmanage**: what happens to a resource that leaves the template. Detach leaves it in Azure; delete removes it. Set separately for resources, resource groups and management groups.
- **Deny settings**: none, deny delete, or deny write and delete, enforced by a deny assignment on the managed resources. Principals and actions can be excluded.
- **Out of sync**: a stack whose managed list no longer matches what Azure holds refuses to update unless the bypass flag is set.

## In nebaz

- Stacks lists the subscription's own stacks, then every resource group's (one call per group, at most 200 groups). Management-group stacks are above the subscription and are not read.
- A stack with failed resources reads degraded. Resources shows each managed resource with its status and deny status, then the detached and deleted ones; every line is a jump.
- Settings shows the unmanage actions, the deny mode with its exclusions, and the out-of-sync bypass.
- Parameters shows names and types only. Values and the template are dropped before anything is kept, so the e view cannot show them either.
- On any resource, the ownership ribbon says "in stack NAME" once this list has been loaded.
- @audit flags a stack that deletes on unmanage, one with no deny settings, one with detached resources and one with failed resources.

## Learn more

- Deployment stacks: https://learn.microsoft.com/azure/azure-resource-manager/bicep/deployment-stacks
- Create a stack: https://learn.microsoft.com/azure/azure-resource-manager/bicep/quickstart-create-deployment-stacks
- Deny assignments: https://learn.microsoft.com/azure/role-based-access-control/deny-assignments
