# Resource locks

A lock stops a resource, a resource group or a subscription from being deleted or changed by mistake, whatever the caller's role. It applies to everything below where it is set, and only someone allowed to remove the lock (an Owner or User Access Administrator) can take it off.

## Key ideas

- **CanNotDelete**: users can read and change the resource, but not delete it.
- **ReadOnly**: users can only read. This blocks more than it seems: anything that is a POST, such as listing a storage account's keys, is refused too.
- **Inheritance**: a lock on a group covers every resource in it, including new ones.
- **Control plane only**: a lock guards Azure Resource Manager operations, not data inside a resource; a locked database can still have its rows deleted.

## In nebaz

- Each lock explains its level, what it is on and that it applies below, with its notes and owners. Related jumps to what it locks.
- The list is read at the subscription, so locks on groups and resources in it are included.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources
