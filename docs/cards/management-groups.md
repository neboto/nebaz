# Management groups

Management groups sit above subscriptions and organise them into a tree, so access, policy and budgets can be set once for many subscriptions. Every tenant has a root management group at the top that everything else is under.

## Key ideas

- **Hierarchy**: up to six levels below the root; each group has one parent and any number of child groups and subscriptions.
- **Inheritance**: role assignments and policy assignments at a group apply to every subscription and resource below it.
- **Root group**: the tenant root group, which a Global Administrator must elevate access to manage.
- **Default group**: where new subscriptions land unless placed elsewhere.
- **Landing zones**: the Cloud Adoption Framework's common layout of platform, landing zone and sandbox groups.

## In nebaz

- The list is the groups you can read; for a subscription Reader with nothing at a group, it is empty, and says so.
- Group is a lazy read of the parent and the direct children (groups and subscriptions, the current one marked), each a jump. Assignments lists the loaded policy assignments made at the group.

## Learn more

- Overview: https://learn.microsoft.com/azure/governance/management-groups/overview
- Landing zones: https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/
- Elevate access: https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
