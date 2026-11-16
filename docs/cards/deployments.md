# Deployments

A deployment is one run of an ARM template or a Bicep file: Azure Resource Manager works out what the template declares and creates or updates each resource. Every run is kept as a record on the scope it ran at, with its state, its operations and its error. This is Azure's counterpart to a CloudFormation stack's events.

## Key ideas

- **Scope**: a deployment runs at a resource group, a subscription, a management group or the tenant. A group deployment creates resources in that group; a subscription deployment creates groups, policy and role assignments.
- **Operations**: one per resource the deployment touched, with what it did (Create, Read), the status code and the provider's error. A failed deployment's real cause is in its failed operation, not in the top-level "at least one operation failed".
- **Mode**: Incremental leaves resources the template does not mention alone. Complete deletes them from the group.
- **Template**: inline (Bicep and local files are sent as JSON), a linked template URI, or a template spec version.
- **History**: a group keeps at most 800 deployments; Azure deletes the oldest automatically when it gets close.
- **Parameters and outputs**: kept on the record in plain text unless typed securestring. An output can carry a key.

## In nebaz

- Group deployments reads every resource group's history (one call per group, at most 200 groups and 200 deployments each), newest first. Subscription deployments is one list.
- Operations lists the failed ones first, each with its resource (a jump) and the provider's error. Resources is what it deployed and what each resource waited for. Error is the whole nested error.
- Parameters shows names and types only. Values, a template link's SAS token and an operation's request and response bodies are dropped before anything is kept, so the e view cannot show them either.
- Never sent, because they are POSTs: export template, what-if, validate, cancel.
- A deployment has no region here: the location filter never hides one.

## Learn more

- Deployment history: https://learn.microsoft.com/azure/azure-resource-manager/templates/deployment-history
- Find the error code: https://learn.microsoft.com/azure/azure-resource-manager/troubleshooting/find-error-code
- Deployment modes: https://learn.microsoft.com/azure/azure-resource-manager/templates/deployment-modes
- Deploy to a group (Bicep): https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-to-resource-group
- Automatic history deletions: https://learn.microsoft.com/azure/azure-resource-manager/templates/deployment-history-deletions
