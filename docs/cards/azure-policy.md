# Azure Policy

Azure Policy enforces rules on what can be created and how it must be configured, and reports what is out of line: allowed regions, required tags, no public IPs, diagnostics on. Rules are written once as definitions and applied by assigning them to a scope.

## Key ideas

- **Definitions**: a rule (if these fields match, then an effect) with parameters. Microsoft ships hundreds of built-ins; custom ones live in a management group or a subscription.
- **Effects**: Deny blocks a request; Audit and AuditIfNotExists report; Modify and Append change it; DeployIfNotExists deploys what is missing; Disabled turns it off.
- **Initiatives**: a set of definitions assigned as one, such as the Microsoft cloud security benchmark.
- **Assignments**: a definition or initiative applied at a management group, subscription or resource group, with its parameters, exclusions and a managed identity for Modify and DeployIfNotExists. DoNotEnforce evaluates without blocking or changing anything.
- **Exemptions**: take a scope out of an assignment, as a Waiver or Mitigated, optionally until a date.
- **Compliance**: each resource evaluated against each assignment; remediation tasks fix existing resources.

## In nebaz

- Assignments, Exemptions and Definitions read at the subscription, so they include what management groups above it assign and store.
- An assignment shows its scope, whether it is inherited, enforcement (DoNotEnforce flagged), its definition, parameters and exemptions. An exemption shows its category and days left.
- Never read: compliance results (the query is a POST; C copies az policy state list).
- @audit: policy-not-enforced, policy-exemption-expiry.

## Learn more

- Overview: https://learn.microsoft.com/azure/governance/policy/overview
- Definition structure: https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics
- Effects: https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics
- Assignments: https://learn.microsoft.com/azure/governance/policy/concepts/assignment-structure
- Exemptions: https://learn.microsoft.com/azure/governance/policy/concepts/exemption-structure
- Remediation: https://learn.microsoft.com/azure/governance/policy/how-to/remediate-resources
