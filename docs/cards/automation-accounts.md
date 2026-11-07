# Azure Automation

Azure Automation runs scripts, called runbooks, on a schedule, from a webhook or on demand: stopping dev VMs every evening, patching, cleaning up resources. Runbooks run in Azure's sandboxes, or on your own machines through hybrid runbook workers.

## Key ideas

- **Runbooks**: PowerShell or Python scripts. Published is what runs; an edited runbook keeps a draft until it is published again.
- **Schedules**: when runbooks start. A job schedule ties one schedule to one runbook, with its parameters and the worker group to run on.
- **Jobs**: each run of a runbook, with a status (Completed, Failed, Suspended, Stopped) and its output.
- **Hybrid runbook workers**: your VMs or Arc servers, in groups, that run runbooks next to the resources they manage. The extension-based workers are the current kind; the agent-based ones are retired.
- **Shared assets**: variables, credentials, certificates and connections the runbooks use.
- **Identity**: runbooks authenticate with the account's managed identity. Run As accounts are retired.

## In nebaz

- Runbooks shows each runbook's schedules and its newest job, ⚠ when it failed. Jobs reads the last 7 days (at most 200).
- Hybrid workers lists each group's machines (a jump to the VM or Arc server), ⚠ when one has not been seen for a day: jobs sent to it wait.
- Never read, though Reader allows most of them: variables (an unencrypted value comes back in the body), credentials, certificates, connections, runbook content and job output.
- @audit: automation-local-auth (with local auth on, a webhook URL starts a runbook with no Entra ID sign-in).

## Learn more

- Overview: https://learn.microsoft.com/azure/automation/overview
- Runbook types: https://learn.microsoft.com/azure/automation/automation-runbook-types
- Hybrid runbook workers: https://learn.microsoft.com/azure/automation/automation-hybrid-runbook-worker
- Disable local authentication: https://learn.microsoft.com/azure/automation/disable-local-authentication
- From Run As to managed identities: https://learn.microsoft.com/azure/automation/migrate-run-as-accounts-managed-identity
