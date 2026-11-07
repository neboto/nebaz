# What changed recently

When something breaks, the first question is what changed. Azure records it in three places: the Activity Log (every create, update and delete through Azure Resource Manager, with who did it), deployments (the template runs that made the change) and Resource Health (when a resource became unavailable or degraded, and why).

## Key ideas

- **Activity Log**: subscription-level events, kept for 90 days: the operation, the caller, the status and a correlation id linking the steps of one request.
- **Deployments**: each ARM, Bicep or Terraform-through-ARM deployment to a resource group, with its status and what it deployed.
- **Resource Health**: a resource's own availability (Available, Unavailable, Degraded, Unknown), with the cause when Azure knows it, platform or user-initiated.
- **Service Health**: Azure-wide incidents and planned maintenance, separate from a single resource's health.

## In nebaz

- @changes merges the three, newest first, over a window chosen with [ and ] (15 minutes to 7 days). All, Activity, Deployments and Health filter one list without another call.
- Activity rows from services and managed identities rather than people are noise (a).
- W on any resource opens its own change timeline; the m chart draws the same events as markers.
- Never read: a deployment's parameters or outputs, or Resource Graph's change history (a POST).

## Learn more

- Activity Log: https://learn.microsoft.com/azure/azure-monitor/fundamentals/activity-log
- Deployment history: https://learn.microsoft.com/azure/azure-resource-manager/templates/deployment-history
- Resource Health: https://learn.microsoft.com/azure/service-health/resource-health-overview
- Service Health: https://learn.microsoft.com/azure/service-health/overview
