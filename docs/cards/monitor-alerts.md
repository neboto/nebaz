# Azure Monitor alerts

Azure Monitor alerts tell someone when something needs attention. An alert rule watches a signal on its scope; when the condition is met, it fires an alert, and the rule's action groups notify people or start automation. Alert processing rules can suppress or add actions on the way.

## Key ideas

- **Metric alerts**: a threshold or dynamic threshold on a platform or custom metric, checked every minute or more; availability test alerts are a kind.
- **Log search alerts**: a KQL query against a workspace or App Insights, run on a schedule, firing on the result count or a measured value.
- **Activity log alerts**: an event in the Activity Log, such as a deletion, a policy action, or Service Health and Resource Health notices.
- **Severity and state**: Sev0 (critical) to Sev4 (verbose); a fired alert is New, Acknowledged or Closed, and its condition Fired or Resolved.
- **Action groups**: who to tell and what to run: email, SMS, voice, app push, webhooks, Logic Apps, Functions, runbooks, Event Hubs, ITSM.
- **Alert processing rules**: suppress notifications during maintenance, or add action groups to every alert in a scope.

## In nebaz

- The three rule sub-tabs show each rule's condition (a log alert's query as code, never run), scopes and actions, ⚠ when it notifies no one.
- Every resource's Related lists the rules that watch it. An action group's Used by lists the rules and processing rules naming it.
- Fired alerts lists the last 30 days, newest first: Fired is unavailable, Acknowledged pending, Resolved available, Closed stopped.
- Receivers are trimmed: a webhook's URL to its scheme and host, a phone number to its last four digits. Never sent: a state change on an alert (a POST).

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview
- Alert types: https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-types
- Action groups: https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups
- Processing rules: https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-processing-rules
- Service Health alerts: https://learn.microsoft.com/azure/service-health/alerts-activity-log-service-notifications-portal
