# Azure Logic Apps

Logic Apps runs workflows: a trigger (a schedule, an HTTP request, a message on a queue, a new email) starts a run, and the run executes actions in order, calling HTTP endpoints, Azure services and hundreds of SaaS connectors. Each run's inputs and outputs are kept in its run history.

## Key ideas

- **Consumption and Standard**: a Consumption logic app is one workflow (`Microsoft.Logic/workflows`), billed per action. A Standard logic app is an App Service site that hosts many workflows, and lists with the function apps.
- **Triggers**: a Recurrence trigger fires on a schedule; a Request trigger is called on a signed callback URL (its `sig` is the key), which access control can limit to caller IP ranges or an Entra ID policy.
- **Actions**: built-in steps (HTTP, Compose, Condition, For each, Scope) and managed connector steps (Office 365, Service Bus, SQL…).
- **API connections**: a managed connector step signs in through an API connection (`Microsoft.Web/connections`), a separate resource holding the credentials or the OAuth token. When the token expires or the password changes, every workflow using it fails until someone signs in again.
- **Run history**: each run's status, duration and error; secure inputs and outputs hide a step's data from the history.

## In nebaz

- Workflows: Definition shows the triggers and actions in run order (type, method, the URI without its query string, the connector), never their inputs, headers or parameter values.
- Network shows who may call the triggers (⚠ when any IP with the signed URL can) and the inbound and outbound addresses.
- Triggers and Runs are lazy reads: each trigger's schedule and last fire, and the latest 25 runs with failures ⚠ and their error.
- Connections shows each connection's status (⚠ when not connected); an API connection's Used by names the workflows that use it.
- Never read: callback URLs, run inputs and outputs, connection keys or parameter values.

## Learn more

- Overview: https://learn.microsoft.com/azure/logic-apps/logic-apps-overview
- Consumption and Standard: https://learn.microsoft.com/azure/logic-apps/single-tenant-overview-compare
- Securing access: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app
- API connections: https://learn.microsoft.com/azure/connectors/introduction
- Run history: https://learn.microsoft.com/azure/logic-apps/monitor-logic-apps
