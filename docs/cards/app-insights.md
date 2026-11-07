# Application Insights

Application Insights is Azure Monitor's application performance monitoring: requests, dependencies, exceptions, traces and custom events sent from your code (through OpenTelemetry or its SDKs), with application maps, failures and performance views and availability tests. The data is stored in a Log Analytics workspace.

## Key ideas

- **Component**: the resource an application reports to. Workspace-based components keep their data in a Log Analytics workspace; classic ones are retired.
- **Connection string**: how an application finds the component. It replaces the instrumentation key, which is no longer used for ingestion on its own.
- **Sampling**: keeps a share of the telemetry to cut volume and cost, preserving related items together.
- **Availability tests**: requests from Azure's locations to your endpoint, alerting when it fails.
- **Local auth**: whether ingestion without Entra ID is accepted.

## In nebaz

- Overview shows the application type, app id, ingestion mode, workspace, retention, sampling, public ingestion and query, local auth and IP masking.
- The instrumentation key and connection string are stripped from the JSON before nebaz keeps it, so neither the detail pane nor e shows them.
- Related jumps to the workspace. App Service apps can't link here: that link is an app setting, which nebaz never reads.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
- OpenTelemetry: https://learn.microsoft.com/azure/azure-monitor/app/opentelemetry-enable
- Connection strings: https://learn.microsoft.com/azure/azure-monitor/app/connection-strings
- Sampling: https://learn.microsoft.com/azure/azure-monitor/app/opentelemetry-sampling
- Availability tests: https://learn.microsoft.com/azure/azure-monitor/app/availability
