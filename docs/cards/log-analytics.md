# Log Analytics workspaces

A Log Analytics workspace stores the logs and metrics that Azure Monitor collects (resource logs, VM agents, App Insights, Defender, Sentinel) in tables you query with the Kusto Query Language (KQL). It is where most of an estate's operational data ends up.

## Key ideas

- **Tables and plans**: data lands in tables. Analytics tables support every query and alert; Basic and Auxiliary tables cost less to ingest but query more slowly and with limits.
- **Retention**: interactive retention (30 days by default, up to 2 years) and long-term retention, up to 12 years, at a lower price.
- **Pricing**: pay as you go per GB, or commitment tiers for a daily volume. A daily cap stops ingestion for the rest of the day when reached.
- **Access control mode**: workspace permissions, or resource-context access, where someone who can read a resource can read its logs.
- **Workspace id**: the customer id (a GUID) that agents and queries name, separate from the ARM id.
- **Data collection rules**: what the Azure Monitor agent collects and which table it goes to.

## In nebaz

- Overview shows the customer id, SKU and commitment tier, retention, daily cap and reset time, ingestion status, public ingestion and query, local auth and the access mode.
- AKS clusters, App Insights components and Container Apps environments link here from their own Related.
- Never run: a query. nebaz reads the workspace's settings, not its data.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview
- Table plans: https://learn.microsoft.com/azure/azure-monitor/logs/data-platform-logs
- Retention: https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-configure
- Access control: https://learn.microsoft.com/azure/azure-monitor/logs/manage-access
- Daily cap: https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap
- Queries: https://learn.microsoft.com/azure/azure-monitor/logs/get-started-queries
