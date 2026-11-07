# Azure Functions

Azure Functions runs small pieces of code in response to events: an HTTP request, a timer, a queue message, a new blob. You write the function; the platform starts and scales instances as events arrive. Logic Apps Standard workflows run on the same runtime, so they are listed here too.

## Key ideas

- **Triggers and bindings**: a trigger starts the function; input and output bindings read from and write to other services without client code.
- **Hosting plans**: Flex Consumption (serverless, pay per use, VNet support, the recommended serverless plan), Consumption, Premium (pre-warmed instances, no cold start) and Dedicated (an App Service plan), or Container Apps.
- **Storage account**: every function app needs one for its runtime state; the AzureWebJobsStorage setting points at it, ideally through a managed identity.
- **Durable Functions**: orchestrations that keep state across long-running, multi-step work.
- **Same platform as App Service**: TLS, FTPS, networking, identity and Key Vault references work as they do for web apps.

## In nebaz

- Functions shows the App Service rows whose kind is a function app (Logic Apps Standard included), with the same sections as Apps: Configuration (lazy), Hostnames and Networking.
- App settings, connection strings and function keys are never read; neither are the functions' code or invocations.
- @audit: app-https-only, app-min-tls, app-ftps.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-functions/functions-overview
- Hosting plans: https://learn.microsoft.com/azure/azure-functions/functions-scale
- Flex Consumption: https://learn.microsoft.com/azure/azure-functions/flex-consumption-plan
- Triggers and bindings: https://learn.microsoft.com/azure/azure-functions/functions-triggers-bindings
- Connections: https://learn.microsoft.com/azure/azure-functions/manage-connections
