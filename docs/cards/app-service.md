# Azure App Service

App Service hosts web apps and APIs, in code (.NET, Java, Node.js, Python, PHP) or in containers, on Windows or Linux. Azure runs the servers, the OS and the runtime; you deploy the app and choose how much compute it gets through its App Service plan.

## Key ideas

- **App Service plan**: the compute, a number of workers of one size, that every app in the plan shares. Tiers go from Free and Basic through Standard and Premium to Isolated, which runs in an App Service Environment in your VNet.
- **Scaling**: more workers (scale out, by rule or automatically) or a bigger tier (scale up).
- **Deployment slots**: staging copies of an app on Standard and up, swapped into production with no downtime.
- **Networking**: VNet integration for the app's outbound calls; access restrictions and private endpoints for who may call in.
- **Security settings**: HTTPS only, the minimum TLS version, FTPS or no FTP at all, managed identity, and app settings read from Key Vault references.
- **SCM site (Kudu)**: the deployment and diagnostics site beside each app, with its own access restrictions.

## In nebaz

- Apps: Configuration is a lazy read of the runtime, always on, TLS, FTPS, health check, VNet routing and access restrictions. App settings and connection strings are never read (a POST, and they hold secrets).
- Hostnames shows each binding's TLS state; Networking shows public access, the integration subnet and outbound IPs.
- Plans: the SKU and tier, OS, workers of the maximum, the app count and zone redundancy.
- Never sent: start, stop, restart, swap, or a request to the app itself.
- @audit: app-https-only, app-min-tls, app-ftps.

## Learn more

- Overview: https://learn.microsoft.com/azure/app-service/overview
- Plans: https://learn.microsoft.com/azure/app-service/overview-hosting-plans
- Deployment slots: https://learn.microsoft.com/azure/app-service/deploy-staging-slots
- Networking: https://learn.microsoft.com/azure/app-service/networking-features
- Security: https://learn.microsoft.com/azure/app-service/overview-security
- Key Vault references: https://learn.microsoft.com/azure/app-service/app-service-key-vault-references
