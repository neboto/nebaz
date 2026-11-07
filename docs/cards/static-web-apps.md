# Azure Static Web Apps

Static Web Apps hosts static front ends (HTML, JavaScript, a single-page app or a static site generator's output) from a Git repository, distributed globally, with an optional API behind it. Each push builds and deploys through GitHub Actions or Azure Pipelines, and each pull request gets its own preview environment.

## Key ideas

- **Plans**: Free (hobby projects) and Standard (custom authentication, more custom domains, private endpoints, an SLA, linked backends).
- **Environments**: production from the main branch; preview environments from pull requests or other branches, removed when the PR closes.
- **APIs**: managed Azure Functions inside the app, or linked backends you run yourself: a function app, a container app or API Management.
- **Configuration file**: staticwebapp.config.json sets routes, fallbacks, headers and which roles may reach a path.
- **Custom domains**: validated by DNS, with free managed certificates.

## In nebaz

- Configuration shows staging environments, the build locations, public access, private endpoints and the database connections.
- Environments, Custom domains and Backends are lazy reads: each environment's branch, pull request and status (Failed or Detached ⚠), each domain's status, and each linked backend as a jump.
- Never read: the deployment token or app settings.

## Learn more

- Overview: https://learn.microsoft.com/azure/static-web-apps/overview
- Plans: https://learn.microsoft.com/azure/static-web-apps/plans
- Preview environments: https://learn.microsoft.com/azure/static-web-apps/preview-environments
- APIs: https://learn.microsoft.com/azure/static-web-apps/apis-overview
- Configuration: https://learn.microsoft.com/azure/static-web-apps/configuration
