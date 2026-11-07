# Azure Container Registry

A container registry stores container images and other OCI artifacts (Helm charts, for example) for AKS, Container Apps, App Service and anything else that pulls images. Each registry has a login server name such as myregistry.azurecr.io.

## Key ideas

- **SKUs**: Basic, Standard and Premium. Premium adds geo-replication, private endpoints, IP rules and customer-managed keys.
- **Authentication**: Entra ID identities with roles such as AcrPull and AcrPush. The admin user is one shared username and password; anonymous pull lets anyone pull.
- **Network access**: public by default; Premium can restrict to IP rules or private endpoints and let trusted Azure services through.
- **Geo-replication**: copies of the registry in other regions, so pulls are local and survive a regional outage.
- **Webhooks and tasks**: notify on push or delete; build images in the registry.

## In nebaz

- Security flags the admin user and anonymous pull, and shows network access, encryption and private endpoints.
- Replications is one lazy read, made only for Premium registries. Webhooks shows status and actions, never the service URI (it can carry a token).
- Never read: the admin credentials or the images' contents.
- @audit: acr-admin-user, acr-anonymous-pull.

## Learn more

- Overview: https://learn.microsoft.com/azure/container-registry/container-registry-intro
- SKUs: https://learn.microsoft.com/azure/container-registry/container-registry-skus
- Authentication: https://learn.microsoft.com/azure/container-registry/container-registry-authentication
- Geo-replication: https://learn.microsoft.com/azure/container-registry/container-registry-geo-replication
- Private link: https://learn.microsoft.com/azure/container-registry/container-registry-private-endpoints
