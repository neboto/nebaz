# Azure Front Door

Azure Front Door is Microsoft's global entry point for web applications: requests reach the nearest of its edge locations, which end TLS, cache content, apply WAF rules and send the request to the best origin over Microsoft's network. Standard and Premium are the current tiers; Front Door (classic) is being retired.

## Key ideas

- **Profile and endpoints**: a profile holds endpoints, each with a host name on azurefd.net, plus your custom domains.
- **Routes**: match domains, paths and protocols to an origin group, with caching, HTTPS redirect and rule sets.
- **Origin groups and origins**: the backends (App Service, storage, a load balancer, any host), with health probes, priority and weight.
- **Private Link origins**: on Premium, Front Door reaches an origin through a private endpoint that the origin's owner approves.
- **Custom domains**: validated by a DNS TXT record, with a managed or your own certificate.
- **Locking down origins**: an origin should only accept traffic from Front Door: the AzureFrontDoor.Backend service tag and the X-Azure-FDID header with your profile's id.

## In nebaz

- Endpoints, Origins, Domains and Security are lazy reads: each route and its origin group, each origin with its host header (flagged for Container Apps and App Service when it would be rejected) and Private Link status, each domain's validation state and certificate, and the WAF policy on each domain.
- Overview shows the Front Door id that the X-Azure-FDID header carries. The domain validation token is never shown.

## Learn more

- Overview: https://learn.microsoft.com/azure/frontdoor/front-door-overview
- Routing: https://learn.microsoft.com/azure/frontdoor/front-door-routing-architecture
- Origins: https://learn.microsoft.com/azure/frontdoor/origin
- Private Link: https://learn.microsoft.com/azure/frontdoor/private-link
- Secure the origin: https://learn.microsoft.com/azure/frontdoor/origin-security
- Classic retirement: https://learn.microsoft.com/azure/frontdoor/tier-migration
