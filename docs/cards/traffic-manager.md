# Azure Traffic Manager

Traffic Manager spreads traffic across endpoints in different regions or outside Azure using DNS: it answers each query with the endpoint that the routing method and health checks pick, and the client then connects there directly. It never sees the traffic itself.

## Key ideas

- **Routing methods**: Priority (failover), Weighted, Performance (lowest latency), Geographic, MultiValue (several healthy addresses) and Subnet.
- **Endpoints**: Azure (a public IP, an App Service), External (any FQDN or IP) or Nested (another profile, to combine methods).
- **Endpoint monitoring**: HTTP, HTTPS or TCP probes; a degraded endpoint is left out of answers.
- **TTL**: how long resolvers cache an answer, and so how fast clients follow a failover.
- **Profile name**: clients use myapp.trafficmanager.net, usually behind your own CNAME.

## In nebaz

- Routing explains the method and shows the FQDN and TTL; Monitor shows the probe settings; Endpoints lists them by priority with their status, Degraded and Stopped ⚠.
- The state is the profile's monitor status: Online is available, Inactive unavailable, Degraded or CheckingEndpoints pending, a Disabled profile stopped.
- Related jumps to each endpoint's target (public IPs, App Service sites, child profiles).

## Learn more

- Overview: https://learn.microsoft.com/azure/traffic-manager/traffic-manager-overview
- Routing methods: https://learn.microsoft.com/azure/traffic-manager/traffic-manager-routing-methods
- Endpoint monitoring: https://learn.microsoft.com/azure/traffic-manager/traffic-manager-monitoring
- Nested profiles: https://learn.microsoft.com/azure/traffic-manager/traffic-manager-nested-profiles
