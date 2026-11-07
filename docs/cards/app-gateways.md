# Azure Application Gateway

Application Gateway is a regional web traffic load balancer (layer 7): it ends TLS, reads the HTTP request and sends it to a backend pool by host name and path. With the WAF tier it also inspects requests against attack rules. It runs in a subnet of your virtual network.

## Key ideas

- **Frontend and listeners**: a public or private IP; each listener is a port, a protocol and optionally host names, with its TLS certificate (often from Key Vault).
- **Rules**: tie a listener to a backend pool through backend settings, or to a path map that picks a pool per URL path; a rule can redirect instead.
- **Backend settings**: the protocol and port to the backend, the host name sent, affinity, timeouts and the health probe.
- **Backend pools**: VMs, scale sets, IP addresses or FQDNs such as App Service and Container Apps. Those need the right host header, or the backend rejects the request.
- **v2 SKUs**: Standard_v2 and WAF_v2, with autoscaling and zones. The v1 SKUs are retired.
- **Its own subnet**: the gateway needs a dedicated subnet, and an NSG there has to allow the GatewayManager ports.

## In nebaz

- Frontends, Listeners, Rules and Backends show the chain a request follows: listener, rule, settings, pool, with each backend address matched to a resource in the loaded lists. A listener no rule uses and an empty pool are flagged.
- Certificates are shown by name and Key Vault secret id, never their content. WAF lists the gateway's, listeners' and path rules' policies.
- Never sent: backend health (a POST). N opens the network access lens on the gateway's subnet.
- @audit: waf-not-blocking (on its WAF policy).

## Learn more

- Overview: https://learn.microsoft.com/azure/application-gateway/overview
- How it works: https://learn.microsoft.com/azure/application-gateway/how-application-gateway-works
- Components: https://learn.microsoft.com/azure/application-gateway/application-gateway-components
- Infrastructure and subnet: https://learn.microsoft.com/azure/application-gateway/configuration-infrastructure
- Key Vault certificates: https://learn.microsoft.com/azure/application-gateway/key-vault-certs
