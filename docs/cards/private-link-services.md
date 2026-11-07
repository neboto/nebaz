# Azure Private Link service

A Private Link service offers your own service, running behind a Standard load balancer, to consumers in other virtual networks, subscriptions or tenants through their private endpoints. Neither side's address ranges matter: the consumer sees a private IP in its own network.

## Key ideas

- **Load balancer frontend**: the service sits on a Standard internal load balancer's frontend IP (or, newer, a destination IP directly).
- **NAT IPs**: source addresses from your subnet that consumer traffic arrives from; the consumer's own IP is hidden unless the TCP proxy protocol is on.
- **Alias**: a global name for the service that consumers use to request a connection without seeing your resource id.
- **Visibility and auto-approval**: which subscriptions may find the service, and which are approved without a manual step.
- **Connections**: each consumer's private endpoint, Pending until approved.

## In nebaz

- Frontend shows the load balancer (a jump), its private IP and subnet, and the NAT IP configurations. Visibility shows the alias, the visibility and auto-approval lists.
- Connections lists each consumer endpoint with its status, ⚠ unless approved; an endpoint in a loaded list is a jump.

## Learn more

- Overview: https://learn.microsoft.com/azure/private-link/private-link-service-overview
- Private Link: https://learn.microsoft.com/azure/private-link/private-link-overview
