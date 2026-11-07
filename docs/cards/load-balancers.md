# Azure Load Balancer

Azure Load Balancer spreads TCP and UDP traffic across a pool of backend machines (layer 4): it doesn't look inside HTTP. A public load balancer takes traffic from the internet; an internal one serves a private IP inside a virtual network.

## Key ideas

- **Frontend**: the IP the load balancer listens on, public or private.
- **Backend pool**: the NICs (or IP addresses) that receive the traffic.
- **Health probes**: TCP, HTTP or HTTPS checks; an instance that fails stops receiving new flows.
- **Rules**: load-balancing rules map a frontend port to the pool; inbound NAT rules forward a port to one instance; outbound rules give the pool its SNAT for internet access.
- **SKUs**: Standard (zone-redundant, closed until an NSG allows traffic), Gateway (chains an appliance) and the cross-region (Global) tier. The Basic SKU is retired.
- **HA ports**: an internal Standard load balancer can balance every port at once, the usual way to put appliances in front of a subnet.

## In nebaz

- Frontends, Backend pools (NICs or addresses) and Rules (load-balancing rules, health probes, inbound NAT and outbound rules).
- Related jumps to the frontend public IPs and subnets and the backend NICs; a route's appliance next hop is matched to a load balancer frontend.
- @audit: lb-empty-pool (a pool with no NIC and no address; Global load balancers skipped).

## Learn more

- Overview: https://learn.microsoft.com/azure/load-balancer/load-balancer-overview
- Components: https://learn.microsoft.com/azure/load-balancer/components
- Health probes: https://learn.microsoft.com/azure/load-balancer/load-balancer-custom-probe-overview
- Outbound rules: https://learn.microsoft.com/azure/load-balancer/outbound-rules
- SKUs: https://learn.microsoft.com/azure/load-balancer/skus
