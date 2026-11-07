# Azure Virtual WAN

Virtual WAN is a hub-and-spoke network that Microsoft runs for you: virtual hubs in the regions you choose connect your VNets, branches (VPN sites), users (point-to-site) and ExpressRoute circuits, and route between all of them. You don't build the hub VNet or its routing yourself.

## Key ideas

- **WAN and hubs**: the WAN is the container; each hub is a Microsoft-managed VNet in one region with its own router. Hubs in one WAN are joined to each other.
- **Basic and Standard**: Basic allows site-to-site VPN only; Standard adds ExpressRoute, point-to-site, VNet-to-VNet through the hub and hub-to-hub transit.
- **Connections**: each VNet connects to one hub; the hub router learns its prefixes.
- **Route tables**: associations (which table a connection uses) and propagations (which tables learn its routes), plus static routes.
- **Routing intent**: send internet and private traffic through a firewall or security appliance in the hub: a secured hub.

## In nebaz

- WANs: the type and what Basic lacks, branch-to-branch and VNet-to-VNet, and each hub in it.
- Hubs: Hub (routing state, ⚠ when failed, router ASN and IPs, capacity), Gateways, and lazy Connections (each VNet with its route tables) and Routing (routing intent, each table's routes with jumpable next hops).
- The hubs' gateways and the VPN sites have their own card.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-wan/virtual-wan-about
- Global transit: https://learn.microsoft.com/azure/virtual-wan/virtual-wan-global-transit-network-architecture
- Hub routing: https://learn.microsoft.com/azure/virtual-wan/about-virtual-hub-routing
- Routing intent: https://learn.microsoft.com/azure/virtual-wan/how-to-routing-policies
- Secured hubs: https://learn.microsoft.com/azure/firewall-manager/secured-virtual-hub
