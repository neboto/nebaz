# Route tables

A route table holds user-defined routes that override Azure's system routes for the subnets it is attached to. The usual reason is to send traffic through a firewall or another network appliance instead of straight to its destination.

## Key ideas

- **System routes**: Azure's defaults, within the VNet, to peered VNets, to the internet and to on-premises learned over a gateway.
- **User-defined routes**: an address prefix and a next hop. The most specific prefix wins; with equal prefixes, a user route beats BGP, which beats a system route.
- **Next hop types**: VirtualAppliance (an IP, such as a firewall), VirtualNetworkGateway, VnetLocal, Internet, or None (drop).
- **Gateway route propagation**: whether routes learned from a VPN or ExpressRoute gateway reach the subnets. Off is common for spokes behind a firewall.
- **Per subnet**: one route table per subnet; one table can serve many subnets.

## In nebaz

- Routes lists each prefix and its next hop. Under a VirtualAppliance route, the next hop IP is matched to a NIC or load balancer frontend in the loaded lists, as a jump.
- Related jumps to each subnet the table is attached to and to each matched appliance.
- Never sent: Azure's effective-routes call (a POST).

## Learn more

- Traffic routing: https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview
- Manage route tables: https://learn.microsoft.com/azure/virtual-network/manage-route-table
