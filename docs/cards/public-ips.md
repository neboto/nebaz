# Public IP addresses

A public IP address is its own resource, attached to the thing that should be reachable from the internet or reach out to it: a NIC, a load balancer, a VPN gateway, a firewall, a Bastion host or a NAT gateway. You keep the address when you detach it, and you pay for it while you have it.

## Key ideas

- **SKU**: Standard, always static, zone-redundant where offered and closed to inbound traffic until an NSG allows it. The Basic SKU is retired.
- **Allocation**: static keeps the address for the resource's life; dynamic (Basic only) could change when the resource was stopped.
- **IPv4 and IPv6**: one of each can be attached to a dual-stack configuration.
- **DNS label**: an optional name under the region's cloudapp.azure.com domain that points at the address.
- **Prefixes**: a reserved, contiguous range of public addresses to allocate from, useful when a partner allowlists your range.
- **Routing preference and tier**: the Microsoft network or the internet for the route in; regional or global (for a cross-region load balancer).

## In nebaz

- The state is attached or unattached. Overview shows the address, allocation, SKU and tier, what it is attached to, the DNS label and the zones.
- Related jumps to the owner (NIC, load balancer, gateway, firewall, Bastion host), the NAT gateway and the prefix.
- @audit: pip-unattached (billed but unused).

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses
- Prefixes: https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-address-prefix
- Basic SKU retirement: https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-basic-upgrade-guidance
