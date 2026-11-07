# Azure NAT Gateway

A NAT gateway gives the machines in one or more subnets a fixed set of public IP addresses for outbound internet traffic, with no inbound connections. It is the recommended way out to the internet as default outbound access is retired: subnets in new virtual networks are private by default, so their machines need an explicit way out.

## Key ideas

- **Outbound only**: replies to outbound flows come back; nothing can start a connection to the NAT gateway's addresses.
- **Public IPs and prefixes**: up to 16 addresses, each giving 64,512 SNAT ports, so many concurrent connections don't run out.
- **Precedence**: on a subnet, the NAT gateway is used for outbound traffic ahead of a load balancer's outbound rules or a VM's own public IP.
- **Idle timeout**: how long an idle TCP flow keeps its port, 4 to 120 minutes.
- **Zones**: a NAT gateway is zonal or has no zone; the StandardV2 SKU is zone-redundant.

## In nebaz

- Overview shows the SKU, the idle timeout, the zones and how many addresses, prefixes and subnets it has.
- Related jumps to its public IPs (v4 and v6), its prefixes and each subnet.

## Learn more

- Overview: https://learn.microsoft.com/azure/nat-gateway/nat-overview
- Default outbound access: https://learn.microsoft.com/azure/virtual-network/ip-services/default-outbound-access
- SNAT with NAT gateway: https://learn.microsoft.com/azure/nat-gateway/nat-gateway-snat
