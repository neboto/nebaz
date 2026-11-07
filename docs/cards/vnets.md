# Azure Virtual Network

A virtual network (VNet) is your private, isolated network in Azure: the building block that lets resources such as virtual machines talk to each other, to the internet and to on-premises networks. A VNet lives in one region and one subscription; you connect VNets to each other with peering, and to on-premises with a VPN or ExpressRoute gateway.

## Key ideas

- **Address space**: one or more private CIDR ranges (10.0.0.0/16). Plan them so they never overlap a network you will peer with or reach on-premises: overlapping ranges cannot be connected.
- **Subnets**: slices of the address space. Azure keeps five addresses in each one. Some services need a subnet of their own, often delegated to them (Container Apps, SQL managed instances, Power Platform).
- **Network security groups (NSGs)**: allow and deny rules on a subnet or a NIC. Rules are checked by priority, lowest number first; the defaults at 65000 and up allow traffic inside the VNet and outbound to the internet.
- **Peering**: joins two VNets over the Microsoft backbone. It is not transitive: A to B and B to C does not give A to C.
- **Routes**: Azure's system routes, overridden by route tables (user-defined routes), typically to send traffic through a firewall.
- **Private endpoints**: a PaaS service (storage, Key Vault, SQL) given a private IP in your subnet, usually with a private DNS zone so its name resolves to that IP.

## In nebaz

- VNets list with their address space; Subnets and Peerings are sections, and every subnet is also its own sub-tab (@subnet) with its NSG, route table, delegation and the NICs and endpoints in it.
- N on a subnet, a NIC or an NSG opens the network access lens: the effective NSG rules, in order, worked out from the rules themselves (never Azure's effective-rules call, which is a POST).
- Flow logs is one lazy read of the subscription's flow logs.
- @audit: subnet-no-nsg, subnet-pp-no-nsg, peering-not-connected, flow-logs-missing.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview
- Subnets: https://learn.microsoft.com/azure/virtual-network/virtual-network-manage-subnet
- Network security groups: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
- Peering: https://learn.microsoft.com/azure/virtual-network/virtual-network-peering-overview
- Limits: https://learn.microsoft.com/azure/azure-resource-manager/management/azure-subscription-service-limits
