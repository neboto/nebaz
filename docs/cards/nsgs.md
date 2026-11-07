# Network security groups

A network security group (NSG) is a list of allow and deny rules for traffic to and from Azure resources in a virtual network. You attach it to a subnet, to a network interface, or to both; traffic has to pass every NSG on its way.

## Key ideas

- **Rules**: source, destination, port, protocol, direction and allow or deny, checked by priority from 100 upwards. The first match decides; later rules are not read.
- **Default rules**: at 65000 and up, they allow traffic within the VNet and from the Azure load balancer, allow outbound to the internet, and deny everything else. They cannot be removed, only overridden.
- **Service tags and ASGs**: a rule can name a service tag (Internet, VirtualNetwork, Storage.WestEurope) or an application security group instead of IP ranges.
- **Subnet and NIC**: inbound traffic is checked by the subnet's NSG and then the NIC's; outbound in the opposite order.
- **Stateful**: a reply to allowed traffic is allowed back without a rule of its own.
- **Flow logs**: NSG flow logs are being retired in favour of VNet flow logs.

## In nebaz

- Inbound and Outbound list the custom rules by priority, then the default rules dimmed. Used by lists the subnets and NICs it is attached to.
- N opens the network access lens, which evaluates the rules in order together with the other NSG on the path (worked out from the rules, never Azure's effective-rules call, which is a POST).
- Flow logs is a lazy read of its NSG flow logs and the VNet flow logs on its subnets.
- @audit: nsg-open-internet (critical for all ports, SSH or RDP open to the internet), subnet-no-nsg.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
- How rules are evaluated: https://learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works
- Service tags: https://learn.microsoft.com/azure/virtual-network/service-tags-overview
- VNet flow logs: https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview
