# Network interfaces

A network interface (NIC) connects a virtual machine to a virtual network. It holds the VM's private IP addresses, can carry a public IP, and is where a network security group or an application security group can apply. A NIC is its own resource: a VM has one or more, and a NIC can outlive the VM it was attached to.

## Key ideas

- **IP configurations**: each NIC has one or more, each with a private IP in a subnet (static or dynamic), optionally a public IP. One is primary.
- **NSG on the NIC**: rules here apply on top of the subnet's NSG; traffic has to pass both.
- **Application security groups**: a NIC's IP configuration can join ASGs, so NSG rules can name a group of machines instead of IP addresses.
- **Accelerated networking**: hands the network path to the host's hardware for lower latency, on the sizes that support it.
- **IP forwarding**: lets the VM pass on traffic not addressed to it, which a firewall or router appliance needs.

## In nebaz

- The list shows each NIC as attached or unattached. IP configurations lists each one's private IP, allocation, public IP and ASGs.
- Related jumps to the VM, the NSG, each subnet, public IP and ASG.
- N opens the network access lens: the subnet's and the NIC's NSG rules evaluated in order, worked out from the rules themselves (never Azure's effective-rules call, which is a POST).
- @audit: nic-orphaned (no VM, private endpoint, private link service or hosted workload uses it).

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface
- IP addresses: https://learn.microsoft.com/azure/virtual-network/ip-services/virtual-network-network-interface-addresses
- Accelerated networking: https://learn.microsoft.com/azure/virtual-network/accelerated-networking-overview
