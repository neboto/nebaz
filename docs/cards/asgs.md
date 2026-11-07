# Application security groups

An application security group (ASG) is a name for a set of network interfaces, such as "web servers" or "database servers". Network security group rules can then use the name as a source or destination instead of IP addresses, so the rules keep working as machines come and go.

## Key ideas

- **Membership**: a NIC's IP configuration joins an ASG. The ASG holds no list of its own; the NICs name it.
- **Rules**: an NSG rule can name ASGs as its source, its destination or both, alongside or instead of IP ranges and service tags.
- **One network**: every NIC in an ASG, and every ASG in one rule, must be in the same virtual network.

## In nebaz

- Members lists the NICs that name the ASG, each with its IP configuration and VM. Rules lists each NSG rule that names the ASG and whether it is the source or the destination.
- Both are worked out from the NIC and NSG lists, so they fill in once those lists are loaded.
- The network access lens (N on a NIC or NSG) resolves ASGs the same way.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-network/application-security-groups
- In NSG rules: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
