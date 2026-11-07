# Azure Bastion

Azure Bastion lets you open RDP and SSH sessions to virtual machines from the portal or the native client, without giving the VMs public IPs or opening ports 22 and 3389 to the internet. It runs in its own subnet of the virtual network, or, for the Developer SKU, as a shared service.

## Key ideas

- **AzureBastionSubnet**: a dedicated subnet, /26 or larger, named exactly that.
- **SKUs**: Developer (free, one session at a time, no subnet), Basic, Standard (native client, IP-based connections, shareable links, scale units) and Premium (session recording, private-only deployment).
- **Reach**: VMs in the same VNet and in peered VNets.
- **Scale units**: on Standard and Premium, more instances for more concurrent sessions.

## In nebaz

- Features shows which ones are on and what the SKU allows: copy and paste, native client tunnelling, IP-based connection, shareable links, file copy, Kerberos, session recording, private-only.
- Network shows the VNet, the subnet and the public IP, as jumps.
- Never sent: starting a session or a tunnel (C copies the command).

## Learn more

- Overview: https://learn.microsoft.com/azure/bastion/bastion-overview
- SKUs: https://learn.microsoft.com/azure/bastion/bastion-sku-comparison
- Native client: https://learn.microsoft.com/azure/bastion/native-client
- Bastion with NSGs: https://learn.microsoft.com/azure/bastion/bastion-nsg
