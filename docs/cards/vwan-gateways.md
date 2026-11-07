# Virtual WAN gateways and VPN sites

A Virtual WAN hub holds its own gateways: a site-to-site VPN gateway for branches, an ExpressRoute gateway for circuits and a point-to-site gateway for remote users. A VPN site describes one branch: its device, links and address space.

## Key ideas

- **Scale units**: a hub gateway's capacity is set in scale units, each a fixed amount of bandwidth.
- **VPN sites and links**: a site is a branch; each link is one of its internet connections (provider, speed, public IP, BGP). A site connects to a hub's VPN gateway, one tunnel pair per link.
- **ExpressRoute gateway**: connects circuits to the hub, with a routing weight and optional FastPath per connection.
- **Point-to-site gateway**: users connect with the VPN client, authenticated by a VPN server configuration (certificates, RADIUS or Entra ID), and get addresses from client pools.
- **NAT rules**: translate overlapping branch address ranges on the VPN gateway.

## In nebaz

- VPN gateways: Configuration (scale units, BGP, instance IPs), Connections (each site and each link: status, protocol, BGP, IPsec policy, bytes) and NAT rules.
- ER gateways: Configuration and each circuit connection. P2S gateways: Configuration and Clients (connected count and bytes; per-user sessions are a POST, never sent).
- VPN sites: Site, Links, and the hub gateways it connects to.

## Learn more

- Site-to-site: https://learn.microsoft.com/azure/virtual-wan/virtual-wan-site-to-site-portal
- Point-to-site: https://learn.microsoft.com/azure/virtual-wan/point-to-site-concepts
- ExpressRoute in Virtual WAN: https://learn.microsoft.com/azure/virtual-wan/virtual-wan-expressroute-portal
- Gateway settings: https://learn.microsoft.com/azure/virtual-wan/gateway-settings
- NAT rules: https://learn.microsoft.com/azure/virtual-wan/nat-rules-vpn-gateway
