# Virtual network gateways

A virtual network gateway connects a virtual network to networks outside it: a VPN gateway over encrypted tunnels across the internet, or an ExpressRoute gateway over a private circuit. The other side of a site-to-site VPN is a local network gateway, and the link between the two is a connection.

## Key ideas

- **GatewaySubnet**: the gateway lives in a subnet with exactly that name, /27 or larger.
- **Gateway type and SKU**: VPN (VpnGw1 to VpnGw5) or ExpressRoute (ErGw, ErGwScale). The AZ SKUs spread the gateway across availability zones; Microsoft is moving the non-AZ VPN SKUs to their AZ versions.
- **Active-active**: two gateway instances, each with its own public IP and tunnels, so maintenance or a failure doesn't drop the connection.
- **Local network gateway**: your on-premises VPN device: its public IP or FQDN, and your address ranges or BGP peer.
- **Connections**: IPsec (site-to-site), VNet-to-VNet or ExpressRoute, each with its status. IPsec connections use a shared key and Azure's or your own IPsec policy.
- **BGP and point-to-site**: dynamic routes with your devices; P2S lets single users connect with the VPN client.

## In nebaz

- VNet gateways: Configuration, IP configurations (⚠ a subnet not named GatewaySubnet), BGP, Point-to-site (root certificates by name) and its connections.
- Connections: status (⚠ when not connected), bytes in and out, each tunnel's status, the IPsec policy. The shared key is never read.
- Local gateways: the on-premises endpoint, address space and BGP, and its connections.
- @audit: vpn-connection-down, er-connection-down, gateway-not-zone-redundant.

## Learn more

- VPN Gateway: https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpngateways
- VPN Gateway settings: https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings
- SKUs: https://learn.microsoft.com/azure/vpn-gateway/about-gateway-skus
- Active-active: https://learn.microsoft.com/azure/vpn-gateway/about-active-active-gateways
- ExpressRoute gateways: https://learn.microsoft.com/azure/expressroute/expressroute-about-virtual-network-gateways
- IPsec policies: https://learn.microsoft.com/azure/vpn-gateway/ipsec-ike-policy-howto
