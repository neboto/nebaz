# Azure ExpressRoute circuits

An ExpressRoute circuit is a private connection between your network and Microsoft's, set up through a connectivity provider or directly on Microsoft's ports (ExpressRoute Direct). Traffic doesn't cross the public internet, and the bandwidth is reserved.

## Key ideas

- **Provider and peering location**: the provider who carries the circuit and the meet-me site where it reaches Microsoft. A circuit is not ready until the provider has provisioned it.
- **Peerings**: private peering reaches your virtual networks; Microsoft peering reaches Microsoft 365 and Azure's public services. Each is a pair of BGP sessions for redundancy.
- **SKU**: Local, Standard or Premium (reach across geopolitical regions, more routes and VNets), metered or unlimited data.
- **Connections**: a circuit reaches a VNet through a connection to an ExpressRoute virtual network gateway, or to a Virtual WAN hub.
- **Global Reach**: joins two circuits, so your sites talk to each other over Microsoft's network.
- **Authorisations**: let a gateway in another subscription connect to the circuit.

## In nebaz

- Provider explains the circuit and provider states (a circuit the provider has not provisioned can't carry traffic); the service key is masked.
- Peerings shows each peering's state, VLAN, ASNs and prefixes, ⚠ while Microsoft peering prefixes await validation. Global Reach, Authorizations (name and status only) and Connections follow.
- @audit: er-circuit-not-provisioned, er-connection-down.

## Learn more

- Overview: https://learn.microsoft.com/azure/expressroute/expressroute-introduction
- Circuits and peering: https://learn.microsoft.com/azure/expressroute/expressroute-circuit-peerings
- Workflows and states: https://learn.microsoft.com/azure/expressroute/expressroute-workflows
- Global Reach: https://learn.microsoft.com/azure/expressroute/expressroute-global-reach
- SKUs and locations: https://learn.microsoft.com/azure/expressroute/expressroute-locations-providers
