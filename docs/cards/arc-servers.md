# Azure Arc-enabled servers

Azure Arc brings machines that run outside Azure (in your datacentre, at the edge, or in another cloud) into Azure Resource Manager. Each machine gets an Azure resource, so you can manage it like a VM: tags, RBAC, Azure Policy, Defender for Servers, Azure Monitor and Update Manager, all through extensions.

## Key ideas

- **Connected Machine agent**: installed on the machine (azcmagent). It sends a heartbeat to Azure and runs the extensions. It ships about monthly, and versions older than a year are not supported.
- **Status**: Connected while heartbeats arrive; Disconnected after about 15 minutes without one. After 45 days disconnected, the machine's identity certificate lapses and it is expired: it has to be onboarded again.
- **Extensions**: how Azure services reach the machine (the Azure Monitor agent, Defender's MDE, patching, custom scripts). Each has its own state and can fail on its own.
- **Extended Security Updates (ESU)**: paid security updates for Windows Server 2012 and 2012 R2 after end of support, licensed through Arc. An eligible machine with no licence assigned gets none.
- **Private link scope**: lets machines reach Arc through a private endpoint instead of public endpoints.

## In nebaz

- Status reads Expired after 45 days disconnected, as the portal does; ARM itself still says Disconnected. Agent shows how long a machine has been disconnected.
- Extensions is one lazy read per server: type, version, state (⚠ when failed) and the first line of its message. An extension's settings are never shown, and ARM never returns the protected ones.
- Licensing & patching flags an ESU-eligible machine with no licence.
- Never sent: run commands, patch assessment or installation (they change the machine).
- @audit: arc-machine-disconnected, arc-agent-behind.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-arc/servers/overview
- The agent: https://learn.microsoft.com/azure/azure-arc/servers/agent-overview
- Agent releases: https://learn.microsoft.com/azure/azure-arc/servers/agent-release-notes
- ESU through Arc: https://learn.microsoft.com/azure/azure-arc/servers/prepare-extended-security-updates
- Private link: https://learn.microsoft.com/azure/azure-arc/servers/private-link-security
