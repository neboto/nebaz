# Azure Arc-enabled Kubernetes

Arc connects a Kubernetes cluster that runs outside Azure, on-premises, at the edge or on another cloud, to Azure: the cluster then shows up as a resource you can manage with Azure Policy, GitOps, monitoring and Azure RBAC. Agents installed in the cluster keep an outbound connection to Azure; no inbound port is needed.

## Key ideas

- **Agents**: a set of deployments in the cluster's azure-arc namespace that hold the connection, refresh the identity certificate and apply what Azure sends.
- **Connectivity**: Connected, Offline when the agents have not checked in, and Expired once the cluster's managed identity certificate has expired (after 90 days offline). An expired cluster must be connected again.
- **Cluster extensions**: features installed through Azure, such as Flux (GitOps), Azure Monitor and Defender for Containers.
- **Cluster connect and Azure RBAC**: reach the API server through Azure, and use Entra ID role assignments for Kubernetes authorisation.
- **Private link**: the agents can reach Azure through a private link scope instead of the internet.

## In nebaz

- The list shows connectivity, the Kubernetes version and distribution, and the node count.
- Agent flags an offline or expired cluster, and an identity certificate that expires within 14 days or has expired; each agent error is a ⚠ line.
- Never sent: cluster connect or the user credential call (they would give access to the cluster).
- @audit: arc-cluster-offline.

## Learn more

- Overview: https://learn.microsoft.com/azure/azure-arc/kubernetes/overview
- Agents: https://learn.microsoft.com/azure/azure-arc/kubernetes/conceptual-agent-overview
- Connectivity status: https://learn.microsoft.com/azure/azure-arc/kubernetes/conceptual-connectivity-modes
- Cluster connect: https://learn.microsoft.com/azure/azure-arc/kubernetes/conceptual-cluster-connect
