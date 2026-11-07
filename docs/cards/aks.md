# Azure Kubernetes Service (AKS)

AKS runs Kubernetes for you: Azure operates the control plane, the API server and etcd, and you run your workloads on node pools of virtual machines in your subscription. You choose the Kubernetes version, the networking and how people and workloads authenticate.

## Key ideas

- **Control plane**: run by Azure. The API server is public by default; you can limit it to authorised IP ranges or make the cluster private.
- **Node pools**: groups of VMs (scale sets) with one size and OS. A system pool runs cluster add-ons; user pools run your workloads. Pools can autoscale and can use Spot VMs.
- **Node resource group**: the MC_ group where AKS keeps the nodes, disks, load balancer and public IPs. Leave it to AKS.
- **Networking**: Azure CNI (pod IPs from the VNet or an overlay) or kubenet, with network policy on top.
- **Identity and access**: Entra ID sign-in with Kubernetes RBAC or Azure RBAC. Local accounts (the cluster admin certificate) can be disabled. Workload identity gives pods an Entra ID identity.
- **Upgrades**: Kubernetes versions get about a year of support; node images are updated more often, on their own channel.

## In nebaz

- Clusters: Network, API access and Add-ons, and the state from provisioning, then the power state. Node pools is a section and also its own sub-tab, with each pool's mode, size, count, autoscale and taints.
- Related jumps to the node resource group, the kubelet and user identities and the monitoring workspace.
- Never fetched: kubeconfig credentials, run command, anything inside the cluster.
- @audit: aks-public-api, aks-local-accounts, aks-rbac-disabled.

## Learn more

- Overview: https://learn.microsoft.com/azure/aks/what-is-aks
- Core concepts: https://learn.microsoft.com/azure/aks/core-aks-concepts
- Node pools: https://learn.microsoft.com/azure/aks/create-node-pools
- Network concepts: https://learn.microsoft.com/azure/aks/concepts-network
- API server access: https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges
- Disable local accounts: https://learn.microsoft.com/azure/aks/local-accounts
- Supported versions: https://learn.microsoft.com/azure/aks/supported-kubernetes-versions
