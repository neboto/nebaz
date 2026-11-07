# Azure Container Instances

Container Instances runs a container, or a small group of them, on demand: no VM, no cluster, billed by the second. It suits batch jobs, build agents and simple tasks more than long-lived services that need scaling.

## Key ideas

- **Container group**: one or more containers scheduled together on the same host, sharing a lifecycle, an IP address and volumes. It is the resource you deploy.
- **Restart policy**: Always, OnFailure or Never. Never and OnFailure suit run-to-completion work.
- **Networking**: a public IP with an optional DNS label, or a private IP in a delegated VNet subnet.
- **Resources**: CPU and memory per container, GPUs on some SKUs, and Confidential and Spot options.
- **Volumes**: Azure Files shares, secret volumes, empty directories and Git repositories.

## In nebaz

- Container groups is a sub-tab of the Container Apps tab. Containers is one lazy read: each container's image, resources, ports, environment variable names (secure ones marked), live state, restarts and latest events.
- Network and Configuration show the IP, DNS label, subnets, OS, restart policy, registries and volumes by kind (never their contents).
- Never sent: exec, attach or logs (they reach into the container).

## Learn more

- Overview: https://learn.microsoft.com/azure/container-instances/container-instances-overview
- Container groups: https://learn.microsoft.com/azure/container-instances/container-instances-container-groups
- Virtual network: https://learn.microsoft.com/azure/container-instances/container-instances-vnet
- Restart policy: https://learn.microsoft.com/azure/container-instances/container-instances-restart-policy
