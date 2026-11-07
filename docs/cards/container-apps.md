# Azure Container Apps

Container Apps runs containers without a Kubernetes cluster to manage: you give it an image, and it handles ingress, HTTPS, scaling (down to zero) and revisions. Apps and jobs live in an environment, which is the boundary for networking and logs.

## Key ideas

- **Environment**: shared by the apps and jobs in it. It can be inside your VNet, and internal (reachable only from that network) or external. Workload profiles choose the compute: Consumption, or dedicated sizes.
- **Revisions**: an immutable snapshot of an app's configuration. In multiple-revision mode, traffic can be split between revisions by weight or label.
- **Ingress**: external (the internet) or internal (the environment), with IP restrictions, custom domains and certificates.
- **Scale rules**: replicas between a minimum and a maximum, driven by HTTP traffic or KEDA scalers such as a queue's length.
- **Jobs**: containers that run to completion, started manually, on a cron schedule or by events.
- **Secrets and identity**: secrets stored on the app or read from Key Vault through a managed identity.

## In nebaz

- Apps: Ingress, Scale, Containers, Revisions (lazy), Auth (lazy), Identity and Secrets. Secret and environment variable values are stripped before nebaz keeps the JSON; you see names and Key Vault references only.
- Environments: Network (internal or external, subnet, DNS), workload profiles. Keys and connection strings are stripped.
- Jobs: the trigger and Executions (lazy, a failed one ⚠). Container groups (Container Instances) has its own card.
- Never sent: exec into a container, log streams, starting a job.
- @audit: aca-ingress-open, aca-allow-insecure, aca-secrets-not-kv, aca-env-external-pp-vnet.

## Learn more

- Overview: https://learn.microsoft.com/azure/container-apps/overview
- Environments: https://learn.microsoft.com/azure/container-apps/environment
- Revisions: https://learn.microsoft.com/azure/container-apps/revisions
- Ingress: https://learn.microsoft.com/azure/container-apps/ingress-overview
- Scaling: https://learn.microsoft.com/azure/container-apps/scale-app
- Jobs: https://learn.microsoft.com/azure/container-apps/jobs
- Secrets: https://learn.microsoft.com/azure/container-apps/manage-secrets
