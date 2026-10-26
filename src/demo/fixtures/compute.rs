//! Demo fixtures: the `compute` area (see `docs/DEMO.md` for who owns what):
//! VMs, disks and scale sets, AKS, Container Registry, App Service, Container Apps.
//! The NIC sub-tab is `network`'s.

use super::{fx, Fixture};

pub static FIXTURES: &[Fixture] = &[
    // ── VMs: the model list, then the `statusOnly` pass for power state ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Compute/virtualMachines", when ["statusOnly=true"], "vms.status-only.json"),
    // A Flexible scale set's Instances: the VM list filtered to the set.
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Compute/virtualMachines", when ["virtualMachineScaleSets/vmss-batch-flex"], "vmss-batch-flex.vms.json"),
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Compute/virtualMachines", "vms.json"),
    // The lazy Instance view section, then the single GET (`$expand=instanceView`).
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vm-jump-01/instanceView", "vm-jump-01.instance-view.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vm-legacy-app-01/instanceView", "vm-legacy-app-01.instance-view.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-network-prod/providers/Microsoft.Compute/virtualMachines/vm-nva-01/instanceView", "vm-nva-01.instance-view.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vm-jump-01", "vm-jump-01.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vm-legacy-app-01", "vm-legacy-app-01.json"),
    // The hub's FortiGate NVA (network's story; its VM rows live here).
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-network-prod/providers/Microsoft.Compute/virtualMachines/vm-nva-01", "vm-nva-01.json"),
    // vmss-batch-flex's two VMs (Flexible orchestration: ordinary VMs).
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vmss-batch-flex_3f2a9c1e/instanceView", "vmss-batch-flex_3f2a9c1e.instance-view.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vmss-batch-flex_8b41d7a0/instanceView", "vmss-batch-flex_8b41d7a0.instance-view.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vmss-batch-flex_3f2a9c1e", "vmss-batch-flex_3f2a9c1e.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachines/vmss-batch-flex_8b41d7a0", "vmss-batch-flex_8b41d7a0.json"),
    // ── Scale sets: a Uniform web tier (instance 2 on the old image) and
    //    the Flexible batch set above ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Compute/virtualMachineScaleSets", "scale-sets.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-legacy-web/virtualMachines", "vmss-legacy-web.instances.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-legacy-web", "vmss-legacy-web.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-batch-flex", "vmss-batch-flex.json"),
    // ── Disks ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Compute/disks", "disks.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/disks/disk-legacy-data-01", "disk-legacy-data-01.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/disks/vm-jump-01_OsDisk_1_3f9a2c7e8b1d4e6fa0c5b7d9e2f41a68", "vm-jump-01.os-disk.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/disks/vm-legacy-app-01_OsDisk_1_8d2e4f6a1b3c4d5e9f7a0b2c4d6e8f13", "vm-legacy-app-01.os-disk.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-network-prod/providers/Microsoft.Compute/disks/vm-nva-01_OsDisk_1_5c2e8a4f9d1b4e7a8c3f6b0d2e4a9c71", "vm-nva-01.os-disk.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/disks/vmss-batch-flex_3f2a9c1e_OsDisk_1_4c8e2a7f1d934b65a0e79f3c5b1d8a26", "vmss-batch-flex_3f2a9c1e.os-disk.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Compute/disks/vmss-batch-flex_8b41d7a0_OsDisk_1_d1b7f3a96e244c8085fa2c9e7a3d1b58", "vmss-batch-flex_8b41d7a0.os-disk.json"),
    // ── AKS: clusters (node pools are flattened from them), one pool GET each ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.ContainerService/managedClusters", "managed-clusters.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.ContainerService/managedClusters/aks-platform-prod/agentPools/system", "aks-pool-system.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.ContainerService/managedClusters/aks-platform-prod/agentPools/batch", "aks-pool-batch.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.ContainerService/managedClusters/aks-platform-prod", "aks-platform-prod.json"),
    // ── Container Registry ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.ContainerRegistry/registries", "registries.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.ContainerRegistry/registries/acrcontosoprod/replications", "acrcontosoprod.replications.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.ContainerRegistry/registries/acrcontosoprod/webhooks", "acrcontosoprod.webhooks.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-platform-prod/providers/Microsoft.ContainerRegistry/registries/acrcontosoprod", "acrcontosoprod.json"),
    // ── App Service: sites (web and function apps), their `config/web`, plans ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Web/sites", "sites.json"),
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.Web/serverfarms", "serverfarms.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Web/sites/app-legacy-portal/config/web", "app-legacy-portal.config-web.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Web/sites/func-legacy-reports/config/web", "func-legacy-reports.config-web.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Web/sites/app-legacy-portal", "app-legacy-portal.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Web/sites/func-legacy-reports", "func-legacy-reports.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-legacy-prod/providers/Microsoft.Web/serverfarms/asp-legacy", "asp-legacy.json"),
    // ── Container Apps: apps, environments, jobs (prod and dev) ──
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.App/containerApps", "container-apps.prod.json"),
    fx!("compute", "/subscriptions/{{dev}}/providers/Microsoft.App/containerApps", "container-apps.dev.json"),
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.App/managedEnvironments", "managed-environments.prod.json"),
    fx!("compute", "/subscriptions/{{dev}}/providers/Microsoft.App/managedEnvironments", "managed-environments.dev.json"),
    fx!("compute", "/subscriptions/{{prod}}/providers/Microsoft.App/jobs", "jobs.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-api/revisions/ca-orders-api--v231/replicas", "ca-orders-api.v231.replicas.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-worker/revisions/ca-orders-worker--v118/replicas", "ca-orders-worker.v118.replicas.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-api/revisions", "ca-orders-api.revisions.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-worker/revisions", "ca-orders-worker.revisions.json"),
    fx!("compute", "/subscriptions/{{dev}}/resourceGroups/rg-dev/providers/Microsoft.App/containerApps/ca-orders-api-dev/revisions", "ca-orders-api-dev.revisions.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-api", "ca-orders-api.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/containerApps/ca-orders-worker", "ca-orders-worker.json"),
    fx!("compute", "/subscriptions/{{dev}}/resourceGroups/rg-dev/providers/Microsoft.App/containerApps/ca-orders-api-dev", "ca-orders-api-dev.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/managedEnvironments/cae-orders-prod", "cae-orders-prod.json"),
    fx!("compute", "/subscriptions/{{dev}}/resourceGroups/rg-dev/providers/Microsoft.App/managedEnvironments/cae-orders-dev", "cae-orders-dev.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/jobs/caj-nightly-export/executions", "caj-nightly-export.executions.json"),
    fx!("compute", "/subscriptions/{{prod}}/resourceGroups/rg-orders-prod/providers/Microsoft.App/jobs/caj-nightly-export", "caj-nightly-export.json"),
];
