# Virtual Machine Scale Sets

A scale set runs a group of virtual machines from one model, so you can grow and shrink the group by count, by schedule or by load, and spread it across zones and fault domains. It is the basis for many services' own machines, such as AKS node pools.

## Key ideas

- **Orchestration mode**: Uniform (identical instances managed through the set) or Flexible (ordinary VMs that belong to the set and can differ). Flexible is the recommended mode for new sets.
- **Model**: the image, size, disks, network and extensions every new instance gets. A changed model reaches existing instances through the upgrade policy.
- **Upgrade policy**: Manual, Automatic or Rolling; automatic OS image upgrades can be switched on separately.
- **Autoscale**: rules in Azure Monitor that change the capacity on a metric or a schedule.
- **Spot**: spare capacity at a discount that Azure can take back, with an eviction policy and a maximum price.
- **Instance repairs and scale-in policy**: replace unhealthy instances; choose which instances go first when the set shrinks.

## In nebaz

- The list shows each set's mode and size × capacity. Model, Scaling and Network describe the model; extensions are shown by name and type only (their settings, custom data and user data are stripped before nebaz keeps the JSON).
- Instances is one lazy read: power state, zone and, for Uniform sets, whether the instance has the latest model. A Flexible set's instances are VMs and jump to the VMs tab.
- @audit: vmss-instance-not-latest-model (Uniform sets only, at info level).

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-machine-scale-sets/overview
- Orchestration modes: https://learn.microsoft.com/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-orchestration-modes
- Upgrade policies: https://learn.microsoft.com/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-upgrade-policy
- Autoscale: https://learn.microsoft.com/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-autoscale-overview
