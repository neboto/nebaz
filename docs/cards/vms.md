# Azure Virtual Machines

A virtual machine is a Windows or Linux server that Azure runs for you on its hardware: you choose the size (CPU and memory), the image it starts from and the disks and network it uses, and you manage the operating system yourself. You pay for compute while it is allocated, so a stopped VM still costs money until it is deallocated.

## Key ideas

- **Size**: the family and shape of the hardware (D for general purpose, E for memory, F for compute, N for GPU). A resize may need a restart, and not every size is offered in every region or zone.
- **Power state**: running, stopped (the OS is shut down but the hardware is still reserved and billed) or deallocated (released; only the disks are billed).
- **Disks**: an OS disk and optional data disks, each a managed disk of its own. A temporary disk on many sizes is lost when the VM moves.
- **Availability**: availability zones (separate datacentres in a region), availability sets (separate racks) and scale sets.
- **Extensions and the VM agent**: the agent inside the VM reports health and runs extensions (monitoring, scripts, configuration) that Azure installs.
- **Image**: the marketplace, a Compute Gallery or a custom image. A marketplace plan carries the publisher's licence terms.

## In nebaz

- The list shows each VM's size (and marketplace plan) and its power state. Instance view is one lazy read: the agent, the OS, boot diagnostics and the disk statuses.
- Networking and Storage list the NICs and disks; Related jumps to them, to the availability set, the scale set and the gallery image.
- m shows the VM's platform metrics; N opens the network access lens over its NICs.
- Never sent: run commands, serial console, start, stop or any other action. C copies the az commands instead.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-machines/overview
- Sizes: https://learn.microsoft.com/azure/virtual-machines/sizes/overview
- States and billing: https://learn.microsoft.com/azure/virtual-machines/states-billing
- Availability options: https://learn.microsoft.com/azure/virtual-machines/availability
- Extensions: https://learn.microsoft.com/azure/virtual-machines/extensions/overview
