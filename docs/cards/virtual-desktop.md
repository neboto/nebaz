# Azure Virtual Desktop

Azure Virtual Desktop delivers Windows desktops and apps from VMs in Azure. Users connect through a Microsoft-run broker; the VMs, registered with the service as session hosts, run the desktops.

## Key ideas

- **Host pool**: a set of session hosts built from the same image. Pooled pools share each host between users, load balanced breadth-first or depth-first up to a session limit. Personal pools give each user one host, assigned automatically or directly.
- **Session host status**: Available is the healthy state. Needs Assistance and Upgrade Failed still take new sessions; Unavailable and Shutdown don't. Drain mode stops new sessions on a host.
- **Agent**: runs on each host, reports its health checks and updates itself, inside the pool's maintenance windows when scheduled agent updates are on.
- **Application group**: a Desktop or a RemoteApp group of one host pool. Users see it only when a workspace publishes it.
- **Workspace**: what users subscribe to in their client; it lists application groups.
- **Scaling plan**: autoscale schedules (ramp-up, peak, ramp-down, off-peak) that start and stop a pool's hosts.

## In nebaz

- Host pools: Session hosts (one lazy read per pool, trouble first) shows each host's status, sessions, heartbeat, agent and failed health checks, with ⏎ to its VM. A VM's Related names the pool once that read has been made.
- Configuration covers the pool type, load balancing, the registration token's expiry and agent updates. The token itself is never read.
- App groups name their pool and workspace, flagging a group no workspace publishes. Scaling plans show their schedules and pools.
- @audit: avd-pool-no-available-hosts, avd-agent-behind, avd-personal-no-assignment, avd-app-group-unpublished.

## Learn more

- Overview: https://learn.microsoft.com/azure/virtual-desktop/overview
- Terminology: https://learn.microsoft.com/azure/virtual-desktop/terminology
- Statuses and health checks: https://learn.microsoft.com/azure/virtual-desktop/session-host-status-health-checks
- Load balancing: https://learn.microsoft.com/azure/virtual-desktop/configure-host-pool-load-balancing
- Personal desktop assignment: https://learn.microsoft.com/azure/virtual-desktop/configure-host-pool-personal-desktop-assignment-type
- Scaling plans: https://learn.microsoft.com/azure/virtual-desktop/autoscale-create-assign-scaling-plan
- Scheduled agent updates: https://learn.microsoft.com/azure/virtual-desktop/scheduled-agent-updates
- Drain mode: https://learn.microsoft.com/azure/virtual-desktop/drain-mode
- Private Link: https://learn.microsoft.com/azure/virtual-desktop/private-link-overview
