# Azure DDoS Protection

Azure protects every public IP against common distributed denial-of-service attacks at no charge. DDoS Network Protection adds tuning to your traffic, attack metrics and alerts, rapid response support and cost protection, for the virtual networks a plan covers.

## Key ideas

- **Network Protection**: a DDoS protection plan, linked to virtual networks; every public IP in them is covered. One plan can cover VNets across subscriptions in a tenant, and its fixed monthly cost includes 100 public IPs.
- **IP Protection**: the same mitigation per public IP, without the plan's extras, for a few addresses.
- **Adaptive tuning**: mitigation thresholds learned from each IP's own traffic.
- **Telemetry**: attack metrics and diagnostic logs per public IP in Azure Monitor.

## In nebaz

- Protected lists each VNet and public IP the plan covers, as jumps. A VNet shows its DDoS plan in Overview.
- @audit: ddos-plan-unused (a plan with no VNets still costs its monthly fee).

## Learn more

- Overview: https://learn.microsoft.com/azure/ddos-protection/ddos-protection-overview
- SKUs: https://learn.microsoft.com/azure/ddos-protection/ddos-protection-sku-comparison
