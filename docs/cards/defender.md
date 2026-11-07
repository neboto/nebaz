# Microsoft Defender for Cloud

Defender for Cloud checks your Azure, multicloud and on-premises resources against security best practice and reports what to fix (posture management), and with its paid plans also detects attacks on workloads such as servers, storage, databases and containers (workload protection).

## Key ideas

- **Recommendations**: each resource assessed against a security control, Healthy, Unhealthy or Not applicable, with a severity and steps to fix it.
- **Secure score**: the share of the security controls' points you've earned. Fixing every resource in a control earns its points.
- **Security alerts**: detections of suspicious activity on a resource, with severity, the MITRE ATT&CK tactics and the entities involved; related alerts are grouped into incidents.
- **Plans**: Foundational CSPM is free; Defender CSPM and the workload plans (Servers, Storage, SQL, Containers, Key Vault, App Service, Resource Manager, APIs, AI) are paid and turned on per subscription.
- **Microsoft cloud security benchmark**: the default standard the recommendations come from.

## In nebaz

- Recommendations: one row per recommendation and resource; unhealthy rows by severity, healthy and not applicable as noise (a). Resources lists every resource with the same recommendation.
- Alerts: severity, status, tactics and entities. Their evidence and extended properties are dropped before nebaz keeps the JSON.
- Secure score and its controls; Plans: on or off, with sub-plans and extensions.
- Defender's findings stay here; @audit runs its own checks and never repeats them. Never sent: anything that changes a plan or an alert.

## Learn more

- Overview: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction
- Recommendations: https://learn.microsoft.com/azure/defender-for-cloud/review-security-recommendations
- Secure score: https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls
- Security alerts: https://learn.microsoft.com/azure/defender-for-cloud/alerts-overview
