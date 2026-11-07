# Web Application Firewall policies

A Web Application Firewall (WAF) policy holds the rules that inspect web requests for attacks such as SQL injection and cross-site scripting. A policy is attached to an Application Gateway (the whole gateway, a listener or a path) or to Front Door; the two use separate policy types.

## Key ideas

- **Mode**: Detection logs what the rules match; Prevention blocks it. Policies usually start in Detection while false positives are tuned out.
- **Managed rule sets**: Microsoft's rules, the Default Rule Set (DRS) or the OWASP Core Rule Set (CRS), plus the bot manager rule set. Rule groups and single rules can be turned off or set to another action.
- **Exclusions**: request attributes (a header, a cookie, an argument) that the managed rules skip, to fix false positives without turning a rule off.
- **Custom rules**: evaluated first, by priority: match conditions on IPs, geography, headers or the URL, with an allow, block, log or rate-limit action.
- **Body inspection limits**: how much of a request body is read, and the file upload limit.

## In nebaz

- Settings explains the mode and shows the inspection limits. Managed rules lists each set and version with its overrides and exclusions; Custom rules lists each rule's conditions.
- Associations lists the gateways, listeners, path rules and Front Door security policies using the policy, each a jump.
- m on a gateway or a Front Door profile (or on the policy) opens the WAF view: actions, the block rate and the rules that matched most.
- @audit: waf-not-blocking (a policy in Detection, or disabled).

## Learn more

- Overview: https://learn.microsoft.com/azure/web-application-firewall/overview
- On Application Gateway: https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview
- On Front Door: https://learn.microsoft.com/azure/web-application-firewall/afds/afds-overview
- Managed rule sets: https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules
- Exclusions: https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-waf-configuration
