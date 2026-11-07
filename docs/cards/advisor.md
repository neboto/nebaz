# Azure Advisor

Azure Advisor reviews how your resources are set up and used and recommends changes in five categories: cost, reliability, security, operational excellence and performance. Cost recommendations come with estimated savings, such as resizing an underused VM or buying a reservation.

## Key ideas

- **Categories**: Cost, Reliability (formerly high availability), Security (Defender for Cloud's recommendations, relayed), Operational excellence and Performance.
- **Impact**: high, medium or low, Advisor's measure of how much a recommendation matters.
- **Advisor score**: a percentage per category and overall, for how closely you follow the recommendations, with its history.
- **Postpone and dismiss**: a recommendation can be snoozed for a time or dismissed; it leaves the list until then.
- **Refresh**: recommendations are computed periodically; the portal can ask for a fresh computation.

## In nebaz

- Recommendations: one row per recommendation and resource, named by the problem, with impact as the state and savings in the list. Each says when Advisor last updated it.
- Security recommendations are Defender's, relayed: noise (a), with a jump to the Defender row.
- Score shows each category's score, the possible gain and the daily history. Suppressions shows what is snoozed or dismissed, and until when.
- Never sent: a refresh (generateRecommendations, a POST), or a snooze, dismissal or reactivation.

## Learn more

- Overview: https://learn.microsoft.com/azure/advisor/advisor-overview
- Advisor score: https://learn.microsoft.com/azure/advisor/advisor-score
- Cost recommendations: https://learn.microsoft.com/azure/advisor/advisor-reference-cost-recommendations
- Reliability recommendations: https://learn.microsoft.com/azure/advisor/advisor-reference-reliability-recommendations
