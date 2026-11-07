# Cost Management budgets

A budget sets an amount you expect to spend on a subscription, resource group or filtered set of resources over a month, a quarter or a year, and notifies people as the actual or forecast cost reaches its thresholds. A budget never stops spending by itself; its action groups can start automation that does.

## Key ideas

- **Amount and time grain**: the limit, and the period it resets over.
- **Thresholds**: percentages of the amount, each on actual or forecasted cost, with emails, roles and action groups to tell.
- **Filters**: narrow the budget to resource groups, resources, meters or tags.
- **Data delay**: cost data arrives hours behind usage, so a budget alert follows the spend, not the moment it happens.

## In nebaz

- Budget shows the amount, the spend and forecast with their share of it (⚠ at or past 100%), the time grain and the period.
- Notifications lists each threshold, lowest first, as crossed, not reached or off, with who it tells; Filter shows each clause.
- The state compares the spend and forecast with the amount: over budget, forecast over or within.
- Never read: actual cost and usage (the Cost Management query is a POST).

## Learn more

- Budgets: https://learn.microsoft.com/azure/cost-management-billing/costs/tutorial-acm-create-budgets
- Cost alerts: https://learn.microsoft.com/azure/cost-management-billing/costs/cost-mgt-alerts-monitor-usage-spending
- Cost Management: https://learn.microsoft.com/azure/cost-management-billing/costs/overview-cost-management
