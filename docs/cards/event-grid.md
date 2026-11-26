# Azure Event Grid

Event Grid routes events: a publisher sends an event to a topic, and every event subscription on that topic whose filter matches gets a copy, pushed to its destination (a function, a queue, an event hub, a webhook). Delivery is retried with backoff until the event is delivered, its attempts run out or its time to live expires.

## Key ideas

- **System topics**: the events an Azure resource raises (a storage account's blob created and deleted, a subscription's resource writes, a key vault's secret near expiry). One per source; created when the first subscription is.
- **Custom topics**: an endpoint your own apps publish to (`*.eventgrid.azure.net`), with an access key, a SAS token or an Entra ID token.
- **Domains**: many topics behind one endpoint and one set of keys, for a multi-tenant publisher with one topic per customer.
- **Event subscriptions**: on a topic, each one a destination, a filter (event types, subject prefix and suffix, advanced filters on the data), a retry policy and an optional dead-letter container.
- **Dead-lettering**: an event that cannot be delivered is written to a blob container; without one it is dropped for good once retries or its time to live run out.
- **Webhook validation**: a webhook must answer a validation handshake before the subscription delivers; until then it waits in AwaitingManualAction.

## In nebaz

- Three sub-tabs: Topics, System topics and Domains, one subscription-wide list each.
- Subscriptions (a lazy read on each) shows where every event subscription delivers (⏎ on the destination opens it), its filter, retry policy and dead-letter destination, with ⚠ when it is not delivering or has no dead-letter.
- Network on a topic or domain shows who may publish: ⚠ when any IP with an access key can. A domain's Topics lists its topics.
- Never read: access keys, a webhook's full URL or a delivery attribute's value.
- Namespaces (MQTT and pull delivery) and partner topics are not browsed yet; they show in All resources.

## Learn more

- Overview: https://learn.microsoft.com/azure/event-grid/overview
- System topics: https://learn.microsoft.com/azure/event-grid/system-topics
- Domains: https://learn.microsoft.com/azure/event-grid/event-domains
- Event filtering: https://learn.microsoft.com/azure/event-grid/event-filtering
- Delivery and retry: https://learn.microsoft.com/azure/event-grid/delivery-and-retry
- Dead-lettering: https://learn.microsoft.com/azure/event-grid/manage-event-delivery
- Securing a topic: https://learn.microsoft.com/azure/event-grid/security-authentication
