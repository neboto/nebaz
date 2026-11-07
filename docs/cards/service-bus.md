# Azure Service Bus

Service Bus is a message broker: applications send messages to queues and topics, and receivers take them off when they're ready. It decouples senders from receivers, evens out load, and holds messages through a receiver's failure.

## Key ideas

- **Namespace**: the container and endpoint for queues and topics.
- **Queues**: each message goes to one receiver. Messages are locked while processed, and moved to the dead-letter queue when delivery keeps failing or they expire.
- **Topics and subscriptions**: publish once, and each subscription gets its own copy, filtered by rules.
- **Sessions, scheduling and duplicate detection**: ordered handling of related messages, delivery at a set time, and dropping repeats.
- **Tiers**: Basic (queues only), Standard (topics, pay per operation) and Premium (dedicated messaging units, VNet rules, private endpoints, larger messages).
- **Authentication**: Entra ID roles, or shared access signature (SAS) keys, which can be disabled.

## In nebaz

- Network is a lazy read that sums up effective access in one line, then the public access, IP and VNet rules and private endpoints. A Deny default with no rule is flagged, since the service doesn't enforce it.
- Queues and Topics are lazy reads: active, dead-lettered and scheduled counts, size, lock duration, max deliveries and sessions.
- Access policies shows names and rights only. Never read: the SAS keys or connection strings (POST calls), or any message.
- @audit: sb-local-auth, sb-min-tls, sb-public-network.

## Learn more

- Overview: https://learn.microsoft.com/azure/service-bus-messaging/service-bus-messaging-overview
- Queues, topics and subscriptions: https://learn.microsoft.com/azure/service-bus-messaging/service-bus-queues-topics-subscriptions
- Dead-letter queues: https://learn.microsoft.com/azure/service-bus-messaging/service-bus-dead-letter-queues
- Tiers: https://learn.microsoft.com/azure/service-bus-messaging/service-bus-premium-messaging
- Disable local auth: https://learn.microsoft.com/azure/service-bus-messaging/disable-local-authentication
