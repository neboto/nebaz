# Azure Event Hubs

Event Hubs ingests streams of events at high volume: telemetry, logs, clickstreams. Producers append events to partitions; consumers read them at their own pace and position, and many can read the same stream. It also speaks the Apache Kafka protocol.

## Key ideas

- **Namespace and event hubs**: the namespace is the endpoint and capacity; each event hub is one stream (a Kafka topic).
- **Partitions**: ordered sequences that events are spread across; they set how many consumers can read in parallel.
- **Consumer groups**: independent views of the stream, each with its own positions.
- **Retention**: events are kept for a time, not removed when read. Compaction keeps only the latest event per key.
- **Capacity**: throughput units (Standard), processing units (Premium) or capacity units (Dedicated); auto-inflate raises throughput units with load.
- **Capture**: writes the stream to Blob Storage or Data Lake in Avro or Parquet, for batch processing.

## In nebaz

- Network, Security and Access policies work as for Service Bus. Basic has no firewall, VNet rules or private endpoints.
- Event hubs is a lazy read: partitions, retention and cleanup policy, status, and Capture with its destination storage account as a jump.
- Never read: the SAS keys or connection strings (POST calls), or any event.
- @audit: eh-local-auth, eh-min-tls, eh-public-network.

## Learn more

- Overview: https://learn.microsoft.com/azure/event-hubs/event-hubs-about
- Features: https://learn.microsoft.com/azure/event-hubs/event-hubs-features
- Scalability: https://learn.microsoft.com/azure/event-hubs/event-hubs-scalability
- Capture: https://learn.microsoft.com/azure/event-hubs/event-hubs-capture-overview
- Kafka: https://learn.microsoft.com/azure/event-hubs/azure-event-hubs-apache-kafka-overview
