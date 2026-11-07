# Azure AI Search

Azure AI Search indexes your content for full-text, vector and hybrid search, and is a common retrieval layer for AI applications (RAG). Indexers pull data from storage, databases and other sources on a schedule, optionally enriching it with AI skills on the way.

## Key ideas

- **Indexes**: the searchable data, with fields, analysers and vector fields.
- **Indexers, data sources and skillsets**: crawl a source (blob storage, SQL, Cosmos DB) into an index; a skillset adds OCR, chunking or embeddings.
- **Replicas and partitions**: replicas add query capacity and availability (2 for a read SLA, 3 for read and write); partitions add storage. Search units are replicas × partitions.
- **Tiers**: Free, Basic, Standard (S1 to S3) and Storage Optimized (L1, L2).
- **Semantic ranker**: re-ranks results by meaning, a separately billed feature.
- **Authentication and network**: API keys (admin and query) or Entra ID roles; private endpoints, and shared private links for indexers to reach private data sources.

## In nebaz

- Service shows replicas, partitions, search units, hosting mode and the semantic ranker. Network shows public access, IP rules and private endpoints.
- Security shows whether keys, Entra ID or both are accepted, and the identity. Shared private links is a lazy read, ⚠ unless approved.
- Never read: the admin or query keys (POST calls), or the indexes' contents.

## Learn more

- Overview: https://learn.microsoft.com/azure/search/search-what-is-azure-search
- Capacity: https://learn.microsoft.com/azure/search/search-capacity-planning
- Tiers: https://learn.microsoft.com/azure/search/search-sku-tier
- Role-based access: https://learn.microsoft.com/azure/search/search-security-rbac
- Shared private links: https://learn.microsoft.com/azure/search/search-indexer-howto-access-private
