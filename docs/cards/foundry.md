# Microsoft Foundry resources

A Foundry resource is the Azure resource behind Microsoft Foundry (formerly Azure AI Foundry), and replaces the earlier hub, Azure OpenAI and Azure AI Services resources: you deploy models from the catalogue (OpenAI's and others) into it, call them through its endpoint, and organise work in projects. The same list also holds Azure OpenAI and single-purpose AI accounts such as Speech, Vision and Language, told apart by their kind.

## Key ideas

- **Kind**: AIServices (a Foundry resource), OpenAI, or a single service such as SpeechServices or TextAnalytics.
- **Deployments**: a model and version made callable under a deployment name, with a deployment type: Global or Data Zone (where data is processed), Standard (pay per token, with rate limits) or Provisioned (reserved throughput units, PTUs).
- **Projects**: workspaces inside a Foundry resource for agents, evaluations and files, each with its own access.
- **Guardrails**: content filters on each deployment that block harmful prompts and completions.
- **Authentication and network**: Entra ID roles (such as Cognitive Services OpenAI User) or API keys, which can be disabled; public access, network rules and private endpoints.

## In nebaz

- Deployments is a lazy read: model, version, SKU and capacity, PTUs, rate limits, state and the content filter policy. Projects is read only when the resource allows them.
- Network shows public access, the ACLs, outbound restriction and private endpoints; Security shows key auth, identity and encryption.
- Never read: the API keys (a POST), or anything that calls a model. The endpoint is shown as text, never requested.
- @audit: foundry-public-network, foundry-local-auth.

## Learn more

- What is Foundry: https://learn.microsoft.com/azure/foundry/what-is-foundry
- Deployment types: https://learn.microsoft.com/azure/foundry/foundry-models/concepts/deployment-types
- Quotas and limits: https://learn.microsoft.com/azure/foundry/openai/quotas-limits
- Guardrails: https://learn.microsoft.com/azure/foundry/guardrails/guardrails-overview
- Disable key authentication: https://learn.microsoft.com/azure/ai-services/disable-local-auth
