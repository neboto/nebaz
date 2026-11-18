# Template specs

A template spec is an ARM template stored in Azure as a resource. Teams publish a template once, version it, and let others deploy it by id with ordinary Azure RBAC deciding who may read it. A Bicep file is compiled to JSON when it is published.

## Key ideas

- **Version**: each publish is a version (1.0.0, 2026-10). A deployment names the version it used, so a spec can change without changing what already ran.
- **Main and linked templates**: a version holds one main template and any linked templates packaged with it.
- **Access**: reading a spec needs read access on it. The Template Spec Reader role grants only that.
- **Deploying**: a deployment or a stack points at a version's id instead of sending a template.

## In nebaz

- Template specs is one subscription-wide list.
- Versions is read when opened: each version's description and times, its parameter names and types, and the resource types it declares.
- A version's template is never kept: a default value or a variable can be a secret. Only names and types are read out of it.
- A deployment or stack that came from a spec links it in Related.

## Learn more

- Template specs: https://learn.microsoft.com/azure/azure-resource-manager/templates/template-specs
- Template specs in Bicep: https://learn.microsoft.com/azure/azure-resource-manager/bicep/template-specs
- Create a template spec: https://learn.microsoft.com/azure/azure-resource-manager/templates/quickstart-create-template-specs
