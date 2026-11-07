# App registrations and service principals

An application that signs in with Microsoft Entra ID has two parts. The app registration is its definition, kept once in its home tenant: its credentials, redirect URIs, the permissions it asks for and the API it exposes. A service principal is the app's instance in a tenant (the "enterprise application"): what is actually granted roles, consented to and assigned to users.

## Key ideas

- **Application (client) id**: shared by the registration and every service principal made from it, in any tenant.
- **Credentials**: client secrets and certificates, each with an expiry. When one expires, the app stops signing in. Federated credentials need no secret.
- **API permissions**: delegated (acting as a signed-in user) or application (acting as itself), granted by consent; application permissions always need an admin.
- **Single sign-on**: a service principal can sign users in to a SaaS app with SAML, with its own signing certificate and claims.
- **Owners**: users who can change the app, including adding credentials to it.
- **Managed identities** are service principals too, with no registration and no credential to manage.

## In nebaz

- Both tabs read Microsoft Graph, GET only. Credentials show names, key ids and dates, never a value or hint; the state is the worst credential expiry.
- App registrations: federated credentials, token configuration, API permissions (named from each API's service principal), redirect URIs, the exposed API and owners.
- Service principals: credentials, SAML single sign-on with the signing certificate, claims, app role assignments, OAuth2 grants and owners.
- @audit: appreg-credential-expiry, sp-credential-expiry (expired, or expiring within 30 days).

## Learn more

- Applications and service principals: https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals
- Credentials: https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials
- Permissions and consent: https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview
- SAML single sign-on: https://learn.microsoft.com/entra/identity/enterprise-apps/add-application-portal-setup-sso
- Enterprise applications: https://learn.microsoft.com/entra/identity/enterprise-apps/what-is-application-management
