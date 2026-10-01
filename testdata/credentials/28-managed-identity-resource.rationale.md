# 28 — a user-assigned managed identity's credential, as Resource Manager returns it

Microsoft's own sample response for *Federated Identity Credentials - Get*
(REST API version 2023-01-31), copied verbatim, 2026-09-13.

## Document

An Azure Resource Manager resource: `id`, `name`, `type`, and a `properties`
object holding `issuer`, `subject` and `audiences`.

## Expected

Issuer `https://oidc.prod-aks.azure.com/TenantGUID/IssuerGUID`; admits
`{aud="api://AzureADTokenExchange", sub="system:serviceaccount:ns:svcaccount"}`
exactly; no anomaly; `Name` is the resource's `name`, `ID` the resource's
`id`, and `Source` the resource's own bytes.

## Why

A user-assigned managed identity's credentials are not Graph objects: they
are Resource Manager resources under
`Microsoft.ManagedIdentity/userAssignedIdentities/{name}/federatedIdentityCredentials`,
and the REST reference defines the credential's members as
`properties.audiences`, `properties.issuer` and `properties.subject`. The
list endpoint wraps them in the same `value` collection Graph uses. The
parser reads the credential where the API put it, so that a collector hands
over the response body as received and a credential pinned to one Kubernetes
service account is reported as exactly that, never as a document with no
issuer, no subject and no audience, which is what reading the envelope as
the credential produced.

The issuer's path keeps its case: `NormaliseIssuer` lower-cases the host
alone, because a per-tenant issuer's path is part of its identity.

## Sources

- https://learn.microsoft.com/en-us/rest/api/managedidentity/federated-identity-credentials/get?view=rest-managedidentity-2023-01-31 (updated 2025-09-16): the sample response and the *FederatedIdentityCredential* definition table
- https://learn.microsoft.com/en-us/rest/api/managedidentity/federated-identity-credentials/list?view=rest-managedidentity-2023-01-31: the `value` collection with `nextLink`
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (updated 2026-08-17): flexible credentials exist "only for federated identity credentials configured on application objects currently", so a managed identity's credential is classic
