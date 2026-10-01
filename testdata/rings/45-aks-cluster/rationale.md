# 45 — an AKS cluster's issuer, its tenant spelled as its whole path

A per-tenant issuer: AKS's tenant is spelled `<region>/<tenant_id>/<cluster_uuid>`.

**Expected.** `ClusterServiceAccount` → **outsider**, exact: the tenant
`eastus/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/00000000-0000-0000-0000-000000000000`, by id,
recyclable (unverified), not declared.

**Why.** A named outsider needs a vendor sentence that the tenant's owner decides who obtains tokens
naming it, and no single sentence says so of a cluster. The census records it as a chain of quoted
links, marked as one (census v0.2.0): the issuer publishes one cluster's API server's signing
keys; a token names one of that cluster's service accounts; Kubernetes issues a service account's
token to whoever the cluster's authorization gives `create` on `serviceaccounts/token`, and to
whoever it lets create workloads in the account's namespace; and Microsoft puts that authorization,
through Kubernetes RBAC or Azure RBAC, in the hands of the cluster's owner. No sentence in the release
says what either GUID in the path is, so the tenant is spelled from all of it, the region and both
GUIDs, as the vendor's example issuer shows them. The user declares the cluster as
`issuer:<issuer URL>`.

> "By default, the issuer uses the base URL https://{region}.oic.prod-aks.azure.com, where the value for {region} matches the location where you deployed the AKS cluster." — https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer · read 2026-09-23 (recorded in the census, `match`)
> ""issuer": "https://eastus.oic.prod-aks.azure.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/00000000-0000-0000-0000-000000000000/"" — https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer · read 2026-09-23 (recorded in the census, `match`)
> "You can enable the OIDC issuer on your AKS clusters, which allows Microsoft Entra ID (or another cloud provider's identity and access management platform) to discover the API server's public signing keys." — https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer · read 2026-09-23 (recorded in the census, `tenant_membership`)
> "A service account is a type of non-human account that, in Kubernetes, provides a distinct identity in a Kubernetes cluster." — https://kubernetes.io/docs/concepts/security/service-accounts/ · read 2026-09-23
> "Users with create rights on serviceaccounts/token can create TokenRequests to issue tokens for existing service accounts." — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "Additionally, since Pods can run as any ServiceAccount, granting permission to create workloads also implicitly grants the API access levels of any service account in that namespace." — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "Once authenticated, you can use the built-in Kubernetes role-based access control (RBAC) to manage access to namespaces and cluster resources based on a user's identity or group membership." — https://learn.microsoft.com/en-us/azure/aks/kubernetes-rbac-entra-id · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "AKS Automatic clusters are preconfigured with Azure RBAC for Kubernetes authorization, so you can focus on assigning the right Microsoft Entra role assignments to users, groups, and service principals." — https://learn.microsoft.com/en-us/azure/aks/entra-id-authorization · read 2026-09-24 (recorded in the census, `tenant_membership`)
