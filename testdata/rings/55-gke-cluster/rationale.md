# 55 — a GKE cluster's issuer

A per-tenant issuer: a GKE issuer URL names its project, its location and its cluster, and the census
matches the URL by its pattern.

**Expected.** `ClusterServiceAccount` → **outsider**, exact: the tenant `proj/us-central1/c1`, the
cluster, by name, recyclable (unverified), not declared.

**Why.** A named outsider needs a vendor sentence that the tenant's owner decides who obtains tokens
naming it, and no single sentence says so of a cluster. The census records it as a chain of quoted
links, marked as one (census v0.2.0): the cluster's API server signs the tokens; a token
names one of that cluster's service accounts; Kubernetes issues a service account's token to whoever
the cluster's authorization gives `create` on `serviceaccounts/token`, and to whoever it lets create
workloads in the account's namespace; and Google puts that authorization, through IAM and Kubernetes
RBAC, in the hands of the cluster's owner. No sentence the census read says a cluster's name cannot
pass to another cluster, and unverified recyclability reads as recyclable. The user declares the
cluster as `issuer:<issuer URL>`.

> "Not all implementations of Kubernetes surface this claim, but for those that do (including GKE), it points to a valid OIDC Discovery endpoint for the tokens issued by the cluster." — https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-bound-service-account-tokens · read 2026-09-23 (recorded in the census, `match`), and again 2026-09-24
> "The short-lived bearer token is a JSON web token (JWT) that's signed by the API server, which is an OpenID Connect (OIDC) provider." — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/service-accounts · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "Users with create rights on serviceaccounts/token can create TokenRequests to issue tokens for existing service accounts." — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "Additionally, since Pods can run as any ServiceAccount, granting permission to create workloads also implicitly grants the API access levels of any service account in that namespace." — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "You can use both Identity and Access Management (IAM) and Kubernetes RBAC to control access to your GKE cluster:" — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "In GKE, IAM and Kubernetes RBAC are integrated to authorize users to perform actions if they have sufficient permissions according to either tool." — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control · read 2026-09-24 (recorded in the census, `tenant_membership`)
