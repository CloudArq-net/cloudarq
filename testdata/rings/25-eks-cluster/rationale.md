# 25 — an Amazon EKS cluster's issuer

A per-tenant issuer: an EKS issuer URL names its cluster, and the census matches the URL by its
pattern, never by host alone.

**Expected.** `ClusterServiceAccount` → **outsider**, exact: the tenant
`EXAMPLED539D4633E53DE1B71EXAMPLE`, the cluster, named by id, recyclable (unverified), not declared.

**Why.** A named outsider needs a vendor sentence that the tenant's owner decides who obtains tokens
naming it, and no single sentence says so of a cluster. The census records it as a chain of quoted
links, marked as one (census v0.2.0): the cluster's Kubernetes issues the tokens; a token
names one of that cluster's service accounts; Kubernetes issues a service account's token to whoever
the cluster's authorization gives `create` on `serviceaccounts/token`, and to whoever it lets create
workloads in the account's namespace; and AWS puts that authorization in the hands of whoever created
the cluster, through the `aws-auth` ConfigMap or access entries. Whether a cluster's id can pass to
another customer is not documented, and unverified recyclability reads as recyclable. The user
declares the cluster as `issuer:<issuer URL>`.

> "Your cluster has an OpenID Connect (OIDC) issuer URL associated with it." — https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html · read 2026-09-23
> "Amazon EKS hosts a public OIDC discovery endpoint for each cluster that contains the signing keys for the `ProjectedServiceAccountToken` JSON web tokens so external systems, such as IAM, can validate and accept the OIDC tokens that are issued by Kubernetes." — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html · read 2026-09-23
> "A service account is a type of non-human account that, in Kubernetes, provides a distinct identity in a Kubernetes cluster." — https://kubernetes.io/docs/concepts/security/service-accounts/ · read 2026-09-23
> "Users with create rights on serviceaccounts/token can create TokenRequests to issue tokens for existing service accounts." — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "Additionally, since Pods can run as any ServiceAccount, granting permission to create workloads also implicitly grants the API access levels of any service account in that namespace." — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "The IAM principal that created the cluster is the initial user that can access the cluster by using `kubectl`. The initial user must add other users to the list in the `aws-auth` `ConfigMap` and assign permissions that affect the other users within the cluster." — https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "You can add and manage access to the cluster by using the EKS API, AWS Command Line Interface, AWS SDKs, AWS CloudFormation, and AWS Management Console. This means you can manage users with the same tools that you created the cluster with." — https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html · read 2026-09-24 (recorded in the census, `tenant_membership`)
