# 54 — an EKS cluster with its region's host declared

Case 25's document, with `issuer:https://oidc.eks.us-east-1.amazonaws.com` declared, as a user
might write to declare every cluster it runs in the region.

**Expected.** `ClusterServiceAccount` → **outsider**, exact: the tenant
`EXAMPLED539D4633E53DE1B71EXAMPLE` on the us-east-1 cluster's issuer, not declared. The declaration
is read, echoed, and said to move nothing.

**Why.** An `issuer:` declaration names one tenant of a per-tenant issuer by its issuer URL, and
matches that URL whole (case 47). The region's host is no cluster's issuer URL. Census v0.2.0 matches EKS
issuers by the pattern `https://oidc.eks.<region>.amazonaws.com/id/<cluster_oidc_id>`, which holds
no account, so the issuer URL of every cluster in the region begins with the host, whoever runs the
cluster. Read as a prefix, the declaration would move clusters nobody declared to *your pipelines*,
a ring nearer than who can obtain their tokens.

> "Your cluster has an OpenID Connect (OIDC) issuer URL associated with it." — https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html · read 2026-09-23
> "To use AWS Identity and Access Management (IAM) roles for service accounts, an IAM OIDC provider must exist for your cluster’s OIDC issuer URL." — https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html · read 2026-09-23
