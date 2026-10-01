# 47 — one cluster id in two regions, one of them declared

A declaration of a per-tenant issuer matches the whole issuer URL, never the census entry and the
tenant it names. The owner declared is the us-east-1 cluster's issuer.

**Expected.**
- `DeclaredCluster` → **yours**, exact: the tenant `EXAMPLED539D4633E53DE1B71EXAMPLE` on the
  us-east-1 issuer, declared.
- `SameIDOtherRegion` → **outsider**, exact: the tenant `EXAMPLED539D4633E53DE1B71EXAMPLE` on the
  eu-west-1 issuer, not declared.

**Why.** The census matches an EKS issuer by its pattern and names the tenant by the cluster's id
alone, which excludes the region, and no sentence the census read makes that id unique across
regions. The issuer URL is the cluster's, so the URL, region included, is what is declared: a
cluster elsewhere with the same id is another issuer's tenant, and stays a named outsider.

> "Your cluster has an OpenID Connect (OIDC) issuer URL associated with it." — https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html · read 2026-09-23 (recorded in the census, `match`)
