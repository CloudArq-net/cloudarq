# 36 — a binding on a mapped attribute

Hand-written fixture, 2026-09-13, bound against provider 03.

## Document

`principalSet://…/workloadIdentityPools/github/attribute.repository/acme/infra`.

## Expected

Bind returns true and `{aud="…/providers/github", repository="acme/infra", sub=like:"repo:acme/infra:*"}`,
exact.

## Why

Google's identifier for "All identities in a workload identity pool with a
certain attribute" is `principalSet://…/workloadIdentityPools/POOL_ID/attribute.ATTRIBUTE_NAME/ATTRIBUTE_VALUE`.
The value runs to the end of the member, slashes included: `acme/infra` is
one repository name. Provider 03 maps `attribute.repository` from
`assertion.repository`, so the member is Exact on `repository`, met with the
provider's own condition.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers
