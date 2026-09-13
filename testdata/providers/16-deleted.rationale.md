# 16 — a soft-deleted provider

Hand-written fixture, 2026-09-13.

## Document

`"state": "DELETED"` with an `expireTime`, beside an exact condition.

## Expected

`{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact: a whole-grant caveat and a `provider-deleted` anomaly.

## Why

Google: "DELETED: The provider is soft-deleted. Soft-deleted providers are
permanently deleted after approximately 30 days. You can restore a
soft-deleted provider using providers.undelete." An undelete is one call
away, so the set is kept and declared an upper bound, for the reason case
15 gives, and departing from the Pass 1 table's `Nothing()` as case 15
does. The list method "Lists all non-deleted WorkloadIdentityPoolProviders
in a WorkloadIdentityPool. If showDeleted is set to true, then deleted
providers are also listed.", so this shape reaches the parser from a get,
or from a list made with showDeleted.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (State)
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers/list
