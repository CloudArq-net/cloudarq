# 38 — a binding on the whole pool

Hand-written fixture, 2026-09-13, bound against provider 03.

## Document

`principalSet://…/workloadIdentityPools/github/*`.

## Expected

Bind returns true and `{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`,
exact: the provider's own set, on the service account.

## Why

Google's identifier for "All identities in a workload identity pool" is
`principalSet://…/workloadIdentityPools/POOL_ID/*`. Every identity the
pool's providers admit reaches the account, so the member adds no
constraint and the grant is the provider's set retargeted. A pool holds
several providers; the binding admits each provider's set, and each Bind
states one of them.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers
