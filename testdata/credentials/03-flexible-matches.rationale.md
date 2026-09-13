# 03 — flexible credential with matches

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] matches 'repo:acme/*' and claims['repository_owner_id'] eq '123456'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_owner_id="123456", sub=like:"repo:acme/*"}`,
exact, no anomalies.

## Why

Microsoft: `matches` "Enables the use of single-character (denoted by `?`)
and multi-character (denoted by `*`) wildcard matching for the specified
claim". The pattern is kept as a `Glob`; whether `*` crosses `/` and `:` is
not stated on the page, and the package comment records the assumption that
it does, as AWS's does, which can only admit more than Entra.
`repository_owner_id` supports `eq` under GitHub.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
