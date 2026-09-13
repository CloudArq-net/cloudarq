# 05 — subject and claimsMatchingExpression both set

Hand-written fixture, 2026-09-13.

## Document

`subject: "repo:acme/infra:ref:refs/heads/main"` beside
`claims['sub'] matches 'repo:acme/*' and claims['repository_id'] eq '456789'`.

## Expected

The union of the two readings:
`{aud, repository_id="456789", sub=like:"repo:acme/*"} | {aud, sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a caveat on `sub` and an anomaly `subject-and-expression`.

## Why

Microsoft: "The `claimsMatchingExpression` and `subject` properties are
mutually exclusive, so you can't define both within a federated identity
credential", and on Graph, "If **subject** is defined,
**claimsMatchingExpression** must be `null`." The document is outside the
documented space, so which constraint Entra applies cannot be known from it.
The only reading that is never narrower than either possibility is the Join
of both. Leaving `sub` Unknown while keeping `repository_id` exact, the first
design, rejected the token `{sub: main, repository_id: 999999}` that the
subject-only reading admits, and was therefore narrower than one of the two
things the document might mean.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
