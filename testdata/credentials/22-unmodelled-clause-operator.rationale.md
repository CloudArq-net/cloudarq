# 22 — a comparison operator the language does not have, in a well-formed clause

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] eq '…main' and claims['repository_id'] startsWith '4567'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_id=?("undocumented operator"), sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a caveat and an `unmodelled-construct` anomaly on
`repository_id` whose Construct is the operator word, `startsWith`; `sub`
stays exact.

## Why

The clause has the documented shape, `claims['<name>'] <operator> '<value>'`,
with a word in the operator position that Microsoft does not list: for
GitHub, "Claim `repository_id` supports operator `eq`." Unlike case 07, the
clause is attributable to one claim and is joined to the rest by `and`, so
whatever the operator means it can only narrow `repository_id`; Unknown on
that claim is sound and keeps what the other clause states. The same
treatment applies to an operator written in another case, `EQ`, since the
grammar says "just the operator name" and the name is `eq`.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
