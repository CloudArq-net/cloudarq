# 02 — flexible credential with eq

Hand-written fixture, 2026-09-13.

## Document

`subject: null` and a `claimsMatchingExpression` of two `eq` clauses joined by
`and`: `sub` and `repository_id`. The expression object carries an
`@odata.type` annotation, which is ignored.

## Expected

`{aud="api://AzureADTokenExchange", repository_id="456789", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, no anomalies.

## Why

Microsoft's operator table: `eq` is "Used for explicitly matching against a
specified claim"; `and` is the "Boolean operator for combining expressions
against multiple claims". Under GitHub, "Claim `sub` supports operators `eq`
and `matches`" and "Claim `repository_id` supports operator `eq`", so both
clauses are inside the documented language and each is an `Exact` on its
claim, met in one Term.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
