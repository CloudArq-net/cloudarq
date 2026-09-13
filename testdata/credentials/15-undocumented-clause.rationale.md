# 15 — a claim and an operator Microsoft does not list for the issuer

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] eq '…' and claims['repository_id'] matches '45*' and claims['environment'] eq 'production'`.

## Expected

`{aud="api://AzureADTokenExchange", environment=?("undocumented claim"), repository_id=?("undocumented operator"), sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a caveat and an `unmodelled-construct` anomaly on each of
`environment`, with Construct `claims['environment']`, and `repository_id`,
with Construct `matches`; `sub` stays exact.

## Why

Microsoft documents a closed set per issuer. For GitHub: "Claim
`repository_id` supports operator `eq`." and no `environment` at all. A
document that reads back from Graph with either clause is outside that space:
if Entra accepted it and evaluates the clause, an Exact or Glob would be
right; if Entra accepted it and does not evaluate the clause, an Exact or
Glob would be narrower than Entra. Unknown on that claim is right in both
cases, and the clauses are joined by `and`, so the other claims keep their
values.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14), "Issuer URLs, supported claims, and operators by platform"
