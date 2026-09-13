# 24 — a GitHub expression with no clause on sub

Hand-written fixture, 2026-09-13.

## Document

`claims['repository_id'] eq '456789'` alone, under the GitHub issuer.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("required claim missing")}`,
inexact, with a caveat on `sub` and an `unmodelled-construct` anomaly with
Construct `missing required claim`, whose sentence names `sub`.

## Why

The same rule as case 23, missing the other half: "a flexible federated
identity credential must match the `sub` claim and one or both of the
following immutable claims". Read literally the expression would pin
`repository_id` and leave `sub` unconstrained, which is the shape a null
subject with no expression has, and the one this parser exists to refuse
reading as "any subject". Under the documented rule the expression cannot
exist; under an undocumented acceptance it may or may not be applied. `sub`
Unknown with the fact stated covers both, and `repository_id` does not
survive, because an expression Entra does not apply constrains nothing.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14), GitHub tab
