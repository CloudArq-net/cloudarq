# 11 — two audiences

Hand-written fixture, 2026-09-13.

## Document

`audiences: ["api://AzureADTokenExchange", "api://acme-exchange"]`.

## Expected

`{aud=("api://AzureADTokenExchange" | "api://acme-exchange"), sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, with an `audience-count` anomaly on `aud` and no caveat.

## Why

Graph: audiences "can only accept a single value"; the considerations page
lists the error "Federated identity credentials must have exactly one
audience." A list of two is outside Graph's contract, so which one Entra
would apply is not stated; the union contains whichever it is and admits
nothing outside the two, so it is never narrower than Entra and never wider
than the document. The fact is recorded for the reporter.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations (updated 2026-06-15)
