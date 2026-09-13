# 10 — no issuer

Hand-written fixture, 2026-09-13.

## Document

A classic credential with the `issuer` member left out.

## Expected

A Grant with `Issuer` empty, admitting
`{aud="api://AzureADTokenExchange", sub="repo:acme/infra:ref:refs/heads/main"}`
exactly, with a `missing-issuer` anomaly and no caveat.

## Why

Graph: `issuer` is "Required"; Microsoft: "*issuer* is the URL of the
external identity provider and must match the `issuer` claim of the external
token being exchanged. Required." A document without one cannot have come
from Graph, but the parser must be total over what it is handed. The Grant is
still emitted: `trust.Anomaly` lives on a Grant and nowhere else, so a parser
that returned no Grant would have nowhere to state the fact, and the
credential would vanish from the report, which is silence. The admitted set is
what the document says and is exact; what is unknown is the issuer, and the
issuer is not a claim, so no caveat is warranted.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations (updated 2026-06-15)
- internal/trust/grant.go: `Anomalies []Anomaly` is a field of Grant only
