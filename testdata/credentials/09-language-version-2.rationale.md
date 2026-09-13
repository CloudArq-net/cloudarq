# 09 — languageVersion 2

Hand-written fixture, 2026-09-13.

## Document

A well-formed version-1 expression with `"languageVersion": 2`.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("language version")}`, inexact,
with a caveat on `sub` and an `unmodelled-construct` anomaly whose Construct
is the version as written, `2`, so that a reporter can count credentials by
the version they claim.

## Why

Graph: "languageVersion Int32 — Indicated the language version to be used.
Should always be set to 1. Required." Microsoft: "`languageVersion` should
always be set to 1." A document claiming another version claims a language
this parser has no documentation for; reading its text under version 1 rules
would be a guess presented as a set. The expression is not modelled, `sub`
carries the Unknown, and the audience keeps its exact value because it is not
part of the expression.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentityexpression?view=graph-rest-beta
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
