# 06 — neither subject nor claimsMatchingExpression

Hand-written fixture, 2026-09-13.

## Document

`subject: null`, no `claimsMatchingExpression`: what a flexible credential
looks like when read through Graph v1.0.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("no subject constraint")}`,
inexact, with a caveat on `sub` and an anomaly `no-subject-constraint`.

## Why

Graph documents `subject` as "Nullable. Defaults to `null` if not set" and
`claimsMatchingExpression` the same, so a document with neither is
well-formed. But the v1.0 endpoint omits `claimsMatchingExpression`
altogether, so this shape is also exactly what a flexible credential looks
like when read from the wrong endpoint. The constraint may exist unseen. An
unconstrained subject would report a credential that admits every token from
the issuer, which is the widest possible finding, made on evidence that does
not support it; Unknown with the reason stated is the honest set.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
- product/CONTEXT.md, "Azure Graph: always /beta"
