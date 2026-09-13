# 34 — google.subject with no mapping

Hand-written fixture, 2026-09-13.

## Document

An OIDC provider with no `attributeMapping` and a condition on
`google.subject`.

## Expected

`{aud="…/providers/github"}`: everything from the issuer, inexact, with a
whole-grant caveat and an `unmodelled-construct` anomaly whose Construct is
`google.subject`.

## Why

Google: "For OIDC providers, you must supply a custom mapping, which must
include the google.subject attribute." The default mapping Google states
applies to AWS providers alone, so for this document `google.subject`
resolves to nothing, and a clause on it cannot be attributed to a claim. A
parser that assumed `assertion.sub` would answer `{sub="…main"}`, exact, on
a document outside what Google documents, whether the API refuses it or
maps the subject some other way being unstated; the reading here is top with the
caveat on the whole grant, the same rule that governs an attribute mapped
by an expression (case 10) and a bound member on one (case 40).

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping)
