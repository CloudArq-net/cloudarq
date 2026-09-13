# 50 — a member whose selector holds a percent escape

Hand-written fixture, 2026-09-14, bound against provider 03.

## Document

One binding to `principal://…/workloadIdentityPools/github/%73ubject/repo:acme/infra:ref:refs/heads/main`.

## Expected

Bind returns true: `{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`,
the whole pool, inexact, with a whole-grant caveat and an
`unmodelled-construct` anomaly whose Construct is `%`, saying which
identities the member selects is not stated.

## Why

Decoded, `%73ubject` is `subject` and the member selects one identity;
taken as written it is a form Google documents for no pool. Which reading
Google applies is not documented, and the member is not decoded (case 49).
The union of the two readings is at most the whole pool, so the member is
read as the pool with the doubt stated; the same holds for `%2A` in place
of `*` and for an escape inside an attribute name. A percent escape inside
the value of a documented selector, `subject/repo%3Aacme`, leaves the claim
alone Unknown, as before. Before this fixture the parser matched the
selector's kind byte for byte and returned false with no anomaly.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers
