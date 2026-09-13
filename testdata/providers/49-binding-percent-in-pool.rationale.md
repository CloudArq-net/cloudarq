# 49 — a member whose pool segment holds a percent escape

Hand-written fixture, 2026-09-14, bound against provider 03, whose pool is
`…/workloadIdentityPools/github`.

## Document

One binding to `principalSet://…/workloadIdentityPools/git%68ub/*`.

## Expected

Bind returns true: `{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`,
the whole pool, inexact, with a whole-grant caveat and an
`unmodelled-construct` anomaly whose Construct is `%`, saying the pool
could not be compared.

## Why

A principal identifier is URL-path text, and none of Google's pages read
says whether percent escapes in one are decoded. Decoded, `git%68ub` is
`github`, the provider's own pool, and the service account is reachable by
every identity in it; taken as written it names no pool of that project.
The Pass 1 rule is that a member containing `%` "is Unknown with an
anomaly rather than decoded", and a pool that cannot be compared under
either reading is read as this provider's, the wide direction, with the
doubt stated. A segment that differs from the provider's and holds no
escape differs under every reading, so `…/locations/europe/workloadIdentityPools/git%68ub/*`
is still not a binding on a provider in `global`. Before this fixture the
parser compared the pool byte for byte and returned false with no anomaly:
a binding that may exist, reported as absent, in silence.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers (no statement on percent-encoding)
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers
