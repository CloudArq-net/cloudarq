# 51 — a binding on a subject longer than Google's limit

Hand-written fixture, 2026-09-14, bound against provider 03.

## Document

One binding to `principal://…/workloadIdentityPools/github/subject/repo:acme/infra:xxx…`,
the subject 216 bytes long.

## Expected

Bind returns true: `{aud="…/providers/github", sub="repo:acme/infra:xxx…"}`,
inexact: a caveat on `sub` and a `subject-length` anomaly whose Construct
is `subject`.

## Why

Google: "google.subject: … Cannot exceed 127 bytes." No credential maps
to a 216-byte subject, so the member selects an identity Google never
issues. The value is kept as the Meet with the provider's set and declared
an upper bound, for the reason case 48 gives: the limit is documented, not
observed, and the set must not read as proven empty on documentation
alone. Before this fixture the grant was stated exact with no anomaly.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping, google.subject)
- https://cloud.google.com/iam/docs/principal-identifiers
