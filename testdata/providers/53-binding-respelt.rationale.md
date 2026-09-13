# 53 — a member whose fixed text is spelt in another case

Hand-written fixture, 2026-09-14, bound against provider 03.

## Document

One member `Principal://IAM.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/subject/repo:acme/infra:ref:refs/heads/main`:
the scheme and the host differ from Google's spelling in case alone.

## Expected

Bind returns true: `{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
the Meet of the provider's prefix with the member's subject, inexact,
with a whole-grant caveat and an `unmodelled-construct` anomaly whose
Construct is `spelling`, saying the member is read as the principal it
resembles.

## Why

Google prints the scheme as `principal://` or `principalSet://`, the host
as `iam.googleapis.com` and the segments as `projects`, `locations` and
`workloadIdentityPools`, and says nothing about a member that spells any
of them otherwise. Under a reader that folds case the member selects one
subject; under one that does not it names no principal IAM knows, and the
binding admits nobody. The union of the two readings is the subject, so
the member is read as the principal it resembles, with the doubt stated
on the whole grant rather than on a claim, since it is the binding's
existence that is in doubt. A parse that read the member as not a pool
principal at all reported a binding that may exist as absent, the narrow
direction. The values the member names are compared as for any member: a
respelt member of another pool or another project is no binding on this
provider. ParseMembers reports `Pool` in Google's spelling of the fixed
text with the values as written, so that a caller sees which pool it
names.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers (Workload identity pool)
