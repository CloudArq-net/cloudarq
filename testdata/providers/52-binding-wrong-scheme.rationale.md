# 52 — a subject selector under principalSet://

Hand-written fixture, 2026-09-14, bound against provider 03.

## Document

One member `principalSet://…/workloadIdentityPools/github/subject/repo:acme/infra:ref:refs/heads/main`:
the subject form, under the scheme Google documents for the other three.

## Expected

Bind returns true: `{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`,
the whole pool, inexact, with a whole-grant caveat and an
`unmodelled-construct` anomaly whose Construct is `subject`.

## Why

The scheme is part of the form: Google prints "Single identity in a
workload identity pool" as `principal://…/subject/SUBJECT_ATTRIBUTE_VALUE`
and the three set forms as `principalSet://…`, and documents no subject
under `principalSet://`. Whether IAM accepts this member, and whether it
would select the one subject, is not stated. Reading it as the subject
would be an Exact on a reading the page does not give; reading it as
absent would report a binding that may exist as no binding; the whole
pool with the doubt stated is the union of every reading, and the member
is read so, as case 47 reads every form Google does not document for the
pool. `principal://…/*` is the mirror image and is read the same way.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers (Workload identity pool)
