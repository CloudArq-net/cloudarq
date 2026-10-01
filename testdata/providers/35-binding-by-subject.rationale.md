# 35 — a binding on one subject

Hand-written fixture, 2026-09-13: the IAM policy of a service account, as
`getIamPolicy` returns it, bound against provider 03 (any branch of one
repository by prefix).

## Document

One binding of `roles/iam.workloadIdentityUser` to
`principal://…/workloadIdentityPools/github/subject/repo:acme/infra:ref:refs/heads/main`.

## Expected

Bind returns true and a Grant on the service account admitting
`{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact: the Meet of the provider's `sub=like:"repo:acme/infra:*"` with the
member's Exact.

## Why

Google's principal identifier for "Single identity in a workload identity
pool" is `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT_ATTRIBUTE_VALUE`,
and the provider page says of google.subject: "The principal IAM is
authenticating. You can reference this value in IAM bindings." The value
is the mapped subject, which provider 03 maps from `assertion.sub`, so the
member is Exact on `sub`; a workload reaches the service account only
through both documents, so the grant is their Meet, on the account.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping)
