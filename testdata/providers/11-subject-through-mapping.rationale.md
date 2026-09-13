# 11 — google.subject through the mapping

Hand-written fixture, 2026-09-13.

## Document

`"google.subject": "assertion.sub"` and
`"attributeCondition": "google.subject == 'repo:acme/infra:ref:refs/heads/main'"`.

## Expected

`{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`, exact.

## Why

Google: "google: The Google attributes mapped from the assertion in the
attribute_mappings." and, of the mapping, "the following maps the sub claim
of the incoming credential to the subject attribute on a Google token:
{"google.subject": "assertion.sub"}". A mapping whose value is exactly a
reference to one assertion field names that claim, so a constraint on
`google.subject` is a constraint on `sub`, and the set is the same as case 01.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers
