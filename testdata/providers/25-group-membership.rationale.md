# 25 — membership of a mapped group

Hand-written fixture, 2026-09-13, from Google's own example: "The
following example shows how to only allow credentials with a mapped
google.groups value of admins: "'admins' in google.groups"".

## Document

`"google.groups": "assertion.groups"` and `"attributeCondition": "'admins' in google.groups"`.

## Expected

`{aud="…/providers/okta"}` with `groups` Unknown: inexact, a caveat on
`groups`, an `unmodelled-construct` anomaly whose Construct is `in`.

## Why

Google: "google.groups: Groups the external identity belongs to." The
mapping names the claim `groups`, whose value is a list; the lattice models
a claim as one string, so membership of a list-valued claim cannot be
stated and the claim is Unknown. The example is Google's own, so it must
parse without refusal, and Unknown declared by name is the honest answer.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeCondition, attributeMapping)
