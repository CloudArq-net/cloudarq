# 45 — google.groups compared with a string

Hand-written fixture, 2026-09-13.

## Document

`"google.groups": "assertion.groups"` and
`"attributeCondition": "google.groups == 'admins'"`.

## Expected

`{aud="…/providers/github"}` with `groups` Unknown: inexact, a caveat on
`groups`, an `unmodelled-construct` anomaly whose Construct is
`google.groups` and whose sentence says Google documents it as the set of
groups the identity belongs to.

## Why

Google: "google.groups: Groups the external identity belongs to. You can
grant groups access to resources using an IAM principalSet binding; access
applies to all members of the group." and, on the concept page,
"google.groups: Optional. A set of groups that the identity belongs to."
Its only documented condition on it is membership, "'admins' in
google.groups" (case 25). The lattice models a claim as one string, so a
set-valued attribute is outside what it can state under any form it is
compared in: `==`, `in [...]`, `startsWith`, `endsWith` and `contains` on
`google.groups` all leave the mapped claim Unknown, declared, exactly as
membership and a group binding (case 37) do. An Exact on `groups` would be
a set the parser declares exact over a value it cannot hold.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping, attributeCondition)
- https://cloud.google.com/iam/docs/workload-identity-federation (Attribute mappings)
