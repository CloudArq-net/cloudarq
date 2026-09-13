# 37 — a binding on a group

Hand-written fixture, 2026-09-13, bound against provider 03.

## Document

`principalSet://…/workloadIdentityPools/github/group/admins`.

## Expected

Bind returns true and
`{aud="…/providers/github", groups=?("group membership"), sub=like:"repo:acme/infra:*"}`,
inexact: `groups` is Unknown in the term, with a caveat on `groups` and an
`unmodelled-construct` anomaly whose Construct is `group`. The Unknown is
met into the provider's own term claim by claim, so that it shows beside
the other constraints; a set built from the Unknown alone would be
everything to the lattice and leave no trace in the Meet.

## Why

Google's identifier for "Workload identity pool group" is
`principalSet://…/workloadIdentityPools/POOL_ID/group/GROUP_ID`, and
"google.groups: Groups the external identity belongs to. You can grant
groups access to resources using an IAM principalSet binding; access
applies to all members of the group." Provider 03 maps `google.groups` from
`assertion.groups`, a list-valued claim the lattice models as one string,
so membership cannot be stated: the claim is Unknown, declared, exactly as
`'admins' in google.groups` is in case 25.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping)
