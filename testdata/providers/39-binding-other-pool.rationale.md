# 39 — members that do not name the provider's pool

Hand-written fixture, 2026-09-13, bound against provider 03, whose pool is
`…/workloadIdentityPools/github`.

## Document

One member for the pool `gitlab` and one service account member.

## Expected

Bind returns false for both. ParseMembers still returns both, the first
with its pool parsed and the second with none.

## Why

A binding admits identities of the pool it names and no other; the
provider's name, "Output only. The resource name of the provider.", carries
its pool, and a member for another pool is not a binding on this provider.
A `serviceAccount:` member is a Google identity, not a federated one, and
names no pool at all. Neither is a grant of this provider, so neither is a
Grant; they are not silence, because ParseMembers hands every member to
the caller, and a collector that wants to know what the account trusts
beyond this provider has them.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (name)
