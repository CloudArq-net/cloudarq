# 47 — a member on the pool in a form Google does not document for it

Hand-written fixture, 2026-09-13, rewritten 2026-09-14, bound against
provider 03, whose pool is `…/workloadIdentityPools/github`.

## Document

One member on the provider's own pool:
`principalSet://…/github/namespace/default`.

## Expected

Bind returns true: `{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`,
the whole pool, inexact, with a whole-grant caveat and an
`unmodelled-construct` anomaly whose Construct is `namespace`, saying
that the form is one Google documents for no workload identity pool and
that the whole pool is read as admitted.

## Why

Google documents four principal identifiers for a workload identity pool:
"Single identity in a workload identity pool"
`principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT_ATTRIBUTE_VALUE`,
"Workload identity pool group" `principalSet://…/POOL_ID/group/GROUP_ID`,
"All identities in a workload identity pool with a certain attribute"
`principalSet://…/POOL_ID/attribute.ATTRIBUTE_NAME/ATTRIBUTE_VALUE`, and
"All identities in a workload identity pool" `principalSet://…/POOL_ID/*`.
`namespace/NAMESPACE`, `kubernetes.serviceaccount.uid/` and
`kubernetes.cluster/` are documented for the GKE pool
`PROJECT_ID.svc.id.goog` alone. Whether IAM accepts such a member on
another pool, and what it would select if it did, is not stated on the
page. A parse that returned false read a binding that may exist as
absent, which is the narrow direction; and its ground, that the wide
reading "would list a GKE namespace as a binding of a GitHub provider",
did not hold, because a GKE member names the pool `PROJECT_ID.svc.id.goog`
and a member of another pool is no binding on this provider whatever its
selector (case 39). The union of every reading Google might give the
member is at most the whole pool, so the member is read as the pool with
the doubt stated, exactly as a selector holding a percent escape is (case
50). The same rule reads a documented selector under the other scheme
(case 52), an empty or absent selector, and any other text after the pool.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers (Workload identity pool, GKE)
