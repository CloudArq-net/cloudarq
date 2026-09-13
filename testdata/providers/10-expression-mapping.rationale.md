# 10 — an attribute mapped by an expression

Hand-written fixture, 2026-09-13. The third of the three things the Pass 1
names as most likely to go wrong.

## Document

`"attribute.repository": "assertion.repository.extract('{org}/')"` and
`"attributeCondition": "attribute.repository == 'acme'"`.

## Expected

`{aud="…/providers/github"}`: everything from the issuer, inexact, with a
whole-grant caveat (empty claim) and an `unmodelled-construct` anomaly whose
Construct is the mapping expression.

## Why

Google: "Each value must be a Common Expression Language function that maps
an identity provider credential to the normalized attribute specified by the
corresponding map key." and "attribute: The custom attributes mapped from
the assertion in the attribute_mappings." The condition constrains
`attribute.repository`, which is not a token claim but the result of
`extract` over one. This parser does not evaluate mapping expressions, so
the clause cannot be attributed to any claim: a parser that skipped the
mapping and read `attribute.repository` as a claim named `repository` would
answer `{repository="acme"}`, rejecting every real token, whose
`repository` is `acme/infra`. The clause therefore contributes top with the
caveat on the whole grant, not on a claim it may not constrain.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping, attributeCondition)
