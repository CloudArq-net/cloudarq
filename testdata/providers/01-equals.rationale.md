# 01 — equality on a claim

Hand-written fixture, 2026-09-13, after Google's REST reference for
`projects.locations.workloadIdentityPools.providers` (page dated 2025-09-25).

## Document

`"attributeCondition": "assertion.sub == 'repo:acme/infra:ref:refs/heads/main'"`
with one allowed audience.

## Expected

`{aud="https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, no anomaly. Issuer `https://token.actions.githubusercontent.com`.

## Why

Google: "A Common Expression Language expression, in plain text, to restrict
what otherwise valid authentication credentials issued by the provider should
not be accepted. The expression must output a boolean representing whether to
allow the federation." and "assertion: JSON representing the authentication
credential issued by the provider." CEL's `==` on two strings is equality of
the strings, case kept, so the set of admitted `sub` values is the singleton.
The audience: "Token exchange requests are rejected if the token audience does
not match one of the configured values." One configured value is one Exact.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers
- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`==` on strings)
