# 32 — no provider configuration

Hand-written fixture, 2026-09-13.

## Document

A provider with none of `oidc`, `aws`, `saml`, `x509`.

## Expected

Issuer `""`; `{}`: everything, inexact, with a whole-grant caveat and a
`missing-issuer` anomaly whose Construct is `provider_config`, plus an
`unmodelled-construct` anomaly for the clause that could not be attributed.

## Why

Google: "Union field provider_config. Identity provider configuration
types. provider_config can be only one of the following: aws, oidc, saml,
x509". With none set, which identity provider is trusted is not stated, and
neither is the shape of its credential: an AWS provider's `assertion.account`
is the same fact the AWS parser spells `aws:principalaccount`, an OIDC
provider's claims are the token's own, so a clause on `assertion.sub` cannot
be attributed to a claim without knowing which. The grant is the whole
provider, declared, rather than a guess at its claim space. A document with
two of the four is read the same way, with the anomaly saying so.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (provider_config)
