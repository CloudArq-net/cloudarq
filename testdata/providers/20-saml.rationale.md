# 20 — a SAML provider

Hand-written fixture, 2026-09-13.

## Document

`"saml": {"idpMetadataXml": …}` with a condition on `assertion.subject`.

## Expected

Issuer `""`; `{}`: everything, inexact, with a whole-grant caveat and an
`unmodelled-construct` anomaly whose Construct is `saml`, plus one for the
clause it could not attribute.

## Why

Google: "saml: An SAML 2.0 identity provider." and "idpMetadataXml:
Required. SAML identity provider (IdP) configuration metadata XML doc." The
credential is a SAML assertion, whose subject and attributes this parser
does not model as token claims, and whose issuer is an entity ID inside the
metadata rather than an OIDC issuer URL the registry knows. Nothing in the
condition can be attributed to a claim of a token this product models, so
the grant is the whole issuer, declared an upper bound; a parser that read
`assertion.subject` as a claim named `subject` would be guessing the shape
of a document it has not modelled.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (Saml)
