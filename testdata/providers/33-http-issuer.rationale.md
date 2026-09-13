# 33 — an issuer that is not an HTTPS endpoint

Hand-written fixture, 2026-09-13.

## Document

`"issuerUri": "http://token.actions.githubusercontent.com"`.

## Expected

Issuer `https://token.actions.githubusercontent.com`;
`{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, with an `issuer-scheme` anomaly that is a fact, not a doubt.

## Why

Google: "issuerUri: Required. The OIDC issuer URL. Must be an HTTPS
endpoint." Whether the API refuses another scheme at create is not stated
on the page; a request body or a Terraform rendering can carry one, and a
live document can if the API accepts it. The Pass 1 table read such a
value as Issuer "" with `missing-issuer`; this fixture departs from it. The
value is read as the issuer it names once normalised, the registry key
`trust.NormaliseIssuer` gives any scheme, and the fact is recorded, which
is the convention the Azure parser follows for the same defect
(`IssuerScheme`). This is the narrower of the two readings in the join,
where `mayShareIssuer` pairs a blank issuer with every counterparty and a
named one with its own. It is not narrower than Google: the document names
one host, and no reading of it admits a token from another, so the only
identities the provider could admit are that host's. A blank issuer would
pair the grant with every counterparty, reporting a doubt about the scheme
as the absence of an issuer. The admitted set is what the document says;
the issuer is what is doubtful, and the fact is recorded on the anomaly
rather than on the set.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (Oidc.issuerUri)
- internal/parse/azure/credential.go (IssuerScheme)
- internal/join/link.go (mayShareIssuer)
