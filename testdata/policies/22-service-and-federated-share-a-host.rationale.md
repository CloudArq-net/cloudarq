# 22 — a service principal and a federated provider can share a host and are not one issuer

Hand-written fixture, 2026-09-13.

## Document

`AllowCognitoIdentities` trusts the built-in provider
`{"Federated": "cognito-identity.amazonaws.com"}` through
`sts:AssumeRoleWithWebIdentity`, with `cognito-identity.amazonaws.com:aud`
pinned to an identity pool id. `DenyTheCognitoService` is a Deny for the
service principal `{"Service": "cognito-identity.amazonaws.com"}` on
`sts:AssumeRole`.

## Expected

Two grants on two issuers.

- `AllowCognitoIdentities`: issuer `https://cognito-identity.amazonaws.com`,
  `{aud="us-east-1:0f2b7c1e-5a3d-4e6f-9b8a-1c2d3e4f5a6b"}`, exact when the
  vocabulary knows the provider's claims.
- `DenyTheCognitoService`: issuer
  `aws:service:cognito-identity.amazonaws.com`, everything, exact, with the
  `service-principal` anomaly whose sentence is
  `cognito-identity.amazonaws.com is an AWS service principal; who can make it act, or receives its session, is not read`.
  The sentence says what a trust policy does not show, and never that a
  service is not an outside identity: a service can assume a role for
  identities outside IAM and hand them its session, as IAM Roles Anywhere
  does, "for workloads such as servers, containers, and applications that
  run outside of AWS".

A token with that `aud` is admitted by the Allow and subtracted by nothing:
the Deny names a different principal kind on a different action.

## Why

The principal page lists `"Federated": "cognito-identity.amazonaws.com"`
among the four built-in OIDC providers, whose identities call
`sts:AssumeRoleWithWebIdentity`, and describes service principals as a
separate kind, "an identifier for a service", in the form
`service-name.amazonaws.com`, which assume a role through `sts:AssumeRole`.
The same host names both. AWS admits every Cognito identity whose `aud`
matches, whatever the Deny on the service says.

Giving a service principal the issuer `trust.NormaliseIssuer(service)`,
`https://cognito-identity.amazonaws.com`, would give it the federated
provider's issuer too. A consumer that subtracts a Deny from the grants of
its own issuer would then subtract the exact, everything-denying service
Deny from the federated Allow, and the role would read as admitting no
Cognito identity: an under-approximation, reported exact.
The pseudo-issuer of every AWS principal, `aws:sts`, already exists for the
same reason, so that a Deny on the service `sts.amazonaws.com` cannot land
on the accounts' issuer; a service has a pseudo-issuer of its own,
`aws:service:` followed by its name, ASCII lower-cased because a service
principal is a DNS name. No Federated principal can spell it: a bare name
comes out of NormaliseIssuer with an https scheme, and a SAML provider is
its ARN.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html (fetched 2026-09-27)
- internal/parse/aws/principal.go, `AWSPrincipalIssuer` and `ServiceIssuerPrefix`
