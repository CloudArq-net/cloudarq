# 24 — a condition key starts with the provider's name as registered, trailing slash included

Hand-written fixture, 2026-09-13.

## Document

Two statements for the provider ARN
`arn:aws:iam::123456789012:oidc-provider/acme.eu.auth0.com/`, registered
with a trailing slash the way an Auth0 tenant's issuer URL ends.
`ProviderRegisteredWithATrailingSlash` pins `acme.eu.auth0.com/:aud`.
`KeyWithoutTheSlashNamesAnotherProvider` pins `acme.eu.auth0.com:aud`, the
same host with no slash.

## Expected

Two grants, both on issuer `https://acme.eu.auth0.com`, the registry key,
which has no trailing slash.

- `ProviderRegisteredWithATrailingSlash`: `{aud="AbCdEf0123456789"}`, exact
  when the vocabulary knows the issuer's claims; a token with that `aud` is
  admitted. Without the vocabulary the claim is Unknown, declared, with the
  vocabulary anomaly naming the key `acme.eu.auth0.com/:aud`.
- `KeyWithoutTheSlashNamesAnotherProvider`: `{acme.eu.auth0.com:aud="AbCdEf0123456789"}`,
  exact: the key is another provider's, one registered without the slash,
  and a token from this one never carries it.

## Why

The IAM condition keys page: "Define condition keys using the name of the
OIDC provider (token.actions.githubusercontent.com) followed by a claim
(:aud): token.actions.githubusercontent.com:aud." The name of the provider
is what the ARN carries after `oidc-provider/`, as registered. A provider
created from the URL `https://acme.eu.auth0.com/` keeps the slash in its
name, and its keys are `acme.eu.auth0.com/:aud`; that shape is deployed in
Mozilla's public CloudFormation for their Auth0 tenant, where the principal
is `:oidc-provider/auth.mozilla.auth0.com/` and the keys
`auth.mozilla.auth0.com/:aud` and `auth.mozilla.auth0.com/:amr`.

An earlier draft derived the prefix a provider's keys start with from
`trust.NormaliseIssuer`, which drops a trailing slash because the registry
keys issuers without one. The prefix then never matched the key AWS
populates, the key was read as another provider's, the grant put an exact
constraint on a claim no token carries and admitted nobody, with no
anomaly: a silent under-approximation on a production shape. The issuer is
still the registry key; the prefix is the provider name as written in the
principal, ASCII case-folded like every key comparison here.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (fetched 2026-09-13)
- https://github.com/mozilla/security/blob/master/operations/cloudformation-templates/infosec-prod_oidc_federated_roles.yaml (fetched 2026-09-13)
- internal/trust/normalise.go, `NormaliseIssuer`
- specs/B2-aws-trust-policy-parser.md §3, §11
