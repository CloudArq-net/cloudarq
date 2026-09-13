# 11 — every Principal shape projects a grant

Hand-written fixture, 2026-09-13.

## Document

Eight statements: `"Principal": "*"`; `{"AWS": "*"}`; `{"AWS": [a role
ARN, a bare account id]}`; a Federated OIDC provider ARN with `sub` pinned;
`{"Federated": "accounts.google.com"}` with its `aud` pinned;
`{"Service": "ec2.amazonaws.com"}`; a `CanonicalUser`; and a Deny with
`NotPrincipal`.

## Expected

Eleven grants, none dropped: one per principal, and two for each `"*"`.

- `BareStar`, `AWSStar`: two grants each, the two faces of `"*"` (case
  14). The AWS face, issuer `aws:sts`, admits everything, exactly, with the
  `any-principal` anomaly "the statement applies to every principal,
  including anonymous ones". The other face has no issuer, admits
  everything, and is inexact: every AWS service assumes a role through
  `sts:AssumeRole` too, and which services `"*"` covers is not stated, so
  an `unmodelled-construct` anomaly says
  `the statement applies to every principal, and which AWS services it covers through sts:AssumeRole is not known`.
- `RoleArnAndBareAccountId`: two exact grants on the same issuer,
  `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci"}`
  and `{aws:principalaccount="999999999999"}`.
- `FederatedOIDCProvider`: issuer `https://token.actions.githubusercontent.com`,
  `{sub="repo:acme/infra:ref:refs/heads/main"}`, exact.
- `FederatedBuiltInProvider`: issuer `https://accounts.google.com`,
  `{aud="123456789012-abcdef.apps.googleusercontent.com"}`, exact when the
  vocabulary knows Google's claims.
- `ServicePrincipal`: issuer `aws:service:ec2.amazonaws.com`, everything,
  exact, `service-principal` anomaly.
- `CanonicalUser`: issuer `aws:sts`, everything, inexact,
  `unmodelled-construct` whose sentence is
  `a CanonicalUser principal is not modelled by this parser, so who it names is not known`.
- `NotPrincipalIsADifferentThing`: no issuer, a Deny that denies nothing,
  inexact, with the NotPrincipal anomaly, whose sentence is
  `NotPrincipal is not supported in a role trust policy and names who is excluded rather than who is admitted, so who the statement admits is not known`,
  and the Deny-not-applied one.

Every anomaly sentence states a fact about the document rather than a
consequence for the grant: a grant beside it may be emptied by the action
test, exactly, and "the statement is not constrained" would then be false.

## Why

The principal page: "For anonymous users, the following elements are
equivalent: "Principal": "*" "Principal" : { "AWS" : "*" }", so both are
every principal; an anomaly says so and the AWS face is exactly everything.
The same page's alternative to `"*"` is to "specify intended principals,
services, or AWS accounts", and the global condition keys page exempts
service principals from a Deny on `"Principal": "*"` by condition, so a
service is among the principals `"*"` names; the second face carries that
as an upper bound, since which services can assume the role is not stated
(case 14). "The
account ARN and the shortened account ID behave the same way. Both delegate
permissions to the account", so a bare id is the account constraint and is
not normalised into a role ARN; a role ARN is the ARN and its account. The
issuer of every AWS principal is the pseudo-issuer `aws:sts`, because their
identity reaches a trust policy through the aws:PrincipalArn family of keys,
which are the claims of that issuer. It is not spelled as a URL: every
issuer a Federated principal can name comes out of trust.NormaliseIssuer
with an https scheme or is a SAML provider ARN, and a service's issuer is
`aws:service:` followed by its name, so a Deny on the service
`sts.amazonaws.com` cannot land on the account grants' issuer, and a Deny
on a service cannot land on a federated provider of the same name (case
22).

The same page: "An OIDC federated principal can represent an OIDC IDP in
your AWS account, or the 4 built in identity providers: Login with Amazon,
Google, Facebook, and Amazon Cognito", written as bare names such as
`"Federated": "accounts.google.com"`. A parser that projected only
`oidc-provider/` ARNs would read that role as trusting nobody; the bare name
is an issuer, recovered with trust.NormaliseIssuer like the ARN's resource.
"The service principal in an IAM policy can't be "Service": "*"", so a
wildcard there is malformed. The canonical user id is an S3 identity this
parser does not model, and says so.

The NotPrincipal page: "You cannot use the NotPrincipal element in an IAM
identity-based policy nor in an IAM role trust policy", and "NotPrincipal
must be used with "Effect":"Deny"". It names who is excluded rather than who
is admitted, so the statement is Unknown as a whole; being a Deny, an
Unknown would deny more than the policy does, so the Deny is not applied
and carries the sentence saying so.

Nothing here projects zero grants for a principal that exists. That is the
rule the brief opens with: Prowler's cross-account check gates on `"AWS" in
Principal`, and a Federated principal never enters the branch.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html, aws:PrincipalIsAWSService (fetched 2026-09-13)
- internal/trust/normalise.go, `NormaliseIssuer`
- specs/B2-aws-trust-policy-parser.md §11
