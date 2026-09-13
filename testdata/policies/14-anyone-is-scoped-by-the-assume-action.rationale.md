# 14 — `"*"` is every AWS principal and every other identity, each through its own action

Hand-written fixture, 2026-09-13.

## Document

`AllowOneAccount` trusts account `111111111111` through `sts:AssumeRole`.
`DenyEveryoneThroughWebIdentity` is a Deny for `"Principal": "*"` on
`sts:AssumeRoleWithWebIdentity` alone. `AllowEveryoneThroughEveryAction`
trusts `{"AWS": "*"}` on `"Action": "*"`.

## Expected

Five grants.

- `AllowOneAccount`: issuer `aws:sts`, `{aws:principalaccount="111111111111"}`,
  exact.
- `DenyEveryoneThroughWebIdentity` projects two grants, one per face of
  `"*"`. The AWS face, issuer `aws:sts`, denies nothing, exactly, with a
  `not-an-assume-action` anomaly: the statement grants no `sts:AssumeRole`,
  so no AWS principal is denied by it. The other face has no issuer, denies
  nothing, and is inexact: an `unmodelled-construct` anomaly whose sentence
  is
  `the statement applies to every principal, and which identity providers' tokens it covers through sts:AssumeRoleWithWebIdentity is not known`
  says what the statement leaves unstated, and the Deny-not-applied anomaly
  says the Deny is not applied. Both carry the `any-principal` note.
- `AllowEveryoneThroughEveryAction` projects the same two faces as Allows:
  the AWS face admits everything, exactly; the other face admits
  everything, inexact, and its sentence names every assume action, since
  `"*"` grants all three:
  `the statement applies to every principal, and which AWS services and identity providers' tokens it covers through sts:AssumeRole, sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known`.

Account `111111111111` therefore keeps its grant: nothing on issuer
`aws:sts` subtracts from it.

## Why

The principal page: `"Principal": "*"` and `{"AWS": "*"}` are equivalent
and "grants access to all users, including anonymous users (public
access)". The Action page: the element "describes the specific action or
actions that will be allowed or denied", so a Deny, like an Allow, applies
only to the actions it names, and the action an identity assumes a role
through depends on what it is: an AWS principal or an AWS service calls
`sts:AssumeRole`, an OIDC identity `sts:AssumeRoleWithWebIdentity`, a SAML
identity `sts:AssumeRoleWithSAML`. A Deny for `"*"` on the web identity
action alone therefore never applies to an `sts:AssumeRole` call by account
`111111111111`.

The grant model carries no action; a grant's issuer implies it. So `"*"`
is projected as two principals: every AWS principal, on the pseudo-issuer,
which assumes through `sts:AssumeRole`, and every identity the statement
does not name an issuer for, on no issuer: the tokens of every identity
provider through the two federated actions, and every AWS service through
`sts:AssumeRole`. Each face is tested against its own actions. Projected
as one grant on the pseudo-issuer that any assume action satisfied, the
Deny above would have subtracted the account's whole grant, reporting a
role nobody can assume when the account can: the under-approximation this
parser exists to never produce.

Services belong on the second face because `"*"` names them: the principal
page's alternative to a wildcard is to "specify intended principals,
services, or AWS accounts in the Principal element", and the global
condition keys page shows a Deny on `"Principal": "*"` that has to exempt
service principals by a condition on `aws:PrincipalIsAWSService`, which it
would not need if `"*"` passed them by. Which services can assume a role
under a bare `"*"`, and whether STS honours a web identity token under one
and from which providers, is not stated on the pages read; the face says
so with a caveat rather than guessing either way, and its sentence names
only the assume actions the statement grants. An earlier draft projected
this face only for the federated actions, so `"*"` on `sts:AssumeRole`
alone read as trusting no service: the same under-approximation, one
principal kind over. The face exists only when the statement grants some
assume action, or when its actions cannot be read, because a face that
admits nobody through an action the statement never names would say
nothing.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html, aws:PrincipalIsAWSService (fetched 2026-09-13)
- internal/join/link.go, `denialsAgainst`: a Deny counts against grants of its own issuer, and a blank issuer may be any
- specs/B2-aws-trust-policy-parser.md §11
