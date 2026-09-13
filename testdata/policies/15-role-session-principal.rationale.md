# 15 — a role session principal is not the value `aws:PrincipalArn` carries

Hand-written fixture, 2026-09-13.

## Document

Four statements on `sts:AssumeRole`. `SessionWithTheRoleArnInACondition`
trusts the session `arn:aws:sts::123456789012:assumed-role/ci/build-42` and
requires `aws:PrincipalArn` to equal `arn:aws:iam::123456789012:role/ci`.
`SessionAlone` trusts the same session with no condition. `AllowTheRole`
trusts the role `arn:aws:iam::123456789012:role/ci`. `DenyOneSessionOfIt`
denies the session.

## Expected

Four grants, all on issuer `aws:sts`.

- `SessionWithTheRoleArnInACondition`:
  `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci"}`,
  inexact: a caveat on `aws:principalarn` and an `unmodelled-construct`
  anomaly naming the session ARN, whose sentence is
  `the AWS principal "arn:aws:sts::123456789012:assumed-role/ci/build-42" is one session of a role in account 123456789012; aws:PrincipalArn holds the role's ARN, which the session ARN does not spell, so which identity of that account it names is not known`.
  The caller AWS admits, whose `aws:PrincipalArn` is the role ARN, is
  admitted.
- `SessionAlone`:
  `{aws:principalaccount="123456789012", aws:principalarn=?("arn:aws:sts::123456789012:assumed-role/ci/build-42")}`,
  inexact, same caveat and anomaly.
- `AllowTheRole`:
  `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci"}`,
  exact.
- `DenyOneSessionOfIt`: a Deny that denies nothing, inexact, with the
  session anomaly and the Deny-not-applied anomaly. Every session of the
  role stays admitted through `AllowTheRole`; AWS admits every session but
  `build-42`, so the set is an upper bound and says so.

## Why

The principal page documents the session form,
`"Principal": { "AWS": "arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name" }`,
and says of the condition key that "the role session principal is granted
the permissions based on the ARN of role that was assumed, and not the ARN
of the resulting session". The condition keys page: for `aws:PrincipalArn`,
"For IAM roles, the request context returns the ARN of the role, not the
ARN of the user that assumed the role", with the example value
`arn:aws:iam::123456789012:role/role-name` and the instruction "Do not
specify the assumed role session ARN as a value for this condition key".

So a session principal names a narrower thing than the role, one session
of it, and the request context of that session carries the role's ARN,
never the session's. Pinning `aws:principalarn` to the session ARN, as an
earlier draft of this parser did, produced a constraint no request
context satisfies: met with the condition in the first statement it gave
a provably empty set, exact, for a caller AWS admits. The role's ARN
cannot be recovered from the session ARN either, because a role's path
(`role/path/ci`) is not part of `assumed-role/ci/…`, and the session name
is not a claim this model carries. The account is in the ARN and is
exact; the ARN is Unknown, declared, and a condition on `aws:PrincipalArn`
then narrows it to whatever the policy says.

Under a Deny the Unknown makes the Deny inapplicable, which keeps the
result an upper bound: applying a Deny on an ARN the parser cannot state
would risk denying sessions the policy does not.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §11
