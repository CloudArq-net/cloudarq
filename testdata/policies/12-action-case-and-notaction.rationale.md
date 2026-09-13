# 12 — Action in any case with wildcards anywhere; NotAction widens

Hand-written fixture, 2026-09-13.

## Document

Six GitHub statements pinning `sub` to the main branch, differing only in
the action: `STS:assumeROLEwithwebidentity`; `["sts:TagSession",
"sts:*WithWebIdentity"]`; `*`; `sts:Assume?oleWithWebIdentity`;
`sts:AssumeRole`; and `"NotAction": "s3:*"`.

## Expected

Six grants. The first four are exact,
`{sub="repo:acme/infra:ref:refs/heads/main"}`: each action set covers
`sts:AssumeRoleWithWebIdentity`. `AssumeRoleIsNotTheWebIdentityAction` is
nothing, exact, with a `not-an-assume-action` anomaly whose sentence is
`the actions do not include sts:AssumeRoleWithWebIdentity, so this statement lets nobody assume the role through this principal`.
`NotActionInverts` is everything, inexact, with a whole-grant caveat and an
`unmodelled-construct` anomaly on `NotAction` at `statement[5].Action`.

## Why

The Action page: "The prefix and the action name are case insensitive", so
the pattern is ASCII lower-cased before matching; and "You can also use
wildcards (* or ?) as part of the action name", anywhere, so the pattern is
matched with eval.Glob rather than by a prefix test, which is how
`sts:*WithWebIdentity` and `sts:Assume?oleWithWebIdentity` cover the action
and `sts:AssumeRole` does not. An OIDC principal assumes a role through
`sts:AssumeRoleWithWebIdentity` alone, so a statement without it lets
nobody in through that principal; the test is exact and the anomaly says
why the set is empty. The sentence names the principal rather than the
statement because `"*"` is two principals at once (case 14), and a
statement that lets nobody in through one of them may let everyone in
through the other.

"Statements must include either an Action or NotAction element." NotAction
grants every action but the ones listed. The brief makes computing that
complement an explicit non-goal, so the statement is Unknown as a whole,
declared by the caveat; it is never read as granting nothing.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html (fetched 2026-09-13)
- internal/eval/glob.go
- specs/B2-aws-trust-policy-parser.md §12
