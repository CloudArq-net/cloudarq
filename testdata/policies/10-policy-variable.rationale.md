# 10 — policy variables are not literals, and the escapes are

Hand-written fixture, 2026-09-13.

## Document

Version `2012-10-17`, three statements: `sub` pinned to
`${aws:PrincipalTag/team}` under StringEquals; `sub` pinned to
`repo:acme/${*}:ref:refs/heads/main` under StringEquals; `sub` matched by
`repo:acme/${*}:*` under StringLike.

## Expected

- `{aud="sts.amazonaws.com", sub=?("${aws:PrincipalTag/team}")}`, inexact,
  anomaly `unmodelled-construct` naming `${aws:PrincipalTag/team}`.
- `{aud="sts.amazonaws.com", sub="repo:acme/*:ref:refs/heads/main"}`,
  exact: the one subject with a literal asterisk, and not the main branch.
- `{aud="sts.amazonaws.com", sub=?("${*}")}`, inexact, anomaly naming `${*}`
  with the sentence
  `the value "repo:acme/${*}:*" on sub holds the escaped wildcard ${*} under StringLike, which this parser cannot express, so the claim is not constrained`.

## Why

The variables page: a policy variable is replaced per request, so
`${aws:PrincipalTag/team}` is not a value a token's `sub` could be compared
with ahead of time; Unknown is the only bound. The same page defines the
predefined escapes, "${*} - use where you need an * (asterisk) character",
likewise `${?}` and `${$}`; under StringEquals the escape yields the
character and the set stays exact. Under StringLike a literal `*` is a
character eval.Glob cannot express, because every `*` in a pattern is a
wildcard there, so that value is Unknown rather than a pattern that admits
more than the policy does.

The version page: with no Version, or with `2008-10-17`, variables "aren't
recognized as variables and are instead treated as literal strings in the
policy", so under those the text is an exact value as written. A Version
this parser cannot read leaves the question open, and a value holding `${`
is Unknown either way.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §10
