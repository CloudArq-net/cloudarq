# 13 — a StringLike of `*` is a presence test, not the absence of one

Hand-written fixture, 2026-09-13.

## Document

Three GitHub statements. `AllowOnlyJobsThatRunInAnEnvironment` pins `aud`
and adds `StringLike` on `environment` with the value `*`.
`AllowAcmeRepositories` pins `aud` and matches `sub` against `repo:acme/*`.
`DenyAnyJobThatRunsInAnEnvironment` is a Deny with only the `StringLike`
on `environment` with `*`.

## Expected

- `AllowOnlyJobsThatRunInAnEnvironment`:
  `{aud="sts.amazonaws.com", environment=?("StringLike")}`, inexact, with a
  caveat on `environment` and an `unmodelled-construct` anomaly naming
  `StringLike` whose sentence is
  `StringLike on environment matches every value but only when the claim is present, which this parser cannot express, so the claim is not constrained`.
  A token with `aud` and no `environment` is admitted by the parser; AWS
  rejects it, so the set is an upper bound and says so.
- `AllowAcmeRepositories`: `{aud="sts.amazonaws.com", sub=like:"repo:acme/*"}`,
  exact.
- `DenyAnyJobThatRunsInAnEnvironment`: a Deny that denies nothing, inexact:
  `Admits` is empty with the presence caveat and the Deny-not-applied
  caveat, and both anomalies. A token `{aud, sub=repo:acme/infra:…}` with no
  `environment` claim is admitted by the second Allow and not subtracted.

## Why

The operators page: "If the key that you specify in a policy condition is
not present in the request context, the values do not match and the
condition is false. … This logic applies to all condition operators except
...IfExists and Null check." So `StringLike` with `*` passes only when the
key is present, whatever its value: it is a presence test. GitHub's OIDC
reference describes the claim as "The name of the environment used by the
job" and adds it to the subject "when the job references an environment";
a job that references none has no environment to name, so tokens without
the claim exist.

`eval.Glob("*")` admits every string, and a Term drops a claim that admits
every value because an absent claim already means that. Handed straight to
the Term, the constraint would therefore vanish, and vanish in both
directions: an Allow would admit tokens without the claim and report the
set as exact, and a Deny would deny every token, including the ones AWS
does not deny, which is the under-approximation this parser exists to
never produce. Presence is not a set of values a StringSet can state, as
case 07 already says of `Null`, so the claim is Unknown with the sentence
above. Under a Deny that Unknown makes the Deny inapplicable, and the
result stays an upper bound. The same reading covers `**`, `***` and a
value list that contains a bare `*` beside other patterns, because each of
those admits every string too.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- https://docs.github.com/en/actions/reference/security/oidc (fetched 2026-09-13)
- internal/eval/glob.go, `Glob`; internal/eval/admitted.go, `normaliseTerm`
- specs/B2-aws-trust-policy-parser.md §5, §8
