# 05 — ForAllValues reads like a restriction and is not one

Hand-written fixture, 2026-09-13.

## Document

`StringEquals` on `aud` and `repository_id`, then
`ForAllValues:StringLike` on `sub` with `repo:acme/infra:*`.

## Expected

`{aud="sts.amazonaws.com", repository_id="456789", sub=?("ForAllValues:StringLike")}`,
inexact, with one caveat on `sub` and one `unmodelled-construct` anomaly on
`sub` naming `ForAllValues:StringLike`, whose sentence is
`ForAllValues:StringLike on sub passes when the claim is absent, so it does not restrict what it looks like it restricts`.
A token with `aud` and `repository_id` and no `sub` is admitted;
`repository_id` is still required. This is conformance case 07's AWS
document, judged by the harness under WidensWithAnomaly.

## Why

The operators page: "The ForAllValues qualifier returns true if there are no
context keys in the request or if the context key value resolves to a null
dataset, such as an empty string." Over the set of all requests the
condition passes whenever `sub` is absent, so on its own it restricts
nothing; only another condition that forces `sub` to exist would make it
bite, and none does here. The multivalued page adds "Do not use condition
set operators ForAllValues or ForAnyValue with single-valued context keys",
which GitHub's `sub` is. Unknown on `sub`, declared, is the sound reading;
the sentence is the finding.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html (fetched 2026-09-13)
- internal/trust/conformance.go, case 07
- specs/B2-aws-trust-policy-parser.md §5
