# 03 — keys in any case, values as written

Hand-written fixture, 2026-09-13.

## Document

`StringEquals` on `TOKEN.ACTIONS.GITHUBUSERCONTENT.COM:aud` and
`Token.Actions.GitHubUserContent.com:SUB`, the value of the second being
`repo:Acme/Infra:ref:refs/heads/Main`.

## Expected

One exact grant, `{aud="sts.amazonaws.com", sub="repo:Acme/Infra:ref:refs/heads/Main"}`.
It admits a token whose `sub` is spelled exactly that way and rejects
`repo:acme/infra:ref:refs/heads/main`.

## Why

The Condition page: "Context key names are not case-sensitive. For example,
including the aws:SourceIP context key is equivalent to testing for
AWS:SourceIp." So both keys name the provider's `aud` and `sub`, whatever
their case; the provider identifier before the colon is compared to the
principal's normalised issuer with ASCII case folded, and the claim name
after it is handed to the vocabulary, which spells GitHub's claims in lower
case. The same page: "Case-sensitivity of context key values depends on the
condition operator that you use", and the operators table has
"StringEquals Exact matching, case sensitive", so the value is kept as
written and admits one spelling.

An operator spelled unlike the grammar (`stringequals`) is not recognised
and widens to Unknown: no page read says operator names fold case, and a
guess in the narrow direction is the one this parser never makes.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §3
