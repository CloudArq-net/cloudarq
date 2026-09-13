# 01 — Statement written as one object, not a list

Hand-written fixture, 2026-09-13.

## Document

`"Statement": { … }`: a single statement as a bare object, trusting the
GitHub Actions provider on `sts:AssumeRoleWithWebIdentity` with `aud` and
`sub` pinned by `StringEquals`.

## Expected

One statement, Sid `SingleObjectStatement`, no document anomaly, projecting
one exact grant for `https://token.actions.githubusercontent.com`:
`{aud="sts.amazonaws.com", sub="repo:acme/infra:ref:refs/heads/main"}`.
The same document with the brackets added projects the same grant.

## Why

The grammar page: "If the element takes an array (marked with [ and ]) but
only one value is included, the brackets are optional." A parser that reads
Statement as a list and finds an object would count zero statements and
report the role as trusting nobody, which is the under-approximation the
brief opens with. The object is a list of one.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §1
