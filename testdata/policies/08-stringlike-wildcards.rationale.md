# 08 — a star crosses every delimiter; an equals has no wildcard

Hand-written fixture, 2026-09-13.

## Document

`StringLike` on `sub` with `repo:acme*/infra*:*`, and `StringEquals` on
`aud` with the value `*`.

## Expected

`{aud="*", sub=like:"repo:acme*/infra*:*"}`, exact. It admits
`sub = repo:acme-evil/infrastructure:ref:refs/heads/main` with `aud = *`,
the intended `repo:acme/infra:environment:production` too, and rejects
`aud = sts.amazonaws.com`.

## Why

The operators page on StringLike: "The values can include multi-character
match wildcards (*) and single-character match wildcards (?) anywhere in
the string." No sentence on the page gives `*` any awareness of `/` or `:`,
so `acme*` matches `acme-evil` and `infra*` matches `infrastructure`: an
owner an outsider can register. The parser keeps the pattern intact and
hands it to eval.Glob, whose matcher has no delimiter special-casing.

The same table has "StringEquals Exact matching, case sensitive": a `*`
under StringEquals is the literal character, so `aud = "*"` admits the one
audience spelled `*` and not every audience. The two operators never share
a code path, so neither can inherit the other's reading.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- internal/eval/glob.go
- specs/B2-aws-trust-policy-parser.md §8
