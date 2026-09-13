# 09 — a wildcard character inside a prefix

Hand-written fixture, 2026-09-13. The second of the three things the Pass 1
names as most likely to go wrong.

## Document

`assertion.sub.startsWith('repo:acme/*')`.

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on `sub`,
an `unmodelled-construct` anomaly whose Construct is `startsWith`.

## Why

CEL's `startsWith` compares characters literally: Google admits subjects
that begin with the eight characters `repo:acme/*`, asterisk included. The
lattice's pattern language reads `*` as zero or more of anything, so
`Glob("repo:acme/**")` would admit `repo:acme/infra`, which Google rejects,
while claiming to be exact; and a `?` in a prefix would admit any one
character where Google requires a question mark. Neither set can be stated,
so the claim is Unknown, declared.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`startsWith`)
- internal/eval/glob.go (`*` and `?` are the only metacharacters)
