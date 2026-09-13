# 13 — a regular expression

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub.matches('^repo:acme/[a-z]+:ref:refs/heads/main$')`.

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on
`sub`, an `unmodelled-construct` anomaly whose Construct is `matches`.

## Why

CEL's `matches` is RE2 matching. The lattice's sets are exact values and
`*`/`?` patterns; a regular expression is neither, and the brief's non-goal
stands: no general CEL interpreter. The claim is Unknown, declared by name.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`matches`)
- specs/B0-trust-grant-model.md ("Do not write a general CEL interpreter")
