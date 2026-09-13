# 12 — an exclusion

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub != 'repo:acme/infra:ref:refs/heads/main'`.

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on
`sub`, an `unmodelled-construct` anomaly whose Construct is `!=`.

## Why

Google admits every credential whose subject is anything but the one
value. The lattice has no complement, and the set of every string but one
is not a union of exact values or patterns; the sound upper bound is every
value, which is what Unknown on `sub` says, with the caveat that says why.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`!=`)
- specs/B0-trust-grant-model.md ("anything else → Unknown + an Anomaly naming it")
