# 04 — a suffix and a substring, met

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub.endsWith(':ref:refs/heads/main') && assertion.sub.contains('/infra:')`.

## Expected

`{aud="…/providers/github", sub=(like:"*/infra:*" & like:"*:ref:refs/heads/main")}`,
exact.

## Why

`endsWith(s)` admits the strings matching `*s`; `contains(s)` admits those
matching `*s*`; `&&` is the Meet. Two globs on one claim meet into the
lattice's intersection node, which keeps both patterns and answers
membership exactly; it is the canonical form for this set, so the rendering
is the intersection, not one merged pattern.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`endsWith`, `contains`, `&&`)
- internal/eval/stringset.go (inter: glob ∧ glob keeps both patterns)
