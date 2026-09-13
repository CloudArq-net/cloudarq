# 03 — a prefix on the subject

Hand-written fixture, 2026-09-13. The binding fixtures 35 to 39 bind
members of this provider's pool.

## Document

`"attributeCondition": "assertion.sub.startsWith('repo:acme/infra:')"`.

## Expected

`{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`, exact.

## Why

CEL's `startsWith` is a prefix test on the string. The set of strings with
prefix p is the glob `p*`, since `*` in the lattice's pattern language is
zero or more of any character, separators included; the prefix holds no `*`
or `?`, so no character of it is read as a wildcard (case 08 is the one that
does). The glob is the rendering the conformance harness requires for "one
repo, any branch", so the parser produces exactly `Glob("repo:acme/infra:*")`.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`startsWith`)
- internal/eval/glob.go (Glob: `*` crosses `/` and `:`)
