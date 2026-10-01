# 28 — an empty prefix

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub.startsWith('')`.

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on
`sub`, an `unmodelled-construct` anomaly whose Construct is `startsWith`.

## Why

Every string starts with the empty string, but `assertion.sub` on a
credential with no `sub` is an evaluation error, and an error is a
rejection: the clause is a presence test. The pattern `*` would normalise to
Any and drop out of the Term, reading "present, any value" as "absent
passes"; that is wider than Google, and undeclared. The AWS parser meets the
same shape in a StringLike of stars and makes it Unknown for the same
reason, so this one does too, and the same rule applies to `endsWith('')`
and `contains('')`.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (no_such_field is a runtime error; errors are rejections)
- internal/parse/aws/condition.go (valueSet: "Presence is not a set of values")
