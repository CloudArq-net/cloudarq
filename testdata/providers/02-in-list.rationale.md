# 02 — membership of a literal list

Hand-written fixture, 2026-09-13.

## Document

`"attributeCondition": "assertion.repository in ['acme/infra', 'acme/web']"`.

## Expected

`{aud="…/providers/github", repository=("acme/infra" | "acme/web")}`, exact:
one Term whose `repository` claim is the union of the two values.

## Why

CEL's `in` on a list is membership; a string claim is in a list of string
literals exactly when it equals one of them. The union lives inside the one
Term, as the AWS parser renders a multi-valued `StringEquals`, so that the
same logical grant renders the same way from both providers; `A || B` on one
claim is a Join of Terms and renders as two Terms (case 06), which is a
different set to the lattice even where it admits the same tokens.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`in` on lists)
- internal/parse/aws/condition.go (valueSet: one StringSet per claim)
