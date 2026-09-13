# 11 — an overlap that exists, but past the bound the example search gives up

The role constrains `sub` with four patterns at once, and the application with four more
(Azure's `claimsMatchingExpression` accepts several `matches` on one claim joined by `and`;
the AWS document is the parser's reading of an equivalent set of conditions). Each side's
`sub` is therefore the intersection of four patterns, and the overlap is the intersection of
eight:

`*:ref:refs/heads/*`, `*infra*`, `*main*`, `repo:*/infra:*`, `repo:*:ref:*`,
`repo:acme/*:ref:refs/heads/*`, `repo:acme/infra:*`, `repo:acme/infra:ref:refs/heads/*`.

A string matching all eight exists: `repo:acme/infra:ref:refs/heads/main`. The witness walk in
`internal/join/witness.go` finds it when allowed 126,481 states and not one fewer (measured on
this pair in canonical pattern order, 2026-09-13, as the smallest bound at which the walk
returns it). The walk is bounded at 65,536 states, because patterns of the shape
`*a*b*c*` make the search the shortest common supersequence problem, which is NP-hard in the
number of patterns, and a pure function over customer patterns must return. Past the bound the
walk gives up, and giving up is not a decision: the overlap is not provably empty (`inter.IsEmpty`
in `internal/eval/stringset.go` never claims emptiness), so the pair is a link, `Indeterminate`,
whose reason says that no example could be constructed. `witness` renders as `null`.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; no example identity could be constructed for identities from https://token.actions.githubusercontent.com with sub matching all of *:ref:refs/heads/*, *infra*, *main* and 5 more patterns.

The sentence names three of the eight patterns and counts the rest (compare case 16: a list
longer than four members is abbreviated so that the sentence stays one); `overlap` holds all
eight.

This is the honest direction, and the same sentence a pair with no common string gets (case 02):
the walk's negative answer is never printed as a fact, because it is not always one. Raising the
bound would turn this link `Established` with the example above; removing it would let a
six-pattern `*x*x*…` shape run for minutes. Both are choices the case pins.
