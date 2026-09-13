# 02 — the overlap cannot be proved either way, so the link is Indeterminate

The role admits `sub` like `repo:acme/*`; the application admits `sub` like `repo:acme-evil/*`
together with `repository_owner_id = 999999`. No string matches both patterns: the tenth
character is `/` in one and `-` in the other. The lattice cannot prove that. Its `Meet` of two
patterns is an intersection node whose `IsEmpty` answers false unless emptiness is proved
(`internal/eval/stringset.go`, `inter.IsEmpty`), so the overlap
`{repository_owner_id="999999", sub=(like:"repo:acme-evil/*" & like:"repo:acme/*")}` is not provably
empty, and spec property 3 says a pair that is not provably disjoint always has a link.

The witness walk finds no string both patterns match, and its negative answer is deliberately
not used to drop the pair: only a proof of emptiness drops a pair. So the link exists and is
`Indeterminate`, with the reason stating exactly what could not be done. `witness` renders as
`null`. Both records are conclusive and both grants exact, so nothing else is in doubt.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; no example identity could be constructed for identities from https://token.actions.githubusercontent.com with repository_owner_id 999999 and sub matching all of repo:acme-evil/* and repo:acme/*.

This is the honest direction. A lookalike organisation is precisely the pair a tool must not
report as "no relationship" on the strength of a heuristic; when the automata unit lands in
`eval` and proves the emptiness, this link will disappear because the proof exists, not because
the walk failed.
