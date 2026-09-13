# 03 — a whole organisation, pinned by its immutable id

**Expected:** `{sub like "repo:acme/*", repository_owner_id = "123456"}` on every provider.

**Why.** `repo:acme/*` alone would admit any repository whose owner is spelled `acme`,
including a namespace registered by someone else after a rename. Pinning
`repository_owner_id` to the organisation's numeric id closes that: GitHub assigns the id
once and never reuses it. AWS states the pair with `StringLike` and `StringEquals` in one
statement, which is a conjunction; Azure with a flexible expression
`claims['sub'] matches 'repo:acme/*' and claims['repository_owner_id'] eq '123456'`;
GCP with `startsWith` and `==` joined by `&&`. Each is one Term with two constraints.

**Witnesses.** A branch and an environment subject under `acme`, each carrying the owner
id.

**Counters.** `acme-evil` and `acmeco` with the right owner id (the glob is anchored at
`acme/`); the right subject with a different owner id; and the right subject with no
owner id at all, because a constrained claim that the token does not carry fails.
