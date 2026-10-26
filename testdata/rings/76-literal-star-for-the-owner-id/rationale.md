# 76 — a star for the owner's id, under StringEquals

A trap: `repo:octo-org@*/*` written under `StringEquals` where `StringLike` was meant. It reads like
case 03's pattern, and it is one subject spelled with a star.

**Expected.** `StarForTheOwnerIDUnderStringEquals` → **outsider**, unknown: no farther out than the
owner `octo-org`, pinned by name, recyclable, as an upper bound. Never platform, exact. The grant
carries the note `wildcard-is-literal` on `sub`.

**Why.** `StringEquals` is exact matching, so each `*` in the value is the character, not a
wildcard, and the grant admits only a token whose `sub` is the text `repo:octo-org@*/*`. That text
fits neither subject form GitHub prints: in the immutable form an id follows each `@`, and no form
the engine reads takes a `*` there. Read whole, the value would pin nobody and land with anyone on
GitHub, exactly, which is wider than the same text under `StringLike`, a pattern that admits it
among others, and says no condition confines the tokens to one owner, which is false. It is read as
a bound instead: the one subject it admits begins with its literal prefix `repo:octo-org@`, and the
`@` closes the owner's name, so whatever token carries it is `octo-org`'s. Whether GitHub ever mints
a token with that subject is not read, so the place is not exact, and the grant may admit nobody.

> "Exact matching, case sensitive" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringEquals`) · read 2026-10-26
> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string. You must specify wildcards to achieve partial string matches." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-10-26
> "Immutable format example: `repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-10-26
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-10-26
