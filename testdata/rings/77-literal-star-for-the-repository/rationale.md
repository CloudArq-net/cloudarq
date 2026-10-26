# 77 — a star for the repository, under StringEquals

A trap: `repo:octo-org/*` written under `StringEquals` where `StringLike` was meant. It reads like
every repository of `octo-org`, and it is one subject spelled with a star.

**Expected.** `StarForTheRepositoryUnderStringEquals` → **outsider**, unknown: no farther out than
the owner `octo-org`, pinned by name, recyclable, as an upper bound. The grant carries the note
`wildcard-is-literal` on `sub`.

**Why.** `StringEquals` is exact matching, so the `*` is the character, not a wildcard, and the
grant admits only a token whose `sub` is the text `repo:octo-org/*`. That text fits the name form
GitHub prints, `repo:` and the owner's name, a `/`, then the repository's: the form reads its owner,
so whatever token carries it is `octo-org`'s, and the place is that owner's. The `*` stands where the
form reads a repository's name, and GitHub's rule for a repository's name allows no `*`, so whether
any token carries that subject is not read: the place is an upper bound, not exact, and the grant may
admit nobody. What the place does not say, the note does: the grant is not every repository of
`octo-org`, and a token matches only if its subject is that exact text.

> "Exact matching, case sensitive" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringEquals`) · read 2026-10-26
> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string. You must specify wildcards to achieve partial string matches." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-10-26
> "Previous format example: `repo:octo-org/octo-repo:ref:refs/heads/main`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-10-26
> "The repository name must not exceed 100 characters, and can only contain ASCII letters, digits, and the characters `.`, `-`, and `_`." — https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository · read 2026-10-26
