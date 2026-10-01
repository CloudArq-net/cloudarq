# 62 — A pattern on GitHub's `repository` claim that closes the owner's name

A trap: `acme/*` on `repository` reads like a pattern that pins nothing, and it confines the tokens
to one owner.

**Expected.** `AnyRepositoryOfAcme` → **platform**, unknown. Never platform, exact.

**Why.** GitHub writes `repository` as the owner's name, a `/`, and the repository's name, and a
name holds no `/`, so every value `acme/*` admits belongs to the owner `acme`: the same population
as `repo:acme/*` on `sub`, which reads as a named outsider. The census records `repository` as a
claim naming a repository, not how its value is composed, so the engine cannot read the pattern for
an owner. Reading it as pinning nothing would place the grant with anyone on GitHub, exactly, and
say no condition confines its tokens to one owner, which is false. The pattern is read as not read:
the platform, unknown, which is where the grant may be and no nearer.

> "repository" : "my-org/my-repo" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-26
> "The @ separator is used between names and IDs because @ cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-26
