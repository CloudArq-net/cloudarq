# 39 — subjects led by the owner, by name and by id

GitHub's customised owner forms.

**Expected.**
- `OwnerLedByName` → **outsider**, exact: the owner `acme`, pinned by name, recyclable.
- `OwnerLedByID` → **outsider**, exact: the owner with id `123456`, pinned by id, not recyclable.

**Why.** `repository_owner:acme` is complete: the value ends where the name does, and `:` cannot
occur inside a value. `repository_owner_id:123456:*` closes the id with `:`.

> "For example: `"sub": "repository_owner:monalisa"`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "In your cloud provider's OIDC configuration, configure the `sub` condition to require a `repository_owner_id` claim that matches the required value." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Any `:` within the metadata values will be replaced with `%3A` in the subject claim." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
