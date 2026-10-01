# 38 — a subject led by the repository id

GitHub's customised repository form, recorded in census v0.2.0 with its repository part.

**Expected.** `RepositoryByID` → **outsider**, exact: the repository `456789`, by id, not
recyclable. It cannot be declared.

**Why.** A repository's admins can make the subject lead with its id, and `repository_id:456789:*`
closes the id with `:`, which no value in a subject holds, so every token admitted is one
repository's. The string does not name the repository's owner.

> "In your cloud provider's OIDC configuration, configure the `sub` condition to require a `repository_id` claim that matches the required value." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Any `:` within the metadata values will be replaced with `%3A` in the subject claim." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
