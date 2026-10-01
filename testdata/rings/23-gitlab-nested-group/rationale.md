# 23 — a GitLab subgroup in the subject

A trap: a GitLab subgroup, which a declared group covers and which never covers its parent.

**Expected.** `GitLabSubgroup` → **anyone**, unknown.

**Why.** GitLab.com's claims are not read: the parser knows the claim vocabulary of no issuer
but GitHub, so every condition on a `gitlab.com:` key is Unknown, and census v0.2.0 records
GitLab.com with `anonymous_tokens` alone. The research found no chain of GitLab sentences that
rules out tokens for people with no account, so the census writes it `unverified`, and an
unverified fact reads as *anyone*, unknown.

**What the case guards.** Read as a subject, `project_path:acme/platform/*` pins the top-level
group `acme` at most: a declared `acme` covers its subgroups, never the reverse, and never a
sibling that shares a prefix.

> "Subject of the token (“subject” claim). Defaults to project_path:{group}/{project}:ref_type:{type}:ref:{branch_name}. Can be configured for the project with the projects API." — https://docs.gitlab.com/ci/secrets/id_token_authentication/ · read 2026-09-23
