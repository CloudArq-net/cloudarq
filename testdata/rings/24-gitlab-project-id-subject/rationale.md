# 24 — a GitLab subject led by the project id

A trap: a GitLab subject led by the project's id, which names a tenant the string does not.

**Expected.** `GitLabProjectByID` → **anyone**, unknown.

**Why.** GitLab.com's claims are not read: the parser knows the claim vocabulary of no issuer
but GitHub, so every condition on a `gitlab.com:` key is Unknown, and census v0.2.0 records
GitLab.com with `anonymous_tokens` alone. The research found no chain of GitLab sentences that
rules out tokens for people with no account, so the census writes it `unverified`, and an
unverified fact reads as *anyone*, unknown.

**What the case guards.** Read as a subject, one led by `project_id:<id>:` names one project, a
tenant the string does not name, and `project_id:4815162342:*` closes the id with its `:`.

> "Accepts an array starting with project_path or project_id." — https://docs.gitlab.com/api/projects/ (`ci_id_token_sub_claim_components`) · read 2026-09-23
> "Subject of the token (“subject” claim). Defaults to project_path:{group}/{project}:ref_type:{type}:ref:{branch_name}. Can be configured for the project with the projects API." — https://docs.gitlab.com/ci/secrets/id_token_authentication/ · read 2026-09-23
