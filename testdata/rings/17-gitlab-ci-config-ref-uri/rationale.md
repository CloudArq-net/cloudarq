# 17 — GitLab's `ci_config_ref_uri` pinned

A trap: GitLab's `ci_config_ref_uri` names a pipeline definition, not a tenant.

**Expected.** `GitLabPipelineDefinition` → **anyone**, unknown.

**Why.** GitLab.com's claims are not read: the parser knows the claim vocabulary of no issuer
but GitHub, so every condition on a `gitlab.com:` key is Unknown, and census v0.2.0 records
GitLab.com with `anonymous_tokens` alone. The research found no chain of GitLab sentences that
rules out tokens for people with no account, so the census writes it `unverified`, and an
unverified fact reads as *anyone*, unknown.

**What the case guards.** `ci_config_ref_uri` pins no tenant however its claim is read: it names
a pipeline definition, and GitLab documents it as null whenever the definition lives in another
project, so the census records it as naming none. That is sound and imprecise.

> "This claim is null unless the pipeline definition is located in the same project." — https://docs.gitlab.com/ci/secrets/id_token_authentication/ · read 2026-09-23
> "Subject of the token (“subject” claim). Defaults to project_path:{group}/{project}:ref_type:{type}:ref:{branch_name}. Can be configured for the project with the projects API." — https://docs.gitlab.com/ci/secrets/id_token_authentication/ · read 2026-09-23
