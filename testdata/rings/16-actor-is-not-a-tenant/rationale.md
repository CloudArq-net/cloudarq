# 16 — `actor_id` pinned, the repository left open

A trap: `actor_id` names the person who started a run, not a tenant.

**Expected.** `OneActorAnyRepository` → **platform** (anyone on GitHub), exact.

**Why.** `actor_id` names the person who started the run, not the owner of the repository the token
is minted for. Anyone who owns a repository can hold a token whose actor is someone who starred,
forked or commented on it, and a re-run keeps the original actor, so an actor pin confines nobody.
Only owners, repositories and enterprises are tenants; `actor` and `actor_id` are recorded as
naming none. `repo:*` pins nothing either: its literal prefix stops at the leading literal.

> "The personal account that initiated the workflow run." — https://docs.github.com/en/actions/reference/security/oidc (`actor`) · read 2026-09-23
> "The ID of personal account that initiated the workflow run." — https://docs.github.com/en/actions/reference/security/oidc (`actor_id`) · read 2026-09-23
> "Any workflow re-runs will use the privileges of `github.actor`, even if the actor initiating the re-run (`github.triggering_actor`) has different privileges." — https://docs.github.com/en/actions/reference/workflows-and-actions/contexts · read 2026-09-23
