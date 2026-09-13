# 02 — one repository, any branch

**Expected:** `{sub like "repo:acme/infra:*"}`. AWS and GCP only; Azure is inexpressible.

**Why.** `StringLike` on AWS makes `*` match any run of characters including `/` and `:`,
so `repo:acme/infra:*` admits every `ref`, `environment` and `pull_request` subject of the
repository. GCP has no glob; `assertion.sub.startsWith("repo:acme/infra:")` admits the same
strings, so the GCP parser, once it exists (`internal/parse/gcp` is a placeholder today),
must project it to the same glob. Azure is declared inexpressible with the reason in
`internal/trust/conformance.go` (`azureNeedsAnImmutableClaim`): a classic credential matches
the subject exactly, and a flexible expression on `sub` must be combined with an immutable
claim, so "any branch of this repository, by name alone" cannot be written.

**Witnesses.** `main`, `dev`, and an environment subject of the same repository.

**Counters.** `repo:acme/infra-evil:...` and `repo:acme/infrastructure:...`: the pattern
ends in `infra:` before the star, so a repository whose name merely starts with `infra` is
outside it. The empty token.
