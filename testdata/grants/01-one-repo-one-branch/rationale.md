# 01 — one repository, one branch

**Expected:** `{sub = "repo:acme/infra:ref:refs/heads/main"}`, exact, on every provider.

**Why.** GitHub issues `sub` as `repo:<owner>/<repo>:ref:refs/heads/<branch>` for a push
to a branch, so pinning `sub` to the whole string admits one branch of one repository and
nothing else. AWS states it with `StringEquals` on `token.actions.githubusercontent.com:sub`;
Azure with a classic credential whose `subject` is the string; GCP with
`assertion.sub == "..."` in the attribute condition. All three compare the whole string
byte for byte, so the three documents admit the same set and the harness judges each
parser's projection `Equal` to the reference (the GCP parser does not exist yet).

**Witnesses.** The pinned subject alone, and the pinned subject with a `repository_id`
claim: an extra claim the policy never mentions is unconstrained, not rejected.

**Counters.** The `dev` branch of the same repository; a look-alike organisation
(`acme-evil`); the immutable spelling of the same branch (`repo:acme@123456/infra@456789:...`),
which is a different string and so is not admitted by a name-based pin; and the empty
token, because a token without `sub` cannot satisfy a constraint on `sub`.
