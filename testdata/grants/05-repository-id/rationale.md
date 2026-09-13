# 05 — constrained on repository_id, not on sub

**Expected:** `{repository_id = "456789"}` on every provider, with `sub` unconstrained.

**Why.** A policy that pins only the immutable `repository_id` admits every ref,
environment and pull request of that repository under any name it is ever given, which
is the durable way to trust one repository. AWS states it with `StringEquals` on
`token.actions.githubusercontent.com:repository_id` and no condition on `sub`. GCP states
it as `assertion.repository_id == "456789"`. Azure's flexible language requires an
expression on `sub`, so the document uses `claims['sub'] matches '*'`, which admits
every subject and normalises away, leaving the same set; the Azure parser records an
informational anomaly that Microsoft does not document whether such a credential is
accepted, and no caveat, because the set is exact either way.

**Witnesses.** The repository id with the `main` subject, and the same id under a renamed
and moved repository: the rename changes `sub` and the policy does not care.

**Counters.** A different repository id with the right subject; the right subject with no
repository id.
