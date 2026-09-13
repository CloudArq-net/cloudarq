# 07 — one repository, any branch, stated with ForAllValues

**Expected:** `{sub like "repo:acme/infra:*", repository_id = "456789"}`; AWS is the
`Expressive` provider, `Unknown` on `sub`, construct `ForAllValues:StringLike`.

**Why.** The AWS document writes the subject pattern under `ForAllValues:StringLike`.
AWS evaluates a `ForAllValues` condition as true when the key is absent from the request,
so on its own the operator does not pin anything; the case exists so that the AWS parser
does not read it as a plain `StringLike`. The reference set is the pattern conjoined with
the `repository_id` pin, and the harness relation for AWS is `WidensWithAnomaly`: the
parser must report `sub` as `Unknown` with a caveat and an anomaly naming
`ForAllValues:StringLike`, and the projection of everything except `sub` must equal the
reference. Azure and GCP have no such operator; their documents state the same intent
plainly (`matches` with `eq`; `startsWith` with `==`) and are judged `Equal`.

**Witnesses.** `main` and `dev` of the repository with the right id.

**Counters.** A look-alike repository with the right id; the right subject with a
different id. The witnesses and counters are checked against the reference set, never
against the widened AWS projection.
