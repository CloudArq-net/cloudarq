# 05 — a hand-written Google state: named providers, bindings placed by pool, an unbound pool

**Hand-written to the documented format** (format 1.0): the values are what the recorded plan
of case 02 shows for the same resource types, with the computed `name`, `state`, `id` and
`etag` filled as the API returns them (`name` with the project number, as Google documents).

**What the rendering must say, and why.**

- `google_iam_workload_identity_pool_provider.github` has a name of the API's form and no
  audiences (`allowed_audiences: []`, which Terraform writes for an unset list in a state; the
  reader reads it as absent, Google's "If this list is empty, the OIDC token audience must be
  equal to the full canonical resource name"), so the parser derives the two forms of the
  default audience as a fact, not a doubt. `gitlab` names its audience.
- `google_service_account_iam_member.deploy` selects `attribute.repository/acme/infra` of the
  `github` pool: bound to the `github` provider only (`TestDifferentialState` compares the
  bound grant with `Provider.Bind` over the built documents); the `gitlab` provider is of
  another pool id and is never asked.
- `google_service_account_iam_binding.ci` binds a subject principal of the `github` pool, with
  a condition the parser does not evaluate (its doubt), and `user:alice@acme.example`, which is
  no pool principal: the unbound-member grant.
- `google_service_account_iam_policy.release` holds two members in its `policy_data`: one of
  the `gitlab` pool, bound to the gitlab provider exactly, and one of a `legacy` pool no
  provider in the document serves, which yields the unbound-member grant naming the pool.
- `google_iam_workforce_pool_provider.staff` contains `pool_provider`, a family the table does
  not map: listed as unread and named on every grant.
- `google_service_account.deploy` is passed over.

Sources: as case 02, and https://developer.hashicorp.com/terraform/internals/json-format.
