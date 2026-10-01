# 12 — the conformance corpus as Google providers

**Hand-written to the documented format** (format 1.2, from the corpus by a script, the values
copied out of `testdata/grants/*/gcp.json`): one
`google_iam_workload_identity_pool_provider.conformance["NN"]` per case, as a create plan, with
the shapes recorded in case 02: `oidc` a list of one object, `attribute_mapping` an object,
`attribute_condition` null for case 06, `name` and `state` unknown.

`TestDifferentialConformance` holds the reader's grant for each to what `gcp.ParseProvider`
makes of the corpus document: the built document lacks the corpus document's `name` and
`state`, which are unknown before apply and bear on nothing when `allowedAudiences` is set,
so the two readings must be the same set with the same anomalies. This is the test that a
builder mapping `oidc[0]` to `oidc`, the map to `attributeMapping` and the list to
`allowedAudiences` cannot pass by handing the string through.
