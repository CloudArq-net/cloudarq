# 13 — an errored plan

**Hand-written to the documented format** (format 1.2): one created role and the flags
`errored: true`, `complete: false`, `applyable: false`.

The format: "errored indicates whether planning failed. An errored plan cannot be applied, but
the actions planned before failure may help to understand the error." The role is read as any
created role is, and every grant carries one plan-incomplete anomaly, the errored sentence,
which subsumes the incomplete one: the document holds the actions planned before the
failure, and the rest are not stated.

Source: https://developer.hashicorp.com/terraform/internals/json-format (plan representation).
