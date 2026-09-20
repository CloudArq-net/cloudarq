# 04 — a hand-written AWS state: modules two deep, count instances, an absent policy, a mark, an unread type

**Hand-written to the documented format** (format 1.0), not recorded: a state with
`aws_iam_role` needs an apply against AWS. The shape follows the values representation the
format documents and the state recorded with the builtin provider
(`scratchpad/critic-a/probe/state.json`: `values.root_module.resources`, `child_modules[]`
each with `address`, `resources` and, recursively, `child_modules`; `index` on counted and
for_each instances). The role values are what the AWS provider stores: `assume_role_policy`
as `NormalizeJsonString` renders it, `arn`, `name`, `unique_id` known.

**What the rendering must say, and why.**

- `deploy`, `counted[0]`, `counted[1]`, `module.ci[0].aws_iam_role.runner["build"]`,
  `...["release"]`, `module.ci[1].aws_iam_role.runner["build"]` and
  `module.ci[1].module.inner.aws_iam_role.deep`, two modules down, each yield the parser's
  reading of the stored string (`TestDifferentialAWS`). A reader that did not recurse
  `child_modules` would lose four of them silently: "Each module object can optionally have
  its own nested child_modules, recursively describing the full module tree".
- `legacy` has no `assume_role_policy` key and `nulled` has it null. The state has no
  after_unknown, and the format says unknown and null are both "treated as absent or null";
  a required attribute absent or null is read as not stated, the grant admits everything with
  the absent-attribute anomaly, never "no trust policy".
- `marked` has `sensitive_values.assume_role_policy: true`: read and evaluated, the quote and
  the evidence redacted to the digest.
- `awscc_iam_role.cc` ends in `_iam_role`, a trust-bearing family the table does not map: it is
  listed under `Unread` and every grant carries the unread-resource anomaly naming the type,
  so the state is never read as holding exactly ten roles.
- `aws_iam_openid_connect_provider.gh` is passed over.
- Every record's Params carry `arn` and `name`, both known in a state; the origin sentence is
  the state one.

Source: https://developer.hashicorp.com/terraform/internals/json-format (values representation,
`child_modules`, `sensitive_values`).
