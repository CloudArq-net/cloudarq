# 14 — a hand-written refresh-only plan: no changes listed, every resource in the prior state

**Hand-written to the documented format** (format 1.2), shaped after the refresh-only plan
recorded with the builtin provider on 2026-09-14 (`terraform plan -refresh-only -out=ro.tfplan`
then `terraform show -json ro.tfplan`, Terraform 1.15.5, `scratchpad/unit-a-fix/probe-forget/refresh-only.json`):
the top level holds `applyable: false`, `complete: true`, `configuration`, `errored: false`,
`format_version`, `planned_values` with an empty `root_module`, `prior_state`,
`terraform_version` and `timestamp`, and no `resource_changes` member at all; `prior_state`
lists every managed resource with fully known values ("Because the state is always fully
known, this is always complete"). The role values are what the AWS provider stores; the
`awscc_iam_role` and the data document are as case 04 and case 01 shape them.

**What the rendering must say, and why.**

- The plan lists no change, so a reader of `resource_changes` alone sees nothing, and a
  document with four roles in it prints as "no trust". Terraform's own reason for writing a
  no-op change for every resource it checks is to let "outside consumers of the plan
  distinguish between us affirming that we checked something and concluded no changes were
  needed vs. that something being entirely excluded e.g. due to -target"
  (`internal/terraform/node_resource_abstract_instance.go`, `planForget`, at v1.15.5); a
  resource in `prior_state` with no change listed for its address was excluded, not checked,
  and exists as the prior state holds it. `deploy`, `marked`, `counted[0]` and
  `module.ci.aws_iam_role.runner`, two of them counted or in a child module, are each read
  from the prior state with the no-change-listed anomaly, the prior-state origin sentence,
  `"from":"prior_state"` in the record's Params, and `arn` and `name`, both known in a
  state. `Plan.Resources` lists them with no actions.
- `marked` has `sensitive_values.assume_role_policy: true`: read and evaluated, the quote
  and the evidence redacted to the digest, as in a state.
- `awscc_iam_role.cc` is trust-shaped and unmapped: listed under `Unread` and named on
  every grant. `data.aws_iam_policy_document.doc` is kept for renderings and yields no
  grant; `aws_iam_openid_connect_provider.gh` is passed over.
- `complete: true` and `errored: false` add nothing; a targeted plan, which has the same
  shape for its untargeted resources with `complete: false`, is case 06.

Sources: https://developer.hashicorp.com/terraform/internals/json-format ("prior_state" is
"a representation of the state that the configuration is being applied to, using the state
representation described above"; "Because the state is always fully known, this is always
complete"); Terraform v1.15.5, `internal/terraform/node_resource_abstract_instance.go`
(`planForget`, the sentence on no-op changes and `-target`), read on 2026-09-14.
