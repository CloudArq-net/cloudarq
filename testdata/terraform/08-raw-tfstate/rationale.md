# 08 — a raw terraform.tfstate is refused

**Recorded**: the `terraform.tfstate` written by `terraform apply` with the builtin provider
on 2026-09-13 (`scratchpad/b3/source-vs-deployed/tfdemo`, Terraform 1.15.5), copied verbatim
under the `.json` name the corpus loader looks for. It carries `version: 4`, `serial`,
`lineage` and `resources[].instances`, the shape only the state file has.

Both readers refuse it with "this is a raw state file; run terraform show -json and pass its
output", before reading any of it: the state file carries every sensitive value of every
resource in clear ("Terraform still stores the values of sensitive variables in your state"),
and the product never opens it. `terraform show -json` output has `format_version` and
`values` instead, and a document is told from the other by these marks alone.

Source: https://developer.hashicorp.com/terraform/language/values/variables (sensitive values
in state); the Pass 1 binding decision 1.
