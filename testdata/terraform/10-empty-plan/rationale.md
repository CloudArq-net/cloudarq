# 10 — the empty plan

**Recorded**: `terraform plan -out=p.tfplan` over an empty `main.tf` and `terraform show -json
p.tfplan`, Terraform 1.15.5, 2026-09-14 (`scratchpad/unit-a/probe-empty`). The output has
`planned_values`, `configuration`, `complete: true`, `errored: false` and no
`resource_changes` member at all.

`ParsePlan` accepts it: `resource_changes` absent is a plan with no changes, and `Grants` states
nothing, with `Plan.Resources` empty for the caller to say "zero resources examined".
`ParseState` refuses it, naming `planned_values` as the plan member it found.
