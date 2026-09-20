# 09 — the empty state

**Recorded**: `terraform show -json` in an initialised workspace with no state, Terraform
1.15.5, 2026-09-14, printed `{"format_version":"1.0"}` and nothing else (`scratchpad/unit-a/probe-empty`).

`ParseState` accepts it as a State with no resources, no unread types, no `terraform_version`,
and `Grants` states nothing. A caller must read that as "zero resources examined", never as
"no trust": `State.Resources` is the count to print. `ParsePlan` refuses the same document,
because none of the plan's members is present.
