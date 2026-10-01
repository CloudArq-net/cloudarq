# 06 — a hand-written targeted plan: no-op, delete, a deposed object, replace, update with an unknown, forget, a replace that forgets, an untargeted resource, a policy with no statement

**Hand-written to the documented format** (format 1.2), shaped after the actions recorded with
the builtin provider on 2026-09-14 (a plan of the actions below, a destroy plan, a plan that
forgets and a targeted plan): a
delete has `after: null`, `after_unknown: {}` and `after_sensitive: false`; a no-op repeats
`before` as `after`; an update whose attribute is unknown omits it from `after` and marks it;
a replace is `["delete", "create"]` with `replace_paths`; a `removed` block with
`destroy = false` plans `["forget"]` with `before` full, `after: null`, `after_unknown: {}`,
`after_sensitive: false` and `action_reason: delete_because_no_resource_config`, and the
resource stays in `planned_values` with `sensitive_values: false` and no values; a targeted
plan is `complete: false`, lists only its targets in `resource_changes`, and holds every
resource in `prior_state`.

**What the rendering must say, and why.**

- `kept` (no-op) and `replaced` (replace, read from `after`, the v2 policy) read exactly.
- `old` (delete) has no `after`: "For ["create"] and ["delete"] actions, either "before" or
  "after" is unset (respectively)". The grant is read from `before`, what the prior state
  holds, with the planned-delete anomaly and the prior-state origin sentence, so that a
  destroy plan does not print as a clean verdict. The second `old` entry is a deposed object
  (`deposed: "deadbeef"`), read the same way and named by its key in the evidence Params.
- `rotated` (update) marks `assume_role_policy` unknown: everything, declared, naming
  `aws_iam_openid_connect_provider.gh.arn`.
- `forgotten` (forget) is read from `before`, as a delete is, with the planned-forget anomaly
  and the prior-state origin sentence: Terraform's plan output for the recorded forget says
  the object "will no longer be managed by Terraform, but will not be destroyed", and its
  warning "If you apply this plan, Terraform will discard its tracking information for the
  following objects, but it will not delete them", so the role and its trust continue to
  exist after apply, unmanaged. A reader that took `after` alone would report the policy as
  unset, an over-approximation with a false reason, or as absent, an under-approximation.
- `reborn` (`["create", "forget"]`) is a replace whose prior object is forgotten rather than
  destroyed: two objects exist once the plan is applied, and both are read, the created one
  from `after` first and the forgotten one from `before` with the planned-forget anomaly;
  the listing holds one resource. Terraform 1.15.5 lists this action pair as valid in
  `internal/command/jsonplan/plan.go` but its core plans it nowhere; at `main`
  (2026-09-09) a replace of a resource with `lifecycle { destroy = false }` plans it, and
  `["forget", "create"]` too, so the reader keys on the word `forget` rather than on the
  pair. The documented format page lists neither action.
- `hollow` (create) carries `{"Statement":[],"Version":"2012-10-17"}`: the AWS parser
  projects no statement and says "Statement is an empty list, so the document grants
  nothing", and the reader states one grant admitting nothing, exactly, with that sentence
  beside its own, so that the role is not silence. Whether IAM accepts an empty Statement
  list at CreateRole was not checked; a refused document leaves no role, an accepted one
  admits nobody, and the reading holds either way.
- `untargeted` is in `prior_state` alone: the plan lists no change for it, as a targeted plan
  lists only its targets (recorded: `terraform plan -target=terraform_data.kept` leaves
  `terraform_data.role` out of `resource_changes` and in `prior_state`). It is read from the
  prior state with the no-change-listed anomaly and `"from":"prior_state"`; case 14 is the
  refresh-only plan, where every resource is in that position.
- `complete: false` puts the plan-incomplete anomaly on every grant: "complete indicates that
  Terraform expects that after applying this plan the actual state will match the desired
  state"; resources a targeted plan does not list are not absent, and the grants are a lower
  bound.

Sources: https://developer.hashicorp.com/terraform/internals/json-format (plan representation,
`complete`, `deposed`, change representation, "prior_state");
https://developer.hashicorp.com/terraform/language/block/removed ("Set `destroy` to `false` to
remove the resource from state without destroying the actual resource"); Terraform v1.15.5
and `main` @ 2026-09-09, `internal/command/jsonplan/plan.go` (the actions list, with
`["forget"]` and `["create", "forget"]`, and "For ["create"] and ["delete"]/["forget"]
actions, either "before" or "after" is unset (respectively)"),
`internal/terraform/node_resource_abstract_instance.go` (`planForget` at v1.15.5;
`resourceLifecycleForget` and the replace cases at `main`), `internal/terraform/context_plan.go`
(the warning), read on 2026-09-14.

**What a forget reads.** The object a forget reads is `before`, the prior state's record of the
resource. The format has no `before_unknown`, because a value Terraform has already recorded is
known by construction, and the reader reads unknowns from `after_unknown` only. So a forgotten
(or deleted, or unlisted) object is read whole and exact whatever its `after` would have been;
the sensitive mark still applies, from `before_sensitive`, and the value is evaluated and
redacted as `forgotten` above shows. The same rule decides a forgotten credential's target: the
`before` object states `application_id`, and the reader takes the attribute's value when the
document states it, so the target is that value and no `target-after-apply` anomaly is stated.
`TestUnknownBeforeAfter` draws a forget and a create-forget on every run, as its guard counts,
and `TestTargetResolution` draws the same actions for a credential's target.
