# 02 — a recorded Google plan: providers with oidc and aws, nested unknowns, bindings

**Recorded**, not written. Terraform v1.15.5, provider `hashicorp/google` 8.2.0, 2026-09-14,
from `scratchpad/unit-a/rec-google/main.tf` with `terraform init`, `terraform plan
-out=plan.tfplan`, `terraform show -json plan.tfplan > plan.json`. The provider block carries
`access_token = "placeholder"`, which the provider never presents because a plan of creates
reads nothing; the provider cache was deleted the moment the JSON was recorded. The plan
records the SDK's shapes: `oidc`, `aws`, `saml`, `x509` and `condition` are lists of at most
one object, `attribute_mapping` an object, `disabled` null when unset, `name` and `state`
unknown on every create.

**What the rendering must say, and why.**

- `known` builds to the API document `{attributeCondition, attributeMapping, displayName,
  oidc{allowedAudiences, issuerUri}}` in canonical form and reads to what `gcp.ParseProvider`
  makes of it (pinned in `TestBuiltDocumentsAreCanonical`; the conformance plan in case 12 is
  compared with the API documents). `name` and `state` are unknown and left out; nothing is
  derived from `id`, `project` or the pool id, because `name` carries the project number and
  a derived default audience would be one no token has (Google: `name` is
  `projects/{project_number}/...`; `id` is `projects/{{project}}/...`).
- `aws` builds to `{aws: {accountId}}`, issuer `aws:sts`, the AWS parser's pseudo-issuer.
- `disabled` has `disabled: true` and no audiences: the parser's own doubts, provider-disabled
  and the underivable default audience, both caveats.
- `nested_unknown`: `attribute_mapping` is wholly unknown (the SDK marks the map, not the
  entry) and `oidc[0].allowed_audiences` is unknown beside a known `issuer_uri`. The marks
  sit one level down; the reader finds them beneath the attribute and widens the whole grant,
  naming both paths and `google_iam_workload_identity_pool.github.name`, with the issuer still
  stated from the known `issuer_uri`. A reader that tested only the top-level boolean would
  hand the parser a document with no mapping and one audience, and read the whole pool as
  admitted with no doubt.
- `unknown_condition`: `attribute_condition` unknown; Google reads an absent condition as
  "all valid authentication credential are accepted", so the reader never hands a partial
  document to the parser and widens instead.
- The bindings. Every provider is nameless before apply, so the parser cannot place a member's
  pool; the reader meets a member with every provider whose `workload_identity_pool_id` is the
  member's pool id (`github`), never with the `aws-prod` provider, and the parser states the
  doubt on each. A provider that could not be read binds as everything with its own reason.
  `user:alice@acme.example` and `serviceAccount:deploy@...` are not pool principals and yield
  the unbound-member grant. `google_service_account_iam_member.deploy` has an unknown
  `service_account_id` referencing `google_service_account.deploy`, which the plan holds once,
  so its target is that address (target-after-apply). `policy_data` is the JSON string
  `data.google_iam_policy` renders (`json.Marshal` of a `cloudresourcemanager.Policy`, verified
  in the provider's `data_source_google_iam_policy.go`), handed to `gcp.ParseMembers` verbatim.

Sources: https://raw.githubusercontent.com/hashicorp/terraform-provider-google/main/website/docs/r/iam_workload_identity_pool_provider.html.markdown
(`attribute_condition`: "If unspecified, all valid authentication credential are accepted";
`name` and `state` computed; `id` format); the same repository's
`google_service_account_iam.html.markdown` (`service_account_id`, `member`, `members`,
`policy_data`, `condition`) and `google/services/resourcemanager/data_source_google_iam_policy.go`.
