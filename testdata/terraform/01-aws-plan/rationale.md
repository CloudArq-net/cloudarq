# 01 — a recorded AWS plan: known, unknown, collapsed, rendered, deferred, counted, moduled, marked

**Recorded**, not written. Terraform v1.15.5, provider `hashicorp/aws` 6.64.0 (`.terraform.lock.hcl`
of the recording), 2026-09-14, from the configuration under
`scratchpad/unit-a/rec-aws` (`main.tf`, `provider.tf`, `ci/main.tf`, `cases/*.json` copied from
`testdata/grants/*/aws.json`), with `terraform init`, `terraform plan -out=plan.tfplan`,
`terraform show -json plan.tfplan > plan.json`. The provider block uses `access_key = "test"`
and the four `skip_*` flags, so no call reaches AWS and no key-shaped string sits in the file
(the earlier `tfexp` recording carried a placeholder access key of the shape
`scripts/preflight.sh` scans for, and is not reused). The provider cache was deleted the moment
the JSON was recorded.

**What the rendering must say, and why.**

- `known`, `heredoc`, `fromdoc`, `counted[0]`, `counted[1]`, `module.ci[*].aws_iam_role.runner[*]`
  carry `after.assume_role_policy`, the provider-normalised string (keys sorted, minified, as
  `NormalizeJsonString` renders it), so each reads to exactly what `aws.ParseTrustPolicy` makes
  of that string: `TestDifferentialAWS` compares the two byte for byte after stripping the
  reader's own anomalies. The heredoc's author text survives only in
  `configuration...constant_value`, which the reader does not quote.
- `collapsed`: the two `token.actions.githubusercontent.com:sub` keys of the `jsonencode`
  object constructor collapse to the last value before the provider sees anything (Terraform
  1.15.5, `product/B3-RESEARCH-2026-09-13.md` correction 3), so the plan string carries
  `"repo:*"` alone and the grant admits `sub=like:"repo:*"`: the narrower first value is gone
  and no text a plan reader holds can show it. Only the HCL reader (unit B) can.
- `unknown` references the OIDC provider created in the same plan. The format:
  "after_unknown is an object value with similar structure to after, but with all unknown
  leaf values replaced with true, and all known leaf values omitted" and "Any unknown values
  are omitted or set to null, making them indistinguishable from absent values". The string is
  absent from `after` and `after_unknown.assume_role_policy` is `true`; the grant admits
  everything, declared, and the sentence names `aws_iam_openid_connect_provider.gh.arn` and
  `local.sub` from `configuration`, with the implied step `aws_iam_openid_connect_provider.gh`
  dropped ("Multi-step references will be unwrapped and duplicated for each significant
  traversal step"). Checkov's CKV_AWS_393 passes this role.
- `transformed` is `replace(data.aws_iam_policy_document.doc.json, ...)` with an unknown
  replacement: the policy is unknown, the document is known and sits in `prior_state`. The
  rendering is attached as a second evidence record (`rendering_for`) with the
  `rendered-document` anomaly; it is not a Grant of its own, because a data document is not a
  target and the policy may differ from it.
- `deferred` is built from a data document whose principal is the unknown ARN: the data read
  is deferred, listed in `resource_changes` with `mode: "data"` and `after_unknown.json = true`
  (Terraform also writes `action_reason: read_because_config_unknown`, a display hint the
  reader does not key on). The sentence says the document is itself read only after apply.
- `marked` wraps its policy in `sensitive(...)`: the value is in `after` in clear and
  `after_sensitive.assume_role_policy` is `true`. The set is evaluated on the value, exact; the
  Source and the evidence carry the reader's statement with the value's SHA-256, never the
  value, as the format's purpose for the marks says.
- `conformance["01".."07"]` read the seven `testdata/grants` AWS documents through `file()`;
  the plan strings are the provider's normalisation of those files, and
  `TestDifferentialConformance` holds the reader to the parser's reading of the files
  themselves.
- Every grant carries `terraform-origin` with the plan sentence; `complete: true` and
  `errored: false` add nothing. The OIDC provider resource and the two data documents are not
  in the table and are not trust-shaped, so they yield nothing and are not listed as unread.

Sources: https://developer.hashicorp.com/terraform/internals/json-format (values, change and
configuration representations, fetched 2026-09-14);
https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/iam_role.html.markdown
(`assume_role_policy` Required; `arn`, `name` exported).
