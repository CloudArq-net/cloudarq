# 03 — a hand-written Azure plan: credentials on an application created in the same plan

**Hand-written to the documented format** (format 1.2), not recorded: the azuread provider
obtains a token at configure time ("building client: unable to obtain access token",
observed 2026-09-14 with placeholder credentials), so it cannot plan without a tenant. The
shapes follow the recorded Google plan of case 02, produced by the same plugin SDK, and the
azuread provider's schema at main (v3.9.0, 2026-06-18): `application_id` Required ForceNew,
`audiences` TypeList MaxItems 1 of string, `display_name`, `issuer`, `subject` Required
strings, `description` Optional, `credential_id` Computed; there is no expression argument,
so a flexible credential cannot be stated here. `azurerm_federated_identity_credential` has
`name`, `user_assigned_identity_id`, `audience` (a list), `issuer`, `subject`, all Required,
and an exported `id`.

**What the rendering must say, and why.**

- `existing` names an existing application: target `application /applications/6b1e...` as the
  attribute states it, and the credential builds to
  `{audiences, issuer, name, subject}`, which `azure.ParseFederatedCredential` reads to
  `{aud, sub}` exactly.
- `immutable` and `main` reference `azuread_application_registration.infra.id`, created in the
  same plan: `application_id` is unknown, the plan holds exactly one instance of the referenced
  resource, so both resolve to the target `application azuread_application_registration.infra`
  with the target-after-apply anomaly. Two credentials of one application are one target,
  which is what the join's struct equality on TargetRef needs; two distinct targets here would
  be a fan-out that does not exist.
- `unknown_subject` interpolates an unknown `client_id` into its subject: the grant admits
  everything, declared, naming `azuread_application_registration.infra.client_id`; the issuer
  is known and stated.
- `runner` is the managed identity's credential, target `userAssignedIdentity` named by
  `user_assigned_identity_id`.
- `azuread_application_registration.infra` is not in the table and not trust-shaped.
- The plan has no `prior_state`, as a fresh workspace's plan has, and is accepted.

Sources: https://raw.githubusercontent.com/hashicorp/terraform-provider-azuread/main/docs/resources/application_federated_identity_credential.md
and the resource's Go schema at
`internal/services/applications/application_federated_identity_credential_resource.go`
(fetched by the critic, `scratchpad/critic-a/azuread-fic.go`);
https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/main/website/docs/r/federated_identity_credential.html.markdown.

**A forgotten or deleted credential's target (2026-09-20).** The `before` object of a forget or
a delete states `application_id` in full, so a credential the plan stops managing resolves its
target from that value, never through the configuration's references, even when its `after`
would have been unknown; `TestTargetResolution` recorded and now pins this (see case 06's
rationale for the decision).
