# 08 — `"*"` on `sts:AssumeRoleWithSAML` alone

A trap: `"*"` on the SAML action alone is the role's own account's SAML providers, not anyone.

**Expected.**
- the face with no issuer → **SAML sign-ins**, unknown: every SAML provider in the role's own account.
- the AWS face (`aws:sts`) → **nobody**.

**Why.** AWS accepts SAML assertions only through a SAML provider in the role's own account, so the
face that admits every issuer admits, on this action, the account's own SAML providers, and who
each signs in is set in its metadata, which the policy does not carry. That is the SAML line beside
the rings, not *anyone*. No provider is named, so none can be declared.

> "SAML IDPs used in a role trust policy must be in the same account that the role is in." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html · read 2026-09-23
> "You can use a wildcard (*) to specify all principals in the `Principal` element of a resource-based policy or in condition keys that support principals." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
