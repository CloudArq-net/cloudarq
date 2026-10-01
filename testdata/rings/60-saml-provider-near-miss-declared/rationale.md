# 60 — a SAML provider one letter from the one declared

A trap: the user declared `CorpIdP`, and the policy trusts `CorpIdQ`.

**Expected.** `CorpIdQ` → **SAML sign-ins**, unknown, naming the provider
`arn:aws:iam::123456789012:saml-provider/CorpIdQ`, not declared. The declaration of `CorpIdP` is
echoed and said to move nothing. The ring of anyone holds no grant and is unknown beside the line, as
in case 20.

**Why.** A declaration names a SAML provider by its whole ARN, and a trust policy names the provider
the same way, so only the ARN declared moves a provider's sign-ins into *your people*: a provider
whose name is one letter away is another provider, and its sign-ins are placed as if nothing had been
declared.

> "SAML IDPs used in a role trust policy must be in the same account that the role is in." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html · read 2026-09-23
