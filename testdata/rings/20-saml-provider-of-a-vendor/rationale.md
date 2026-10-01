# 20 — a SAML provider named for a vendor

A trap: a SAML provider in the user's account that signs in a vendor's people.

**Expected.** `VendorSSO` → **SAML sign-ins**, unknown, naming the provider
`arn:aws:iam::123456789012:saml-provider/VendorSSO`, not declared. The ring of anyone holds no grant
and is unknown beside the line; its sentence says only that no grant is placed there.

**Why.** A trust policy names a SAML provider by its ARN; who the provider signs in is set in the
metadata uploaded to it, which the policy does not carry. A vendor's identity provider registered for
support access is the vendor's people, not the user's, so a SAML trust is never placed in *your
people* until the user declares the provider (case 35).

Nothing the policy carries says whom the provider signs in, so nothing read rules out people with no
account anywhere, and the ring of anyone is not established while the line holds the grant.

> "SAML IDPs used in a role trust policy must be in the same account that the role is in." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html · read 2026-09-23
> "Additionally, you must use AWS Identity and Access Management (IAM) to create a SAML provider entity in your AWS account that represents your identity provider. You must also create an IAM role that specifies this SAML provider in its trust policy." — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html · read 2026-09-23
