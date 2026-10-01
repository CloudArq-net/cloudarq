# 35 — a SAML provider the user declared

Declaring a SAML provider moves its sign-ins into *your people*.

**Expected.** `CompanySSO` → **people**, unknown: the provider
`arn:aws:iam::123456789012:saml-provider/VendorSSO`, declared. The ring of anyone holds no grant and
is unknown, as in case 20.

**Why.** The user declared the provider as `saml:arn:aws:iam::123456789012:saml-provider/VendorSSO`,
so its sign-ins are the user's people. Who the provider signs in is still set in its metadata,
which is not read, so the state stays unknown. A declaration moves where a population is placed, never
what is known of it: it says whose the provider is, not whom it signs in, so nothing read rules out
people with no account anywhere, and the ring of anyone is not established, declared or not.

> "SAML IDPs used in a role trust policy must be in the same account that the role is in." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html · read 2026-09-23
