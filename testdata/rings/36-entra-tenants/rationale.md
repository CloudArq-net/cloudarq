# 36 — Microsoft Entra ID: the personal-account tenant and a work tenant

A per-tenant issuer: an Entra issuer URL names its tenant, and the census matches the URL by its
pattern.

**Expected.**
- `PersonalMicrosoftAccounts` → **platform** (anyone with a Microsoft account), exact.
- `OneWorkTenant` → **platform**, unknown: who can join the work tenant is not established.

**Why.** The personal-account tenant is the one anyone with a Microsoft account signs in to, so the
census lists it as a tenant anyone can join, and a match on it never reads outsider.

A work tenant would be a named outsider only if a vendor sentence said the tenant's owner decides
who obtains tokens naming it. None does, and Microsoft's defaults say otherwise: every user, guests
included, can invite outsiders into the tenant, and every user can consent to another tenant's
application, which gives that application an identity in this one. The census therefore records the
work tenant's membership as unverified (census v0.2.0), and a tenant whose membership is not
established reads as the platform, unknown.

The row of the platform is exact, because the first grant admits the whole platform for certain. It
gives no reason: the reason the first grant is there, that anyone can join its tenant, is not the
second's.

> "For work and school accounts, the GUID is the immutable tenant ID of the organization that the user is signing in to. For sign-ins to the personal Microsoft account tenant (services like Xbox, Teams for Life, or Outlook), the value is 9188040d-6c67-4c5b-b112-36a304b66dad." — https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference · read 2026-09-23
> "By default, all users in your organization, including B2B collaboration guest users, can invite external users to B2B collaboration." — https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "By default, all users are allowed to consent to applications for permissions that don't require administrator consent." — https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent · read 2026-09-24 (recorded in the census, `tenant_membership`)
> "A multitenant application also has a service principal created in each tenant where a user from that tenant has consented to its use." — https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals · read 2026-09-24 (recorded in the census, `tenant_membership`)
