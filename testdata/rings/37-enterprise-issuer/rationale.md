# 37 — GitHub's per-enterprise issuer

GitHub's enterprise path, matched by its pattern beside the shared entry.

**Expected.** `EnterpriseIssuer` → **outsider**, exact: the tenant `acme-ent`, the enterprise, by
name, recyclable, not declared.

**Why.** An enterprise can have its tokens issued from a URL of its own, and GitHub says that ensures
only the enterprise's repositories can use them, so census v0.2.0 records the path's `tenant_membership` as
controlled. The slug is a name GitHub hands to another customer after a change, so the tenant is
recyclable.

> "This configuration means that your enterprise will receive the OIDC token from a unique URL, and you can then configure your cloud provider to only accept tokens from that URL. This helps ensure that only the enterprise's repositories can access your cloud resources using OIDC." — https://docs.github.com/en/enterprise-cloud@latest/actions/reference/security/oidc · read 2026-09-23
> "When you change the slug, GitHub does not set up any redirects from the old URL. Your old enterprise slug will immediately become available for another customer to use." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-your-enterprise-account/changing-the-url-for-your-enterprise · read 2026-09-23
