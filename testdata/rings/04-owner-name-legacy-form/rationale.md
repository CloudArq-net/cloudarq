# 04 — the legacy form's owner prefix

**Expected.** `OwnerNameLegacyForm` → **outsider**, exact: the owner `acme`, pinned by name,
recyclable.

**Why.** `repo:acme/*` runs through the legacy form's owner part and its `/`. It matches no
immutable-form token of `acme`, whose owner name ends at `@`: for repositories created, renamed or
transferred since 15 July 2026 it fails closed, which narrows who gets in and never widens it.

> "Syntax: `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Syntax: `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "To help prevent this scenario, repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Repositories created before July 15, 2026 keep the previous format unless you opt in to immutable subject claims." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
> "After changing your username, your old username becomes available for anyone else to claim." — https://docs.github.com/en/account-and-profile/concepts/username-changes · read 2026-09-23
> "After changing your organization's name, your old organization name becomes available for someone else to claim." — https://docs.github.com/en/organizations/managing-organization-settings/renaming-an-organization · read 2026-09-23
