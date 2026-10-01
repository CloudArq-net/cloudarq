# 02 — the immutable form, the owner's name and id both written

**Expected.** `OwnerByNameAndID` → **outsider**, exact: the owner with id `123456`, named `acme`,
pinned by id, not recyclable.

**Why.** `repo:acme@123456/*` runs through both owner parts of GitHub's immutable form: the name up
to `@` and the id up to `/`. The pin goes through the deepest part it runs through, so it is the
id, which is never reused. A re-registered `acme` has another id and is not admitted; a legacy
token of `acme` has no id and is not admitted either.

> "Syntax: `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Syntax: `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "To help prevent this scenario, repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Repositories created before July 15, 2026 keep the previous format unless you opt in to immutable subject claims." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "For repositories using immutable subject claims, the `sub` format includes immutable owner and repository IDs (not available on GitHub Enterprise Server)." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
