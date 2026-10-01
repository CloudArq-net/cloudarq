# 41 — a union of three owners' prefixes

The union rule, where every member pins.

**Expected.** `ThreeOwners` → **outsider**, exact: the owners `acme`, `beta` and `gamma`, each pinned
by name, recyclable, none declared.

**Why.** A list of values under `StringLike` admits a token matching any one of them, and each member
here runs through the legacy form's owner and its `/`, so every token admitted belongs to one of the
three owners. A union pins only when every member pins, and then to all their owners (case 30 is the
same union with one member open). Declaring one of the three moves nothing: the grant is yours only
when all three are declared.

> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-09-23
> "Syntax: `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Syntax: `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "To help prevent this scenario, repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Repositories created before July 15, 2026 keep the previous format unless you opt in to immutable subject claims." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
