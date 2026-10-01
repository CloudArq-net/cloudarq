# 32 — the default document with `github:acme` declared

The default document's one question, *is acme yours?*, answered yes.

**Expected.**
- `DeployFromMain` → **yours**, exact: the owner `acme`, pinned by name, recyclable, declared.
- `PreviewFromAcmeRepositories` → **platform** (anyone on GitHub), exact: declaring moves nothing it
  pins nobody to.

**Why.** Declaring an owner moves a grant pinned to it from outsider to yours, and can never move
anything outward or out of the rings. The owner declared and the owner pinned are the same
namespace, scope and kind, and their names are spelled alike. The second statement shows what
declaring cannot do: `repo:acme*` still admits every name that begins `acme`.

> "Syntax: `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Syntax: `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "To help prevent this scenario, repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Repositories created before July 15, 2026 keep the previous format unless you opt in to immutable subject claims." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
