# 27 — a Deny for `"*"` beside an Allow for one owner

A trap: a Deny for `"*"`, which subtracts nothing from an Allow's ring.

**Expected.**
- `AcmeRepositories` → **outsider**, exact: the owner `acme`, pinned by name, recyclable.
- the Deny's face with no issuer → **refused**.
- the Deny's AWS face (`aws:sts`) → **refused**.

**Why.** A Deny is in no ring and never subtracts from an Allow's: what it takes away is a set the
lattice cannot take away, and this one, a negated operator the parser does not model, is not applied
at all. The Allow's place is decided by the Allow alone, as if the Deny were not there, which can
only leave it where it is or further out.

> "Syntax: `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Syntax: `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "To help prevent this scenario, repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Repositories created before July 15, 2026 keep the previous format unless you opt in to immutable subject claims." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
