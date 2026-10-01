# 26 — a question mark inside the owner

A trap: `repo:acm?/*`, where `?` ends the literal prefix as `*` does.

**Expected.** `OneCharacterOfTheOwnerOpen` → **platform** (anyone on GitHub), exact.

**Why.** `?` stands for any one character, so it ends the literal prefix as `*` does: the prefix is
`repo:acm`, which does not reach the owner's `/`. `acme`, `acmx` and every other four-letter name
beginning `acm` match, and anyone can register one.

> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
