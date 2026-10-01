# 01 — the default document: a branch pinned to an owner, and an owner prefix that is not one

The README shows this document. Every construct in it is modelled, so its rings carry no
Unknown.

**Expected.**
- `DeployFromMain` → **outsider**, exact: the owner `acme`, pinned by name, recyclable, not declared.
- `PreviewFromAcmeRepositories` → **platform** (anyone on GitHub), exact.

**Why.** `repo:acme/infra:ref:refs/heads/main` is an exact subject in GitHub's legacy form: after
the leading literal `repo:` the owner runs to the `/`, which no owner name can hold, so every token
that equals it was issued to a repository of the owner named `acme`. `repo:acme*` stops before the
delimiter: `acme-evil`, `acmex` and every other name that begins `acme` match it, and anyone with a
GitHub account can register one, so the prefix confines nobody. It was written to mean acme's
repositories; without the `/` it admits every owner whose name begins `acme`. IAM's save-time check
accepts it, because its value is not solely a wildcard.

A name can be released and taken by someone else, so the pin carries the recyclable fact; who holds
`acme` today is not read from the policy, and the ring does not answer it.

> "Syntax: `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Syntax: `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "To help prevent this scenario, repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Repositories created before July 15, 2026 keep the previous format unless you opt in to immutable subject claims." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "The `@` separator is used between names and IDs because `@` cannot appear in GitHub usernames or repository names." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
> "Usernames for user accounts on GitHub can only contain alphanumeric characters and dashes (`-`)." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication · read 2026-09-23
> "The GitHub organization name is required and must be alphanumeric including dashes (-)." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html (AWS's sentence; no GitHub page read states a character set for organisation names) · read 2026-09-23
> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-09-23
> "After changing your username, your old username becomes available for anyone else to claim." — https://docs.github.com/en/account-and-profile/concepts/username-changes · read 2026-09-23
> "After changing your organization's name, your old organization name becomes available for someone else to claim." — https://docs.github.com/en/organizations/managing-organization-settings/renaming-an-organization · read 2026-09-23
> "When GitHub's OIDC IdP is the trusted Principal for your role, IAM checks the role trust policy condition to verify that the condition key `token.actions.githubusercontent.com:sub` is present and that its value is not solely a wildcard character (* and ?) or null." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html · read 2026-09-23

Who a GitHub token is minted for is an account, by a chain of five sentences, which is why the
unpinned statement is the platform and not *anyone*:

> "Each job requests an OIDC token from GitHub's OIDC provider, which responds with an automatically generated JSON web token (JWT) that is unique for each workflow job where it is generated." — https://docs.github.com/en/actions/concepts/security/openid-connect · read 2026-09-23
> "Workflows are defined by a YAML file checked in to your repository and will run when triggered by an event in your repository, or they can be triggered manually, or at a defined schedule." — https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows · read 2026-09-23
> "The repository from where the workflow is running." — https://docs.github.com/en/actions/reference/security/oidc (`repository`) · read 2026-09-23
> "You can own repositories individually, or you can share ownership of repositories with other people in an organization." — https://docs.github.com/en/repositories/creating-and-managing-repositories/about-repositories · read 2026-09-23
> "Every person who uses GitHub signs in to a user account." — https://docs.github.com/en/get-started/learning-about-github/types-of-github-accounts · read 2026-09-23
