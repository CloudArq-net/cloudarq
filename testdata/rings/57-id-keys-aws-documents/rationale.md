# 57 — GitHub's owner id, repository id and enterprise id, keys AWS documents

The vendor's own hardening must still pin: a condition on a key AWS documents for GitHub reads the
claim of the same name.

**Expected.**
- `OwnerByID` → **outsider**, exact: the owner `123456`, by id, not recyclable, not declared.
- `RepositoryByID` → **outsider**, exact: the repository `456789`, by id, not recyclable; a
  repository cannot be declared.
- `EnterpriseByID` → **outsider**, exact: the enterprise `123`, by id, recyclable; an enterprise
  cannot be declared.

**Why.** AWS's GitHub tab lists `repository_owner_id`, `repository_id` and `enterprise_id`, each
carrying the claim of its name (census v0.2.0), and the census records each as naming an
owner, a repository and an enterprise. GitHub recommends conditioning on the ids because they do not
change when a name does, and says the owner's and the repository's ids are immutable; of the
enterprise's id it says only that a slug change leaves it alone, which is less, so the enterprise's
id reads as recyclable (census v0.2.0).

> "This example template enables predictable OIDC claims with system-generated GUIDs that do not change between renames of entities (such as renaming a repository)." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23 (recorded in the census, `tenancy_claims`)
> "For repositories using immutable subject claims, the `sub` format includes immutable owner and repository IDs (not available on GitHub Enterprise Server)." — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23 (recorded in the census, `tenancy_claims`)
> "The enterprise ID, which can be used as an alternative to the slug in many cases, is not affected by a slug change." — https://docs.github.com/en/enterprise-cloud@latest/admin/managing-your-enterprise-account/changing-the-url-for-your-enterprise · read 2026-09-23 (recorded in the census, `tenancy_claims`)
> "AWS STS condition key IdP JWT claim Available in session actor actor No actor_id actor_id No job_workflow_ref job_workflow_ref No repository repository No repository_id repository_id No repository_owner_id repository_owner_id No workflow workflow No ref ref No environment environment No enterprise_id enterprise_id No" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
