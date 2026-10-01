# 33 — the default document with `github:Acme` declared

A trap: an owner declared in another letter case than the one pinned.

**Expected.**
- `DeployFromMain` → **outsider**, exact: the owner `acme`, not declared.
- `PreviewFromAcmeRepositories` → **platform**, exact.

**Why.** Names compare exactly unless the census records a vendor sentence that GitHub's names are
unique regardless of case, and no GitHub page read says so. The REST reference's sentence below
describes a path parameter the API resolves, not the namespace. Comparing exactly can only leave a
declared owner unmatched, which keeps the grant outward.

> "The organization name. The name is not case sensitive." — https://docs.github.com/en/rest/actions/oidc · read 2026-09-23
