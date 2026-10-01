# 28 — a grant that admits nobody

A trap: a grant that admits no token, which is in no ring at all.

**Expected.** `WrongAction` → **nobody**.

**Why.** A GitHub token assumes a role through `sts:AssumeRoleWithWebIdentity`, and the statement
grants only `sts:AssumeRole`, so it lets nobody in through this principal, whatever its conditions
say. A grant that provably admits no token is in no ring: *nobody* is not the innermost ring, it is
no ring at all.

> "Use this principal type in your role trust policy to allow or deny permissions to call `AssumeRoleWIthWebIdentity` using an OIDC IDP that exists in your AWS account, or one of the four built in IDPs." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (the vendor's spelling) · read 2026-09-23
