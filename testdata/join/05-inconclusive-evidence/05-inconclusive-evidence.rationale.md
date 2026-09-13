# 05 — inconclusive evidence cannot produce Established

Both grants pin `sub = repo:acme/infra:ref:refs/heads/main`, so the overlap is that identity and
a witness exists. The role's provenance holds two records: `iam:GetRole` with status `denied`,
and `iam:ListRoles` with status `ok`. `denied` is a fact, not an absence
(`internal/evidence/evidence.go`), and `Status.Conclusive()` is false for it, so spec property 4
applies: no link derived from this evidence may be `Established`.

The link is `Indeterminate` and the reason names the call, the target and the status, in
words. All three records stay in the provenance, sorted by API name
(`graph:federatedIdentityCredentials.list`, `iam:GetRole`, `iam:ListRoles`), because the denial
is part of the story a reader needs: which call to grant before the pair can be established.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; the call iam:GetRole for role arn:aws:iam::111111111111:role/deploy returned denied.
