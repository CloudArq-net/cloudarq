# 10 — two roles proved by one response carry it once

One `iam:ListRoles` call returns every role in the account with its trust policy (IAM API
Reference, *ListRoles*: each `Role` carries `AssumeRolePolicyDocument`), and the collector
attaches that one response to each role's grant. The role `deploy` admits `sub` like
`repo:acme/*:ref:refs/heads/main`; the role `release` admits `sub` like `repo:acme/infra:*`; both
from the GitHub Actions issuer with the AWS audience.

Two roles in one account are two targets, and a pair. The package knows no cloud and no account,
by design (`internal/trust/grant.go`: nothing downstream of the model knows which cloud a Grant
came from), so the invariant the constructor enforces is that each side names a target and
carries evidence; folding same-account pairs into one line is the reporter's. The shortest string
both patterns match is `repo:acme/infra:ref:refs/heads/main`, a subject GitHub issues, so the link
is `Established`.

The provenance is the evidence of both sides. Both sides cite the same response, byte for byte,
and a document read once is one record, so the link carries it once. A second fetch of the same
document at another time would be a second record (compare the `fetched_at` rule in
`internal/join/link.go`); this is one fetch.

> Identities admitted by role arn:aws:iam::111111111111:role/deploy are also admitted by role arn:aws:iam::111111111111:role/release: both admit identities from https://token.actions.githubusercontent.com with sub matching all of repo:acme/*:ref:refs/heads/main and repo:acme/infra:*, for example sub=repo:acme/infra:ref:refs/heads/main.

One link, one provenance record.
