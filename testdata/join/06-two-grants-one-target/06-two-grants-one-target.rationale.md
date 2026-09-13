# 06 — two statements on one role are two grants, and a target never pairs with itself

The role's trust policy has two Allow statements, one admitting `sub` like `repo:acme/infra:*` and
one admitting `sub` like `repo:acme/tools:*`. The trust model is one `Grant` per statement
(`internal/trust/grant.go`), so the corpus holds two grants with the same `TargetRef` and the
same `iam:GetRole` record. The application pins `sub = repo:acme/tools:ref:refs/heads/main`.

- The two role grants share a target and never pair (spec property 2: a grant never fans out
  with itself, and a target is one thing however many statements grant it).
- application × role (infra statement): an exact value against a pattern that does not match it
  meets to `None`; provably empty, no link.
- application × role (tools statement): the pattern matches the value, the overlap is the value,
  and the link is `Established`. Its `grants[1].admits` renders the tools statement's set, which
  is how a reader tells which of the role's two statements the link is about; a grant reference
  names one statement, by its admitted set, its caveats and its effect, so two statements on one
  role never share one.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d are also admitted by role arn:aws:iam::111111111111:role/deploy: both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/tools:ref:refs/heads/main.

One link, two provenance records.
