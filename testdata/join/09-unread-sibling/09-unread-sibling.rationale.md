# 09 — a statement whose effect could not be read is a possible Deny on its target

The role's trust policy has two statements. The first allows `sub` like `repo:acme/*`. The
second spells its effect `deny`, in lower case, which the AWS API would reject (IAM User Guide,
*IAM JSON policy elements: Effect*: the valid values are `Allow` and `Deny`) and the parser
cannot read; the model carries that statement as a second `Grant` on the same role with
`EffectUnknown`, admitting `sub` like `repo:acme/infra:*`. Both grants come from the one
`iam:GetRole` call. Two applications trust the same issuer: one pins
`repo:acme/infra:ref:refs/heads/main`, the other `repo:acme/tools:ref:refs/heads/main`.

`EffectUnknown` must be treated as possibly Allow (`internal/trust/grant.go`), so the second
statement pairs, and its own links say its effect could not be read. It is also possibly Deny,
and a Deny over exactly these identities would take them out of the first statement's reach; so
on the first statement's links it casts the doubt a Deny casts, wherever it can reach the overlap
(compare case 07). Reading the same corpus with the statement as `Deny` gives the first link the
same confidence for the same reason, one link fewer, and the same third link; the two readings
never disagree on whether a link is `Established`, which is what the two-valued rule requires.

- application `6b1e…` (infra) × role, first statement: the overlap is the infra branch, the
  unread statement's pattern matches it, so it may deny it. `Indeterminate`, naming the unread
  statement. Its evidence is the record the first statement already carries, so the provenance
  holds it once.

  > Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; role arn:aws:iam::111111111111:role/deploy also has a statement from https://token.actions.githubusercontent.com whose effect could not be read, and whether it denies these identities could not be decided.

- application `6b1e…` (infra) × role, second statement: the statement pairs as possibly Allow,
  and its own doubt is its effect. A side is never a doubt about itself, and the first
  statement is an Allow, so nothing else is said.

  > Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; the effect of the statement granting role arn:aws:iam::111111111111:role/deploy could not be read.

- application `9d2f…` (tools) × role, first statement: the overlap is the tools branch, which
  the unread statement's pattern provably does not match, so it cannot deny it and the link is
  `Established`.

  > Identities admitted by application 9d2f4a6b-1c3e-4f5a-8b7c-6d5e4f3a2b1c are also admitted by role arn:aws:iam::111111111111:role/deploy: both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/tools:ref:refs/heads/main.

- application `9d2f…` × role, second statement: an exact value against a pattern that does not
  match it, provably disjoint, no link. application × application: two exact values, no link.

Three links, sorted by the application ids and then by the role's admitted set. The two links
on the first application name the role's two statements by different grant references: the
first statement's renders `"effect": "Allow"`, the second's `"effect": "Unknown"`, beside their
different admitted sets.
