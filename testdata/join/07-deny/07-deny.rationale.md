# 07 — a Deny on the target casts doubt only where it can reach

The role's trust policy allows `sub` like `repo:acme/*` and denies `sub` like `repo:acme/infra:*`
(AWS evaluates an explicit Deny over any Allow: IAM User Guide, *Policy evaluation logic*). The
model carries the Deny as a second `Grant` with `Effect = Deny` on the same target, from the same
`iam:GetRole` call. Two applications trust the same issuer: one pins
`repo:acme/infra:ref:refs/heads/main` with `repository_id = 456789`, the other pins
`repo:acme/tools:ref:refs/heads/main` with `repository_id = 789012`.

The lattice has no complement, so "Allow minus Deny" cannot be computed. What can be decided is
whether a Deny can touch an overlap at all: whether it admits some token the side admits whose
identity is in the overlap, one `Meet` of the three sets. When that meet is provably empty the
Deny cannot remove anything from the overlap and is not a doubt; otherwise the link is
`Indeterminate` and says so.

- The Deny grant is never a side: it admits nobody.
- application `6b1e…` (infra) × role: the overlap is the infra branch; the Deny's pattern matches
  it, so the Deny may apply. `Indeterminate`, with the reason naming the denial. The Deny's
  evidence is the same `iam:GetRole` record the Allow carries, so the provenance holds it once.

  > Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; role arn:aws:iam::111111111111:role/deploy also denies identities from https://token.actions.githubusercontent.com, and whether these are among them could not be decided.

- application `9d2f…` (tools) × role: the overlap is the tools branch; the Deny's pattern
  provably does not match it (an exact value against a pattern is decided by `Contains`), so the
  Deny takes nothing away and the link is `Established`.

  > Identities admitted by application 9d2f4a6b-1c3e-4f5a-8b7c-6d5e4f3a2b1c are also admitted by role arn:aws:iam::111111111111:role/deploy: both admit identities from https://token.actions.githubusercontent.com with repository_id 789012 and sub repo:acme/tools:ref:refs/heads/main.

- application × application: two different exact subjects, provably disjoint, no link.

Two links, sorted by the application ids.
