# 15 — a Deny that provably misses the overlap still counts when its reading is inconclusive

The role's trust policy allows `sub` like `repo:acme/*` and denies `sub` like `repo:acme/tools:*`
(compare case 07). One application trusts the GitHub Actions issuer for exactly
`repo:acme/infra:ref:refs/heads/main` with `repository_id = 456789`, which the Deny's pattern
provably does not match: an exact value against a pattern is decided by `Contains`.

The Deny grant carries two records: the `iam:GetRole` response it shares with the Allow, and a
second `iam:GetRole` call, one minute earlier, that AWS answered with `ThrottlingException` (IAM
API Reference, *Common Error Types*: "Your request rate is too high. The AWS SDKs automatically
retry requests that receive this exception.", HTTP status 400). A throttled response is not conclusive (`Status.Conclusive` in `internal/evidence`), and spec B4
property 4 says no link derived from such a record is `Established`. The join consulted the Deny
to decide whether it reaches the overlap, so the link is derived from it; and a statement whose
reading is inconclusive may deny more than the reading says, so the reach it was read with cannot
rule it out. The Deny therefore counts, the throttled record joins the link's provenance, and the
sentence says why the denial could not be decided.

With one trust-policy document a collector would attach the same records to both statements, and
the Allow's own doubt (`the call iam:GetRole ... returned throttled`, compare case 05) would then
read first; this case attaches the throttled call to the Deny alone so that the rule about
denials is what the link exercises.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; role arn:aws:iam::111111111111:role/deploy also denies identities from https://token.actions.githubusercontent.com, and whether these are among them could not be decided (the call iam:GetRole for role arn:aws:iam::111111111111:role/deploy returned throttled).

One link, `Indeterminate`, three records: the application's, the shared `iam:GetRole`, and the
throttled `iam:GetRole`, in record order.
