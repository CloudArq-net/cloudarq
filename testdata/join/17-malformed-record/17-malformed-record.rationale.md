# 17 — a record that names no call is a doubt the sentence names, not a reason to drop the pair

The role's trust policy pins `sub` to exactly `repo:acme/infra:ref:refs/heads/main`; one
application trusts the GitHub Actions issuer for the same subject. The role's grant carries two
records: the `iam:GetRole` response that proves it, and a second record, a paginated listing the
collector attached without naming the call (`api` is empty). That is a collector bug: the rule of
`internal/evidence` is that a claim must be able to produce the API response that proves it, and
a response nobody can name proves nothing.

The pair is nonetheless real and proved: the `iam:GetRole` record names the role's system and
the application's record names its own. Refusing the role's grant for the one record it cannot
name would report a fan-out with evidence on both sides as absent, which is the under-reporting
property 3 of spec B4 forbids. So the grant is a side, the link is `Indeterminate`, the reason
says what is wrong with the record instead of printing a hole where its name would go, and the
record is carried as it is, `"api": ""`, so that the bug is visible in the provenance rather than
hidden by it. A grant whose records are *all* malformed has no record that names its system and
is refused, named in `FanOut`'s error (compare `TestNewLinkRefusesAGrantThatNamesNothing`).

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; a record for role arn:aws:iam::111111111111:role/deploy names no API call.

One link, `Indeterminate`, three records in record order: the unnamed one first, since an empty
call name sorts before any other.
