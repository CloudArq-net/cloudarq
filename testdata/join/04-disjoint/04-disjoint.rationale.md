# 04 — a proven-empty overlap is no link at all

Three exact subjects: the role and the service account pin `repo:acme/infra:ref:refs/heads/main`,
the application pins `repo:acme/infra:ref:refs/heads/dev`. Two different exact values meet to
`None`, which is the one `StringSet` whose emptiness is proved (`internal/eval/stringset.go`,
`empty.IsEmpty`), so the two pairs that include the application have a provably empty overlap
and produce nothing. That is the only way a pair may be absent from the output: emptiness
proved, never emptiness suspected (compare case 02).

The role and the service account pin the same subject, so their overlap is that one identity
and the link is `Established`. Every claim of the overlap is a single value, so an example would
repeat the description word for word and is left out.

> Identities admitted by role arn:aws:iam::111111111111:role/deploy are also admitted by service-account deploy@acme-prod.iam.gserviceaccount.com: both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/infra:ref:refs/heads/main.

One link, and `witness` is `{"sub": "repo:acme/infra:ref:refs/heads/main"}`.
