# 16 — a list of repositories against a branch pin reads as one sentence

The role's trust policy lists six repositories in one `StringLike` on `sub`: `repo:acme/api:*`,
`repo:acme/app:*`, `repo:acme/cli:*`, `repo:acme/docs:*`, `repo:acme/infra:*` and
`repo:acme/web:*`. "If a single condition operator includes multiple values for a context key,
those values are evaluated using a logical `OR`" (IAM User Guide, *Conditions with multiple
context keys or values*, "Evaluation logic for multiple context keys or values"), and the AWS
parser
(`internal/parse/aws`, read 2026-09-13) renders it as the union of the six patterns on `sub`
within one term. One application trusts the GitHub Actions issuer for `sub` like
`repo:acme/*:ref:refs/heads/main`: the `main` branch of any `acme` repository.

The overlap is `sub` in the union of six intersections, one per repository, each of the form
`repo:acme/*:ref:refs/heads/main & repo:acme/<name>:*`. Every one has a common string, so the
pair is `Established` on the first found in canonical order, `repo:acme/api:ref:refs/heads/main`,
a subject GitHub issues for a branch run.

Listing every alternative would make the sentence grow with the product of the two lists: two
policies of thirty repositories each are nine hundred alternatives, which is not a sentence. The
description names three members of any list and counts the rest, and never says "1 more", since
naming the fourth is shorter than counting it. `overlap` holds all six.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d are also admitted by role arn:aws:iam::111111111111:role/deploy: both admit identities from https://token.actions.githubusercontent.com with sub matching all of repo:acme/*:ref:refs/heads/main and repo:acme/api:* or matching all of repo:acme/*:ref:refs/heads/main and repo:acme/app:* or matching all of repo:acme/*:ref:refs/heads/main and repo:acme/cli:* or one of 3 more alternatives, for example sub=repo:acme/api:ref:refs/heads/main.

One link, two records.
