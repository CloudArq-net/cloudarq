# 01 — the counterparty matches by glob overlap, not by equality

Three targets trust the GitHub Actions issuer, each with a different pattern on `sub`:

| target | `sub` | other claim | audience |
|---|---|---|---|
| role `arn:aws:iam::111111111111:role/deploy` | `repo:acme/*:ref:refs/heads/main` | `repository_owner_id = 123456` | `sts.amazonaws.com` |
| application `6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d` | `repo:acme/infra:*` | `repository_id = 456789` | `api://AzureADTokenExchange` |
| service-account `deploy@acme-prod.iam.gserviceaccount.com` | `repo:acme/*` | — | the workload identity pool provider |

No two subject strings are equal, and no pattern contains another as text, so a tool that
compares subjects finds nothing here. The sets overlap: GitHub issues `sub` as
`repo:<owner>/<repo>:ref:refs/heads/<branch>` for a branch run and `repo:<owner>/<repo>:environment:<name>`
for an environment run (GitHub Docs, the OpenID Connect hardening guide, "Example subject
claims"), and AWS `StringLike` treats `*` as any run of characters including `/` and `:`
(IAM User Guide, *IAM JSON policy elements: Condition operators*, "String condition operators").
The role admits any `acme` repository on `main`; the application admits any run of `acme/infra`;
both admit `acme/infra` on `main`.

Every pair links, and every link is `Established`: each grant is exact, each effect is `Allow`,
each side carries one conclusive record, and an identity both sides admit was built and
confirmed. The audiences differ on every pair, which is why the overlap is taken with `aud` set
aside; against the full admitted sets every pair would be provably disjoint and this file would
be empty, which is the mutation the case exists to catch.

Links are pairwise and sorted by target kind then id: application, role, service-account.

1. application × role. Overlap `{repository_id="456789", repository_owner_id="123456", sub=(like:"repo:acme/*:ref:refs/heads/main" & like:"repo:acme/infra:*")}`.
   The shortest string both patterns match is `repo:acme/infra:ref:refs/heads/main`, a subject
   GitHub really issues.

   > Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d are also admitted by role arn:aws:iam::111111111111:role/deploy: both admit identities from https://token.actions.githubusercontent.com with repository_id 456789, repository_owner_id 123456 and sub matching all of repo:acme/*:ref:refs/heads/main and repo:acme/infra:*, for example repository_id=456789, repository_owner_id=123456, sub=repo:acme/infra:ref:refs/heads/main.

2. application × service-account. Overlap `{repository_id="456789", sub=(like:"repo:acme/*" & like:"repo:acme/infra:*")}`.
   The shortest common string is `repo:acme/infra:`, which GitHub never issues; the sentence
   therefore describes the patterns and offers the string only as an example.

   > Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d are also admitted by service-account deploy@acme-prod.iam.gserviceaccount.com: both admit identities from https://token.actions.githubusercontent.com with repository_id 456789 and sub matching all of repo:acme/* and repo:acme/infra:*, for example repository_id=456789, sub=repo:acme/infra:.

3. role × service-account. Overlap `{repository_owner_id="123456", sub=(like:"repo:acme/*" & like:"repo:acme/*:ref:refs/heads/main")}`.
   The shortest common string deletes both stars: `repo:acme/:ref:refs/heads/main`.

   > Identities admitted by role arn:aws:iam::111111111111:role/deploy are also admitted by service-account deploy@acme-prod.iam.gserviceaccount.com: both admit identities from https://token.actions.githubusercontent.com with repository_owner_id 123456 and sub matching all of repo:acme/* and repo:acme/*:ref:refs/heads/main, for example repository_owner_id=123456, sub=repo:acme/:ref:refs/heads/main.

Each link's provenance holds both sides' records, sorted by API name, and its `witness` is the
example above as claim=value pairs; `overlap` is the canonical rendering quoted above.
