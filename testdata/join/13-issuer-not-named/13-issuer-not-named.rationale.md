# 13 — a statement that names no issuer pairs with every issuer's grants

The role's trust policy is one statement: `Principal: "*"`, `Action: sts:AssumeRoleWithWebIdentity`,
no condition. AWS reads a bare `*` with an Allow effect as "all users, including anonymous
users" (IAM User Guide, *AWS JSON policy elements: Principal*, "All principals"), and
`sts:AssumeRoleWithWebIdentity` is the action an OIDC federated principal assumes through (same
page, "OIDC federated principals"); which identity providers' tokens the role then accepts is
stated nowhere in the document. The AWS parser (`internal/parse/aws`, read 2026-09-13) therefore projects the
statement to two grants on the role: every federated identity, with a **blank issuer**, admitting
everything, with the caveat `the statement applies to every principal, and which identity
providers' tokens that admits through sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is
not known`; and every AWS principal on the pseudo-issuer `aws:sts`, admitting nobody through this
action. One application trusts the GitHub Actions issuer for `repo:acme/infra:*` with
`repository_id = 456789`.

A blank issuer is an issuer the parser could not name, so as far as is known the grant admits
tokens from any issuer, the GitHub Actions issuer included. It pairs with the application, the
pair's issuer is the one the application names, and the link is `Indeterminate` for two reasons,
each stated: the join's own, that which issuers' tokens the role admits is not known, and the
parser's caveat. Refusing the grant instead, as a parser bug, would report the widest trust a
role can express as no fan-out at all, which is the under-reporting this package exists to
prevent.

The `aws:sts` face admits nobody, so it is provably disjoint from the application and makes no
link; it is on the same target as the blank-issuer face, so the two never pair with each other.
Both faces share the one `iam:GetRole` record, and the link carries it once beside the
application's.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; which issuers' tokens role arn:aws:iam::111111111111:role/deploy admits is not known; the identities admitted by role arn:aws:iam::111111111111:role/deploy are an upper bound (the statement applies to every principal, and which identity providers' tokens that admits through sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known at statement[0].Principal).

The witness, `repository_id=456789, sub=repo:acme/infra:`, is data on the link for the reporter;
an `Indeterminate` sentence never prints one. The role's grant reference keeps the blank issuer,
so a reader can see which statement names none.

One link, two provenance records.
