# 03 — an inexact grant never produces an Established link

The role's trust policy pins `repository_id = 456789` and constrains `sub` with
`ForAllValues:StringLike`. The set operator passes when the claim is absent from the request
(IAM User Guide, *Multivalued context keys*: "ForAllValues ... returns true if ... the request has
no context keys"), so it does not restrict what it looks like it restricts; the AWS parser
leaves `sub` Unknown, records the caveat `operator ForAllValues:StringLike is not modelled` at
`statement[0].Condition`, and the grant is not `Exact()`. This is conformance case 07 of the
trust harness (`internal/trust/conformance.go`).

The application pins `sub = repo:acme/infra:ref:refs/heads/main` and `repository_id = 456789`.

Unknown is the identity under `Meet` (`docs/ENGINEERING.md`, section 3), so the overlap is the
application's own set, `{repository_id="456789", sub="repo:acme/infra:ref:refs/heads/main"}`, and it
looks clean: a witness exists and both sides admit it. Nothing in the lattice says the role's
side was an upper bound. The caveat on the grant is the only carrier, which is why the link
gates `Established` on both grants being exact and not on the overlap alone. The link is
`Indeterminate`, its reason is the caveat's own sentence with its source, and the witness stays
on the link as data. The role's grant reference carries the caveat too, under `caveats`, so the
link is told from one on an exact statement of the same role by its grants alone; every other
case renders `"caveats": []`, which says the statement is exact rather than saying nothing.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; the identities admitted by role arn:aws:iam::111111111111:role/deploy are an upper bound (operator ForAllValues:StringLike is not modelled at statement[0].Condition).
