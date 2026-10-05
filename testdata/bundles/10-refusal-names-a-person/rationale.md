# 10 — refusals that name people, in a bundle written before they were removed

A bundle in the form `cloudarq-collect` 0.2.0 wrote, with no `organization` member, whose refusals
keep AWS's words as they came: each names a person the way AWS's messages do. One role,
`deploy-admin`, trusts the IAM user `arn:aws:iam::123456789012:user/Jane`.

**Expected.** The engine reads each refusal's message through the strip the collector applies
before it writes a bundle, so the findings and standard error say the call, the account, the role
and the permission, and `(removed)` where the person was. Each message is a case of
`testdata/callers/cases.json`, and is said as that case's `want`:

| Case | AWS's words name | Said as |
|---|---|---|
| `federated-user-every-character` | `federated-user/Bob.Smith+1=a,b@example.com-_` | `federated-user/(removed)` |
| `iam-user-path-documented` | `user/division_abc/subdivision_xyz/Jane` | `user/(removed)` |
| `sso-caller-and-role-resource` | `assumed-role/AWSReservedSSO_Admin_0123456789abcdef/alice@example.com` | `assumed-role/AWSReservedSSO_Admin_0123456789abcdef/(removed)` |
| `mfa-named-for-its-user` | `user/Jorge` and `mfa/Jorge` | `user/(removed)` and `mfa/(removed)` |

In the case's output nothing else differs from what an engine that keeps AWS's words writes: those
strings, in the refusals of the JSON and on standard error, alone. `deploy-admin` is answered as it is
without the strip, its `document_sha256` the digest of its policy as written, `Jane` included: the
strip reads a refusal's message and nothing else, and a trust policy is the account's own text.
`bundle_sha256` is the digest of this file as it is, names and all. The command exits 0; the text
holds the role's answer alone, since what the collector was refused is said on standard error.

**Why.** A bundle written before the collector removed the person from what AWS refused still
names them. The engine is the one reader of every bundle, those already written included, so it
applies the same strip as it reads, and whoever is shown the findings sees what a collector that
strips would have written.

**No run of the collector writes this bundle.** One run has one caller, and 0.2.0 asks AWS two
things it can refuse, `iam:ListAccountAliases` and `iam:ListRoles`. The four refusals are gathered
in one bundle so the corpus carries each kind of person an ARN in a refusal names: an IAM Identity
Center session, an IAM user with a path, a federated user, and an MFA device named for its user.
Each refusal's call is the action its message names.

The account, the role ID and the dates are placeholders in AWS's own example form. The messages
and their sources are the table's: `testdata/callers/rationale.md`.
