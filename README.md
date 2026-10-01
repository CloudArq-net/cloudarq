# CloudArq

CloudArq reads an AWS IAM role's trust policy and prints who can assume the role. For each
grant in the policy it gives the set of tokens the grant admits, how far from you the people
holding those tokens are, and one token the grant accepts. It works offline: the command links
no networking package and reads nothing but the file it is given.

When a condition is one the engine cannot evaluate, it says so: the claim is marked
`not evaluated`, and the set printed is an upper bound. Each grant states two things apart.
Its admitted set is exact or an upper bound. Its ring is exact or unknown, and a ring can be
exact over an upper-bound set when no condition left unread could move it nearer: a grant on
one EKS cluster's issuer is placed with that cluster whatever its unread `aud` condition
says (`testdata/rings/25-eks-cluster`). A condition the engine could not read is designed
never to narrow the answer: on an Allow, the claim it names is read as unconstrained, and a
Deny that cannot be evaluated is not applied, with a note saying so. The property tests in
`internal/parse/aws` and `internal/ring` check it on generated policies.

## Install

```sh
go install github.com/CloudArq-net/cloudarq/cmd/cloudarq@latest
```

The module needs Go 1.24.13 or later. Its `toolchain` line names Go 1.27.1, the version the
tests run on, and the `go` command downloads that toolchain when the local one is older, unless
`GOTOOLCHAIN` is set otherwise. `cloudarq version` prints the module version the binary was
built from.

## Example

This policy has two statements. The first admits GitHub Actions tokens from one branch of
`acme/infra`. The second is meant to admit every repository of the `acme` organisation:

```json
"StringLike": {
  "token.actions.githubusercontent.com:sub": "repo:acme*"
}
```

```text
$ cloudarq admits trust-policy.json
read as an aws trust policy · version 2012-10-17 · 1027 bytes · 35 lines · 2 statements
sha256 37c6d52ed599c90229fd8aaabbf38ffb44c5bb73ec196a24cb230a79d011ed37

Anyone on GitHub can assume this role.

  Anyone            exact           No grant is placed with people who have no account anywhere.
  Anyone on GitHub  exact  grant 2  Anyone on GitHub can assume this role; no condition confines its tokens to one owner.
  A named outsider  exact  grant 1  github:acme can assume this role and is not declared as yours.
  Your pipelines    exact           No grant is confined to owners declared as yours.
  Your people       exact           No grant trusts a SAML provider declared as yours.

Each of these can narrow the rings and was not read: the organisation's resource control policies, the calling accounts' service control policies and this account's identity providers.

grant 1 of 2 · statement[0] "DeployFromMain" · Allow · https://token.actions.githubusercontent.com · outsider · exact
This role admits any token from token.actions.githubusercontent.com whose aud is sts.amazonaws.com and whose sub is repo:acme/infra:ref:refs/heads/main.
…
grant 2 of 2 · statement[1] "PreviewFromAcmeRepositories" · Allow · https://token.actions.githubusercontent.com · platform · exact
This role admits any token from token.actions.githubusercontent.com whose aud is sts.amazonaws.com and whose sub matches repo:acme*.
Who holds those identities now is not computed here: no network request is made.

CLAIM            ADMITS               IN WORDS · AS WRITTEN
aud              "sts.amazonaws.com"  exactly this audience · line 27 StringEquals
sub              like:"repo:acme*"    any subject beginning repo:acme · line 30 StringLike
any other claim  any                  unconstrained · no condition names it

a token this grant admits
  {
    "iss": "https://token.actions.githubusercontent.com",
    "aud": "sts.amazonaws.com",
    "sub": "repo:acme"
  }
…
```

In `StringLike`, `*` matches any run of characters, `-` and `/` included, so `repo:acme*` also
admits every repository of an organisation whose name begins with `acme`. `--token` checks one
token against every grant, claim by claim:

```text
$ cloudarq admits trust-policy.json --token '{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme-evil/x:ref:refs/heads/main"}'
token · 3 claims · read as a payload
Admitted by grant 2.
Grant 1 rejects it on sub; grant 2 admits it.
…
grant 2 of 2 · statement[1] "PreviewFromAcmeRepositories" · Allow · https://token.actions.githubusercontent.com · platform · exact
Admitted by grant 2.
Every claim grant 2 names is satisfied: aud and sub.

CLAIM  THE TOKEN                                    THE GRANT ADMITS                             RESULT
iss    https://token.actions.githubusercontent.com  https://token.actions.githubusercontent.com  satisfies
aud    sts.amazonaws.com                            "sts.amazonaws.com"                          satisfies
sub    repo:acme-evil/x:ref:refs/heads/main         like:"repo:acme*"                            satisfies
```

`--owner` declares an owner as yours, and the grant pinned to it moves from *a named outsider*
to *your pipelines*:

```text
$ cloudarq admits trust-policy.json --owner github:acme
…
  A named outsider  exact           No grant is placed with a named outsider.
  Your pipelines    exact  grant 1  github:acme, declared as yours, can assume this role.
```

A condition the engine does not evaluate. In the engine's words, "ForAllValues:StringLike on sub
passes when the claim is absent, so it does not restrict what it looks like it restricts":

```text
$ cloudarq admits unread.json
…
  Anyone on GitHub  unknown  grant 1  Anyone on GitHub could assume this role; one of its conditions was not read.
…
This role admits any token from token.actions.githubusercontent.com whose aud is sts.amazonaws.com and whose sub was not evaluated, so the set shown is an upper bound.
The set shown is an upper bound, not the set: a token not excluded here may still be refused by AWS.

CLAIM            ADMITS                        IN WORDS · AS WRITTEN
aud              "sts.amazonaws.com"           exactly this audience · line 13 StringEquals
sub              ?("ForAllValues:StringLike")  not evaluated · note 1 · line 16 ForAllValues:StringLike
```

Both policies are in the test corpus: `testdata/rings/01-branch-pin-and-owner-prefix/aws.json`
and `testdata/rings/31-unread-subject/aws.json`, each beside a rationale that quotes the AWS
documentation its expected answer rests on.

## Usage

```text
cloudarq admits <file|-> [flags]
cloudarq version
```

`-` reads the policy from standard input. The flags, as `cloudarq` run with no arguments prints
them:

```text
  --json         print the answer as the versioned JSON schema instead
  --owner <o>    declare an owner as yours, as github:acme, github:@123456,
                 aws:111122223333, saml:<provider ARN> or issuer:<issuer
                 URL>; repeat it for each. An owner nobody declared is a
                 named outsider, and one the engine does not read is
                 refused with exit code 2
  --token <t>    read a token, decoded payload or whole, and print for each
                 grant whether it is admitted and why
  --explain      print on standard error what the command reads and calls
                 before it answers, and after it, when a ring's place rests
                 on the engine's reading of AWS's documentation, the
                 sentences it read
  --no-color     never mark the output; NO_COLOR in the environment does
                 the same, and a pipe is never marked
```

The exit code says whether the question was answered, never what the answer was:

| Code | Meaning |
|---|---|
| 0 | The question was answered, whatever the answer. A policy that admits anyone exits 0. |
| 1 | An input was not read: the file could not be opened, the document or the token was not what it claimed to be, or the owners declared were past what the engine reads. The reason goes to standard error, and the answer to standard output whenever the engine was given bytes at all. |
| 2 | The command line was not understood, including an `--owner` the engine does not read. No answer is written. |

`--json` prints the same answer as JSON whose first member is `"v": 1`. `v` changes only when a
field is removed or renamed, or a field's meaning changes. New fields, and new values of an
existing field, arrive under the same `v`; a consumer should ignore fields it does not know and
read a value it does not know as unknown, never as clean.

## What it reads, and what it does not

- **It reads AWS IAM role trust policies**, the document in a role's `AssumeRolePolicyDocument`.
  No other document is read by the command.
- **It reads nothing else about your account.** Service control policies, resource control
  policies and the account's identity providers can narrow who gets in; the answer names them
  as not read rather than assuming them away.
- **It looks nothing up.** Who holds a GitHub organisation name today, or whether an identity
  provider exists in the account, is not computed.
- **It does not rank.** There is no score or severity; the answer is the set of identities, in
  words and as JSON.
- **What it knows about each issuer is data**: which claims name a tenant, the forms a subject
  takes, which condition keys AWS documents for the issuer. That data comes from the census
  module, [`github.com/CloudArq-net/issuers`](https://github.com/CloudArq-net/issuers). An
  issuer the census does not describe gets the widest reading: its conditions are not
  evaluated, and its grant is placed with *anyone*, as unknown.
- **Conditions are evaluated only on the keys AWS documents for an issuer**, as the census
  records them. In census v0.2.0 those issuers are GitHub Actions
  (`token.actions.githubusercontent.com`), Bitbucket Pipelines, Spacelift, CircleCI (its
  `oidc.circleci.com/project-id` key alone), Amazon EKS, Azure Kubernetes Service and Google
  Kubernetes Engine cluster issuers, AWS outbound identity federation, Google
  (`accounts.google.com`), Amazon Cognito identity pools, Login with Amazon, Facebook and
  Microsoft Entra ID. For every other issuer, GitLab.com, HCP Terraform, Buildkite and GitHub's
  per-enterprise issuer path included, each condition is reported `not evaluated`, the set is
  an upper bound, and the grant's ring rests on what the census records of the issuer alone. A
  GitLab.com policy pinned to one project and branch is therefore placed with *anyone*, as
  unknown: the census does not record that GitLab.com's tokens need an account, and the
  conditions that name the project are not read.

The repository also holds readers for Microsoft Entra federated identity credentials, Google
Cloud workload identity pool providers and the JSON of `terraform show -json`. They are tested
against the corpus under `testdata/`; the command does not use them.

## Building and testing

```sh
git clone https://github.com/CloudArq-net/cloudarq
cd cloudarq
make check
```

`make check` builds, vets and tests every package, then runs three stricter checks, and prints
`all checks green` only if all of them pass:

- `make purity`: no pure package imports `net`, `os`, `os/exec`, `syscall`, `bufio`,
  `database/sql`, a source of randomness (`math/rand`, `math/rand/v2`, `crypto/rand`,
  `hash/maphash`) or a cloud SDK, directly or through another package. The one way through is
  `encoding/json`, `fmt`, `crypto/sha256` and `time`, which reach `os` but do IO only on a file
  or connection they are handed.
- `make determinism`: the tests that hold the output byte-identical for identical input run in
  twenty fresh processes, and every run must pass.
- `make cover`: fails if any statement of `internal/eval`, `internal/trust`, `internal/parse`
  or `internal/ring` is not run by their tests. It says only that the code ran; what the code
  must do is held by the corpus under `testdata/`, the property tests, and the conformance
  suite that reads each case in every cloud's syntax.

CI runs the same targets. [docs/OVERVIEW.md](docs/OVERVIEW.md) describes how the engine is
layered and where each part lives.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache License 2.0; see [LICENSE](LICENSE). [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) list the third-party material the repository
contains.
