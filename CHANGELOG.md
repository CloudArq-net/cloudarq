# Changelog

## v0.2.0

A whole AWS account, read by you and answered offline.

- `cloudarq-collect aws`, a second command in its own module (`internal/collect`), reads the
  AWS account your credentials belong to and writes one bundle, `cloudarq.collect/v1`, on
  standard output: the account, its alias, and every role with its trust policy, as `ListRoles`
  paged them. It only reads, with your own credentials from AWS's standard chain, and calls STS
  and IAM to read. Every call AWS refuses, and every cap the collector meets, is written into the
  bundle in AWS's own code and words; `--explain` names each call before it is made. It exits 0
  for a whole read, 3 for a partial one with the bundle still written, 1 when the account
  could not be learned, and 2 for a command line it does not understand. The AWS SDK for Go v2
  enters only its module: a test fails if any package of the engine's module reaches a cloud
  SDK. Each release attaches it built for macOS and Linux, on Intel and ARM.
- `cloudarq admits --bundle <file|->` answers every role of a bundle, each as `admits` answers
  its trust policy alone, with the owners `--owner` declares. With `--json` it prints them as
  findings, `cloudarq.findings/v1`: each role's answer beside the SHA-256 of its policy, the
  SHA-256 of the bundle and the engine's version. A bundle that is not one AWS account's in
  this format is refused in words, and a role whose policy is not read is exit code 1, named on
  standard error.
- The WebAssembly engine exports `findings(bundle, owners)`, and its loader takes the bundle as
  the file's bytes. The differential holds its findings to the native engine's, byte for byte.

## v0.1.0

The first release.

- `cloudarq admits` reads an AWS IAM role trust policy and places each grant in one of five
  rings, by how far the identities it admits are from you: anyone, anyone on a platform, a
  named outsider, your pipelines and your people. Each ring's state is `exact`, or `unknown`
  when something that decides it was not read, such as a condition the engine does not
  evaluate or an issuer the census does not describe.
- For each grant it prints the set of tokens admitted, in a sentence and as a table of claims
  with the line and operator each constraint is written with; the notes the engine recorded;
  one token the grant admits; and where the statement sits in the document, by offset, lines
  and sha256.
- `--owner` declares an owner as yours, as `github:<name>`, `github:@<id>`,
  `aws:<account>`, `saml:<provider ARN>` or `issuer:<URL>`. An owner nobody declared is a
  named outsider. An owner the engine does not read is refused with exit code 2.
- `--token` checks a token, as a decoded payload or whole, against every grant and says, claim
  by claim, why each grant admits or rejects it. A Deny that was not applied lists the claims
  it names as not evaluated.
- `--json` prints the answer as version 1 of its JSON format. `v` changes only when a field is
  removed or renamed, or a field's meaning changes.
- `--explain` prints on standard error what the command reads before it answers, and after it,
  when a ring's place rests on the engine's reading of AWS's documentation, the sentences it
  read.
- A condition the engine cannot evaluate is marked `not evaluated` and widens the answer; a
  Deny that cannot be evaluated is not applied, and says so.
- A condition key is read from the claim AWS documents it reads. A plain operator on a key AWS
  documents as multivalued, or on a claim an issuer's tokens may carry with several values, is
  not evaluated.
- Action names and condition keys are compared without regard to case using the case folding
  of Unicode 17.0.0's `CaseFolding.txt`, not the Go toolchain's tables, so the answer does not
  depend on the Go version that built the binary.
- What the engine knows about each issuer comes from the census module,
  `github.com/CloudArq-net/issuers`.
- The exit code is 0 whenever the question was answered, 1 when an input could not be read, and
  2 when the command line was not understood.
- The command makes no network request and reads no environment variable but `NO_COLOR`.
- `web/wasm` is the engine's WebAssembly entry for TinyGo. Its exports return the same JSON
  answer for a policy, or for a policy and a token. `web/engine` holds its JavaScript loader and
  `build.sh`, which builds the module and compares its answers with the native build's.
- Readers for Microsoft Entra federated identity credentials, Google Cloud workload identity
  pool providers and `terraform show -json` output are included as packages, each tested
  against its corpus under `testdata/`. The command does not use them.
