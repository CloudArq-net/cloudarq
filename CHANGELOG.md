# Changelog

## v0.3.0 (unreleased)

Answers placed again with new owners, AWS's own roles and Organization, refusals without the
person who ran the collector, and downloads that say where they were built.

- **Re-marking.** The WebAssembly engine exports `remark(answer, owners, engine)`: one role's
  answer, kept from the findings, placed again with the owners declared now, with no policy text
  and no new bundle. It returns exactly what `findings` answers for that role with those owners,
  or `{"v":1,"declined":…}` with a sentence saying why: `engine` when another build of the
  engine wrote the answer, `owners` when a declaration of owners was refused whole, and `answer`
  when what was given does not read as an answer this build writes. The differential holds it to
  the native engine's, byte for byte.
- **AWS's own roles.** The findings write each role's `path`, and a bundle whose path IAM would
  not write, or that differs from the path the role's ARN names, is refused; a role listed with
  no path is read with `path` null. A role at `/aws-service-role/<service>/` whose trust admits
  that service, and only that service, is explained in `managed`: AWS made it for the service and
  manages it, and who gets in is whoever can make the service act, which may include the
  Organization's management account or a delegated administrator, and which the engine does not
  read. The explanation sits beside the answer, never in it, and the text form prints it under
  the role's name.
- **The AWS Organization.** `cloudarq-collect` also calls `organizations:DescribeOrganization`,
  named by `--explain` before it is made, and the bundle gains `organization`: its ID and ARN, the
  management account and that account's ARN, and the feature set, never the management account's
  email address. The format stays `cloudarq.collect/v1`. The findings give the Organization's
  `status`: `member`, `not-a-member`, `refused`, or `not-read` for a bundle an earlier collector
  wrote, which is never read as an account in no Organization. A member that does not hold
  together, such as an ARN other than the one AWS writes for that organization and account,
  refuses the bundle.
- **Recognised, and asked about.** The account a bundle was read from is recognised as yours,
  since your own credentials read it: grants pinned to it are placed with your own, the ring says
  "recognised: the account this scan read", and the findings list it in `recognised`, apart from
  what you declared. The Organization's management account and the Organization itself are not
  recognised, since a reseller or a managed service provider may run the one and the other may
  hold other companies' accounts. The findings ask about each in `suggested`, with the
  declaration that answers yes, and a role a yes would move names it in `would_move`, with the
  headline its answer would then open on. The ring of your own is named "Your AWS accounts",
  "Your pipelines", or "Your pipelines and AWS accounts", by what its grants are pinned to.
- **Refusals without the person.** In a refused call's message, where an IAM or STS ARN names a
  user, a role's session, a federated user, a U2F key or an MFA device, the name reads
  `(removed)`; the call, the account, the role and the permission stay. The collector strips every
  ARN in the message the same way, its own caller's included. Where its caller's principal ID
  stands outside an ARN, the part after the colon reads `(removed)`; where it runs on into an ARN,
  so does the rest of that ARN. The collector writes your home directory as `~` in the SDK's words
  for a call that never reached AWS. `admits --bundle`, its `--json` and the WebAssembly
  `findings` take the same names out of a bundle an earlier collector wrote, and `bundle_sha256`
  stays the digest of the file as given. Both copies of the strip read the cases in
  `testdata/callers/cases.json`.
- **The command line as a download.** Each release attaches `cloudarq_<os>_<arch>` beside
  `cloudarq-collect_<os>_<arch>`, for macOS and Linux on Intel and ARM, with one `SHA256SUMS`
  over the eight. `make release VERSION=vX` builds them with `CGO_ENABLED=0`, `-trimpath` and
  `-ldflags "-s -w"` from a tree `git status` lists nothing for, and refuses any binary Go records
  as built from a modified tree and, at a tag, any command line Go does not record at the tag.
- **Attested files.** The release workflow builds the files twice from the tagged source on a
  GitHub-hosted runner, compares the two builds byte for byte, and attests each file.
  `gh attestation verify` checks that the workflow built a file from the tag, and
  `gh release verify-asset` that it is the file attached to the release.
- **One version.** `scripts/version.sh` names the version for the WebAssembly engine and for
  `make release` alike: only a tag written as a release's, `v` and a digit, names it, so a tag
  such as a backup's never does.

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
