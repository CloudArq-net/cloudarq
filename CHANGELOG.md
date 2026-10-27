# Changelog

## v0.6.0

The vendor that publishes an AWS account a role trusts, named beside the account; and a role
whose one way in is one token subject, said in the headline as the policy writes it.

- **The list.** `internal/vendors` holds 108 AWS accounts that vendors publish as their own, 100
  in `aws`, 7 in `aws-us-gov` and 1 in `aws-cn`: for each, the vendor's own pages, or files in
  repositories the vendor owns, that say so, what the vendor uses the account for on each, and
  the date each was read. An account is found by its partition and its ID together; the same
  twelve digits in another partition are another account, and the list does not name it.
- **`listed`.** An owner that is an AWS account the list holds gains `listed`, where the grant's
  principal is an ARN in that account's partition: its `vendor`, and its `uses`, each a `use`,
  the `source` page and the date it was `checked`. It places nothing: the account stays an
  outsider until it is declared, and one declared stays yours and still carries `listed`. A
  principal written as the account's ID alone writes no partition, and names no vendor. An owner
  the list does not hold writes no `listed`, and nothing in its answer changes for the list.
- **In the text.** A sentence that names a listed account names its vendor after it, once
  however many pages publish it: "aws:464622532012, which Datadog publishes as its own, can
  assume this role and is not declared as yours.", and, declared, "aws:464622532012, declared as
  yours, which Datadog publishes as its own, can assume this role." Of two owners named one by
  one, the listed one is named first when no vendor publishes the other, so that the vendor is
  said of it alone: "aws:464622532012, which Datadog publishes as its own, and aws:111122223333
  can assume this role and are not declared as yours." Two vendors in one sentence are each named
  after their own account. The headline, the questions and the fixes name no vendor.
- **`--explain`** gives, under the principal as written, one line for each page that publishes
  the account, as fields: the account, the vendor, the use, the page and the date it was read,
  as in "listed aws:464622532012 · Datadog · AWS integration (role delegation) · <page> · checked
  2026-10-19".
- **One subject.** A role whose one way in is one web-identity grant, placed exactly and pinned
  to one owner, whose `sub` is one value under `StringEquals`, or the subjects beginning with one
  prefix under `StringLike`, a pattern whose one wildcard is a `*` at its end, opens on that
  subject: "Only tokens whose subject is exactly repo:acme/api:ref:refs/heads/main can assume
  this role." or "Only tokens whose subject begins repo:acme/api: can assume this role." The
  subject is quoted as the policy writes it, marked `exact`, and nothing is read into it: the
  owner is all the engine reads from `sub`, so the headline names no repository and no branch.
  It is quoted only when it prints as written, every character of it one a policy may hold as
  written, U+0020 to U+00FF, but for DEL, the C1 controls, the no-break space and the soft
  hyphen: a subject holding a control, a direction mark or embedding, or any character past
  U+00FF keeps the headline it had, and is not quoted escaped.
  The ring's sentence and the question still say the owner is not declared. Beside anything else
  that lets anyone in, in any ring, the headline is as it was, and so it is for two values, two
  owners, any other wildcard, a `*` or a `?` that `StringEquals` compares as the character, and a
  way in not placed exactly; a Deny, or a grant that admits no one, lets no one in and changes
  nothing. With the owner declared, the answer opens on "Nothing outside your company can assume
  this role." as before. Twelve answers of the corpus now open on their subject.
- **Types.** `web/engine/answer.ts` types `listed`.
- **The WebAssembly build** is 6,520 bytes larger, 394,209 bytes brotli.

## v0.5.1

A GitHub subject under `StringEquals` holding a `*` or a `?`, such as `repo:octo-org@*/*` or
`repo:octo-org/*`, was placed exactly, and as open to anyone on GitHub where no subject form reads
an owner in it; `StringEquals` compares it as written, so it admits only a token whose subject is
that text, and every such value is now placed as `unknown`, an upper bound, no farther out than the
owner its text names, or on the platform where it names none. Every `*` or `?` in a `StringEquals`
value on `sub` carries the note `wildcard-is-literal`, which says `StringEquals` compares it as the
character, so only a subject that is exactly that text matches.

## v0.5.0

What the engine finds of each way in, by a rule with a permanent id.

- **Findings.** A population placed exactly whose way in meets a rule gains `finding`, under
  answer `v` 1: `rule`, one of `web-identity/no-owner`, `web-identity/owner-left-open`,
  `aws-account/no-external-id` and `aws-account/any-account`; `callers`, who the way in lets in
  that the rule is about, each a `kind`, `platform` or `aws-account`, and a `value`, null for
  the platform and the account's ID for an account; `through`, the identity provider or the
  service the principal names, and null for an AWS principal; `condition`, each claim the way
  in's term holds; `unread`, the conditions its statement writes that the grant does not read;
  and `inputs`, nine facts about the way in, each written on every finding, `not-read` or
  `not-checked` where the engine did not read or check it. A way in placed as `unknown` meets no
  rule, and neither does one a Deny of the same policy refuses whole. The README's *Findings*
  says what each rule and each member means.
- **A stable id.** Each finding of a role read from a bundle has an `id` and a `pairingKey`,
  SHA-256 hashes of the rule, the role's ARN, the grant's issuer and, for the id, the condition
  and the unread conditions: the same however the policy orders, lays out or names its
  statements. A policy read alone names no role, and its findings have neither.
- **Unread conditions.** Each grant gains `unread`, the conditions its statement writes that it
  does not read, as its findings write them, and null where the engine cannot tell which of the
  statement's principals the grant was read from. An answer marked again keeps them.
- **In the text.** Under the rings, one line for each finding: its rule, the sentence saying who
  the way in lets in, and its id where it has one.
- **Types.** `web/engine/answer.ts` types `finding`, its callers and inputs, and each grant's
  `unread`.
- **The WebAssembly build** uses `-opt=z` in place of `-opt=s`: the module is 21,266 bytes
  smaller, and a call on a policy of 50 statements takes about 0.9 ms longer.

## v0.4.0

Who each way in lets in and how, a fix for each, proven by reading the policy again, and a new
licence.

- **Who and how.** Each population of a grant gains `way`, under answer `v` 1: `who`, the
  population in the words of the ring or line it lands in, read with it alone there; `how`, the
  statement that lets it in, the principal it names and the conditions its term holds, as the
  grant's own sentence states them; `principal`, each place the statement writes the principal
  the grant was read from, as written, with its member and line; and `questions`, what its row
  would ask of its owners. `--explain` prints them for each grant once the command has answered.
- **A fix, proven or named.** Every way in has a `fix`. For a named outsider an Allow statement
  names by an AWS principal, the engine removes that principal, or the member of `Principal` it
  is the only value of, or the statement it is the only principal of, never from a Deny and
  never from `NotPrincipal`, where a removal lets more in. It reads the edited policy again with
  the same owners and offers the edit, as `proven`, only when the edited policy reads with no
  fault the original does not have, no population pinned to the outsider remains, every other
  grant is left one for one and none is made, and each grant left is placed by the same facts
  as its twin. The fix carries the edit (the statement, its Sid and lines, the principal as
  written with the byte offsets of its literal, the grants it takes out), what it shuts out,
  the headline the answer opens on after it and the SHA-256 of the edited policy, never its
  text. Otherwise it is `unproven` and `check` names what refused it. For anyone on a platform
  and for a cloud service, no edit is proven: where the engine can name the condition that
  would narrow the way in, the fix names it in words, as `words`. A population placed as yours
  or your people's keeps its fix in the JSON, so that an answer re-marked with the declaration
  withdrawn says it again, and `--explain` never offers it. For a role AWS manages, `--explain`
  says there is no trust policy fix to make. Each answer places at most 256 grants again to
  prove its fixes, and a principal past that says so.
- **The policy's only way in.** Where the principal is the only principal of the policy's only
  statement, removing it would leave a trust policy with no statement, which IAM refuses. The
  fix then replaces the whole policy with one whose one statement denies `sts:AssumeRole` to
  every AWS principal, keeping the original's `Version` as written (a `Version` IAM refuses,
  written twice, not a string or neither language version, leaves the fix unproven), and proves
  it the same way: the replacement reads with no fault the original lacks beside its own Deny's,
  every grant it makes is a Deny that lets no population in, and every grant of the original
  goes. The edit says it removes the policy. Beside it the fix says whom it shuts out, not to
  apply it while you still work with them, that anyone already in keeps their access until
  their session ends, which can take hours, or until the role's "Revoke active sessions" ends
  those sessions, and that deleting the role instead also removes what its permissions allow.
- **The fixed policy, made where the policy is.** The WebAssembly engine exports
  `fixed(bundle, owners, role, start, end)`: the trust policy of the bundle's role with that
  ARN, with the principal written at those offsets removed, or replaced as above, made from the
  reader's own file, and returned with its SHA-256 only where the role's answer with those
  owners proves the edit; otherwise, why not. The differential holds it to the native engine's
  bytes for every principal the corpus bundles' answers name.
- **The fixes corpus.** `testdata/fixes` holds seventeen cases, each with a rationale for its
  outcome; each answer and what `--explain` prints of it are goldens.
- **Licence.** From v0.4.0 the engine is source available under the Functional Source License,
  Version 1.1, with the Apache License 2.0 as its future licence (FSL-1.1-ALv2): each version
  becomes available under the Apache License 2.0 on the second anniversary of the day it was
  made available. v0.1.0 to v0.3.0 stay under the Apache License 2.0. Third-party material keeps
  its own licence, as NOTICE and THIRD_PARTY_NOTICES list it.

## v0.3.0

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
