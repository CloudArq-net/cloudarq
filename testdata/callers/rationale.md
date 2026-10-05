# Callers — the case table

`cases.json` holds refusal messages, most as AWS words them and some forged, each with the exact text
a strip must turn it into: the same message without the person who made the call. The account, the
role, the call and the permission stay. The file is plain JSON and nothing in it depends on Go, so
an implementation of the grammar below in any language can be held to it, case for case.

Each case has `id`, `shape`, `message`, `want` and `source`. `source` is the AWS page the shape
comes from, or `synthetic`, with the reason below. Accounts and names are AWS's documented example
values (`123456789012`, `777788889999`, John, Jane, Jorge, JaneMFA, mateojackson,
johndoe@example.com) or are made up. AWS's pages were read on 2026-10-04.

## The grammar every `want` follows

- An ARN starts at every occurrence of `arn:`, whatever stands before it, inside a word or inside
  another ARN.
- It runs to the first character outside printable ASCII, U+0021 to U+007E. A space, a tab, a
  carriage return, a newline, U+007F, U+00A0 and every non-ASCII character end it. AWS describes
  user, session, federated and MFA device names as letters, digits, underscores and `+=,.@-`
  (pattern `[\w+=,.@-]`) [U3, U4, U5, MFA], and a path as characters from U+0021 to U+007E between
  slashes [U4, MFA].
- It is split on `:` into six fields, `arn:partition:service:region:account-id:resource` [U8]. The
  resource is everything after the fifth colon, colons included.
- It matches only when the partition is not empty, the service is `iam` or `sts`, the region is
  empty, and the resource is one of these five, which are replaced:
  - `assumed-role/<role>/<session>`: `assumed-role/<role>/` stays and the session becomes `(removed)`;
  - `user/<path and name>`: becomes `user/(removed)`;
  - `federated-user/<name>`: becomes `federated-user/(removed)`;
  - `u2f/<anything>`: becomes `u2f/(removed)`;
  - `mfa/<path and name>`: becomes `mfa/(removed)`.
- What is replaced may be empty: `user/` alone becomes `user/(removed)`, and so do
  `federated-user/`, `u2f/`, `mfa/` and an empty session after `assumed-role/<role>/`.
  `assumed-role/<role>` with no second slash holds no session and is left as it is.
- Anything else is left exactly as it was: root, roles with their paths, policies, groups, other
  services' ARNs, and a message without `arn:`, byte for byte.

Every occurrence in one run of printable characters ends where the run ends, so the removed parts
all end there too and one token replaces them. The token is printable ASCII and holds no `arn:`, so
a second strip finds the same ARNs ending at the same places and writes the same text: stripping
twice equals stripping once, and every `want` stripped again is itself. Its parentheses are
characters no user, session, federated or MFA device name may hold [U3, U4, U5, MFA], so a removed
name can be told from a real one.

AWS's page displays its example messages across several lines [U1]. The table joins those lines
with one space, as one message. Sentences not taken from that page follow the form of its examples:
`User: <ARN> is not authorized to perform: <action>`, then `on resource: <ARN>` or the context [U1].

## The shapes

- **`no-arn`** (4). Nothing changes, byte for byte. `Rate exceeded` is the throttling text the
  collector's tests use; it is marked synthetic because no page read here prints it. "You don't
  have permissions to perform the requested operation." is DescribeOrganization's documented refusal
  [ORG]. `User: reader is not authorized…` (synthetic, in the form of the collector's own test
  fixtures) names someone without an ARN: the grammar reads ARNs, not prose. The fourth (synthetic)
  holds a tab, CR LF, non-ASCII characters of two, three and four bytes in UTF-8 (U+00A0 among
  them) and the word `ARN` without `arn:`.
- **`assumed-role`** (7). `arn:aws:sts::123456789012:assumed-role/Accounting-Role/Jane` [U2]. An
  administrator "might require that you specify your user name as the session name" [U3], and under
  SAML it is "typically a user ID (john) or an email address (johndoe@example.com)" [U6]. The cases
  hold every kind of character in the session pattern, the shortest (2) and longest (64) session
  [U3], and the China partition `aws-cn` [U8]. A session that is not a person, shaped like an
  instance ID, goes too (synthetic): the grammar cannot tell a person from anything else.
- **`assumed-role-sso`** (3). IAM Identity Center names its roles
  `AWSReservedSSO_<permission-set-name>_<unique-suffix>` [U7]. The session after the role goes as any
  session does. The role name stays whole, `+=,.@-` included, which a permission set name may hold
  (`[\w+=,.@-]+`, [PS]). The suffix `0123456789abcdef` is made up. The third case, an Identity
  Center session refused `sts:AssumeRole` on another role, is synthetic: two ARNs in [U1]'s form.
- **`iam-user`** (6). AWS's own messages: `User: arn:aws:iam::123456789012:user/John is not
  authorized to perform: codecommit:ListRepositories…` and `…user/mateojackson…` [U1], with the
  policies AWS puts in the context clause (a service control policy, a resource control policy, a
  permissions boundary) and a secret's ARN with its region, all of which stay. One message names
  two people, a caller and a user as resource; both go.
- **`iam-user-path`** (4). `user/division_abc/subdivision_xyz/Jane` [U2]. AWS suggests a path "to
  match your company organizational structure" [U2], so it goes with the name. A path may hold `:`
  [U4], and since the resource is everything after the fifth colon, a colon in the path does not
  split the ARN again. Also: the same person twice, and the GovCloud partition `aws-us-gov` [U8].
- **`federated-user`** (2). `arn:aws:sts::123456789012:federated-user/John` [U2]. The name is
  chosen by whoever calls GetFederationToken, "such as Bob", up to 32 characters [U5]. The second
  case uses every kind of character the pattern allows.
- **`u2f`** (1). `arn:aws:iam::123456789012:u2f/user/John/default` [U2] holds the user's name;
  everything after `u2f/` goes.
- **`mfa`** (3). `arn:aws:iam::123456789012:mfa/JaneMFA` and "The multi-factor authentication
  device assigned to the user named Jorge: arn:aws:iam::123456789012:mfa/Jorge" [U2]. A device
  named for a person names the person, as a U2F key's ARN does, so everything after `mfa/` goes.
  AWS writes the form `mfa/virtual-device-name-with-path` [U2] and gives a virtual MFA device a
  path [MFA]. The third case puts AWS's example path `division_abc/subdivision_xyz/` [U2] before
  JaneMFA.
- **`root`** (1). `arn:aws:iam::123456789012:root` [U2] names the account only and stays.
- **`role-caller`** (4). `User: arn:aws:iam::123456789012:role/HR is not authorized…` [U1]. A role
  names no person and stays, path included: Identity Center's
  `role/aws-reserved/sso.amazonaws.com/[region/]AWSReservedSSO_…` [U7], and a role path spelling
  `assumed-role/user/federated-user/u2f/mfa/` [ROLE]. The resource type is the resource's first
  segment, not a word found anywhere in it.
- **`other-arn`** (3). An identity-based policy in the context clause [U1]; a group with a path
  [U2]; and the identity store's `arn:${Partition}:identitystore:::user/${UserId}` [IDS], whose
  resource begins `user/` but whose service is neither `iam` nor `sts`. Its UserId is an
  identifier, here made up, not a name.
- **`unanswered`** (2), synthetic. When a call never reaches AWS, the collector keeps the Go
  error's own text. The first is that text exactly as the collector's pinned SDK (aws-sdk-go-v2
  v1.47.1, service/sts v1.51.1) printed it on 2026-10-04 for GetCallerIdentity against a closed
  local port. The second is the collector's own words for an answer that names no organization
  (`internal/collect/aws/collect.go`). Neither holds `arn:`.
- **`forged`** (22), all synthetic: text AWS does not send, which a strip must still handle exactly.
  - `tab-ends-arn`, `newline-ends-arn`: a tab, CR LF and LF each end an ARN, at the end of a line
    and at the end of the message.
  - `printable-ascii-edges`: `~` and `!` (U+007E, U+0021) are inside the ARN and go with the name;
    U+007F ends it.
  - `non-ascii-ends-arn`: U+1F600 (four bytes in UTF-8, two UTF-16 code units) and U+2019 (three
    bytes) each end an ARN, and what follows stays. Counting bytes, code points or UTF-16 code
    units ends in the same place, since every byte and every code unit of a non-ASCII character is
    outside the range.
  - `text-glued-to-a-name`: `<script>alert(1)</script>` with no space before it is inside the ARN,
    so it goes with the name, and nothing outside the ARN changes.
  - `session-longer-than-aws-allows`: 65 characters, one past [U3]'s limit. The grammar has no
    length limit, so it goes.
  - `xarn-prefix`: `xarn:aws:iam::1:user/bob`. The ARN starts at its `arn:` whatever precedes it.
  - `arn-glued-to-arn`: in `arn:arn:aws:iam::…`, the first occurrence fails (its service reads
    `aws`) and the second matches. A strip that skipped the rest of a failed run would keep the
    name.
  - `arn-inside-a-word`: `Warn:` holds `arn:`, with fewer than six fields after it. Nothing
    changes.
  - `user-arn-inside-a-role-path`: a role path may hold `:` [ROLE], so
    `role/arn:aws:iam::123456789012:user/Jane` is a valid role ARN: a role named Jane, at path
    `/arn:aws:iam::123456789012:user/`. The outer ARN is a role and stays. The `arn:` inside it
    starts a user ARN, which matches, so the role's name is removed. That is kept on purpose:
    removing too much is the safer error, since a role's name lost costs less than a person's
    name kept.
  - `missing-field`: `arn:aws:iam:123456789012:user/John` has five fields. It stays, `John`
    included.
  - `region-filled-in`: every IAM and STS ARN form AWS lists has an empty region [U2]. One with
    `us-east-1` filled in is not AWS's, and it stays, `Jane` included.
  - `empty-partition`: `arn::iam::…`. The partitions AWS lists are `aws`, `aws-cn` and
    `aws-us-gov` [U8]. An empty one is not a match, and it stays, `John` included.
  - `no-break-space-inside-a-name`: in `Ja` U+00A0 `ne`, the U+00A0 ends the ARN: `Ja` goes and
    `ne` stays. This is accepted, since no AWS name may hold U+00A0 [U3, U4, U5].
  - `already-removed`: a message that already holds the token is unchanged.
  - `empty-user-name`, `empty-federated-user-name`, `empty-u2f-name`, `empty-mfa-name`,
    `empty-session`: nothing follows the type, or the role's slash. AWS's minimum lengths allow no
    empty user, session, federated or MFA device name [U3, U4, U5, MFA]; the token replaces the
    empty text all the same, so every match ends in the token, whatever follows its type.
  - `assumed-role-without-session`: `assumed-role/Accounting-Role` has no second slash, so it holds
    no session, and nothing changes.
  - `two-thousand-characters`: exactly 2,000 characters. AWS's `User: ` lead-in, then 105 copies of
    `arn:a:iam:::user/<c>`, one space apart: the shortest text the grammar reads as a user ARN with
    a name, with a one-letter partition, an empty account and a one-character name. The names cycle
    through all 69 ASCII characters of the user name pattern `[\w+=,.@-]` [U4].
    6 + 105 × 18 + 104 = 2,000. Without the lead-in, no number of these ARNs joined by single
    spaces makes 2,000, because 19 × n − 1 = 2,000 has no whole n. Each name grows by 8
    characters, so the `want` is 2,840 characters.

The most a strip can add: the shortest ARN it rewrites is 16 characters, `arn:a:iam:::u2f/` or
`arn:a:iam:::mfa/` with an empty name, and it gains 9. Two of them need a character outside the
range between them, so a message of n characters holds at most ⌊(n + 1) / 17⌋ of them and
strips to at most n + 9 × ⌊(n + 1) / 17⌋ characters. For 2,000 characters that is 117 of them and
3,053 characters, which is the bound a store of stripped messages must allow.

## Not covered here

This table tests the grammar alone. It does not cover:
- the principal-ID form `AROAIDPPEZS35WEXAMPLE:AssumedRoleSessionName` [U9], which holds no `arn:`;
- the collector's pass that replaces its caller's principal ID where it stands outside an ARN. That
  pass and the principal-ID form belong with the collector's own tests, not this table;
- a person named outside an ARN. AWS says "Some AWS services do not support this access denied
  error message format" [U1], and the grammar reads ARNs, not sentences.

## Sources

- [U1] https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html
- [U2] https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
- [U3] https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- [U4] https://docs.aws.amazon.com/IAM/latest/APIReference/API_User.html
- [U5] https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
- [U6] https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
- [U7] https://docs.aws.amazon.com/singlesignon/latest/userguide/referencingpermissionsets.html
- [U8] https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
- [U9] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
- [ROLE] https://docs.aws.amazon.com/IAM/latest/APIReference/API_Role.html
- [MFA] https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateVirtualMFADevice.html
- [PS] https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreatePermissionSet.html
- [IDS] https://docs.aws.amazon.com/service-authorization/latest/reference/list_identitystore.html
- [ORG] https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html
