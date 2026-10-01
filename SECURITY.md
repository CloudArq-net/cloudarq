# Reporting a vulnerability

Report it privately: through GitHub's private vulnerability reporting on this repository
(**Report a vulnerability** under the **Security** tab), or by email to
**support@cloudarq.net**. Please do not open a public issue, pull request or discussion for a
vulnerability.

A report is acknowledged within three working days. The fix and an advisory are published
together, and we ask that the report stay private until then, or for 90 days from the report,
whichever comes first.

Include what you can of:

- the input: the trust policy, and the token if you used `--token`, with account ids and
  organisation names replaced if they are real;
- the exact command line and the output of `cloudarq version`;
- what the command printed, and what it should have printed;
- for a wrong answer, the AWS documentation that says how AWS reads the policy.

## Supported versions

The latest release, and `main`. Fixes are released as a new version and listed in
[CHANGELOG.md](CHANGELOG.md).

## In scope

CloudArq's answer is used to decide who may assume a role, so an answer that shows fewer
people than the policy admits is treated as a vulnerability, not only as a bug:

- a grant placed in a ring nearer to you than the identities it admits;
- a token reported as not admitted by a grant that AWS would accept under the same policy;
- a condition reported as restricting a claim when AWS does not apply it, or a condition the
  engine did not evaluate that is not marked `not evaluated`;
- an admitted set shown as exact when it is only an upper bound;
- a ring placement shown as `exact` that a condition the engine did not read could move
  nearer.

Also in scope:

- input that makes the command or the WebAssembly module crash, hang, or use memory out of
  proportion to its size;
- policy or token content that reaches the terminal as a control sequence;
- the command reading any file other than the one it is given, consulting an environment
  variable other than `NO_COLOR`, writing a file, or making a network request;
- the same classes of defect in the census module,
  [`github.com/CloudArq-net/issuers`](https://github.com/CloudArq-net/issuers), when they
  change an answer of this engine.

## Out of scope

- An answer wider than what AWS enforces, where the answer says the set is an upper bound or
  a claim was not evaluated. That is the engine's stated reading of what it cannot prove.
  If you think it could prove more, an issue is welcome.
- Vulnerabilities in Go or in other projects this repository builds with; please report
  those to the project concerned.
