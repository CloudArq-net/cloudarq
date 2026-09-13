# 04 — the same key twice in one operator block

Hand-written fixture, 2026-09-13.

## Document

Under one `StringEquals`: `token.actions.githubusercontent.com:sub` pinned
to the main branch, then `Token.Actions.GitHubUserContent.com:SUB` pinned
to the dev branch, beside an `aud`.

## Expected

`{aud="sts.amazonaws.com", sub=?("duplicate key token.actions.githubusercontent.com:sub")}`,
inexact, with a caveat on `sub` and a `duplicate-key` anomaly whose
Construct is `StringEquals` and whose sentence is
`the key "token.actions.githubusercontent.com:sub" appears more than once under StringEquals; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained`.
Every `sub` is admitted; `aud` is still required.

## Why

The grammar page: "Individual elements must not contain multiple instances
of the same key. For example, you cannot include the Effect block twice in
the same statement." RFC 8259 §4 says receivers of a duplicate name behave
unpredictably. Which value a deployed copy of this document carries is
therefore not stated anywhere: a decoder that keeps the last would pin
`dev`, one that keeps the first would pin `main`, and one that rejects the
document deploys nothing. Guessing either branch reports a role as pinned
to a branch it may not be pinned to. Unknown on `sub` admits both and is
the only answer that is never narrower than the deployment.

The two spellings are one key because context key names are not
case-sensitive (case 03), so the duplicate test runs on the folded name; a
test on the verbatim names would have met the two constraints and produced
a provably empty set with no caveat, the worst output this program can
produce. The fold is ASCII case, the one AWS documents by example and the
one every key comparison in this parser uses, so that the duplicate test
and the provider-identifier comparison cannot disagree about which keys
are one key. What AWS does with a letter outside ASCII is not documented;
case 19 says what happens to a key holding one.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html (fetched 2026-09-13)
- https://www.rfc-editor.org/rfc/rfc8259#section-4
- specs/B2-aws-trust-policy-parser.md §4
