# 07 — Null reads backwards

Hand-written fixture, 2026-09-13.

## Document

Three statements, each pinning `aud` and adding `Null` on `sub`: the string
`"true"`, the string `"false"`, and the JSON boolean `true`.

## Expected

Each projects `{aud="sts.amazonaws.com", sub=?("Null")}`, inexact, with a
caveat on `sub` and an `unmodelled-construct` anomaly naming `Null`. The
sentences say which way each reads:
`Null on sub is "true": the claim must be absent, which this parser cannot express, so the claim is not constrained`
for the first and third, and
`Null on sub is "false": the claim must be present, which this parser cannot express, so the claim is not constrained`
for the second.

## Why

The operators page: "use either true (the key doesn't exist — it is null)
or false (the key exists and its value is not null)." So `"true"` admits
only tokens without `sub` and `"false"` only tokens with one. Neither
"absent" nor "present" is a set of values a StringSet can state, so both
are Unknown; Unknown admits every token, which is a superset of each. What
the parser can do is print the polarity in plain words, because the
sentence is where a reader is misled.

The pages read show the value as a JSON string. The brief says AWS also
accepts the boolean form; nothing read here confirms or denies it, and
nothing rests on it, since both forms map to the same Unknown with the
same sentence. A value that is neither, such as `"maybe"`, is Unknown with
a sentence quoting it.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §7
