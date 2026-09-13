# 09 — every operator family this parser does not model, and one AWS does not have

Hand-written fixture, 2026-09-13.

## Document

`StringEquals` on `aud`, then `ArnLike`, `Bool`, `NumericLessThan`,
`DateGreaterThan`, `IpAddress` and `BinaryEquals`, each on a different
claim, and `StringFuzzyMatch`, which is not an AWS operator and stands for
the one AWS adds next year.

## Expected

`{actor=?("StringFuzzyMatch"), aud="sts.amazonaws.com", iat=?("DateGreaterThan"), jti=?("BinaryEquals"), repository_visibility=?("Bool"), run_attempt=?("NumericLessThan"), runner_ip=?("IpAddress"), sub=?("ArnLike")}`,
inexact, with a caveat on each of the seven claims and an
`unmodelled-construct` anomaly per operator whose sentence is
`operator <name> on <claim> is not modelled by this parser, so the claim is not constrained`,
the name spelled as AWS spells it for the six operators AWS documents and
quoted, `operator "StringFuzzyMatch" on actor …`, for the one it does not,
so that an empty or lookalike spelling is visible in the sentence.
`aud` is the one constraint that holds: a token with only `aud` is admitted
and one with only `sub` is not.

## Why

The operators page documents the string, numeric, date, boolean, binary,
IP address and ARN families ("The ArnEquals and ArnLike condition operators
behave identically"). Only the two string operators this parser can state
as sets, `StringEquals` and `StringLike`, narrow a claim; every other name,
documented or not, contributes Unknown to its own claim with an anomaly
naming it, and nothing is skipped. An operator that is not recognised
because AWS has not invented it yet must get the same answer as one that is
not modelled yet, or the day AWS adds one the tool reports a narrower set
than the policy grants. `StringFuzzyMatch` is invented for this fixture to
pin that; IAM would refuse a document carrying it.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §9
