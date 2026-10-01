# 14 — a Deny the parser could not evaluate is a doubt wherever it stands

The role's trust policy allows `sub` like `repo:acme/*` and denies, through `StringNotLike`,
every `sub` but `repo:acme/tools:*`. AWS evaluates an explicit Deny over any Allow (IAM User
Guide, *Policy evaluation logic*), and `StringNotLike` is "Negated case-sensitive matching" that
is also true when the key is absent from the request ("If the policy condition requires that the
key is *not* matched, such as `StringNotLike` or `ArnNotLike`, and the right key is not present,
the condition is *true*": IAM User Guide, *IAM JSON policy elements: Condition operators*, the
note at the top of the page and the "String condition operators" table), so the role in fact
admits only the tools repository. The lattice has no
complement, so the AWS parser (`internal/parse/aws`, read 2026-09-13) cannot express the Deny:
it emits the Deny as a grant that admits nothing, with two caveats, `this Deny statement could
not be fully evaluated, so it is not applied; the admitted set is an upper bound` and the
`StringNotLike` explanation. One application trusts the GitHub Actions issuer for
`repo:acme/infra:*`.

Read as it stands, the Deny provably misses the overlap, and a join that trusted that reading
would call the pair `Established` with the example `repo:acme/infra:`, an identity AWS in fact
refuses. For a Deny, an admitted set read as an upper bound is a **lower** bound on what is
denied: what it denies is at least what was read, and may be more. So a Deny read with a caveat
counts against every pair on its target whatever its reach, and the sentence carries the
caveats as the reason the denial could not be ruled out.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; role arn:aws:iam::111111111111:role/deploy also denies identities from https://token.actions.githubusercontent.com, and whether these are among them could not be decided (StringNotLike on sub admits every value but the ones listed and passes when the claim is absent; this parser does not model complements, so the claim is not constrained at statement[1].Condition; this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound at statement[1]).

The Deny is never a side. Its evidence is the `iam:GetRole` record the Allow already carries, so
the provenance holds it once. One link, `Indeterminate`, two records.
