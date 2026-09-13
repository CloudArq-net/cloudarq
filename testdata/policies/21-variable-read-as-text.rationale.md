# 21 — a variable AWS reads as text is exact, and the grant says so

Hand-written fixture, 2026-09-13.

## Document

No `Version` member. One GitHub statement pinning `aud` and pinning `sub`
to `${aws:username}` under `StringEquals`.

## Expected

`{aud="sts.amazonaws.com", sub="${aws:username}"}`, exact: the one subject
spelled `${aws:username}`, which no GitHub token carries. The grant
carries a `variable-is-literal` anomaly on `sub` whose Construct is
`${aws:username}` and whose sentence is
`the value "${aws:username}" on sub holds "${aws:username}", which is literal text because this document's Version does not resolve policy variables; if a variable was meant, the condition does not do what it looks like it does`.
No caveat: the anomaly is a fact about the document, not about admission.

## Why

The version page: "For example, variables such as ${aws:username} aren't
recognized as variables and are instead treated as literal strings in the
policy", said of a policy without `"Version": "2012-10-17"`, and the
variables page says the same of a document with no Version element at
all. So the admitted set is the literal string and is exact; case 10
already pins that.

What case 10 did not pin is the sentence. A customer who wrote a variable
and got a literal has a condition that does not do what it looks like it
does, which the brief names as the most valuable single sentence this
product prints, and an earlier draft printed nothing: the grant was exact
and silent. The anomaly is informational, kind `variable-is-literal`, so
`Exact` stays true and a reporter still has the fact to print. The same
note is recorded for a key holding `${` under such a Version (case 20).

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §5, §10
