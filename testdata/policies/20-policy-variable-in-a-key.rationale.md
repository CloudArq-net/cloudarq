# 20 — a policy variable in a condition key

Hand-written fixture, 2026-09-13.

## Document

Version `2012-10-17`. `VariableInTheClaimPosition` pins `aud` and puts
`${aws:username}` where a claim name goes:
`token.actions.githubusercontent.com:${aws:username}`.
`VariableInTheProviderPosition` puts `${aws:PrincipalTag/provider}` where
the provider identifier goes.

## Expected

- `VariableInTheClaimPosition`: `{${aws:username}=?("${aws:username}"), aud="sts.amazonaws.com"}`,
  inexact, with a caveat on the claim `${aws:username}` and an
  `unmodelled-construct` anomaly whose Construct is `${aws:username}` and
  whose sentence is
  `the condition key "token.actions.githubusercontent.com:${aws:username}" holds the policy variable ${aws:username}; AWS documents variables in condition values and the Resource element, not in keys, so which key it names is not known and the claim is not constrained`.
  A token with `aud` alone is admitted.
- `VariableInTheProviderPosition`: everything, inexact, the same shape of
  anomaly on the claim `${aws:principaltag/provider}:sub`.

## Why

The variables page: "You can use policy variables in the Resource element
and in string comparisons in the Condition element." A key is neither, so
by that sentence AWS reads the key as the literal text, which names no
context key, and the operators page then makes the condition false: "If
the key that you specify in a policy condition is not present in the
request context, the values do not match and the condition is false."
Under that reading each statement admits nothing.

An earlier draft produced exactly that: it read `${aws:username}` as a
claim name, put an exact constraint on a claim no token carries, and
called the grant exact. The brief's rule for variables is that one is
never compared as a literal, and the page that says where a variable may
go does not say what IAM does with one somewhere else; whether IAM refuses
the document, ignores the key or compares it as text is not stated.
Unknown on that key, declared, is never narrower than any of those, and
the sentence names the variable so a reader can see what was meant.

Under `2008-10-17`, or with no Version, the variables page says such text
"is treated as literal strings in the policy", so the key is a key like
any other and is read as written; the grant then carries a
`variable-is-literal` note, as case 21 shows for a value.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §10
