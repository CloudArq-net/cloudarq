# 50 — an unread constraint on the subject beside an open one

Case 31 with an open pattern added on the same claim.

**Expected.** `OpenSubjectBesideAnUnreadOne` → **platform** (anyone on GitHub), unknown.

**Why.** The parser does not model `ForAnyValue` and leaves `sub` Unknown there. The `StringLike`
beside it is read, and `repo:*` pins no owner. Meeting the two keeps the read pattern alone, since
an unread constraint can only narrow (`Unknown` is the identity under `Meet`), so the term shows
`sub` as `repo:*` and the caveat is the one trace of the other. That constraint names `acme` and
could have pinned the grant to it. Nobody read it, so the state is unknown, as it is for case 31,
which has the unread constraint alone. The place is the platform either way; a clean *anyone on
GitHub* would say the engine read a condition it did not.

> "The ForAnyValue qualifier tests whether at least one member of the set of request context key values matches at least one member of the set of context key values in your policy condition." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html · read 2026-09-23
> "Do not use condition set operators ForAllValues or ForAnyValue with single-valued context keys." — the same page · read 2026-09-23
> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-09-23
