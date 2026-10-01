# 31 — a subject constraint the parser cannot read

A trap: an owner constraint the parser leaves `Unknown` pins nothing.

**Expected.** `SubjectUnderForAllValues` → **platform** (anyone on GitHub), unknown.

**Why.** `ForAllValues:StringLike` passes when the key is absent, so it does not restrict what it
looks like it restricts, and the parser leaves `sub` Unknown. An Unknown pins nothing, so no owner
is named and the place is the platform; an Unknown tenancy claim decided it, so the state is
unknown, never a clean *anyone on GitHub*.

> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-09-23
